/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    balance::Completion,
    clock::Clock,
    coordinator::{Shutdown, shut_down},
    dispatch::{BalanceCounters, Reply},
    server::{Channel, StorageServer},
    storage::{envelope_error, reply_error},
};
use crate::{
    api::error::ErrorCode,
    codec::DecodeError,
    transport::{PendingReply, ProtocolVersion, TransportError},
    wire::{self, Dialect, GetKeyReply, GetKeyValuesReply, GetValueReply, ReplyError},
};
use bytes::Bytes;
use crossbeam_utils::CachePadded;
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll, ready},
};
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};

const MAX_LAGGING_REQUESTS_OUTSTANDING: usize = 100_000;

#[derive(Clone)]
pub(crate) struct Lagging {
    sender: UnboundedSender<LaggingRequest>,
    clock: Clock,
}

pub(crate) struct LaggingRequest {
    reply: PendingReply,
    server: Arc<StorageServer>,
    clock: Clock,
    channel: Channel,
    settled: bool,
    delta: f64,
    started: Option<f64>,
}

#[derive(Debug, PartialEq)]
struct Settled {
    penalty: Option<f64>,
    completion: Completion,
    broken_promise: bool,
}

impl Lagging {
    pub(crate) fn spawn(
        runtime: &Handle,
        shutdown: Shutdown,
        clock: Clock,
        counters: Arc<CachePadded<BalanceCounters>>,
    ) -> Self {
        let (sender, receiver) = unbounded_channel();
        runtime.spawn(collect(
            receiver,
            shutdown,
            counters,
            MAX_LAGGING_REQUESTS_OUTSTANDING,
        ));
        Lagging { sender, clock }
    }

    pub(crate) fn push(
        &self,
        reply: PendingReply,
        server: Arc<StorageServer>,
        channel: Channel,
        delta: f64,
        started: Option<f64>,
    ) {
        let _ = self.sender.send(LaggingRequest {
            reply,
            server,
            clock: self.clock,
            channel,
            settled: false,
            delta,
            started,
        });
    }
}

impl LaggingRequest {
    fn release(
        &self,
        now: f64,
        elapsed: Option<f64>,
        penalty: Option<f64>,
        completion: Completion,
    ) {
        self.server
            .queue(self.channel)
            .lock()
            .end_request(now, self.delta, elapsed, penalty, completion);
    }
}

impl Future for LaggingRequest {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let request = self.get_mut();
        let result = ready!(Pin::new(&mut request.reply).poll(cx));
        let settled = settle(request.channel, result);
        let now = request.clock.now();
        request.release(
            now,
            request.started.map(|started| now - started),
            settled.penalty,
            settled.completion,
        );
        request.settled = true;
        if settled.broken_promise {
            let server = &request.server;
            server
                .peer()
                .mark_endpoint_failed(server.token(request.channel));
        }
        Poll::Ready(())
    }
}

impl Drop for LaggingRequest {
    fn drop(&mut self) {
        if !self.settled {
            self.release(self.clock.now(), None, None, Completion::NoResponse);
        }
    }
}

async fn collect(
    mut receiver: UnboundedReceiver<LaggingRequest>,
    mut shutdown: Shutdown,
    counters: Arc<CachePadded<BalanceCounters>>,
    cap: usize,
) {
    let mut lagging = FuturesUnordered::new();
    loop {
        select! {
            () = shut_down(&mut shutdown) => return,
            request = receiver.recv() => {
                let Some(request) = request else {
                    return;
                };
                if lagging.len() >= cap {
                    lagging = FuturesUnordered::new();
                }
                lagging.push(request);
            }
            Some(()) = lagging.next(), if !lagging.is_empty() => {}
        }
        counters.lagging.store(lagging.len(), Ordering::Relaxed);
    }
}

fn settle(channel: Channel, result: Result<(Bytes, ProtocolVersion), TransportError>) -> Settled {
    let (bytes, protocol) = match result {
        Ok(reply) => reply,
        Err(error) => {
            return Settled {
                penalty: None,
                completion: Completion::of_transport(&error),
                broken_promise: false,
            };
        }
    };
    let dialect = Dialect::of(protocol.get());
    match channel {
        Channel::Value => header(dialect, GetValueReply::decode(dialect, &bytes), |reply| {
            (reply.penalty, reply.error)
        }),
        Channel::Key => header(dialect, GetKeyReply::decode(dialect, &bytes), |reply| {
            (reply.penalty, reply.error)
        }),
        Channel::KeyValues => header(
            dialect,
            GetKeyValuesReply::decode(dialect, &bytes),
            |reply| (reply.penalty, reply.error),
        ),
    }
}

fn header<V>(
    dialect: Dialect,
    result: Result<wire::Reply<V>, DecodeError>,
    fields: impl FnOnce(&V) -> (f64, Option<ReplyError>),
) -> Settled {
    let reply: Reply<()> = match result {
        Ok(wire::Reply::Value(reply)) => {
            let (penalty, error) = fields(&reply);
            Reply {
                penalty: Some(penalty),
                result: error.map_or(Ok(()), |error| Err(reply_error(dialect, error))),
            }
        }
        result => envelope_error(dialect, result),
    };
    Settled {
        penalty: reply.penalty,
        completion: reply.completion(),
        broken_promise: reply.result == Err(ErrorCode::BROKEN_PROMISE),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/lagging/tests.rs"]
mod tests;
