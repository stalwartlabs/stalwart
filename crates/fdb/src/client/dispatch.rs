/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    balance::{AlternativesFailed, Attempts, Completion, Hedging, Selected},
    clock::{Clock, Deadline},
    coordinator::Shutdown,
    expiry::{Deadlines, Precision, Timer},
    lagging::Lagging,
    lookup::ShardLocation,
    server::{Channel, Location, StorageServer},
    transaction::Cancellation,
};
use crate::{
    api::error::{Error, ErrorCode, Result},
    transport::{Peer, PendingReply, ProtocolVersion, Request, TransportError, Uid},
};
use bytes::Bytes;
use crossbeam_utils::CachePadded;
use parking_lot::Mutex;
use std::{
    future::{Future, poll_fn},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    runtime::Handle,
    select,
    sync::watch,
    time::{Instant, sleep},
};

type TransportReply = std::result::Result<(Bytes, ProtocolVersion), TransportError>;

const UNCOUNTED: f64 = 0.0;

pub(crate) struct Reply<T> {
    pub(crate) penalty: Option<f64>,
    pub(crate) result: Result<T, ErrorCode>,
}

impl<T> Reply<T> {
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Reply<U> {
        Reply {
            penalty: self.penalty,
            result: self.result.map(f),
        }
    }

    pub(crate) fn completion(&self) -> Completion {
        match self.result {
            Ok(_) => Completion::Response,
            Err(code) => Completion::from_error_code(code),
        }
    }
}

pub(crate) struct Balancer {
    clock: Clock,
    alternatives_failed: Mutex<AlternativesFailed>,
    hedging: CachePadded<Hedging>,
    hedges: Arc<Deadlines>,
    lagging: Lagging,
    counters: Arc<CachePadded<BalanceCounters>>,
}

#[derive(Default)]
pub(crate) struct BalanceCounters {
    pub(crate) hedges_granted: AtomicU64,
    pub(crate) hedges_refused: AtomicU64,
    pub(crate) lagging: AtomicUsize,
}

struct InFlight<'a, F> {
    balancer: &'a Balancer,
    server: &'a Arc<StorageServer>,
    reply: Option<Request<'a, F>>,
    channel: Channel,
    delta: f64,
    started: f64,
}

pub(crate) struct PendingRequest {
    reply: Option<PendingReply>,
    shard: ShardLocation,
    lagging: Lagging,
    replica: usize,
    channel: Channel,
}

enum Outcome<T> {
    Done(T),
    Retry,
}

struct First<'a, F> {
    in_flight: InFlight<'a, F>,
    tried_all: bool,
}

struct HedgeRace<'a, R> {
    reply: R,
    timer: Timer<'a>,
    at: Instant,
}

enum Pair<A, B> {
    First(A),
    Other(B),
}

impl Balancer {
    pub(crate) fn new(runtime: &Handle, shutdown: Shutdown) -> Self {
        let clock = Clock::new();
        let counters = Arc::new(CachePadded::new(BalanceCounters::default()));
        Balancer {
            clock,
            alternatives_failed: Mutex::new(AlternativesFailed::new()),
            hedging: CachePadded::new(Hedging::new()),
            hedges: Deadlines::spawn(runtime, shutdown.clone(), Precision::Fine),
            lagging: Lagging::spawn(runtime, shutdown, clock, counters.clone()),
            counters,
        }
    }

    pub(crate) fn counters(&self) -> &BalanceCounters {
        &self.counters
    }

    fn try_hedge(&self) -> bool {
        let granted = self.hedging.try_hedge();
        let counter = if granted {
            &self.counters.hedges_granted
        } else {
            &self.counters.hedges_refused
        };
        counter.fetch_add(1, Ordering::Relaxed);
        granted
    }

    pub(crate) fn now(&self) -> f64 {
        self.clock.now()
    }

    pub(crate) fn clock(&self) -> &Clock {
        &self.clock
    }

    pub(crate) async fn request<T>(
        &self,
        location: &Location,
        channel: Channel,
        encode: impl Fn(Uid, ProtocolVersion, &mut Vec<u8>),
        decode: impl Fn(Bytes, ProtocolVersion) -> Reply<T>,
        cancel: Option<&Cancellation>,
    ) -> Result<T> {
        let mut now = self.clock.now();
        let mut attempts = location.choose_hedged(
            |server| server.measure(channel, now),
            self.hedging.multiplier(),
        );
        loop {
            check_cancel(cancel)?;
            let Some(Selected {
                replica: server,
                backoff,
                tried_all,
                hedge,
                ..
            }) = attempts.select(|server| server.is_healthy(channel))
            else {
                Box::pin(self.wait_for_alternative(location, channel, cancel)).await?;
                attempts.recovered();
                now = self.clock.now();
                continue;
            };
            if backoff > 0.0 {
                sleep(Duration::from_secs_f64(backoff)).await;
                check_cancel(cancel)?;
                now = self.clock.now();
            }
            let mut in_flight = InFlight::start(self, server, channel, now, &encode);
            let raced = if hedge == Some(0.0) {
                None
            } else if let Some(at) =
                hedge.and_then(|delay| self.clock.instant(Deadline::at(now + delay)))
            {
                HedgeRace {
                    reply: &mut in_flight,
                    timer: Timer::new(&self.hedges),
                    at,
                }
                .await
            } else {
                Some((&mut in_flight).await)
            };
            let result = match raced {
                Some(result) => result,
                None if self.try_hedge() => {
                    attempts.failed();
                    let first = First {
                        in_flight,
                        tried_all,
                    };
                    match Box::pin(self.hedged(
                        channel,
                        &mut attempts,
                        first,
                        &encode,
                        &decode,
                        cancel,
                    ))
                    .await?
                    {
                        Outcome::Done(value) => return Ok(value),
                        Outcome::Retry => {
                            now = self.clock.now();
                            continue;
                        }
                    }
                }
                None => (&mut in_flight).await,
            };
            self.hedging.lone_reply();
            match classify(
                result,
                &decode,
                server.peer(),
                server.token(channel),
                tried_all,
                |penalty, completion| in_flight.finish(penalty, completion),
            )? {
                Outcome::Done(value) => return Ok(value),
                Outcome::Retry => {
                    attempts.failed();
                    now = self.clock.now();
                }
            }
        }
    }

    #[cold]
    async fn hedged<'a, T, F>(
        &'a self,
        channel: Channel,
        attempts: &mut Attempts<'a, Arc<StorageServer>>,
        first: First<'a, F>,
        encode: &'a (impl Fn(Uid, ProtocolVersion, &mut Vec<u8>) + 'a),
        decode: &impl Fn(Bytes, ProtocolVersion) -> Reply<T>,
        cancel: Option<&Cancellation>,
    ) -> Result<Outcome<T>>
    where
        F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>),
    {
        let first_token = first.in_flight.server.token(channel);
        let mut first = Some(first);
        loop {
            check_cancel(cancel)?;
            let Some(pending) = first.as_mut() else {
                return Ok(Outcome::Retry);
            };
            let Some(Selected {
                replica: server,
                backoff,
                tried_all,
                ..
            }) = attempts.select(|server| {
                server.is_healthy(channel) && server.token(channel) != first_token
            })
            else {
                let result = (&mut pending.in_flight).await;
                attempts.advance();
                return first.take().map_or(Ok(Outcome::Retry), |first| {
                    first.classify(result, decode, channel)
                });
            };
            let mut other = pin!(async {
                if backoff > 0.0 {
                    sleep(Duration::from_secs_f64(backoff)).await;
                }
                let mut in_flight =
                    InFlight::start(self, server, channel, self.clock.now(), encode);
                ((&mut in_flight).await, in_flight)
            });
            loop {
                let raced = poll_fn(|cx| {
                    if let Some(pending) = first.as_mut()
                        && let Poll::Ready(result) = Pin::new(&mut pending.in_flight).poll(cx)
                    {
                        return Poll::Ready(Pair::First(result));
                    }
                    other.as_mut().poll(cx).map(Pair::Other)
                })
                .await;
                match raced {
                    Pair::First(result) => {
                        if let Some(done) = first.take() {
                            match done.classify(result, decode, channel)? {
                                Outcome::Done(value) => return Ok(Outcome::Done(value)),
                                Outcome::Retry => continue,
                            }
                        }
                    }
                    Pair::Other((result, in_flight)) => {
                        match classify(
                            result,
                            decode,
                            server.peer(),
                            server.token(channel),
                            tried_all,
                            |penalty, completion| in_flight.finish(penalty, completion),
                        )? {
                            Outcome::Done(value) => return Ok(Outcome::Done(value)),
                            Outcome::Retry => {
                                attempts.failed();
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn send(
        &self,
        shard: &ShardLocation,
        channel: Channel,
        encode: impl FnOnce(Uid, ProtocolVersion, &mut Vec<u8>),
    ) -> Option<PendingRequest> {
        let now = self.clock.now();
        let location = shard.location();
        let selected = location
            .choose(|server| server.measure(channel, now))
            .select(|server| server.is_healthy(channel))?;
        let server = selected.replica;
        let reply = server.peer().send(server.token(channel), encode).ok()?;
        Some(PendingRequest {
            reply: Some(reply),
            shard: shard.clone(),
            lagging: self.lagging.clone(),
            replica: selected.index,
            channel,
        })
    }

    pub(crate) async fn receive<T>(
        &self,
        pending: &mut PendingRequest,
        decode: impl Fn(Bytes, ProtocolVersion) -> Reply<T>,
    ) -> Result<Option<T>> {
        let Some(reply) = pending.reply.as_mut() else {
            return Ok(None);
        };
        let result = reply.await;
        pending.reply = None;
        let PendingRequest {
            shard,
            replica,
            channel,
            ..
        } = pending;
        let Some(server) = shard.location().as_slice().get(*replica) else {
            return Ok(None);
        };
        let outcome = classify(
            result,
            &decode,
            server.peer(),
            server.token(*channel),
            false,
            |penalty, completion| {
                server.queue(*channel).lock().end_request(
                    self.clock.now(),
                    UNCOUNTED,
                    None,
                    penalty,
                    completion,
                );
            },
        )?;
        Ok(match outcome {
            Outcome::Done(value) => Some(value),
            Outcome::Retry => None,
        })
    }

    #[cold]
    async fn wait_for_alternative(
        &self,
        location: &Location,
        channel: Channel,
        cancel: Option<&Cancellation>,
    ) -> Result<()> {
        let delay = self.alternatives_failed.lock().delay(self.clock.now());
        let mut deadline = pin!(sleep(Duration::from_secs_f64(delay)));
        let mut states: Vec<_> = location
            .as_slice()
            .iter()
            .map(|server| server.peer().watch_state())
            .collect();
        loop {
            check_cancel(cancel)?;
            if location
                .as_slice()
                .iter()
                .any(|server| server.is_healthy(channel))
            {
                return Ok(());
            }
            let changed = any_state_changed(&mut states);
            select! {
                () = changed => {}
                () = &mut deadline => return Err(Error::new(ErrorCode::ALL_ALTERNATIVES_FAILED)),
            }
        }
    }
}

pub(crate) async fn any_state_changed(states: &mut Vec<watch::Receiver<()>>) {
    states.retain(|state| state.has_changed().is_ok());
    let mut changes: Vec<_> = states
        .iter_mut()
        .map(|state| Box::pin(state.changed()))
        .collect();
    poll_fn(|cx| {
        if changes
            .iter_mut()
            .any(|change| change.as_mut().poll(cx).is_ready())
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}

fn classify<T>(
    result: Result<(Bytes, ProtocolVersion), TransportError>,
    decode: impl Fn(Bytes, ProtocolVersion) -> Reply<T>,
    peer: &Peer,
    token: Uid,
    tried_all: bool,
    release: impl FnOnce(Option<f64>, Completion),
) -> Result<Outcome<T>> {
    match result {
        Ok((bytes, version)) => {
            let reply = decode(bytes, version);
            release(reply.penalty, reply.completion());
            match reply.result {
                Ok(value) => Ok(Outcome::Done(value)),
                Err(ErrorCode::BROKEN_PROMISE) => {
                    peer.mark_endpoint_failed(token);
                    Ok(Outcome::Retry)
                }
                Err(ErrorCode::SERVER_OVERLOADED | ErrorCode::REQUEST_MAYBE_DELIVERED) => {
                    Ok(Outcome::Retry)
                }
                Err(ErrorCode::PROCESS_BEHIND) if !tried_all => Ok(Outcome::Retry),
                Err(code) => Err(Error::new(code)),
            }
        }
        Err(error) => {
            release(None, Completion::of_transport(&error));
            match error {
                TransportError::MaybeDelivered => Ok(Outcome::Retry),
                error => Err(transport_error(error)),
            }
        }
    }
}

impl PendingRequest {
    pub(crate) fn shard(&self) -> &ShardLocation {
        &self.shard
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(reply) = self.reply.take()
            && let Some(server) = self.shard.location().as_slice().get(self.replica)
        {
            self.lagging
                .push(reply, server.clone(), self.channel, UNCOUNTED, None);
        }
    }
}

impl<R: Future + Unpin> Future for HedgeRace<'_, R> {
    type Output = Option<R::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let race = self.get_mut();
        if let Poll::Ready(result) = Pin::new(&mut race.reply).poll(cx) {
            return Poll::Ready(Some(result));
        }
        race.timer.poll_expired(race.at, cx).map(|()| None)
    }
}

impl<F> First<'_, F> {
    fn classify<T>(
        self,
        result: TransportReply,
        decode: impl Fn(Bytes, ProtocolVersion) -> Reply<T>,
        channel: Channel,
    ) -> Result<Outcome<T>> {
        let First {
            in_flight,
            tried_all,
        } = self;
        let server = in_flight.server;
        classify(
            result,
            decode,
            server.peer(),
            server.token(channel),
            tried_all,
            |penalty, completion| in_flight.finish(penalty, completion),
        )
    }
}

impl<'a, F> InFlight<'a, F> {
    fn start(
        balancer: &'a Balancer,
        server: &'a Arc<StorageServer>,
        channel: Channel,
        now: f64,
        encode: F,
    ) -> Self
    where
        F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>),
    {
        let delta = server.queue(channel).lock().add_request(now);
        InFlight {
            balancer,
            server,
            reply: Some(server.peer().request(server.token(channel), encode)),
            channel,
            delta,
            started: now,
        }
    }

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

    fn finish(mut self, penalty: Option<f64>, completion: Completion) {
        self.reply = None;
        let now = self.balancer.clock.now();
        self.release(now, Some(now - self.started), penalty, completion);
    }
}

impl<F: FnOnce(Uid, ProtocolVersion, &mut Vec<u8>)> Future for InFlight<'_, F> {
    type Output = TransportReply;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportReply> {
        match &mut self.get_mut().reply {
            Some(reply) => Pin::new(reply).poll(cx),
            None => Poll::Ready(Err(TransportError::MaybeDelivered)),
        }
    }
}

impl<F> Drop for InFlight<'_, F> {
    fn drop(&mut self) {
        let Some(reply) = self.reply.take() else {
            return;
        };
        match self.server.peer().adopt(reply) {
            Some(pending) => self.balancer.lagging.push(
                pending,
                self.server.clone(),
                self.channel,
                self.delta,
                Some(self.started),
            ),
            None => self.release(
                self.balancer.clock.now(),
                None,
                None,
                Completion::NoResponse,
            ),
        }
    }
}

fn check_cancel(cancel: Option<&Cancellation>) -> Result<()> {
    cancel.map_or(Ok(()), Cancellation::check)
}

#[cold]
pub(crate) fn transport_error(error: TransportError) -> Error {
    Error::new(match error {
        TransportError::Incompatible { .. } => ErrorCode::CLUSTER_VERSION_CHANGED,
        TransportError::EmptyMessage => ErrorCode::INTERNAL_ERROR,
        error => ErrorCode::new(error.code()),
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/dispatch/tests.rs"]
mod tests;
