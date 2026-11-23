/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Found, Lookup, SECONDS_PER_MINUTE, Snapshot, busy, find, lookup,
    subscription::{Delivery, EwsSubscription, Next, ServerBusy},
};
use crate::{
    ews::{
        context::EwsContext,
        reply::{EWS_CONTENT_TYPE, RESPONSE_CAPACITY, ews_response},
    },
    push::{ExchangePush, ExchangeReceiver},
    session::ExchangeSessionSlot,
};
use common::{
    Server,
    ipc::{PushNotification, ViewerStateChange},
};
use exchange_proto::ews::{
    MessageResult, Operation, Status,
    envelope::XmlDecl,
    requests::notification::GetStreamingEvents,
    responses::notification::{GetStreamingEventsMessage, Notification},
    schema::{ConnectionStatus, ResponseCode},
    types::ids::SubscriptionId,
};
use futures::future::select_all;
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::HttpResponse;
use hyper::{
    StatusCode,
    body::{Bytes, Frame},
};
use std::{borrow::Cow, sync::Arc, time::Duration};
use store::write::now;
use tokio::time::{Instant, sleep_until};
use utils::map::bitmap::Bitmap;

const MAX_STREAM_SUBSCRIPTIONS: usize = 200;
#[cfg(not(stalwart_tests))]
const KEEPALIVE: Duration = Duration::from_secs(45);
#[cfg(stalwart_tests)]
const KEEPALIVE: Duration = Duration::from_secs(2);
const TOO_MANY: &str = "A stream can carry at most 200 subscriptions.";
const INVALID: &str = "Subscription is invalid.";
const REPLACED: &str = "A newer stream was opened for the subscription.";
const UNSUBSCRIBED: &str = "The subscription was removed.";

struct Watched {
    subscription: Arc<EwsSubscription>,
    generation: u64,
}

struct EventStream {
    server: Server,
    ctx: EwsContext,
    watched: Vec<Watched>,
    receiver: ExchangeReceiver,
    notifications: Vec<PushNotification>,
    deadline: Instant,
    pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wake {
    Changed,
    Tick,
    Subscription,
    End,
}

#[derive(Default)]
struct Dropped {
    replaced: Vec<SubscriptionId<'static>>,
    unsubscribed: Vec<SubscriptionId<'static>>,
    busy: Vec<SubscriptionId<'static>>,
}

struct Scanned {
    notifications: Vec<Notification<'static>>,
    more: bool,
    busy: Vec<Arc<EwsSubscription>>,
}

pub(crate) async fn get_streaming_events(
    server: &Server,
    ctx: &EwsContext,
    principal: u32,
    request: &GetStreamingEvents<'_>,
) -> trc::Result<HttpResponse> {
    if request.subscription_ids.len() > MAX_STREAM_SUBSCRIPTIONS {
        let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
        let mut messages = ctx
            .stream_envelope(&mut out, XmlDecl::Emit)
            .shape_a(Operation::GetStreamingEvents);
        messages
            .begin_message(&Status::error(ResponseCode::ErrorInvalidRequest, TOO_MANY))
            .finish();
        messages.finish();
        return Ok(ews_response(out));
    }
    let mut subscriptions: Vec<Arc<EwsSubscription>> =
        Vec::with_capacity(request.subscription_ids.len());
    let mut invalid = Vec::new();
    for id in &request.subscription_ids {
        match lookup(server, ctx, principal, id) {
            Ok(subscription) if subscription.is_streaming() => {
                if !subscriptions
                    .iter()
                    .any(|known| Arc::ptr_eq(known, &subscription))
                {
                    subscriptions.push(subscription);
                }
            }
            Ok(_) | Err(Lookup::NotFound | Lookup::Denied) => {
                invalid.push(SubscriptionId(Cow::Owned(id.0.as_ref().into())));
            }
        }
    }
    if !invalid.is_empty() || subscriptions.is_empty() {
        let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
        let mut messages = ctx
            .stream_envelope(&mut out, XmlDecl::Emit)
            .shape_a(Operation::GetStreamingEvents);
        messages.message(&MessageResult {
            status: Status::error(ResponseCode::ErrorInvalidSubscription, INVALID),
            body: Some(GetStreamingEventsMessage {
                error_subscription_ids: invalid,
                ..Default::default()
            }),
        });
        messages.finish();
        write_closed(ctx, &mut out, XmlDecl::Omit);
        return Ok(ews_response(out));
    }

    let mut types = Bitmap::default();
    for subscription in &subscriptions {
        subscription.scope.add_wake_types(&mut types);
    }
    types.intersection(&ctx.account.data_types);
    let timeout = Duration::from_secs(u64::from(request.connection_timeout) * SECONDS_PER_MINUTE)
        .min(server.core.exchange.max_heartbeat);
    let mut stream = EventStream {
        receiver: server.subscribe_exchange_account(ctx.account.account_id, types),
        server: server.clone(),
        ctx: ctx.clone(),
        watched: subscriptions
            .into_iter()
            .map(|subscription| Watched {
                generation: subscription.open_stream(),
                subscription,
            })
            .collect(),
        notifications: Vec::new(),
        deadline: Instant::now() + timeout,
        pending: true,
    };
    let body = async_stream::stream! {
        let mut decl = XmlDecl::Emit;
        loop {
            let wake = if stream.pending { Wake::Changed } else { stream.wait().await };
            let (chunk, open) = if wake == Wake::End {
                (stream.closed(decl), false)
            } else {
                stream.chunk(decl, wake).await
            };
            decl = XmlDecl::Omit;
            yield Ok::<_, hyper::Error>(Frame::data(chunk));
            if !open {
                break;
            }
        }
    };
    Ok(HttpResponse::new(StatusCode::OK)
        .with_content_type(EWS_CONTENT_TYPE)
        .with_no_store()
        .with_stream_body(BoxBody::new(StreamBody::new(body))))
}

impl EventStream {
    async fn wait(&mut self) -> Wake {
        let mut waits = self
            .watched
            .iter()
            .map(|watched| {
                let mut notified = Box::pin(watched.subscription.wake.notified());
                notified.as_mut().enable();
                notified
            })
            .collect::<Vec<_>>();
        if waits.is_empty() {
            return Wake::End;
        }
        if self.watched.iter().any(Watched::dropped) {
            return Wake::Subscription;
        }
        let now = Instant::now();
        if now >= self.deadline {
            return Wake::End;
        }
        let tick = (now + KEEPALIVE).min(self.deadline);
        loop {
            self.notifications.clear();
            tokio::select! {
                open = self.receiver.recv(&mut self.notifications) => {
                    if !open {
                        return Wake::End;
                    }
                    let account_id = self.ctx.account.account_id;
                    if self.notifications.iter().any(|notification| match notification {
                        PushNotification::StateChange(change)
                        | PushNotification::ViewerStateChange(ViewerStateChange { change, .. }) => {
                            change.account_id == account_id
                        }
                        PushNotification::CalendarAlert(_) | PushNotification::EmailPush(_) => false,
                    }) {
                        return Wake::Changed;
                    }
                }
                _ = select_all(waits.iter_mut()) => return Wake::Subscription,
                _ = sleep_until(tick) => {
                    return if Instant::now() >= self.deadline { Wake::End } else { Wake::Tick };
                }
            }
        }
    }

    async fn chunk(&mut self, decl: XmlDecl, wake: Wake) -> (Bytes, bool) {
        let mut dropped = self.retain_live();
        self.pending = false;
        let mut notifications = Vec::new();
        if wake == Wake::Changed && !self.watched.is_empty() {
            match self.scan().await {
                Ok(scanned) => {
                    notifications = scanned.notifications;
                    self.pending = scanned.more;
                    self.drop_busy(&scanned.busy, &mut dropped);
                }
                Err(err) => {
                    trc::error!(err.details("Failed to scan EWS streaming subscriptions"));
                    let chunk = self.write(decl, notifications, dropped, ConnectionStatus::Closed);
                    return (chunk, false);
                }
            }
        }
        let open = !self.watched.is_empty();
        let status = if open {
            ConnectionStatus::Ok
        } else {
            ConnectionStatus::Closed
        };
        (self.write(decl, notifications, dropped, status), open)
    }

    async fn scan(&self) -> trc::Result<Scanned> {
        let server = self.server.clone();
        let ctx = self.ctx.clone();
        let subscriptions = self
            .watched
            .iter()
            .map(|watched| watched.subscription.clone())
            .collect::<Vec<_>>();
        match tokio::spawn(async move { scan_all(&server, &ctx, &subscriptions).await }).await {
            Ok(result) => result,
            Err(_) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
                .into_err()
                .caused_by(trc::location!())),
        }
    }

    fn drop_busy(&mut self, busy: &[Arc<EwsSubscription>], dropped: &mut Dropped) {
        for subscription in busy {
            self.server.remove_exchange_session::<EwsSubscription>(
                subscription.id.account,
                subscription.id.id,
            );
            subscription.close();
            self.watched
                .retain(|watched| !Arc::ptr_eq(&watched.subscription, subscription));
            dropped.busy.push(SubscriptionId(Cow::Owned(
                subscription.id.encode().as_str().into(),
            )));
        }
    }

    fn closed(&self, decl: XmlDecl) -> Bytes {
        let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
        write_closed(&self.ctx, &mut out, decl);
        Bytes::from(out)
    }

    fn retain_live(&mut self) -> Dropped {
        let mut dropped = Dropped::default();
        let server = &self.server;
        let now = now();
        self.watched.retain(|watched| {
            let subscription = &watched.subscription;
            let live = matches!(
                find(server, subscription.id.account, subscription.id.id, now),
                Found::Live(current) if Arc::ptr_eq(&current, subscription)
            );
            let target = if !live {
                &mut dropped.unsubscribed
            } else if subscription.stream_generation() != watched.generation {
                &mut dropped.replaced
            } else {
                return true;
            };
            target.push(SubscriptionId(Cow::Owned(
                subscription.id.encode().as_str().into(),
            )));
            false
        });
        dropped
    }

    fn write(
        &self,
        decl: XmlDecl,
        notifications: Vec<Notification<'static>>,
        dropped: Dropped,
        status: ConnectionStatus,
    ) -> Bytes {
        let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
        let mut messages = self
            .ctx
            .stream_envelope(&mut out, decl)
            .shape_a(Operation::GetStreamingEvents);
        messages.message(&MessageResult {
            status: Status::SUCCESS,
            body: Some(GetStreamingEventsMessage {
                notifications,
                error_subscription_ids: Vec::new(),
                connection_status: Some(status),
            }),
        });
        for (status, ids) in [
            (
                Status::error(ResponseCode::ErrorNewEventStreamConnectionOpened, REPLACED),
                dropped.replaced,
            ),
            (
                Status::error(ResponseCode::ErrorSubscriptionUnsubscribed, UNSUBSCRIBED),
                dropped.unsubscribed,
            ),
            (busy(), dropped.busy),
        ] {
            if !ids.is_empty() {
                messages.message(&MessageResult {
                    status,
                    body: Some(GetStreamingEventsMessage {
                        error_subscription_ids: ids,
                        ..Default::default()
                    }),
                });
            }
        }
        messages.finish();
        Bytes::from(out)
    }
}

fn write_closed(ctx: &EwsContext, out: &mut Vec<u8>, decl: XmlDecl) {
    let mut messages = ctx
        .stream_envelope(out, decl)
        .shape_a(Operation::GetStreamingEvents);
    messages.message(&MessageResult {
        status: Status::SUCCESS,
        body: Some(GetStreamingEventsMessage {
            connection_status: Some(ConnectionStatus::Closed),
            ..Default::default()
        }),
    });
    messages.finish();
}

async fn scan_all(
    server: &Server,
    ctx: &EwsContext,
    subscriptions: &[Arc<EwsSubscription>],
) -> trc::Result<Scanned> {
    let mut snapshot = Snapshot::load(server, ctx).await?;
    snapshot
        .load_logs(server, ctx.account.account_id, subscriptions)
        .await?;
    let now = now();
    let mut scanned = Scanned {
        notifications: Vec::new(),
        more: false,
        busy: Vec::new(),
    };
    for subscription in subscriptions {
        match subscription.next_batch(&snapshot.input(subscription, now), Delivery::Stream) {
            Ok(Next::Batch(batch) | Next::Replay(batch)) => {
                scanned.more |= batch.more;
                scanned
                    .notifications
                    .push(snapshot.notification(subscription, &batch));
            }
            Ok(Next::Empty | Next::InvalidWatermark | Next::Closed) => {}
            Err(ServerBusy) => scanned.busy.push(subscription.clone()),
        }
    }
    scanned.more |= snapshot.is_behind();
    Ok(scanned)
}

impl Watched {
    fn dropped(&self) -> bool {
        self.subscription.is_closed() || self.subscription.stream_generation() != self.generation
    }
}
