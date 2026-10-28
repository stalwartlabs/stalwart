/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod metrics;
pub mod queue;
pub mod spans;

use crate::{
    otlp::{
        logs::encode_log,
        request::{Framing, RequestBuilder},
        resource::Resource,
        traces::encode_span,
        value::ValueEncoder,
    },
    transport::{
        TransportError,
        conn::tls_connector,
        endpoint::{Endpoint, Signal, Transport},
        sender::{Headers, Outcome, Sender},
    },
};
use bytes::Bytes;
use queue::{SignalKind, SignalQueue};
use rustls::ClientConfig;
use spans::{SpanTracker, report_discarded_spans, tracks_span};
use std::{
    future::{Future, poll_fn},
    pin::{Pin, pin},
    sync::Arc,
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep_until, timeout_at};
use trc::ipc::subscriber::{EventBatch, SharedInterests, SubscriberBuilder};

pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_DRAIN_TIME: Duration = Duration::from_millis(800);
const MIN_EXPORT_TIMEOUT: Duration = Duration::from_millis(100);
const IDLE_WAKEUP: Duration = Duration::from_secs(365 * 24 * 60 * 60);

#[derive(Clone)]
pub struct OtlpConfig {
    pub endpoint: Endpoint,
    pub transport: Transport,
    pub headers: Headers,
    pub tls: Arc<ClientConfig>,
    pub timeout: Duration,
    pub max_request_bytes: usize,
    pub max_pending_bytes: usize,
}

pub struct OtlpTracer {
    pub otlp: OtlpConfig,
    pub resource: Resource,
    pub throttle: Duration,
    pub export_logs: bool,
    pub export_spans: bool,
}

struct TracerState {
    resource: Resource,
    throttle: Duration,
    timeout: Duration,
    max_request_bytes: usize,
    max_pending_bytes: usize,
    logs: Option<SignalQueue>,
    spans: Option<SignalQueue>,
    tracker: SpanTracker,
    values: ValueEncoder,
}

impl std::fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OtlpTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpTracer")
            .field("otlp", &self.otlp)
            .field("throttle", &self.throttle)
            .field("export_logs", &self.export_logs)
            .field("export_spans", &self.export_spans)
            .finish_non_exhaustive()
    }
}

impl OtlpConfig {
    fn framing(&self) -> Framing {
        match self.transport {
            Transport::Http => Framing::Http,
            Transport::Grpc => Framing::Grpc,
        }
    }

    pub(crate) fn sender(&self, signal: Signal, seed: u64) -> Result<Sender, TransportError> {
        Sender::new(
            self.endpoint.clone(),
            self.transport,
            signal,
            self.headers.clone(),
            self.endpoint
                .is_tls()
                .then(|| tls_connector(&self.tls, self.transport)),
            seed,
        )
    }

    fn max_request_bytes(&self) -> usize {
        self.max_request_bytes.clamp(1, MAX_REQUEST_BYTES)
    }

    fn timeout(&self) -> Duration {
        self.timeout.max(MIN_EXPORT_TIMEOUT)
    }
}

impl OtlpTracer {
    pub fn spawn(self, builder: SubscriberBuilder) -> Result<(), TransportError> {
        let seed = u64::from_be_bytes(self.resource.trace_prefix);
        let queue = |kind: SignalKind, signal: Signal, enabled: bool| {
            enabled
                .then(|| {
                    self.otlp
                        .sender(signal, seed ^ signal as u64)
                        .map(|sender| {
                            SignalQueue::new(
                                kind,
                                RequestBuilder::new(&self.resource, self.otlp.framing()),
                                sender,
                            )
                        })
                })
                .transpose()
        };
        let logs = queue(SignalKind::Logs, Signal::Logs, self.export_logs)?;
        let spans = queue(SignalKind::Spans, Signal::Traces, self.export_spans)?;
        let state = TracerState {
            throttle: self.throttle,
            timeout: self.otlp.timeout(),
            max_request_bytes: self.otlp.max_request_bytes(),
            max_pending_bytes: self.otlp.max_pending_bytes,
            resource: self.resource,
            logs,
            spans,
            tracker: SpanTracker::default(),
            values: ValueEncoder::default(),
        };
        let (_, rx, interests) = builder.register();
        tokio::spawn(state.run(rx, interests));
        Ok(())
    }
}

impl TracerState {
    async fn run(
        mut self,
        mut rx: tokio::sync::mpsc::Receiver<EventBatch>,
        interests: SharedInterests,
    ) {
        let mut logs_slot = pin!(None::<(Sender, Bytes, Instant)>.map(start_send));
        let mut spans_slot = pin!(None::<(Sender, Bytes, Instant)>.map(start_send));
        let timer = sleep_until(Instant::now() + IDLE_WAKEUP);
        let mut timer = pin!(timer);

        loop {
            let now = Instant::now();
            let deadline = now + self.timeout;
            if logs_slot.is_none()
                && let Some((sender, body)) = self
                    .logs
                    .as_mut()
                    .and_then(|queue| queue.next_send(&self.resource, self.throttle, now))
            {
                logs_slot.set(Some(start_send((sender, body, deadline))));
            }
            if spans_slot.is_none()
                && let Some((sender, body)) = self
                    .spans
                    .as_mut()
                    .and_then(|queue| queue.next_send(&self.resource, self.throttle, now))
            {
                spans_slot.set(Some(start_send((sender, body, deadline))));
            }
            let wake_at = [&self.logs, &self.spans]
                .into_iter()
                .filter_map(|queue| {
                    queue
                        .as_ref()
                        .and_then(|queue| queue.wake_at(self.throttle))
                })
                .min()
                .unwrap_or(now + IDLE_WAKEUP);
            if timer.deadline() != wake_at {
                timer.as_mut().reset(wake_at);
            }

            tokio::select! {
                biased;
                (sender, outcome) = poll_slot(logs_slot.as_mut()), if logs_slot.is_some() => {
                    logs_slot.set(None);
                    if let Some(queue) = self.logs.as_mut() {
                        queue.complete(sender, outcome, self.throttle);
                    }
                }
                (sender, outcome) = poll_slot(spans_slot.as_mut()), if spans_slot.is_some() => {
                    spans_slot.set(None);
                    if let Some(queue) = self.spans.as_mut() {
                        queue.complete(sender, outcome, self.throttle);
                    }
                }
                _ = timer.as_mut() => {}
                batch = rx.recv() => match batch {
                    Some(events) => self.encode(events, &interests),
                    None => break,
                },
            }
        }

        let drain_deadline = Instant::now() + self.timeout.min(MAX_DRAIN_TIME);
        let resource = &self.resource;
        tokio::join!(
            drain(
                self.logs.as_mut(),
                logs_slot,
                resource,
                self.throttle,
                drain_deadline
            ),
            drain(
                self.spans.as_mut(),
                spans_slot,
                resource,
                self.throttle,
                drain_deadline
            ),
        );
    }

    fn encode(&mut self, events: EventBatch, interests: &SharedInterests) {
        let now = Instant::now();
        let observed = unix_nanos_now();
        let trace_prefix = self.resource.trace_prefix;
        if self.spans.is_some()
            && let Some(event) = events.last()
        {
            self.tracker.sweep(event.inner.timestamp);
        }

        for event in events {
            if let Some(logs) = self.logs.as_mut()
                && logs.has_room(self.max_pending_bytes)
            {
                encode_log(
                    logs.builder(),
                    &mut self.values,
                    &event,
                    observed,
                    &trace_prefix,
                );
                logs.record_added(&self.resource, self.max_request_bytes, now);
            }

            if let Some(spans) = self.spans.as_mut()
                && let Some(span) = event.inner.span.as_ref()
                && let Some(span_id) = span.span_id()
            {
                if !event.inner.typ.is_span_end() {
                    if tracks_span(interests, span) {
                        self.tracker.track(span_id, event);
                    }
                } else if let Some(span_events) = self.tracker.finish(span_id)
                    && spans.has_room(self.max_pending_bytes)
                    && encode_span(
                        spans.builder(),
                        &mut self.values,
                        span,
                        &event,
                        span_events.iter().map(AsRef::as_ref),
                        &trace_prefix,
                    )
                {
                    spans.record_added(&self.resource, self.max_request_bytes, now);
                }
            }
        }

        if let Some((events, spans)) = self.tracker.take_discarded() {
            report_discarded_spans(events, spans);
        }
    }
}

fn start_send(
    (sender, body, deadline): (Sender, Bytes, Instant),
) -> impl Future<Output = (Sender, Outcome)> {
    sender.run(body, deadline)
}

fn poll_slot<F: Future>(mut slot: Pin<&mut Option<F>>) -> impl Future<Output = F::Output> + '_ {
    poll_fn(move |cx| match slot.as_mut().as_pin_mut() {
        Some(future) => future.poll(cx),
        None => Poll::Pending,
    })
}

async fn drain<F: Future<Output = (Sender, Outcome)>>(
    queue: Option<&mut SignalQueue>,
    slot: Pin<&mut Option<F>>,
    resource: &Resource,
    throttle: Duration,
    deadline: Instant,
) {
    if let Some(queue) = queue {
        drain_queue(queue, slot, resource, throttle, deadline).await;
        queue.report_unsent();
    }
}

async fn drain_queue<F: Future<Output = (Sender, Outcome)>>(
    queue: &mut SignalQueue,
    mut slot: Pin<&mut Option<F>>,
    resource: &Resource,
    throttle: Duration,
    deadline: Instant,
) {
    if slot.is_some() {
        match timeout_at(deadline, poll_slot(slot.as_mut())).await {
            Ok((sender, outcome)) => queue.complete(sender, outcome, throttle),
            Err(_) => return,
        }
        slot.set(None);
    }
    queue.seal(resource);
    while let Some((mut sender, body)) = queue.take_sender() {
        if Instant::now() >= deadline {
            return;
        }
        let outcome = sender.send(body, deadline).await;
        let deferred = matches!(outcome, Outcome::Deferred { .. });
        queue.complete(sender, outcome, throttle);
        if deferred {
            return;
        }
    }
}

pub(crate) fn unix_nanos_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

pub(crate) fn unix_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    })
}
