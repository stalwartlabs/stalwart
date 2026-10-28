/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    otlp::{
        request::{RequestBuilder, SealedRequest},
        resource::Resource,
    },
    transport::sender::{Outcome, Sender},
};
use bytes::Bytes;
use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;
use trc::TelemetryEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalKind {
    Logs,
    Spans,
}

pub struct SignalQueue {
    kind: SignalKind,
    builder: RequestBuilder,
    queue: VecDeque<SealedRequest>,
    queued_bytes: usize,
    opened_at: Option<Instant>,
    retry_at: Option<Instant>,
    sender: Option<Sender>,
    discarded: u64,
    oversized: u64,
}

impl SignalKind {
    fn discarded_details(self) -> &'static str {
        match self {
            SignalKind::Logs => "Log export queue full, discarded logs",
            SignalKind::Spans => "Span export queue full, discarded spans",
        }
    }

    fn oversized_details(self) -> &'static str {
        match self {
            SignalKind::Logs => "Log record exceeds the request size limit, discarded logs",
            SignalKind::Spans => "Span exceeds the request size limit, discarded spans",
        }
    }

    fn unsent_details(self) -> &'static str {
        match self {
            SignalKind::Logs => "Logs not exported before shutdown, discarded",
            SignalKind::Spans => "Spans not exported before shutdown, discarded",
        }
    }

    fn failed_details(self) -> &'static str {
        match self {
            SignalKind::Logs => "Failed to export logs",
            SignalKind::Spans => "Failed to export spans",
        }
    }

    fn deferred_details(self) -> &'static str {
        match self {
            SignalKind::Logs => "Failed to export logs, will retry",
            SignalKind::Spans => "Failed to export spans, will retry",
        }
    }

    fn partial_details(self) -> &'static str {
        match self {
            SignalKind::Logs => "Logs partially rejected by the collector",
            SignalKind::Spans => "Spans partially rejected by the collector",
        }
    }
}

impl SignalQueue {
    pub fn new(kind: SignalKind, builder: RequestBuilder, sender: Sender) -> Self {
        Self {
            kind,
            builder,
            queue: VecDeque::new(),
            queued_bytes: 0,
            opened_at: None,
            retry_at: None,
            sender: Some(sender),
            discarded: 0,
            oversized: 0,
        }
    }

    #[inline(always)]
    pub fn builder(&mut self) -> &mut RequestBuilder {
        &mut self.builder
    }

    #[inline(always)]
    pub fn has_room(&mut self, max_pending_bytes: usize) -> bool {
        if self.queued_bytes + self.builder.capacity() < max_pending_bytes {
            true
        } else {
            self.discarded += 1;
            false
        }
    }

    #[inline(always)]
    pub fn record_added(&mut self, resource: &Resource, max_request_bytes: usize, now: Instant) {
        if self.opened_at.is_none() {
            self.opened_at = Some(now);
        }
        if self.builder.body_len_bound() > max_request_bytes {
            self.split(resource, max_request_bytes, now);
        }
    }

    #[cold]
    #[inline(never)]
    fn split(&mut self, resource: &Resource, max_request_bytes: usize, now: Instant) {
        if let Some(request) = self.builder.seal_before_last(resource) {
            self.push(request);
            self.opened_at = Some(now);
        }
        if self.builder.body_len_bound() > max_request_bytes {
            self.builder.discard();
            self.oversized += 1;
            self.opened_at = None;
        }
    }

    pub fn seal(&mut self, resource: &Resource) {
        if let Some(request) = self.builder.seal(resource) {
            self.push(request);
        }
        self.opened_at = None;
    }

    fn push(&mut self, request: SealedRequest) {
        self.queued_bytes += request.capacity;
        self.queue.push_back(request);
    }

    pub fn next_send(
        &mut self,
        resource: &Resource,
        throttle: Duration,
        now: Instant,
    ) -> Option<(Sender, Bytes)> {
        self.sender.as_ref()?;
        if self.retry_at.is_some_and(|retry_at| now < retry_at) {
            return None;
        }
        self.retry_at = None;
        self.report_discarded();
        if self.queue.is_empty()
            && self
                .opened_at
                .is_some_and(|opened_at| now >= opened_at + throttle)
        {
            self.seal(resource);
        }
        let body = self.queue.front()?.body.clone();
        self.sender.take().map(|sender| (sender, body))
    }

    pub fn wake_at(&self, throttle: Duration) -> Option<Instant> {
        if self.sender.is_none() {
            None
        } else if let Some(retry_at) = self.retry_at {
            Some(retry_at)
        } else if self.queue.is_empty() {
            self.opened_at.map(|opened_at| opened_at + throttle)
        } else {
            None
        }
    }

    pub fn take_sender(&mut self) -> Option<(Sender, Bytes)> {
        let body = self.queue.front()?.body.clone();
        self.sender.take().map(|sender| (sender, body))
    }

    pub fn complete(&mut self, sender: Sender, outcome: Outcome, throttle: Duration) {
        let next_attempt_at = sender.next_attempt_at();
        self.sender = Some(sender);
        match outcome {
            Outcome::Delivered => self.pop(),
            Outcome::PartialSuccess { rejected, message } => {
                self.pop();
                trc::event!(
                    Telemetry(TelemetryEvent::OtelExporterError),
                    Details = self.kind.partial_details(),
                    Total = rejected,
                    Reason = message,
                );
            }
            Outcome::Rejected { reason } => {
                if let Some(request) = self.queue.front() {
                    trc::event!(
                        Telemetry(TelemetryEvent::OtelExporterError),
                        Details = self.kind.failed_details(),
                        Total = request.records,
                        Reason = reason,
                    );
                }
                self.pop();
            }
            Outcome::Deferred { reason } => {
                let min_retry_at = Instant::now() + throttle;
                self.retry_at =
                    Some(next_attempt_at.map_or(min_retry_at, |at| at.max(min_retry_at)));
                trc::event!(
                    Telemetry(TelemetryEvent::OtelExporterError),
                    Details = self.kind.deferred_details(),
                    Reason = reason,
                );
            }
        }
    }

    fn pop(&mut self) {
        if let Some(request) = self.queue.pop_front() {
            self.queued_bytes -= request.capacity;
        }
    }

    fn report_discarded(&mut self) {
        if self.discarded > 0 {
            trc::event!(
                Telemetry(TelemetryEvent::OtelExporterError),
                Details = self.kind.discarded_details(),
                Total = std::mem::take(&mut self.discarded),
            );
        }
        if self.oversized > 0 {
            trc::event!(
                Telemetry(TelemetryEvent::OtelExporterError),
                Details = self.kind.oversized_details(),
                Total = std::mem::take(&mut self.oversized),
            );
        }
    }

    pub fn report_unsent(&mut self) {
        self.report_discarded();
        let unsent = self
            .queue
            .iter()
            .map(|request| request.records)
            .sum::<usize>()
            + self.builder.records();
        if unsent > 0 {
            trc::event!(
                Telemetry(TelemetryEvent::OtelExporterError),
                Details = self.kind.unsent_details(),
                Total = unsent,
            );
        }
    }
}
