/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use std::sync::Arc;
use trc::{Event, EventDetails, ipc::collector::SPAN_MAX_HOLD};

const MAX_SPAN_EVENTS: usize = 2048;
const MAX_TRACKED_EVENTS: usize = 1 << 17;
const SWEEP_INTERVAL: u64 = 60 * 60;
const PRESSURE_SWEEP_INTERVAL: u64 = 60;
const PRESSURE_MAX_HOLD: u64 = 60 * 60;

type SpanEvents = Vec<Arc<Event<EventDetails>>>;

#[derive(Default)]
pub(crate) struct SpanTracker {
    spans: AHashMap<u64, SpanEvents>,
    tracked_events: usize,
    next_sweep: u64,
    next_pressure_sweep: u64,
}

impl SpanTracker {
    pub fn track(&mut self, span_id: u64, event: Arc<Event<EventDetails>>) {
        if self.tracked_events >= MAX_TRACKED_EVENTS {
            let timestamp = event.inner.timestamp;
            if timestamp < self.next_pressure_sweep {
                return;
            }
            self.next_pressure_sweep = timestamp + PRESSURE_SWEEP_INTERVAL;
            self.retain_younger_than(PRESSURE_MAX_HOLD, timestamp);
            if self.tracked_events >= MAX_TRACKED_EVENTS {
                return;
            }
        }

        let events = self.spans.entry(span_id).or_default();
        if events.len() < MAX_SPAN_EVENTS {
            events.push(event);
            self.tracked_events += 1;
        }
    }

    pub fn finish(&mut self, span_id: u64) -> Option<SpanEvents> {
        let events = self.spans.remove(&span_id)?;
        self.tracked_events -= events.len();
        Some(events)
    }

    pub fn sweep(&mut self, timestamp: u64) {
        if timestamp >= self.next_sweep {
            self.next_sweep = timestamp + SWEEP_INTERVAL;
            self.retain_younger_than(SPAN_MAX_HOLD, timestamp);
        }
    }

    fn retain_younger_than(&mut self, max_age: u64, timestamp: u64) {
        let mut tracked_events = 0;
        self.spans.retain(|_, events| {
            let keep = events
                .first()
                .and_then(|event| event.inner.span.as_ref())
                .is_some_and(|span| timestamp.saturating_sub(span.inner.timestamp) < max_age);
            if keep {
                tracked_events += events.len();
            }
            keep
        });
        self.tracked_events = tracked_events;
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SPAN_EVENTS, MAX_TRACKED_EVENTS, SpanTracker};
    use std::sync::Arc;
    use trc::{Event, EventDetails, EventType, Key, Level, SmtpEvent, Value};

    fn event(span_id: u64, timestamp: u64) -> Arc<Event<EventDetails>> {
        let span = Arc::new(Event {
            inner: EventDetails {
                typ: EventType::Smtp(SmtpEvent::ConnectionStart),
                timestamp,
                level: Level::Info,
                span: None,
            },
            keys: vec![(Key::SpanId, Value::UInt(span_id))],
        });
        Arc::new(Event {
            inner: EventDetails {
                typ: EventType::Smtp(SmtpEvent::MailFrom),
                timestamp,
                level: Level::Info,
                span: Some(span),
            },
            keys: vec![],
        })
    }

    #[test]
    fn span_tracker_is_bounded() {
        let mut tracker = SpanTracker::default();

        for _ in 0..MAX_SPAN_EVENTS + 10 {
            tracker.track(1, event(1, 1_000));
        }
        assert_eq!(tracker.tracked_events, MAX_SPAN_EVENTS);
        assert_eq!(
            tracker.finish(1).map(|events| events.len()),
            Some(MAX_SPAN_EVENTS)
        );
        assert_eq!(tracker.tracked_events, 0);

        for span_id in 0..MAX_TRACKED_EVENTS as u64 + 100 {
            tracker.track(span_id, event(span_id, 1_000));
        }
        assert_eq!(tracker.tracked_events, MAX_TRACKED_EVENTS);
        assert_eq!(tracker.spans.len(), MAX_TRACKED_EVENTS);

        tracker.track(u64::MAX, event(u64::MAX, 1_000 + 2 * 60 * 60));
        assert_eq!(tracker.tracked_events, 1);
        assert_eq!(tracker.spans.len(), 1);

        tracker.sweep(1_000 + 2 * 60 * 60 + 24 * 60 * 60);
        assert_eq!(tracker.tracked_events, 0);
        assert!(tracker.spans.is_empty());
    }
}
