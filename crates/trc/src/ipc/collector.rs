/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{Arc, LazyLock, atomic::Ordering},
    thread::{Builder, JoinHandle, park_timeout},
    time::{Duration, SystemTime},
};

use ahash::AHashMap;
use atomics::bitset::AtomicBitset;
use event::SPAN_EVENTS;
use ipc::{
    USIZE_BITS,
    channel::{CHANNEL_FLAGS, CHANNEL_UPDATE_MARKER, Receiver},
    subscriber::{Interests, Subscriber},
};
use parking_lot::Mutex;

use crate::*;

pub(crate) type GlobalInterests = AtomicBitset<{ TOTAL_EVENT_COUNT.div_ceil(USIZE_BITS) }>;

pub(crate) static TRACE_INTERESTS: GlobalInterests = GlobalInterests::new();
pub(crate) type CollectorThread = JoinHandle<()>;
pub(crate) static ACTIVE_SUBSCRIBERS: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub(crate) static COLLECTOR_UPDATES: Mutex<Vec<Update>> = Mutex::new(Vec::new());

pub(crate) static EVENT_TYPES: &[EventType] = EventType::variants();

#[allow(clippy::enum_variant_names)]
pub(crate) enum Update {
    RegisterReceiver {
        receiver: Receiver,
    },
    RegisterSubscriber {
        subscriber: Subscriber,
    },
    UnregisterSubscriber {
        id: String,
    },
    UpdateSubscriber {
        id: String,
        interests: Interests,
        lossy: bool,
    },
    UpdateLevels {
        levels: AHashMap<EventType, Level>,
    },
    Shutdown,
}

pub struct Collector {
    receivers: Vec<Receiver>,
    dispatcher: Dispatcher,
    dropped: u64,
    next_maintenance: u64,
}

struct Dispatcher {
    subscribers: Vec<Subscriber>,
    levels: [Level; TOTAL_EVENT_COUNT],
    active_spans: AHashMap<u64, Arc<Event<EventDetails>>>,
}

const HTTP_CONN_START: usize = EventType::Http(HttpEvent::ConnectionStart).to_id() as usize;
const HTTP_CONN_END: usize = EventType::Http(HttpEvent::ConnectionEnd).to_id() as usize;
const IMAP_CONN_START: usize = EventType::Imap(ImapEvent::ConnectionStart).to_id() as usize;
const IMAP_CONN_END: usize = EventType::Imap(ImapEvent::ConnectionEnd).to_id() as usize;
const POP3_CONN_START: usize = EventType::Pop3(Pop3Event::ConnectionStart).to_id() as usize;
const POP3_CONN_END: usize = EventType::Pop3(Pop3Event::ConnectionEnd).to_id() as usize;
const SMTP_CONN_START: usize = EventType::Smtp(SmtpEvent::ConnectionStart).to_id() as usize;
const SMTP_CONN_END: usize = EventType::Smtp(SmtpEvent::ConnectionEnd).to_id() as usize;
const MANAGE_SIEVE_CONN_START: usize =
    EventType::ManageSieve(ManageSieveEvent::ConnectionStart).to_id() as usize;
const MANAGE_SIEVE_CONN_END: usize =
    EventType::ManageSieve(ManageSieveEvent::ConnectionEnd).to_id() as usize;
const EV_ATTEMPT_START: usize = EventType::Delivery(DeliveryEvent::AttemptStart).to_id() as usize;
const EV_ATTEMPT_END: usize = EventType::Delivery(DeliveryEvent::AttemptEnd).to_id() as usize;

const EVENTS_DROPPED: EventType = EventType::Telemetry(TelemetryEvent::EventsDropped);

pub const SPAN_MAX_HOLD: u64 = 60 * 60 * 24;
const MAINTENANCE_INTERVAL: u64 = 60;

pub(crate) static COLLECTOR_THREAD: LazyLock<Arc<CollectorThread>> = LazyLock::new(|| {
    Arc::new(
        Builder::new()
            .name("stalwart-collector".to_string())
            .spawn(move || {
                Collector::default().collect();
            })
            .expect("Failed to start event collector"),
    )
});

impl Collector {
    fn collect(&mut self) {
        let mut do_continue = self.update();

        while do_continue {
            match CHANNEL_FLAGS.swap(0, Ordering::Relaxed) {
                0 => {
                    park_timeout(Duration::from_secs(MAINTENANCE_INTERVAL));
                }
                CHANNEL_UPDATE_MARKER..=u64::MAX => {
                    do_continue = self.update();
                }
                _ => {}
            }

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

            let mut has_closed = false;
            for rx in self.receivers.iter_mut() {
                loop {
                    match rx.try_recv() {
                        Ok(Some(event)) => self.dispatcher.dispatch(event, timestamp),
                        Ok(None) => break,
                        Err(_) => {
                            has_closed = true;
                            break;
                        }
                    }
                }
            }

            if do_continue {
                if has_closed {
                    let dropped = &mut self.dropped;
                    self.receivers.retain(|rx| {
                        if rx.is_closed() {
                            *dropped += rx.take_dropped();
                            false
                        } else {
                            true
                        }
                    });
                }

                if timestamp >= self.next_maintenance {
                    self.maintenance(timestamp);
                }

                let dropped = &mut self.dropped;
                self.dispatcher.subscribers.retain_mut(|subscriber| {
                    match subscriber.send_batch() {
                        Ok(lost) => {
                            *dropped += lost;
                            true
                        }
                        Err(_) => false,
                    }
                });
            }
        }

        for mut subscriber in self.dispatcher.subscribers.drain(..) {
            let _ = subscriber.send_batch();
        }
    }

    fn maintenance(&mut self, timestamp: u64) {
        self.next_maintenance = timestamp + MAINTENANCE_INTERVAL;

        self.dispatcher
            .active_spans
            .retain(|_, span| timestamp.saturating_sub(span.inner.timestamp) < SPAN_MAX_HOLD);

        let dropped = self
            .receivers
            .iter()
            .map(Receiver::take_dropped)
            .sum::<u64>()
            + std::mem::take(&mut self.dropped);
        if dropped > 0 {
            self.dispatcher.report_dropped(dropped, timestamp);
        }
    }

    fn update(&mut self) -> bool {
        for update in COLLECTOR_UPDATES.lock().drain(..) {
            match update {
                Update::RegisterReceiver { receiver } => {
                    self.receivers.push(receiver);
                }
                Update::RegisterSubscriber { subscriber } => {
                    ACTIVE_SUBSCRIBERS.lock().push(subscriber.id.clone());
                    self.dispatcher.subscribers.push(subscriber);
                }
                Update::UnregisterSubscriber { id } => {
                    ACTIVE_SUBSCRIBERS.lock().retain(|s| s != &id);
                    self.dispatcher.subscribers.retain(|s| s.id != id);
                }
                Update::UpdateSubscriber {
                    id,
                    interests,
                    lossy,
                } => {
                    if let Some(subscriber) = self
                        .dispatcher
                        .subscribers
                        .iter_mut()
                        .find(|subscriber| subscriber.id == id)
                    {
                        subscriber.interests = interests;
                        subscriber.lossy = lossy;
                    }
                }
                Update::UpdateLevels { levels } => {
                    for event in EVENT_TYPES.iter() {
                        self.dispatcher.levels[event.to_id() as usize] =
                            levels.get(event).copied().unwrap_or_else(|| event.level());
                    }
                }
                Update::Shutdown => return false,
            }
        }

        true
    }

    pub fn set_interests(mut interests: Interests) {
        if !interests.is_empty() {
            interests.union(&SPAN_EVENTS);
        }

        TRACE_INTERESTS.update(interests);
    }

    pub fn union_interests(interests: Interests) {
        TRACE_INTERESTS.union(interests);
    }

    #[inline(always)]
    pub fn has_interest(event: impl Into<usize>) -> bool {
        TRACE_INTERESTS.get(event)
    }

    pub fn get_subscribers() -> Vec<String> {
        ACTIVE_SUBSCRIBERS.lock().clone()
    }

    pub fn update_custom_levels(levels: AHashMap<EventType, Level>) {
        COLLECTOR_UPDATES
            .lock()
            .push(Update::UpdateLevels { levels });
    }

    pub fn update_subscriber(id: String, interests: Interests, lossy: bool) {
        COLLECTOR_UPDATES.lock().push(Update::UpdateSubscriber {
            id,
            interests,
            lossy,
        });
    }

    pub fn remove_subscriber(id: String) {
        COLLECTOR_UPDATES
            .lock()
            .push(Update::UnregisterSubscriber { id });
    }

    pub fn shutdown() {
        COLLECTOR_UPDATES.lock().push(Update::Shutdown);
        Collector::reload();
    }

    pub fn is_enabled() -> bool {
        !TRACE_INTERESTS.is_empty()
    }

    pub fn reload() {
        CHANNEL_FLAGS.fetch_or(CHANNEL_UPDATE_MARKER, Ordering::Relaxed);
        COLLECTOR_THREAD.thread().unpark();
    }
}

impl Dispatcher {
    #[inline(always)]
    fn dispatch(&mut self, event: Event<EventType>, timestamp: u64) {
        let event_id = event.inner.to_id() as usize;
        let mut event = Event {
            inner: EventDetails {
                level: self.levels[event_id],
                typ: event.inner,
                timestamp,
                span: None,
            },
            keys: event.keys,
        };

        let event = match event_id {
            HTTP_CONN_START
            | IMAP_CONN_START
            | POP3_CONN_START
            | SMTP_CONN_START
            | MANAGE_SIEVE_CONN_START
            | EV_ATTEMPT_START => {
                let event = Arc::new(event);
                match event.span_id() {
                    Some(span_id) => {
                        self.active_spans.insert(span_id, event.clone());
                    }
                    None => missing_span_id(&event),
                }
                event
            }
            HTTP_CONN_END
            | IMAP_CONN_END
            | POP3_CONN_END
            | SMTP_CONN_END
            | MANAGE_SIEVE_CONN_END
            | EV_ATTEMPT_END => {
                match event.span_id() {
                    Some(span_id) => match self.active_spans.remove(&span_id) {
                        Some(span) => event.inner.span = Some(span),
                        None => unregistered_span_id(span_id, &event),
                    },
                    None => missing_span_id(&event),
                }
                Arc::new(event)
            }
            _ => {
                if let Some(span_id) = event.span_id() {
                    match self.active_spans.get(&span_id) {
                        Some(span) => event.inner.span = Some(span.clone()),
                        None => unregistered_span_id(span_id, &event),
                    }
                }
                Arc::new(event)
            }
        };

        for subscriber in self.subscribers.iter_mut() {
            subscriber.push_event(event_id, &event);
        }
    }

    fn report_dropped(&mut self, dropped: u64, timestamp: u64) {
        let event_id = EVENTS_DROPPED.to_id() as usize;
        if Collector::is_metric(event_id) {
            Collector::update_event_counter(
                EVENTS_DROPPED,
                u32::try_from(dropped).unwrap_or(u32::MAX),
            );
        }
        if Collector::has_interest(event_id) {
            self.dispatch(
                Event::with_keys(EVENTS_DROPPED, vec![(Key::Total, Value::UInt(dropped))]),
                timestamp,
            );
        }
    }
}

#[inline(always)]
fn missing_span_id(_event: &Event<EventDetails>) {
    #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
    eprintln!("Missing span ID: {_event:?}");
}

#[inline(always)]
fn unregistered_span_id(_span_id: u64, _event: &Event<EventDetails>) {
    #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
    if _span_id != 0 {
        eprintln!("Unregistered span ID: {_event:?}");
    }
}

impl Default for Collector {
    fn default() -> Self {
        let mut levels = [Level::Disable; TOTAL_EVENT_COUNT];
        for event in EVENT_TYPES.iter() {
            levels[event.to_id() as usize] = event.level();
        }

        Collector {
            receivers: Vec::new(),
            dispatcher: Dispatcher {
                subscribers: Vec::new(),
                levels,
                active_spans: AHashMap::new(),
            },
            dropped: 0,
            next_maintenance: 0,
        }
    }
}
