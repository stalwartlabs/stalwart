/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use atomics::{array::AtomicU32Array, gauge::AtomicGauge, histogram::AtomicHistogram};
use ipc::{
    collector::{Collector, EVENT_TYPES, GlobalInterests},
    subscriber::Interests,
};

use crate::*;

pub(crate) static METRIC_INTERESTS: GlobalInterests = GlobalInterests::new();

static EVENT_COUNTERS: AtomicU32Array<TOTAL_EVENT_COUNT> = AtomicU32Array::new();
static CONNECTION_METRICS: [ConnectionMetrics; TOTAL_CONN_TYPES] = init_conn_metrics();

static MESSAGE_INGESTION_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::MessageIngestTime);
static MESSAGE_INDEX_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::MessageIngestIndexTime);
static MESSAGE_DELIVERY_TIME: AtomicHistogram<12> =
    AtomicHistogram::<18>::new_long_durations(MetricType::DeliveryTotalTime);

static MESSAGE_INCOMING_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes(MetricType::MessageSize);
static MESSAGE_SUBMISSION_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes(MetricType::MessageAuthenticatedSize);
static MESSAGE_OUT_REPORT_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes(MetricType::OutgoingReportSize);

static STORE_DATA_READ_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::StoreDataReadTime);
static STORE_DATA_WRITE_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::StoreDataWriteTime);
static STORE_BLOB_READ_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::StoreBlobReadTime);
static STORE_BLOB_WRITE_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::StoreBlobWriteTime);

static DNS_LOOKUP_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::DnsLookupTime);

static SERVER_MEMORY: AtomicGauge = AtomicGauge::new(MetricType::ServerMemory);
static QUEUE_COUNT: AtomicGauge = AtomicGauge::new(MetricType::QueueCount);
static USER_COUNT: AtomicGauge = AtomicGauge::new(MetricType::UserCount);
static DOMAIN_COUNT: AtomicGauge = AtomicGauge::new(MetricType::DomainCount);

const CONN_SMTP_IN: usize = 0;
const CONN_SMTP_OUT: usize = 1;
const CONN_IMAP: usize = 2;
const CONN_POP3: usize = 3;
const CONN_HTTP: usize = 4;
const CONN_SIEVE: usize = 5;
const TOTAL_CONN_TYPES: usize = 6;

pub struct ConnectionMetrics {
    pub active_connections: AtomicGauge,
    pub elapsed: AtomicHistogram<12>,
}

pub struct EventCounter {
    id: EventType,
    value: u32,
}

impl Collector {
    pub fn record_metric(event: EventType, event_id: usize, keys: &[(Key, Value)]) {
        // Increment the event counter
        if !event.is_span_end() && !event.is_raw_io() {
            EVENT_COUNTERS.add(event_id, 1);
        }

        // Extract variables
        let mut elapsed = 0;
        let mut size = 0;
        for (key, value) in keys {
            match (key, value) {
                (Key::Elapsed, Value::Duration(d)) => elapsed = *d,
                (Key::Size, Value::UInt(s)) => size = *s,
                _ => {}
            }
        }

        match event {
            EventType::Smtp(SmtpEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_IN];
                conn.active_connections.increment();
            }
            EventType::Smtp(SmtpEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_IN];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Imap(ImapEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_IMAP];
                conn.active_connections.increment();
            }
            EventType::Imap(ImapEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_IMAP];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Pop3(Pop3Event::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_POP3];
                conn.active_connections.increment();
            }
            EventType::Pop3(Pop3Event::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_POP3];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Http(HttpEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_HTTP];
                conn.active_connections.increment();
            }
            EventType::Http(HttpEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_HTTP];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_SIEVE];
                conn.active_connections.increment();
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SIEVE];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Delivery(DeliveryEvent::AttemptStart) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_OUT];
                conn.active_connections.increment();
            }
            EventType::Delivery(DeliveryEvent::AttemptEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_OUT];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Delivery(DeliveryEvent::Completed) => {
                QUEUE_COUNT.decrement();
                MESSAGE_DELIVERY_TIME.observe(elapsed);
            }
            EventType::Delivery(
                DeliveryEvent::MxLookup | DeliveryEvent::IpLookup | DeliveryEvent::NullMx,
            )
            | EventType::TlsRpt(_)
            | EventType::MtaSts(_)
            | EventType::Dane(_) => {
                if elapsed > 0 {
                    DNS_LOOKUP_TIME.observe(elapsed);
                }
            }
            EventType::MessageIngest(
                MessageIngestEvent::Ham
                | MessageIngestEvent::Spam
                | MessageIngestEvent::ImapAppend
                | MessageIngestEvent::JmapAppend,
            ) => {
                MESSAGE_INGESTION_TIME.observe(elapsed);
            }
            EventType::Queue(QueueEvent::QueueMessage) => {
                MESSAGE_INCOMING_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::QueueMessageAuthenticated) => {
                MESSAGE_SUBMISSION_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::QueueReport) => {
                MESSAGE_OUT_REPORT_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::QueueAutogenerated | QueueEvent::QueueDsn) => {
                QUEUE_COUNT.increment();
            }
            EventType::MessageIngest(MessageIngestEvent::FtsIndex) => {
                MESSAGE_INDEX_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::BlobWrite) => {
                STORE_BLOB_WRITE_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::BlobRead) => {
                STORE_BLOB_READ_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::DataWrite) => {
                STORE_DATA_WRITE_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::DataIterate) => {
                STORE_DATA_READ_TIME.observe(elapsed);
            }

            _ => {}
        }
    }

    #[inline(always)]
    pub fn is_metric(event: impl Into<usize>) -> bool {
        METRIC_INTERESTS.get(event)
    }

    pub fn set_metrics(interests: Interests) {
        METRIC_INTERESTS.update(interests);
    }

    pub fn collect_counters(_is_enterprise: bool) -> impl Iterator<Item = EventCounter> {
        EVENT_COUNTERS
            .inner()
            .iter()
            .enumerate()
            .filter_map(|(event_id, value)| {
                let value = value.load(Ordering::Relaxed);
                if value > 0 {
                    Some(EventCounter {
                        id: EVENT_TYPES[event_id],
                        value,
                    })
                } else {
                    None
                }
            })
    }

    pub fn collect_gauges(is_enterprise: bool) -> impl Iterator<Item = &'static AtomicGauge> {
        static E_GAUGES: &[&AtomicGauge] =
            &[&SERVER_MEMORY, &QUEUE_COUNT, &USER_COUNT, &DOMAIN_COUNT];
        static C_GAUGES: &[&AtomicGauge] = &[&SERVER_MEMORY, &USER_COUNT, &DOMAIN_COUNT];

        if is_enterprise { E_GAUGES } else { C_GAUGES }
            .iter()
            .copied()
            .chain(CONNECTION_METRICS.iter().map(|m| &m.active_connections))
    }

    pub fn collect_histograms(
        is_enterprise: bool,
    ) -> impl Iterator<Item = &'static AtomicHistogram<12>> {
        static E_HISTOGRAMS: &[&AtomicHistogram<12>] = &[
            &MESSAGE_INGESTION_TIME,
            &MESSAGE_INDEX_TIME,
            &MESSAGE_DELIVERY_TIME,
            &MESSAGE_INCOMING_SIZE,
            &MESSAGE_SUBMISSION_SIZE,
            &MESSAGE_OUT_REPORT_SIZE,
            &STORE_DATA_READ_TIME,
            &STORE_DATA_WRITE_TIME,
            &STORE_BLOB_READ_TIME,
            &STORE_BLOB_WRITE_TIME,
            &DNS_LOOKUP_TIME,
        ];
        static C_HISTOGRAMS: &[&AtomicHistogram<12>] = &[
            &MESSAGE_DELIVERY_TIME,
            &MESSAGE_INCOMING_SIZE,
            &MESSAGE_SUBMISSION_SIZE,
        ];

        if is_enterprise {
            E_HISTOGRAMS
        } else {
            C_HISTOGRAMS
        }
        .iter()
        .copied()
        .chain(CONNECTION_METRICS.iter().map(|m| &m.elapsed))
        .filter(|h| h.is_active())
    }

    #[inline(always)]
    pub fn read_metric_counter(metric_id: usize) -> u32 {
        EVENT_COUNTERS.get(metric_id)
    }

    pub fn read_metric(metric_type: MetricType) -> f64 {
        match metric_type {
            MetricType::ServerMemory => SERVER_MEMORY.get() as f64,
            MetricType::MessageIngestTime => MESSAGE_INGESTION_TIME.average(),
            MetricType::MessageIngestIndexTime => MESSAGE_INDEX_TIME.average(),
            MetricType::MessageSize => MESSAGE_INCOMING_SIZE.average(),
            MetricType::MessageAuthenticatedSize => MESSAGE_SUBMISSION_SIZE.average(),
            MetricType::DeliveryTotalTime => MESSAGE_DELIVERY_TIME.average(),
            MetricType::DeliveryAttemptTime => CONNECTION_METRICS[CONN_SMTP_OUT].elapsed.average(),
            MetricType::DeliveryActiveConnections => {
                CONNECTION_METRICS[CONN_SMTP_OUT].active_connections.get() as f64
            }
            MetricType::QueueCount => QUEUE_COUNT.get() as f64,
            MetricType::OutgoingReportSize => MESSAGE_OUT_REPORT_SIZE.average(),
            MetricType::StoreDataReadTime => STORE_DATA_READ_TIME.average(),
            MetricType::StoreDataWriteTime => STORE_DATA_WRITE_TIME.average(),
            MetricType::StoreBlobReadTime => STORE_BLOB_READ_TIME.average(),
            MetricType::StoreBlobWriteTime => STORE_BLOB_WRITE_TIME.average(),
            MetricType::DnsLookupTime => DNS_LOOKUP_TIME.average(),
            MetricType::HttpActiveConnections => {
                CONNECTION_METRICS[CONN_HTTP].active_connections.get() as f64
            }
            MetricType::HttpRequestTime => CONNECTION_METRICS[CONN_HTTP].elapsed.average(),
            MetricType::ImapActiveConnections => {
                CONNECTION_METRICS[CONN_IMAP].active_connections.get() as f64
            }
            MetricType::ImapRequestTime => CONNECTION_METRICS[CONN_IMAP].elapsed.average(),
            MetricType::Pop3ActiveConnections => {
                CONNECTION_METRICS[CONN_POP3].active_connections.get() as f64
            }
            MetricType::Pop3RequestTime => CONNECTION_METRICS[CONN_POP3].elapsed.average(),
            MetricType::SmtpActiveConnections => {
                CONNECTION_METRICS[CONN_SMTP_IN].active_connections.get() as f64
            }
            MetricType::SmtpRequestTime => CONNECTION_METRICS[CONN_SMTP_IN].elapsed.average(),
            MetricType::SieveActiveConnections => {
                CONNECTION_METRICS[CONN_SIEVE].active_connections.get() as f64
            }
            MetricType::SieveRequestTime => CONNECTION_METRICS[CONN_SIEVE].elapsed.average(),
            MetricType::UserCount => USER_COUNT.get() as f64,
            MetricType::DomainCount => DOMAIN_COUNT.get() as f64,
            _ => EVENT_COUNTERS.get(metric_type.event_id()) as f64,
        }
    }

    pub fn update_gauge(metric_type: MetricType, value: u64) {
        match metric_type {
            MetricType::ServerMemory => SERVER_MEMORY.set(value),
            MetricType::QueueCount => QUEUE_COUNT.set(value),
            MetricType::UserCount => USER_COUNT.set(value),
            MetricType::DomainCount => DOMAIN_COUNT.set(value),
            _ => {}
        }
    }

    pub fn update_event_counter(event_type: EventType, value: u32) {
        EVENT_COUNTERS.add(event_type.into(), value);
    }

    pub fn update_histogram(metric_type: MetricType, value: u64) {
        match metric_type {
            MetricType::MessageIngestTime => MESSAGE_INGESTION_TIME.observe(value),
            MetricType::MessageIngestIndexTime => MESSAGE_INDEX_TIME.observe(value),
            MetricType::DeliveryTotalTime => MESSAGE_DELIVERY_TIME.observe(value),
            MetricType::DeliveryAttemptTime => {
                CONNECTION_METRICS[CONN_SMTP_OUT].elapsed.observe(value)
            }
            MetricType::DnsLookupTime => DNS_LOOKUP_TIME.observe(value),
            _ => {}
        }
    }
}

impl EventCounter {
    pub fn id(&self) -> EventType {
        self.id
    }

    pub fn value(&self) -> u64 {
        self.value as u64
    }
}

impl ConnectionMetrics {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            active_connections: AtomicGauge::new(MetricType::StoreBlobReadTime),
            elapsed: AtomicHistogram::<18>::new_medium_durations(MetricType::StoreBlobReadTime),
        }
    }
}

#[allow(clippy::declare_interior_mutable_const)]
const fn init_conn_metrics() -> [ConnectionMetrics; TOTAL_CONN_TYPES] {
    const INIT: ConnectionMetrics = ConnectionMetrics::new();
    let mut array = [INIT; TOTAL_CONN_TYPES];
    let mut i = 0;
    while i < TOTAL_CONN_TYPES {
        let metric = match i {
            CONN_HTTP => &[
                MetricType::HttpRequestTime,
                MetricType::HttpActiveConnections,
            ],
            CONN_IMAP => &[
                MetricType::ImapRequestTime,
                MetricType::ImapActiveConnections,
            ],
            CONN_POP3 => &[
                MetricType::Pop3RequestTime,
                MetricType::Pop3ActiveConnections,
            ],
            CONN_SMTP_IN => &[
                MetricType::SmtpRequestTime,
                MetricType::SmtpActiveConnections,
            ],
            CONN_SMTP_OUT => &[
                MetricType::DeliveryAttemptTime,
                MetricType::DeliveryActiveConnections,
            ],
            CONN_SIEVE => &[
                MetricType::SieveRequestTime,
                MetricType::SieveActiveConnections,
            ],
            _ => &[MetricType::StoreBlobReadTime, MetricType::StoreBlobReadTime],
        };

        array[i] = ConnectionMetrics {
            elapsed: AtomicHistogram::<18>::new_medium_durations(metric[0]),
            active_connections: AtomicGauge::new(metric[1]),
        };
        i += 1;
    }
    array
}
