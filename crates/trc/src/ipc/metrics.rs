/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use atomics::{array::AtomicU64Array, gauge::AtomicGauge, histogram::AtomicHistogram};
use event::UNCOUNTED_EVENTS;
use ipc::{
    collector::{Collector, GlobalInterests},
    subscriber::Interests,
};

use crate::*;

pub(crate) static METRIC_INTERESTS: GlobalInterests = GlobalInterests::new();

static EVENT_COUNTERS: AtomicU64Array<TOTAL_EVENT_COUNT> = AtomicU64Array::new();
static CONNECTION_METRICS: [ConnectionMetrics; TOTAL_CONN_TYPES] = init_conn_metrics();

static MESSAGE_INGESTION_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::MessageIngestTime);
static SEARCH_INDEX_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::SearchIndexIndexTime);
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

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
static AI_REQUEST_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::AiRequestTime);
#[cfg(feature = "enterprise")]
static AI_INPUT_TOKENS: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_token_counts(MetricType::AiInputTokens);
#[cfg(feature = "enterprise")]
static AI_OUTPUT_TOKENS: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_token_counts(MetricType::AiOutputTokens);
// SPDX-SnippetEnd

static SERVER_MEMORY: AtomicGauge = AtomicGauge::new(MetricType::ServerMemory);
static QUEUE_COUNT: AtomicGauge = AtomicGauge::new(MetricType::QueueCount);
static USER_COUNT: AtomicGauge = AtomicGauge::new(MetricType::UserCount);
static DOMAIN_COUNT: AtomicGauge = AtomicGauge::new(MetricType::DomainCount);
static CACHE_MESSAGES_SIZE: AtomicGauge = AtomicGauge::new(MetricType::CacheMessagesSize);
static CACHE_MESSAGES_LARGE_SIZE: AtomicGauge =
    AtomicGauge::new(MetricType::CacheMessagesLargeSize);
static CACHE_SIZE: AtomicGauge = AtomicGauge::new(MetricType::CacheSize);
static CACHE_SWAP_PENDING: AtomicGauge = AtomicGauge::new(MetricType::CacheSwapPending);
static SERVER_BUFFERED_MEMORY_SMTP: AtomicGauge =
    AtomicGauge::new(MetricType::ServerBufferedMemorySmtp);
static SERVER_BUFFERED_MEMORY_READ: AtomicGauge =
    AtomicGauge::new(MetricType::ServerBufferedMemoryRead);
static SEARCH_INDEX_PENDING_EMAIL: AtomicGauge =
    AtomicGauge::new(MetricType::SearchIndexPendingEmail);
static SEARCH_INDEX_PENDING_CALENDAR: AtomicGauge =
    AtomicGauge::new(MetricType::SearchIndexPendingCalendar);
static SEARCH_INDEX_PENDING_CONTACTS: AtomicGauge =
    AtomicGauge::new(MetricType::SearchIndexPendingContacts);
static SEARCH_INDEX_PENDING_FILE: AtomicGauge =
    AtomicGauge::new(MetricType::SearchIndexPendingFile);
static TASK_MANAGER_PENDING: AtomicGauge = AtomicGauge::new(MetricType::TaskManagerPending);
static TASK_MANAGER_DUE: AtomicGauge = AtomicGauge::new(MetricType::TaskManagerDue);
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
static SEARCH_INDEX_PENDING_TRACING: AtomicGauge =
    AtomicGauge::new(MetricType::SearchIndexPendingTracing);
// SPDX-SnippetEnd

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
    value: u64,
}

impl Collector {
    pub fn record_metric(event: EventType, event_id: usize, keys: &[(Key, Value)]) {
        // Increment the event counter
        if !UNCOUNTED_EVENTS.get(event_id) {
            EVENT_COUNTERS.add(event_id, 1);
        }

        // Extract variables
        let mut elapsed = 0;
        let mut size = 0;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let mut input_tokens = 0;
        #[cfg(feature = "enterprise")]
        let mut output_tokens = 0;
        // SPDX-SnippetEnd
        for (key, value) in keys {
            match (key, value) {
                (Key::Elapsed, Value::Duration(d)) => elapsed = *d,
                (Key::Size, Value::UInt(s)) => size = *s,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                (Key::InputTokens, Value::UInt(t)) => input_tokens = *t,
                #[cfg(feature = "enterprise")]
                (Key::OutputTokens, Value::UInt(t)) => output_tokens = *t,
                // SPDX-SnippetEnd
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
            | EventType::Dane(_)
                if elapsed > 0 =>
            {
                DNS_LOOKUP_TIME.observe(elapsed);
            }
            EventType::MessageIngest(
                MessageIngestEvent::Ham
                | MessageIngestEvent::Spam
                | MessageIngestEvent::ImapAppend
                | MessageIngestEvent::JmapAppend,
            ) => {
                MESSAGE_INGESTION_TIME.observe(elapsed);
            }
            EventType::Queue(QueueEvent::MessageQueued) => {
                MESSAGE_INCOMING_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => {
                MESSAGE_SUBMISSION_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::ReportQueued) => {
                MESSAGE_OUT_REPORT_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::AutogeneratedQueued | QueueEvent::DsnQueued) => {
                QUEUE_COUNT.increment();
            }
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed) => {
                SEARCH_INDEX_TIME.observe(elapsed);
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
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request) => {
                AI_REQUEST_TIME.observe(elapsed);
                AI_INPUT_TOKENS.observe(input_tokens);
                AI_OUTPUT_TOKENS.observe(output_tokens);
            }
            // SPDX-SnippetEnd
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
                        id: EventType::from_id(event_id as u16)?,
                        value,
                    })
                } else {
                    None
                }
            })
    }

    pub fn collect_gauges(is_enterprise: bool) -> impl Iterator<Item = &'static AtomicGauge> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        static E_GAUGES: &[&AtomicGauge] = &[
            &SERVER_MEMORY,
            &QUEUE_COUNT,
            &USER_COUNT,
            &DOMAIN_COUNT,
            &CACHE_MESSAGES_SIZE,
            &CACHE_MESSAGES_LARGE_SIZE,
            &CACHE_SIZE,
            &CACHE_SWAP_PENDING,
            &SERVER_BUFFERED_MEMORY_SMTP,
            &SERVER_BUFFERED_MEMORY_READ,
            &SEARCH_INDEX_PENDING_EMAIL,
            &SEARCH_INDEX_PENDING_CALENDAR,
            &SEARCH_INDEX_PENDING_CONTACTS,
            &SEARCH_INDEX_PENDING_FILE,
            &TASK_MANAGER_PENDING,
            &TASK_MANAGER_DUE,
            &SEARCH_INDEX_PENDING_TRACING,
        ];
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        static E_GAUGES: &[&AtomicGauge] = &[
            &SERVER_MEMORY,
            &QUEUE_COUNT,
            &USER_COUNT,
            &DOMAIN_COUNT,
            &CACHE_MESSAGES_SIZE,
            &CACHE_MESSAGES_LARGE_SIZE,
            &CACHE_SIZE,
            &CACHE_SWAP_PENDING,
            &SERVER_BUFFERED_MEMORY_SMTP,
            &SERVER_BUFFERED_MEMORY_READ,
            &SEARCH_INDEX_PENDING_EMAIL,
            &SEARCH_INDEX_PENDING_CALENDAR,
            &SEARCH_INDEX_PENDING_CONTACTS,
            &SEARCH_INDEX_PENDING_FILE,
            &TASK_MANAGER_PENDING,
            &TASK_MANAGER_DUE,
        ];
        static C_GAUGES: &[&AtomicGauge] = &[&SERVER_MEMORY, &USER_COUNT, &DOMAIN_COUNT];

        if is_enterprise { E_GAUGES } else { C_GAUGES }
            .iter()
            .copied()
            .chain(CONNECTION_METRICS.iter().map(|m| &m.active_connections))
    }

    pub fn collect_histograms(
        is_enterprise: bool,
    ) -> impl Iterator<Item = &'static AtomicHistogram<12>> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        static E_HISTOGRAMS: &[&AtomicHistogram<12>] = &[
            &MESSAGE_INGESTION_TIME,
            &SEARCH_INDEX_TIME,
            &MESSAGE_DELIVERY_TIME,
            &MESSAGE_INCOMING_SIZE,
            &MESSAGE_SUBMISSION_SIZE,
            &MESSAGE_OUT_REPORT_SIZE,
            &STORE_DATA_READ_TIME,
            &STORE_DATA_WRITE_TIME,
            &STORE_BLOB_READ_TIME,
            &STORE_BLOB_WRITE_TIME,
            &DNS_LOOKUP_TIME,
            &AI_REQUEST_TIME,
            &AI_INPUT_TOKENS,
            &AI_OUTPUT_TOKENS,
        ];
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        static E_HISTOGRAMS: &[&AtomicHistogram<12>] = &[
            &MESSAGE_INGESTION_TIME,
            &SEARCH_INDEX_TIME,
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
    pub fn read_metric_counter(metric_id: usize) -> u64 {
        EVENT_COUNTERS.get(metric_id)
    }

    pub fn read_metric(metric_type: MetricType) -> f64 {
        match metric_type {
            MetricType::ServerMemory => SERVER_MEMORY.get() as f64,
            MetricType::MessageIngestTime => MESSAGE_INGESTION_TIME.average(),
            MetricType::SearchIndexIndexTime => SEARCH_INDEX_TIME.average(),
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
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => AI_REQUEST_TIME.average(),
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => AI_INPUT_TOKENS.average(),
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => AI_OUTPUT_TOKENS.average(),
            // SPDX-SnippetEnd
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
            MetricType::CacheMessagesSize => CACHE_MESSAGES_SIZE.get() as f64,
            MetricType::CacheMessagesLargeSize => CACHE_MESSAGES_LARGE_SIZE.get() as f64,
            MetricType::CacheSize => CACHE_SIZE.get() as f64,
            MetricType::CacheSwapPending => CACHE_SWAP_PENDING.get() as f64,
            MetricType::ServerBufferedMemorySmtp => SERVER_BUFFERED_MEMORY_SMTP.get() as f64,
            MetricType::ServerBufferedMemoryRead => SERVER_BUFFERED_MEMORY_READ.get() as f64,
            MetricType::SearchIndexPendingEmail => SEARCH_INDEX_PENDING_EMAIL.get() as f64,
            MetricType::SearchIndexPendingCalendar => SEARCH_INDEX_PENDING_CALENDAR.get() as f64,
            MetricType::SearchIndexPendingContacts => SEARCH_INDEX_PENDING_CONTACTS.get() as f64,
            MetricType::SearchIndexPendingFile => SEARCH_INDEX_PENDING_FILE.get() as f64,
            MetricType::TaskManagerPending => TASK_MANAGER_PENDING.get() as f64,
            MetricType::TaskManagerDue => TASK_MANAGER_DUE.get() as f64,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => SEARCH_INDEX_PENDING_TRACING.get() as f64,
            // SPDX-SnippetEnd
            _ => EVENT_COUNTERS.get(metric_type.event_id()) as f64,
        }
    }

    pub fn update_gauge(metric_type: MetricType, value: u64) {
        match metric_type {
            MetricType::ServerMemory => SERVER_MEMORY.set(value),
            MetricType::QueueCount => QUEUE_COUNT.set(value),
            MetricType::UserCount => USER_COUNT.set(value),
            MetricType::DomainCount => DOMAIN_COUNT.set(value),
            MetricType::CacheMessagesSize => CACHE_MESSAGES_SIZE.set(value),
            MetricType::CacheMessagesLargeSize => CACHE_MESSAGES_LARGE_SIZE.set(value),
            MetricType::CacheSize => CACHE_SIZE.set(value),
            MetricType::CacheSwapPending => CACHE_SWAP_PENDING.set(value),
            MetricType::ServerBufferedMemorySmtp => SERVER_BUFFERED_MEMORY_SMTP.set(value),
            MetricType::ServerBufferedMemoryRead => SERVER_BUFFERED_MEMORY_READ.set(value),
            MetricType::SearchIndexPendingEmail => SEARCH_INDEX_PENDING_EMAIL.set(value),
            MetricType::SearchIndexPendingCalendar => SEARCH_INDEX_PENDING_CALENDAR.set(value),
            MetricType::SearchIndexPendingContacts => SEARCH_INDEX_PENDING_CONTACTS.set(value),
            MetricType::SearchIndexPendingFile => SEARCH_INDEX_PENDING_FILE.set(value),
            MetricType::TaskManagerPending => TASK_MANAGER_PENDING.set(value),
            MetricType::TaskManagerDue => TASK_MANAGER_DUE.set(value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => SEARCH_INDEX_PENDING_TRACING.set(value),
            // SPDX-SnippetEnd
            _ => {}
        }
    }

    pub fn update_event_counter(event_type: EventType, value: u64) {
        EVENT_COUNTERS.add(event_type.into(), value);
    }

    pub fn update_histogram(metric_type: MetricType, value: u64) {
        match metric_type {
            MetricType::MessageIngestTime => MESSAGE_INGESTION_TIME.observe(value),
            MetricType::SearchIndexIndexTime => SEARCH_INDEX_TIME.observe(value),
            MetricType::DeliveryTotalTime => MESSAGE_DELIVERY_TIME.observe(value),
            MetricType::DeliveryAttemptTime => {
                CONNECTION_METRICS[CONN_SMTP_OUT].elapsed.observe(value)
            }
            MetricType::DnsLookupTime => DNS_LOOKUP_TIME.observe(value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => AI_REQUEST_TIME.observe(value),
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => AI_INPUT_TOKENS.observe(value),
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => AI_OUTPUT_TOKENS.observe(value),
            // SPDX-SnippetEnd
            MetricType::StoreDataReadTime => STORE_DATA_READ_TIME.observe(value),
            MetricType::StoreDataWriteTime => STORE_DATA_WRITE_TIME.observe(value),
            MetricType::StoreBlobReadTime => STORE_BLOB_READ_TIME.observe(value),
            MetricType::StoreBlobWriteTime => STORE_BLOB_WRITE_TIME.observe(value),
            _ => {}
        }
    }
}

impl EventCounter {
    pub fn id(&self) -> EventType {
        self.id
    }

    pub fn value(&self) -> u64 {
        self.value
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
