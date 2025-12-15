/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::config::telemetry::StoreTracer;
use ahash::{AHashMap, AHashSet};
use std::{collections::HashSet, future::Future, time::Duration};
use store::{
    Deserialize, SearchStore, Store, ValueKey,
    search::{IndexDocument, SearchField, SearchFilter, SearchQuery, TracingSearchField},
    write::{BatchBuilder, SearchIndex, TaskEpoch, TaskQueueClass, TelemetryClass, ValueClass},
};
use trc::{
    AddContext, AuthEvent, Event, EventDetails, EventType, Key, MessageIngestEvent,
    OutgoingReportEvent, QueueEvent, Value,
    ipc::subscriber::SubscriberBuilder,
    serializers::binary::{deserialize_events, serialize_events},
};
use utils::snowflake::SnowflakeIdGenerator;

const MAX_EVENTS: usize = 2048;

pub(crate) fn spawn_store_tracer(builder: SubscriberBuilder, settings: StoreTracer) {
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        let mut active_spans = AHashMap::new();
        let store = settings.store;
        let mut batch = BatchBuilder::new();

        while let Some(events) = rx.recv().await {
            for event in events {
                if let Some(span) = &event.inner.span {
                    let span_id = span.span_id().unwrap();
                    if !event.inner.typ.is_span_end() {
                        let events = active_spans.entry(span_id).or_insert_with(Vec::new);
                        if events.len() < MAX_EVENTS {
                            events.push(event);
                        }
                    } else if let Some(events) = active_spans.remove(&span_id)
                        && events
                            .iter()
                            .chain([span, &event])
                            .flat_map(|event| event.keys.iter())
                            .any(|(k, v)| matches!((k, v), (Key::QueueId, Value::UInt(_))))
                    {
                        // Serialize events
                        batch
                            .set(
                                ValueClass::Telemetry(TelemetryClass::Span { span_id }),
                                serialize_events(
                                    [span.as_ref()]
                                        .into_iter()
                                        .chain(events.iter().map(|event| event.as_ref()))
                                        .chain([event.as_ref()].into_iter()),
                                    events.len() + 2,
                                ),
                            )
                            .with_account_id((span_id >> 32) as u32) // TODO: This is hacky, improve
                            .with_document(span_id as u32)
                            .set(
                                ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                    due: TaskEpoch::now(),
                                    index: SearchIndex::Tracing,
                                    is_insert: true,
                                }),
                                vec![],
                            );
                    }
                }
            }

            if !batch.is_empty() {
                if let Err(err) = store.write(batch.build_all()).await {
                    trc::error!(err.caused_by(trc::location!()));
                }
                batch = BatchBuilder::new();
            }
        }
    });
}

pub trait TracingStore: Sync + Send {
    fn get_span(
        &self,
        span_id: u64,
    ) -> impl Future<Output = trc::Result<Vec<Event<EventDetails>>>> + Send;
    fn get_raw_span(
        &self,
        span_id: u64,
    ) -> impl Future<Output = trc::Result<Option<Vec<u8>>>> + Send;
    fn purge_spans(
        &self,
        period: Duration,
        search_store: Option<&SearchStore>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl TracingStore for Store {
    async fn get_span(&self, span_id: u64) -> trc::Result<Vec<Event<EventDetails>>> {
        self.get_value::<Span>(ValueKey::from(ValueClass::Telemetry(
            TelemetryClass::Span { span_id },
        )))
        .await
        .caused_by(trc::location!())
        .map(|span| span.map(|span| span.0).unwrap_or_default())
    }

    async fn get_raw_span(&self, span_id: u64) -> trc::Result<Option<Vec<u8>>> {
        self.get_value::<RawSpan>(ValueKey::from(ValueClass::Telemetry(
            TelemetryClass::Span { span_id },
        )))
        .await
        .caused_by(trc::location!())
        .map(|span| span.map(|span| span.0))
    }

    async fn purge_spans(
        &self,
        period: Duration,
        search_store: Option<&SearchStore>,
    ) -> trc::Result<()> {
        let until_span_id = SnowflakeIdGenerator::from_duration(period).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference span id.")
        })?;

        self.delete_range(
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span { span_id: 0 })),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span {
                span_id: until_span_id,
            })),
        )
        .await
        .caused_by(trc::location!())?;

        if let Some(search_store) = search_store {
            search_store
                .unindex(
                    SearchQuery::new(SearchIndex::Tracing)
                        .with_filter(SearchFilter::lt(SearchField::Id, until_span_id)),
                )
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }
}

impl StoreTracer {
    pub fn default_events() -> impl IntoIterator<Item = EventType> {
        EventType::variants().into_iter().filter(|event| {
            !event.is_raw_io()
                && matches!(
                    event,
                    EventType::MessageIngest(
                        MessageIngestEvent::Ham
                            | MessageIngestEvent::Spam
                            | MessageIngestEvent::Duplicate
                            | MessageIngestEvent::Error
                    ) | EventType::Smtp(_)
                        | EventType::Delivery(_)
                        | EventType::MtaSts(_)
                        | EventType::TlsRpt(_)
                        | EventType::Dane(_)
                        | EventType::Iprev(_)
                        | EventType::Spf(_)
                        | EventType::Dmarc(_)
                        | EventType::Dkim(_)
                        | EventType::MailAuth(_)
                        | EventType::Queue(
                            QueueEvent::QueueMessage
                                | QueueEvent::QueueMessageAuthenticated
                                | QueueEvent::QueueReport
                                | QueueEvent::QueueDsn
                                | QueueEvent::QueueAutogenerated
                                | QueueEvent::Rescheduled
                                | QueueEvent::RateLimitExceeded
                                | QueueEvent::ConcurrencyLimitExceeded
                                | QueueEvent::QuotaExceeded
                        )
                        | EventType::Limit(_)
                        | EventType::Tls(_)
                        | EventType::IncomingReport(_)
                        | EventType::OutgoingReport(
                            OutgoingReportEvent::SpfReport
                                | OutgoingReportEvent::SpfRateLimited
                                | OutgoingReportEvent::DkimReport
                                | OutgoingReportEvent::DkimRateLimited
                                | OutgoingReportEvent::DmarcReport
                                | OutgoingReportEvent::DmarcRateLimited
                                | OutgoingReportEvent::DmarcAggregateReport
                                | OutgoingReportEvent::TlsAggregate
                                | OutgoingReportEvent::HttpSubmission
                                | OutgoingReportEvent::UnauthorizedReportingAddress
                                | OutgoingReportEvent::ReportingAddressValidationError
                                | OutgoingReportEvent::NotFound
                                | OutgoingReportEvent::SubmissionError
                                | OutgoingReportEvent::NoRecipientsFound
                        )
                        | EventType::Auth(
                            AuthEvent::Success
                                | AuthEvent::Failed
                                | AuthEvent::TooManyAttempts
                                | AuthEvent::Error
                        )
                        | EventType::Sieve(_)
                        | EventType::Milter(_)
                        | EventType::MtaHook(_)
                        | EventType::Security(_)
                )
        })
    }
}

struct RawSpan(Vec<u8>);
struct Span(Vec<Event<EventDetails>>);

impl Deserialize for Span {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        deserialize_events(bytes).map(Self)
    }
}

impl Deserialize for RawSpan {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

pub fn build_span_document(
    span_id: u64,
    events: Vec<Event<EventDetails>>,
    index_fields: &AHashSet<SearchField>,
) -> IndexDocument {
    let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(span_id);
    let mut keywords = HashSet::new();

    for (idx, event) in events.into_iter().enumerate() {
        if idx == 0
            && (index_fields.is_empty()
                || index_fields.contains(&TracingSearchField::EventType.into()))
        {
            document.index_unsigned(TracingSearchField::EventType, event.inner.typ.code());
        }

        for (key, value) in event.keys {
            match (key, value) {
                (Key::QueueId, Value::UInt(queue_id)) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::QueueId.into())
                    {
                        document.index_unsigned(TracingSearchField::QueueId, queue_id);
                    }
                }
                (Key::From | Key::To | Key::Domain | Key::Hostname, Value::String(address)) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        keywords.insert(address.to_string());
                    }
                }
                (Key::To, Value::Array(value)) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        for value in value {
                            if let Value::String(address) = value {
                                keywords.insert(address.to_string());
                            }
                        }
                    }
                }
                (Key::RemoteIp, Value::Ipv4(ip)) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        keywords.insert(ip.to_string());
                    }
                }
                (Key::RemoteIp, Value::Ipv6(ip)) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        keywords.insert(ip.to_string());
                    }
                }

                _ => {}
            }
        }
    }

    if !keywords.is_empty() {
        let mut keyword_str = String::new();
        for keyword in keywords {
            if !keyword_str.is_empty() {
                keyword_str.push(' ');
            }
            keyword_str.push_str(&keyword);
        }

        document.index_keyword(TracingSearchField::Keywords, keyword_str);
    }

    document
}
