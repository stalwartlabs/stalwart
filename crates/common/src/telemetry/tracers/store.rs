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
use registry::{
    pickle::Pickle,
    schema::structs::{
        Task, TaskIndexTrace, TaskStatus, Trace, TraceEvent, TraceKeyValue, TraceValue,
        TraceValueBoolean, TraceValueDuration, TraceValueEvent, TraceValueFloat, TraceValueInteger,
        TraceValueIpAddr, TraceValueList, TraceValueString, TraceValueUTCDateTime,
        TraceValueUnsignedInt,
    },
    types::{datetime::UTCDateTime, ipaddr::IpAddr},
};
use std::{collections::HashSet, future::Future, time::Duration};
use store::{
    SearchStore, Store, ValueKey,
    search::{IndexDocument, SearchField, SearchFilter, SearchQuery, TracingSearchField},
    write::{BatchBuilder, SearchIndex, TelemetryClass, ValueClass},
};
use trc::{
    AddContext, AuthEvent, Event, EventDetails, EventType, Key, MessageIngestEvent,
    OutgoingReportEvent, QueueEvent, Value, ipc::subscriber::SubscriberBuilder,
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
                                ValueClass::Telemetry(TelemetryClass::Span(span_id)),
                                map_events(
                                    [span.as_ref()]
                                        .into_iter()
                                        .chain(events.iter().map(|event| event.as_ref()))
                                        .chain([event.as_ref()].into_iter()),
                                    events.len() + 2,
                                )
                                .to_pickled_vec(),
                            )
                            .schedule_task(Task::IndexTrace(TaskIndexTrace {
                                status: TaskStatus::now(),
                                trace_id: span_id.into(),
                            }));
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

fn map_events<'x>(
    span_events: impl IntoIterator<Item = &'x Event<EventDetails>>,
    num_events: usize,
) -> Trace {
    let mut events = Vec::with_capacity(num_events);

    for event in span_events {
        let mut key_values = Vec::with_capacity(event.keys.len());
        for (key, value) in &event.keys {
            key_values.push(TraceKeyValue {
                key: *key,
                value: map_value(value),
            });
        }

        events.push(TraceEvent {
            event: event.inner.typ,
            timestamp: UTCDateTime::from_timestamp(event.inner.timestamp as i64),
            key_values,
        });
    }

    Trace { events }
}

fn map_value(value: &Value) -> TraceValue {
    match value {
        Value::String(value) => TraceValue::String(TraceValueString {
            value: value.to_string(),
        }),
        Value::UInt(value) => TraceValue::UnsignedInt(TraceValueUnsignedInt { value: *value }),
        Value::Int(value) => TraceValue::Integer(TraceValueInteger { value: *value }),
        Value::Float(value) => TraceValue::Float(TraceValueFloat { value: *value }),
        Value::Timestamp(value) => TraceValue::UTCDateTime(TraceValueUTCDateTime {
            value: UTCDateTime::from_timestamp(*value as i64),
        }),
        Value::Duration(value) => TraceValue::Duration(TraceValueDuration { value: *value }),
        Value::Bytes(items) => TraceValue::String(TraceValueString {
            value: String::from_utf8_lossy(items).to_string(),
        }),
        Value::Bool(value) => TraceValue::Boolean(TraceValueBoolean { value: *value }),
        Value::Ipv4(ipv4_addr) => TraceValue::IpAddr(TraceValueIpAddr {
            value: IpAddr((*ipv4_addr).into()),
        }),
        Value::Ipv6(ipv6_addr) => TraceValue::IpAddr(TraceValueIpAddr {
            value: IpAddr((*ipv6_addr).into()),
        }),
        Value::Event(event) => TraceValue::Event(TraceValueEvent {
            value: event
                .keys()
                .iter()
                .map(|(k, v)| TraceKeyValue {
                    key: *k,
                    value: map_value(v),
                })
                .collect(),
            event: event.event_type(),
        }),
        Value::Array(values) => TraceValue::List(TraceValueList {
            value: values.iter().map(map_value).collect::<Vec<_>>(),
        }),
        Value::None => TraceValue::Null,
    }
}

pub trait TracingStore: Sync + Send {
    fn purge_spans(
        &self,
        period: Duration,
        search_store: Option<&SearchStore>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl TracingStore for Store {
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
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(0))),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(until_span_id))),
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
        EventType::variants()
            .iter()
            .filter(|event| {
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
            .copied()
    }
}

pub fn build_span_document(
    span_id: u64,
    trace: Trace,
    index_fields: &AHashSet<SearchField>,
) -> IndexDocument {
    let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(span_id);
    let mut keywords = HashSet::new();

    for (idx, event) in trace.events.into_iter().enumerate() {
        if idx == 0
            && (index_fields.is_empty()
                || index_fields.contains(&TracingSearchField::EventType.into()))
        {
            document.index_unsigned(TracingSearchField::EventType, event.event.to_id());
        }

        for TraceKeyValue { key, value } in event.key_values {
            match (key, value) {
                (Key::QueueId, TraceValue::UnsignedInt(TraceValueUnsignedInt { value })) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::QueueId.into())
                    {
                        document.index_unsigned(TracingSearchField::QueueId, value);
                    }
                }
                (
                    Key::From | Key::To | Key::Domain | Key::Hostname,
                    TraceValue::String(TraceValueString { value }),
                ) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        keywords.insert(value);
                    }
                }
                (Key::To, TraceValue::List(TraceValueList { value })) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        for value in value {
                            if let TraceValue::String(TraceValueString { value }) = value {
                                keywords.insert(value);
                            }
                        }
                    }
                }
                (Key::RemoteIp, TraceValue::IpAddr(TraceValueIpAddr { value })) => {
                    if index_fields.is_empty()
                        || index_fields.contains(&TracingSearchField::Keywords.into())
                    {
                        keywords.insert(value.to_string());
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
