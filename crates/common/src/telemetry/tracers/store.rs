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
use std::{future::Future, time::Duration};
use store::{
    Deserialize, Store, ValueKey,
    write::{BatchBuilder, SearchIndex, TaskQueueClass, TelemetryClass, ValueClass, now},
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
            let now = now();

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
                                    due: now,
                                    index: SearchIndex::TracingSpan,
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

pub enum TracingQuery {
    EventType(EventType),
    QueueId(u64),
    Keywords(String),
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
    fn query_spans(
        &self,
        params: &[TracingQuery],
        from_span_id: u64,
        to_span_id: u64,
    ) -> impl Future<Output = trc::Result<Vec<u64>>> + Send;
    fn purge_spans(&self, period: Duration) -> impl Future<Output = trc::Result<()>> + Send;
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

    async fn query_spans(
        &self,
        params: &[TracingQuery],
        from_span_id: u64,
        to_span_id: u64,
    ) -> trc::Result<Vec<u64>> {
        todo!()
    }

    async fn purge_spans(&self, period: Duration) -> trc::Result<()> {
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

        let todo = "delete from index";

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
