/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AggregateTimestamp, SerializedSize};
use crate::{queue::RecipientDomain, reporting::SmtpReporting};
use ahash::{AHashMap, AHashSet};
use common::{
    Server, USER_AGENT,
    config::smtp::{
        report::AggregateFrequency,
        resolver::{Mode, MxPattern},
    },
    ipc::{TlsEvent, ToHash},
};
use mail_auth::{
    flate2::{Compression, write::GzEncoder},
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::{
        DateRange, FailureDetails, Policy, PolicyDetails, PolicyType, Summary, TlsReport,
    },
};
use mail_parser::DateTime;
use registry::{
    pickle::Pickle,
    schema::{
        enums::TlsPolicyType,
        prelude::{ObjectType, Property},
        structs::{Task, TlsFailureDetails, TlsInternalReport, TlsReport, TlsReportPolicy},
    },
    types::{EnumImpl, datetime::UTCDateTime},
};
use reqwest::header::CONTENT_TYPE;
use std::fmt::Write;
use std::{collections::hash_map::Entry, future::Future, sync::Arc, time::Duration};
use store::{
    Deserialize, IterateParams, ValueKey,
    registry::RegistryQuery,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, QueueClass, RegistryClass, ValueClass},
};
use trc::{AddContext, OutgoingReportEvent};

#[derive(Debug, Clone)]
pub struct TlsRptOptions {
    pub record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, serde::Serialize)]
pub struct TlsFormat {
    pub rua: Vec<ReportUri>,
    pub policy: PolicyDetails,
    pub records: Vec<Option<FailureDetails>>,
}

#[cfg(feature = "test_mode")]
pub static TLS_HTTP_REPORT: parking_lot::Mutex<Vec<u8>> = parking_lot::Mutex::new(Vec::new());

pub trait TlsReporting: Sync + Send {
    fn send_tls_aggregate_report(
        &self,
        events: Vec<ReportEvent>,
    ) -> impl Future<Output = ()> + Send;
    fn generate_tls_aggregate_report(
        &self,
        events: &[ReportEvent],
        rua: &mut Vec<ReportUri>,
        serialized_size: Option<&mut serde_json::Serializer<SerializedSize>>,
        span_id: u64,
    ) -> impl Future<Output = trc::Result<Option<TlsReport>>> + Send;
    fn schedule_tls(&self, event: Box<TlsEvent>) -> impl Future<Output = ()> + Send;
}

impl TlsReporting for Server {
    async fn send_tls_aggregate_report(&self, events: Vec<ReportEvent>) {
        let (domain_name, event_from, event_to) = events
            .first()
            .map(|e| (e.domain.as_str(), e.seq_id, e.due))
            .unwrap();

        let span_id = self.inner.data.span_id_gen.generate();

        trc::event!(
            OutgoingReport(OutgoingReportEvent::TlsAggregate),
            SpanId = span_id,
            ReportId = event_from,
            Domain = domain_name.to_string(),
            RangeFrom = trc::Value::Timestamp(event_from),
            RangeTo = trc::Value::Timestamp(event_to),
        );

        // Generate report
        let mut rua = Vec::new();
        let mut serialized_size = serde_json::Serializer::new(SerializedSize::new(
            self.eval_if(
                &self.core.smtp.report.tls.max_size,
                &RecipientDomain::new(domain_name),
                span_id,
            )
            .await
            .unwrap_or(25 * 1024 * 1024),
        ));
        let report = match self
            .generate_tls_aggregate_report(&events, &mut rua, Some(&mut serialized_size), span_id)
            .await
        {
            Ok(Some(report)) => report,
            Ok(None) => {
                // This should not happen
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::NotFound),
                    SpanId = span_id,
                    CausedBy = trc::location!()
                );
                self.delete_tls_report(events).await;
                return;
            }
            Err(err) => {
                trc::error!(
                    err.span_id(span_id)
                        .caused_by(trc::location!())
                        .details("Failed to read TLS report")
                );
                return;
            }
        };

        // Compress and serialize report
        let json = report.to_json();
        let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
        let json = match std::io::Write::write_all(&mut e, json.as_bytes()).and_then(|_| e.finish())
        {
            Ok(report) => report,
            Err(err) => {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::SubmissionError),
                    SpanId = span_id,
                    Reason = err.to_string(),
                    Details = "Failed to compress report"
                );

                self.delete_tls_report(events).await;
                return;
            }
        };

        // Try delivering report over HTTP
        let mut rcpts = Vec::with_capacity(rua.len());
        for uri in &rua {
            match uri {
                ReportUri::Http(uri) => {
                    if let Ok(client) = reqwest::Client::builder()
                        .user_agent(USER_AGENT)
                        .timeout(Duration::from_secs(2 * 60))
                        .build()
                    {
                        #[cfg(feature = "test_mode")]
                        if uri == "https://127.0.0.1/tls" {
                            TLS_HTTP_REPORT.lock().extend_from_slice(&json);
                            self.delete_tls_report(events).await;
                            return;
                        }

                        match client
                            .post(uri)
                            .header(CONTENT_TYPE, "application/tlsrpt+gzip")
                            .body(json.to_vec())
                            .send()
                            .await
                        {
                            Ok(response) => {
                                if response.status().is_success() {
                                    trc::event!(
                                        OutgoingReport(OutgoingReportEvent::HttpSubmission),
                                        SpanId = span_id,
                                        Url = uri.to_string(),
                                        Code = response.status().as_u16(),
                                    );

                                    self.delete_tls_report(events).await;
                                    return;
                                } else {
                                    trc::event!(
                                        OutgoingReport(OutgoingReportEvent::SubmissionError),
                                        SpanId = span_id,
                                        Url = uri.to_string(),
                                        Code = response.status().as_u16(),
                                        Details = "Invalid HTTP response"
                                    );
                                }
                            }
                            Err(err) => {
                                trc::event!(
                                    OutgoingReport(OutgoingReportEvent::SubmissionError),
                                    SpanId = span_id,
                                    Url = uri.to_string(),
                                    Reason = err.to_string(),
                                    Details = "HTTP submission error"
                                );
                            }
                        }
                    }
                }
                ReportUri::Mail(mailto) => {
                    rcpts.push(mailto.as_str());
                }
            }
        }

        // Deliver report over SMTP
        if !rcpts.is_empty() {
            let config = &self.core.smtp.report.tls;
            let from_addr = self
                .eval_if(&config.address, &RecipientDomain::new(domain_name), span_id)
                .await
                .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
            let mut message = Vec::with_capacity(2048);
            let _ = report.write_rfc5322_from_bytes(
                domain_name,
                &self
                    .eval_if(
                        &self.core.smtp.report.submitter,
                        &RecipientDomain::new(domain_name),
                        span_id,
                    )
                    .await
                    .unwrap_or_else(|| "localhost".to_string()),
                (
                    self.eval_if(&config.name, &RecipientDomain::new(domain_name), span_id)
                        .await
                        .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                        .as_str(),
                    from_addr.as_str(),
                ),
                rcpts.iter().copied(),
                &json,
                &mut message,
            );

            // Send report
            self.send_report(
                &from_addr,
                rcpts.iter(),
                message,
                &config.sign,
                false,
                span_id,
            )
            .await;
        } else {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::NoRecipientsFound),
                SpanId = span_id,
            );
        }
        self.delete_tls_report(events).await;
    }

    async fn generate_tls_aggregate_report(
        &self,
        events: &[ReportEvent],
        rua: &mut Vec<ReportUri>,
        mut serialized_size: Option<&mut serde_json::Serializer<SerializedSize>>,
        span_id: u64,
    ) -> trc::Result<Option<TlsReport>> {
        let (domain_name, event_from, event_to, policy) = events
            .first()
            .map(|e| (e.domain.as_str(), e.seq_id, e.due, e.policy_hash))
            .unwrap();
        let config = &self.core.smtp.report.tls;
        let mut report = TlsReport {
            organization_name: self
                .eval_if::<String, _>(
                    &config.org_name,
                    &RecipientDomain::new(domain_name),
                    span_id,
                )
                .await
                .clone(),
            date_range: DateRange {
                start_datetime: DateTime::from_timestamp(event_from as i64),
                end_datetime: DateTime::from_timestamp(event_to as i64),
            },
            contact_info: self
                .eval_if::<String, _>(
                    &config.contact_info,
                    &RecipientDomain::new(domain_name),
                    span_id,
                )
                .await
                .clone(),
            report_id: format!("{}_{}", event_from, policy),
            policies: Vec::with_capacity(events.len()),
        };

        if let Some(serialized_size) = serialized_size.as_deref_mut() {
            let _ = serde::Serialize::serialize(&report, serialized_size);
        }

        for event in events {
            let tls = if let Some(tls) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                    QueueClass::TlsReportHeader(event.clone()),
                )))
                .await?
            {
                tls.deserialize::<TlsFormat>()?
            } else {
                continue;
            };

            if let Some(serialized_size) = serialized_size.as_deref_mut()
                && serde::Serialize::serialize(&tls, serialized_size).is_err()
            {
                continue;
            }

            // Group duplicates
            let mut total_success = 0;
            let mut total_failure = 0;
            let from_key =
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: event.due,
                    policy_hash: event.policy_hash,
                    seq_id: 0,
                    domain: event.domain.clone(),
                })));
            let to_key =
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: event.due,
                    policy_hash: event.policy_hash,
                    seq_id: u64::MAX,
                    domain: event.domain.clone(),
                })));
            let mut record_map = AHashMap::new();
            self.core
                .storage
                .data
                .iterate(IterateParams::new(from_key, to_key).ascending(), |_, v| {
                    let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(v)?;
                    if let Some(failure_details) =
                        archive.deserialize::<Option<FailureDetails>>()?
                    {
                        match record_map.entry(failure_details) {
                            Entry::Occupied(mut e) => {
                                total_failure += 1;
                                *e.get_mut() += 1;
                                Ok(true)
                            }
                            Entry::Vacant(e) => {
                                if serialized_size
                                    .as_deref_mut()
                                    .is_none_or(|serialized_size| {
                                        serde::Serialize::serialize(e.key(), serialized_size)
                                            .is_ok()
                                    })
                                {
                                    total_failure += 1;
                                    e.insert(1u32);
                                    Ok(true)
                                } else {
                                    Ok(false)
                                }
                            }
                        }
                    } else {
                        total_success += 1;
                        Ok(true)
                    }
                })
                .await
                .caused_by(trc::location!())?;

            // Add policy
            report.policies.push(Policy {
                policy: tls.policy,
                summary: Summary {
                    total_success,
                    total_failure,
                },
                failure_details: record_map
                    .into_iter()
                    .map(|(mut r, count)| {
                        r.failed_session_count = count;
                        r
                    })
                    .collect(),
            });

            // Add report URIs
            for entry in tls.rua {
                if !rua.contains(&entry) {
                    rua.push(entry);
                }
            }
        }

        Ok(if !report.policies.is_empty() {
            Some(report)
        } else {
            None
        })
    }

    async fn schedule_tls(&self, event: Box<TlsEvent>) {
        // Find the report by domain name
        let mut batch = BatchBuilder::new();
        let object_id = ObjectType::TlsInternalReport.to_id();
        let item_id;
        let report = match self
            .registry()
            .query::<AHashSet<u64>>(
                RegistryQuery::new(ObjectType::TlsInternalReport)
                    .equal(Property::Domain, event.domain.clone()),
            )
            .await
            .map(|ids| ids.into_iter().next())
        {
            Ok(Some(item_id_)) => {
                match self
                    .store()
                    .get_value::<TlsInternalReport>(ValueKey::from(ValueClass::Registry(
                        RegistryClass::Item {
                            object_id,
                            item_id: item_id_,
                        },
                    )))
                    .await
                {
                    Ok(Some(report)) => {
                        item_id = item_id_;
                        Some(report)
                    }
                    Ok(None) => {
                        batch.clear(ValueClass::Registry(RegistryClass::Index {
                            index_id: Property::Domain.to_id(),
                            object_id,
                            item_id: item_id_,
                            key: event.domain.as_bytes().to_vec(),
                        }));
                        item_id = self.inner.data.queue_id_gen.generate();
                        None
                    }
                    Err(err) => {
                        trc::error!(
                            err.caused_by(trc::location!())
                                .details("Failed to query registry for TLS report")
                        );
                        return;
                    }
                }
            }
            Ok(None) => {
                item_id = self.inner.data.queue_id_gen.generate();
                None
            }
            Err(err) => {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to query registry for TLS report")
                );
                return;
            }
        };

        // Generate policy if missing
        let mut report = if let Some(report) = report {
            report
        } else {
            batch.set(
                ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::Domain.to_id(),
                    object_id,
                    item_id,
                    key: event.domain.as_bytes().to_vec(),
                }),
                vec![],
            );
            let todo = "schedule task";

            TlsInternalReport {
                created_at: UTCDateTime::now(),
                deliver_at: UTCDateTime::from_timestamp(
                    (event.interval.to_timestamp() + event.interval.as_secs()) as i64,
                ),
                domain: event.domain,
                ..Default::default()
            }
        };
        let policy_hash = event.policy.to_hash();
        let policy = if let Some(policy) = report
            .policy_identifiers
            .iter()
            .position(|id| *id == policy_hash)
            .and_then(|idx| report.report.policies.get_mut(idx))
        {
            policy
        } else {
            // Serialize report
            let mut policy = TlsReportPolicy {
                policy_type: TlsPolicyType::NoPolicyFound,
                policy_domain: report.domain.clone(),
                ..Default::default()
            };

            match event.policy {
                common::ipc::PolicyType::Tlsa(tlsa) => {
                    policy.policy_type = TlsPolicyType::Tlsa;
                    if let Some(tlsa) = tlsa {
                        for entry in &tlsa.entries {
                            policy.policy_strings.push(format!(
                                "{} {} {} {}",
                                if entry.is_end_entity { 3 } else { 2 },
                                i32::from(entry.is_spki),
                                if entry.is_sha256 { 1 } else { 2 },
                                entry
                                    .data
                                    .iter()
                                    .fold(String::with_capacity(64), |mut s, b| {
                                        write!(s, "{b:02X}").ok();
                                        s
                                    })
                            ));
                        }
                    }
                }
                common::ipc::PolicyType::Sts(sts) => {
                    policy.policy_type = TlsPolicyType::Sts;
                    if let Some(sts) = sts {
                        policy.policy_strings.push("version: STSv1".to_string());
                        policy.policy_strings.push(format!(
                            "mode: {}",
                            match sts.mode {
                                Mode::Enforce => "enforce",
                                Mode::Testing => "testing",
                                Mode::None => "none",
                            }
                        ));
                        policy
                            .policy_strings
                            .push(format!("max_age: {}", sts.max_age));
                        for mx in &sts.mx {
                            let mx = match mx {
                                MxPattern::Equals(mx) => mx.to_string(),
                                MxPattern::StartsWith(mx) => format!("*.{mx}"),
                            };
                            policy.policy_strings.push(format!("mx: {mx}"));
                            policy.mx_hosts.push(mx);
                        }
                    }
                }
                _ => (),
            }

            for rua in &event.tls_record.rua {
                match rua {
                    ReportUri::Mail(mail) => {
                        if !report.mail_rua.contains(mail) {
                            report.mail_rua.push(mail.clone());
                        }
                    }
                    ReportUri::Http(uri) => {
                        if !report.http_rua.contains(uri) {
                            report.http_rua.push(uri.clone());
                        }
                    }
                }
            }

            report.policy_identifiers.push(policy_hash);
            report.report.policies.push(policy);
            report.report.policies.last_mut().unwrap()
        };

        // Add failure details
        if let Some(failure) = event.failure.map(TlsFailureDetails::from) {
            if let Some(idx) = policy.failure_details.iter().position(|d| d == &failure) {
                policy.failure_details[idx].failed_session_count += 1;
            } else {
                policy.failure_details.push(failure);
            }

            policy.total_failed_sessions += 1;
        } else {
            policy.total_successful_sessions += 1;
        }

        // Write entry
        batch.set(
            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
            report.to_pickled_vec(),
        );

        if let Err(err) = self.core.storage.data.write(batch.build_all()).await {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to write TLS report")
            );
        }
    }
}
