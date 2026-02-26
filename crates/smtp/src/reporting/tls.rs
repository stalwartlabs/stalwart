/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AggregateTimestamp;
use crate::{queue::RecipientDomain, reporting::SmtpReporting};
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
    report::tlsrpt::{FailureDetails, PolicyDetails},
};
use registry::{
    pickle::Pickle,
    schema::{
        enums::TlsPolicyType,
        prelude::{ObjectType, Property},
        structs::{
            Task, TaskStatus, TaskTlsReport, TlsFailureDetails, TlsInternalReport, TlsReport,
            TlsReportPolicy,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, id::ObjectId},
};
use reqwest::header::CONTENT_TYPE;
use std::fmt::Write;
use std::{future::Future, sync::Arc, time::Duration};
use store::{
    SerializeInfallible, ValueKey,
    registry::ObjectIdVersioned,
    write::{BatchBuilder, RegistryClass, ValueClass, assert::AssertValue},
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
        report_id: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn schedule_tls(&self, event: Box<TlsEvent>) -> impl Future<Output = ()> + Send;
}

impl TlsReporting for Server {
    async fn send_tls_aggregate_report(&self, item_id: u64) -> trc::Result<()> {
        let object_id = ObjectType::TlsInternalReport.to_id();
        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });

        let Some(report) = self
            .store()
            .get_value::<TlsInternalReport>(ValueKey::from(key.clone()))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };

        // Delete report
        let mut batch = BatchBuilder::new();
        batch.clear(key).clear(RegistryClass::PrimaryKey {
            object_id: object_id.into(),
            index_id: Property::Domain.to_id(),
            key: report.domain.as_bytes().to_vec(),
        });
        self.core
            .storage
            .data
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        let domain_name = report.domain.as_str();
        let event_from = report.report.date_range_start.timestamp() as u64;
        let event_to = report.report.date_range_end.timestamp() as u64;
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
        let exported_report = mail_auth::report::tlsrpt::TlsReport::from(report.report);
        let json = exported_report.to_json();
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

                return Ok(());
            }
        };

        // Try delivering report over HTTP
        for uri in &report.http_rua {
            if let Ok(client) = reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .timeout(Duration::from_secs(2 * 60))
                .build()
            {
                #[cfg(feature = "test_mode")]
                if uri == "https://127.0.0.1/tls" {
                    TLS_HTTP_REPORT.lock().extend_from_slice(&json);

                    return Ok(());
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

                            return Ok(());
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

        // Deliver report over SMTP
        if !report.mail_rua.is_empty() {
            let config = &self.core.smtp.report.tls;
            let from_addr = self
                .eval_if(&config.address, &RecipientDomain::new(domain_name), span_id)
                .await
                .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
            let mut message = Vec::with_capacity(2048);
            let _ = exported_report.write_rfc5322_from_bytes(
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
                report.mail_rua.iter().map(|v| v.as_str()),
                &json,
                &mut message,
            );

            // Send report
            self.send_report(
                &from_addr,
                report.mail_rua.iter().map(|v| v.as_str()),
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

        Ok(())
    }

    async fn schedule_tls(&self, event: Box<TlsEvent>) {
        let object_id = ObjectType::TlsInternalReport.to_id();
        let pk = ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: object_id.into(),
            index_id: Property::Domain.to_id(),
            key: event.domain.as_bytes().to_vec(),
        });
        let mut rety_count = 0;
        let policy_hash = event.policy.to_hash();

        loop {
            // Find the report by domain name
            let mut batch = BatchBuilder::new();
            let report = match self
                .store()
                .get_value::<ObjectIdVersioned>(ValueKey::from(pk.clone()))
                .await
            {
                Ok(Some(object_id_v)) => {
                    match self
                        .store()
                        .get_value::<TlsInternalReport>(ValueKey::from(ValueClass::Registry(
                            RegistryClass::Item {
                                object_id,
                                item_id: object_id_v.object_id.id().id(),
                            },
                        )))
                        .await
                    {
                        Ok(Some(report)) => Some((object_id_v, report)),
                        Ok(None) => {
                            trc::event!(
                                OutgoingReport(OutgoingReportEvent::NotFound),
                                Id = object_id_v.object_id.id().id(),
                                CausedBy = trc::location!(),
                                Details = "Failed to find TLS report for domain"
                            );

                            return;
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
                Ok(None) => None,
                Err(err) => {
                    trc::error!(
                        err.caused_by(trc::location!())
                            .details("Failed to query registry for TLS report")
                    );
                    return;
                }
            };

            // Create report if missing
            let config = &self.core.smtp.report.tls;
            let (item_id, mut report) = if let Some((mut object_id_v, report)) = report {
                batch.assert_value(pk.clone(), AssertValue::U32(object_id_v.version));
                object_id_v.version += 1;
                batch.set(pk.clone(), object_id_v.serialize());

                (object_id_v.object_id.id().id(), report)
            } else {
                let item_id = self.inner.data.queue_id_gen.generate();
                let deliver_at = (event.interval.to_timestamp() + event.interval.as_secs()) as i64;

                batch
                    .assert_value(pk.clone(), ())
                    .set(
                        pk.clone(),
                        ObjectIdVersioned {
                            object_id: ObjectId::new(ObjectType::TlsInternalReport, item_id.into()),
                            version: 0,
                        }
                        .serialize(),
                    )
                    .schedule_task_with_id(
                        item_id,
                        Task::TlsReport(TaskTlsReport {
                            report_id: item_id.into(),
                            status: TaskStatus::at(deliver_at),
                        }),
                    );

                let created_at = UTCDateTime::now();
                let deliver_at = UTCDateTime::from_timestamp(deliver_at);
                (
                    item_id,
                    TlsInternalReport {
                        created_at,
                        deliver_at,
                        domain: event.domain.clone(),
                        report: TlsReport {
                            report_id: format!("{}_{policy_hash}", created_at.timestamp()),
                            organization_name: self
                                .eval_if::<String, _>(
                                    &config.org_name,
                                    &RecipientDomain::new(&event.domain),
                                    event.span_id,
                                )
                                .await
                                .clone(),
                            contact_info: self
                                .eval_if::<String, _>(
                                    &config.contact_info,
                                    &RecipientDomain::new(&event.domain),
                                    event.span_id,
                                )
                                .await
                                .clone(),
                            date_range_end: deliver_at,
                            date_range_start: created_at,
                            policies: vec![],
                        },
                        ..Default::default()
                    },
                )
            };

            let policy = if let Some(policy) = report
                .policy_identifiers
                .iter()
                .position(|id| *id == policy_hash)
                .and_then(|idx| report.report.policies.get_mut(idx))
            {
                policy
            } else {
                // Create policy
                let mut policy = TlsReportPolicy {
                    policy_type: TlsPolicyType::NoPolicyFound,
                    policy_domain: report.domain.clone(),
                    ..Default::default()
                };

                match &event.policy {
                    common::ipc::PolicyType::Tlsa(tlsa) => {
                        policy.policy_type = TlsPolicyType::Tlsa;
                        if let Some(tlsa) = tlsa {
                            for entry in &tlsa.entries {
                                policy.policy_strings.push(format!(
                                    "{} {} {} {}",
                                    if entry.is_end_entity { 3 } else { 2 },
                                    i32::from(entry.is_spki),
                                    if entry.is_sha256 { 1 } else { 2 },
                                    entry.data.iter().fold(
                                        String::with_capacity(64),
                                        |mut s, b| {
                                            write!(s, "{b:02X}").ok();
                                            s
                                        }
                                    )
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
            if let Some(failure) = event.failure.clone().map(TlsFailureDetails::from) {
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
            let report_bytes = report.to_pickled_vec();
            let max_report_size = self
                .eval_if(
                    &config.max_size,
                    &RecipientDomain::new(&event.domain),
                    event.span_id,
                )
                .await
                .unwrap_or(5 * 1024 * 1024);
            if max_report_size != 0 && report_bytes.len() > max_report_size {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
                    SpanId = event.span_id,
                    Domain = event.domain.clone(),
                    Details = report_bytes.len(),
                    Limit = max_report_size,
                );
                return;
            }

            batch.set(
                ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                report_bytes,
            );

            match self.core.storage.data.write(batch.build_all()).await {
                Ok(_) => {
                    break;
                }
                Err(err) => {
                    if err.is_assertion_failure() && rety_count < 3 {
                        rety_count += 1;
                        continue;
                    }
                    trc::error!(
                        err.caused_by(trc::location!())
                            .details("Failed to write TLS report")
                    );
                    break;
                }
            }
        }
    }
}
