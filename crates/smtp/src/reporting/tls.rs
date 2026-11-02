/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    queue::RecipientDomain,
    reporting::{
        ReportAddress,
        aggregate::{
            ReportItem, ReportScheduler, ReportWindow, read_tls_policies, report_size_limit,
        },
        index::InternalReportIndex,
        send::MtaReportSend,
    },
};
use common::{
    Server, USER_AGENT,
    config::smtp::{
        report::AggregateFrequency,
        resolver::{Mode, MxPattern, TlsaMatching},
    },
    expr::Bump,
    ipc::{ReportingEvent, TlsEvent},
};
use compact_str::{CompactString, ToCompactString};
use mail_auth::mta_sts::{ReportUri, TlsRptRecord};
use registry::{
    schema::{
        enums::TlsPolicyType,
        prelude::ObjectType,
        structs::{TlsInternalReport, TlsReport, TlsReportPolicy},
    },
    types::{EnumImpl, datetime::UTCDateTime},
};
use reqwest::{Method, header::CONTENT_TYPE};
use smtp_report::{
    ReportEnvelope,
    flate2::{Compression, write::GzEncoder},
    tlsrpt::TlsReport as ExportedTlsReport,
};
use std::fmt::Write;
use std::{future::Future, mem, sync::Arc, time::Duration};
use store::{
    ValueKey,
    write::{BatchBuilder, RegistryClass, ValueClass},
};
use trc::{AddContext, OutgoingReportEvent};
use utils::error_chain;

#[derive(Debug, Clone)]
pub struct TlsRptOptions {
    pub record: Arc<TlsRptRecord>,
    pub interval: AggregateFrequency,
}

#[cfg(stalwart_tests)]
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

        let Some(mut report) = self
            .store()
            .get_value::<TlsInternalReport>(ValueKey::from(key.clone()))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let span_id = self.inner.data.span_id_gen.generate();
        let max_size = self
            .eval_if(
                &self.core.smtp.report.tls.max_size,
                &RecipientDomain::new(report.domain.as_str()),
                &mut Bump::new(),
                span_id,
            )
            .await;
        read_tls_policies(
            self.store(),
            item_id,
            &mut report,
            report_size_limit(max_size),
        )
        .await?;

        let mut batch = BatchBuilder::new();
        batch.clear(key).clear(report.primary_key());
        let item = ReportItem::new(ObjectType::TlsInternalReport, item_id);
        item.clear(&mut batch);
        let now = UTCDateTime::now();
        if now < report.report.date_range_end {
            report.report.date_range_end = now;
        }

        // Delete report
        self.store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        if let Err(err) = item.clear_orphans(self.store()).await {
            trc::error!(
                err.span_id(span_id)
                    .details("Failed to clear orphaned report rows")
            );
        }
        let payload = TlsPayload::build(&mut report, span_id);

        if let Some(payload) = payload {
            payload.deliver(self, &report, span_id).await;
        }
        Ok(())
    }

    async fn schedule_tls(&self, event: Box<TlsEvent>) {
        ReportScheduler::default()
            .process(self, &mut vec![ReportingEvent::Tls(event)])
            .await;
    }
}

struct TlsPayload {
    json: String,
    compressed_json: Vec<u8>,
}

impl TlsPayload {
    fn build(report: &mut TlsInternalReport, span_id: u64) -> Option<Self> {
        if report.report.policies.is_empty() {
            return None;
        }
        let event_from = report.report.date_range_start.timestamp() as u64;
        let event_to = report.report.date_range_end.timestamp() as u64;

        trc::event!(
            OutgoingReport(OutgoingReportEvent::TlsAggregate),
            SpanId = span_id,
            ReportId = event_from,
            Domain = CompactString::from(report.domain.as_str()),
            RangeFrom = trc::Value::Timestamp(event_from),
            RangeTo = trc::Value::Timestamp(event_to),
        );

        // Generate report
        let json = ExportedTlsReport::from(mem::take(&mut report.report)).to_json();
        let compressed_json = if !report.http_rua.is_empty() {
            let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
            match std::io::Write::write_all(&mut e, json.as_bytes()).and_then(|_| e.finish()) {
                Ok(report) => report,
                Err(err) => {
                    trc::event!(
                        OutgoingReport(OutgoingReportEvent::SubmissionError),
                        SpanId = span_id,
                        Reason = err.to_compact_string(),
                        Details = "Failed to compress report"
                    );

                    return None;
                }
            }
        } else {
            Vec::new()
        };
        Some(TlsPayload {
            json,
            compressed_json,
        })
    }

    async fn deliver(self, server: &Server, report: &TlsInternalReport, span_id: u64) {
        let TlsPayload {
            json,
            compressed_json,
        } = self;
        let domain_name = report.domain.as_str();

        // Try delivering report over HTTP
        for uri in report.http_rua.as_slice() {
            {
                #[cfg(stalwart_tests)]
                if uri == "https://127.0.0.1/tls" {
                    TLS_HTTP_REPORT.lock().extend_from_slice(&compressed_json);

                    return;
                }

                let request = match server
                    .core
                    .smtp
                    .tls_report_client
                    .request(Method::POST, uri)
                {
                    Ok(request) => request,
                    Err(err) => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::SubmissionError),
                            SpanId = span_id,
                            Url = CompactString::from(uri),
                            Reason = err.as_str(),
                            Details = "Report URI rejected"
                        );
                        continue;
                    }
                };

                match request
                    .timeout(Duration::from_secs(2 * 60))
                    .header(reqwest::header::USER_AGENT, USER_AGENT)
                    .header(CONTENT_TYPE, "application/tlsrpt+gzip")
                    .body(compressed_json.clone())
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            trc::event!(
                                OutgoingReport(OutgoingReportEvent::HttpSubmission),
                                SpanId = span_id,
                                Url = CompactString::from(uri),
                                Code = response.status().as_u16(),
                            );

                            return;
                        } else {
                            trc::event!(
                                OutgoingReport(OutgoingReportEvent::SubmissionError),
                                SpanId = span_id,
                                Url = CompactString::from(uri),
                                Code = response.status().as_u16(),
                                Details = "Invalid HTTP response"
                            );
                        }
                    }
                    Err(err) => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::SubmissionError),
                            SpanId = span_id,
                            Url = CompactString::from(uri),
                            Reason = error_chain(&err),
                            Details = "HTTP submission error"
                        );
                    }
                }
            }
        }

        // Deliver report over SMTP
        let mail_rua = report
            .mail_rua
            .iter()
            .filter(|rcpt| ReportAddress::checked(rcpt.as_str(), span_id).is_some())
            .map(|rcpt| rcpt.as_str())
            .collect::<Vec<_>>();
        if !mail_rua.is_empty() {
            let config = &server.core.smtp.report.tls;
            let mut arena = Bump::new();
            let from_addr = server
                .eval_if(
                    &config.address,
                    &RecipientDomain::new(domain_name),
                    &mut arena,
                    span_id,
                )
                .await
                .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
            let submitter = server
                .eval_if(
                    &server.core.smtp.report.submitter,
                    &RecipientDomain::new(domain_name),
                    &mut arena,
                    span_id,
                )
                .await
                .unwrap_or_else(|| "localhost".to_string());
            let from_name = server
                .eval_if(
                    &config.name,
                    &RecipientDomain::new(domain_name),
                    &mut arena,
                    span_id,
                )
                .await
                .unwrap_or_else(|| "Mail Delivery Subsystem".to_string());
            let mut message = Vec::with_capacity(2048);
            let envelope = ReportEnvelope {
                from: (from_name.as_str(), from_addr.as_str()).into(),
                to: mail_rua,
                submitter: &submitter,
                report_domain: domain_name,
                subject: None,
            };
            match ExportedTlsReport::write_rfc5322_json(json.as_bytes(), &envelope, &mut message) {
                Ok(()) => {
                    server
                        .send_report(
                            &from_addr,
                            envelope.to.iter(),
                            message,
                            &config.sign,
                            false,
                            span_id,
                        )
                        .await;
                }
                Err(err) => {
                    trc::event!(
                        OutgoingReport(OutgoingReportEvent::SubmissionError),
                        SpanId = span_id,
                        Reason = err.to_string(),
                    );
                }
            }
        } else {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::NoRecipientsFound),
                SpanId = span_id,
            );
        }
    }
}

pub(crate) fn tls_report_descriptor(
    event: &TlsEvent,
    window: ReportWindow,
    item: ReportItem,
) -> TlsInternalReport {
    let date_range_start = UTCDateTime::from_timestamp(window.start.cast_signed());
    let mut report = TlsInternalReport {
        created_at: date_range_start,
        deliver_at: UTCDateTime::from_timestamp(item.deliver_at(window).cast_signed()),
        domain: event.domain.clone(),
        report: TlsReport {
            date_range_end: UTCDateTime::from_timestamp(window.end.cast_signed()),
            date_range_start,
            ..Default::default()
        },
        ..Default::default()
    };

    for rua in &event.tls_record.rua {
        match rua {
            ReportUri::Mail(mail) => {
                report.mail_rua.push(mail.clone());
            }
            ReportUri::Http(uri) => {
                report.http_rua.push(uri.clone());
            }
        }
    }

    report
}

pub(crate) async fn complete_tls_report(
    server: &Server,
    report: &mut TlsInternalReport,
    arena: &mut Bump,
    span_id: u64,
) {
    let config = &server.core.smtp.report.tls;
    let domain = RecipientDomain::new(report.domain.as_str());
    report.report.report_id = format!(
        "{}_{}",
        report.report.date_range_start.timestamp(),
        server.inner.data.queue_id_gen.generate()
    );
    report.report.organization_name = server
        .eval_if::<String, _>(&config.org_name, &domain, arena, span_id)
        .await;
    report.report.contact_info = server
        .eval_if::<String, _>(&config.contact_info, &domain, arena, span_id)
        .await;
}

pub(crate) fn tls_report_policy(event: &TlsEvent) -> TlsReportPolicy {
    let mut policy = TlsReportPolicy {
        policy_type: TlsPolicyType::NoPolicyFound,
        policy_domain: event.domain.clone(),
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
                        match entry.matching {
                            TlsaMatching::Full => 0,
                            TlsaMatching::Sha256 => 1,
                            TlsaMatching::Sha512 => 2,
                        },
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

    policy
}
