/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AggregateTimestamp;
use crate::{core::Session, queue::RecipientDomain, reporting::SmtpReporting};
use common::{
    Server,
    config::smtp::report::AggregateFrequency,
    ipc::{DmarcEvent, ToHash},
    network::SessionStream,
};
use compact_str::ToCompactString;
use mail_auth::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    SpfResult,
    common::verify::VerifySignature,
    dmarc::{self},
    report::{AuthFailureType, IdentityAlignment, PolicyPublished, Record, SPFDomainScope},
};
use registry::{
    pickle::Pickle,
    schema::{
        enums::FailureReportingOption,
        prelude::{ObjectType, Property},
        structs::{
            DmarcInternalReport, DmarcReport, DmarcReportRecord, Rate, Task, TaskDmarcReport,
            TaskStatus,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, id::ObjectId},
};
use std::future::Future;
use store::{
    SerializeInfallible, U64_LEN, ValueKey,
    registry::ObjectIdVersioned,
    write::{BatchBuilder, RegistryClass, ValueClass, assert::AssertValue, key::KeySerializer},
};
use trc::{AddContext, OutgoingReportEvent};
use utils::DomainPart;

impl<T: SessionStream> Session<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn send_dmarc_report(
        &self,
        message: &AuthenticatedMessage<'_>,
        auth_results: &AuthenticationResults<'_>,
        rejected: bool,
        dmarc_output: DmarcOutput,
        dkim_output: &[DkimOutput<'_>],
        arc_output: &Option<ArcOutput<'_>>,
    ) {
        let dmarc_record = dmarc_output.dmarc_record_cloned().unwrap();
        let config = &self.server.core.smtp.report.dmarc;

        // Send failure report
        if let (Some(failure_rate), Some(report_options)) = (
            self.server
                .eval_if::<Rate, _>(&config.send, self, self.data.session_id)
                .await,
            dmarc_output.failure_report(),
        ) {
            // Verify that any external reporting addresses are authorized
            let rcpts = match self
                .server
                .core
                .smtp
                .resolvers
                .dns
                .verify_dmarc_report_address(
                    dmarc_output.domain(),
                    dmarc_record.ruf(),
                    Some(&self.server.inner.cache.dns_txt),
                )
                .await
            {
                Some(rcpts) => {
                    if !rcpts.is_empty() {
                        let mut new_rcpts = Vec::with_capacity(rcpts.len());

                        for rcpt in rcpts {
                            if self.throttle_rcpt(rcpt.uri(), &failure_rate, "dmarc").await {
                                new_rcpts.push(rcpt.uri());
                            }
                        }

                        new_rcpts
                    } else {
                        if !dmarc_record.ruf().is_empty() {
                            trc::event!(
                                OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
                                SpanId = self.data.session_id,
                                Url = dmarc_record
                                    .ruf()
                                    .iter()
                                    .map(|u| trc::Value::String(u.uri().to_compact_string()))
                                    .collect::<Vec<_>>(),
                            );
                        }
                        vec![]
                    }
                }
                None => {
                    trc::event!(
                        OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
                        SpanId = self.data.session_id,
                        Url = dmarc_record
                            .ruf()
                            .iter()
                            .map(|u| trc::Value::String(u.uri().to_compact_string()))
                            .collect::<Vec<_>>(),
                    );

                    vec![]
                }
            };

            // Throttle recipient
            if !rcpts.is_empty() {
                let mut report = Vec::with_capacity(128);
                let from_addr = self
                    .server
                    .eval_if(&config.address, self, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_compact_string());
                let mut auth_failure = self
                    .new_auth_failure(AuthFailureType::Dmarc, rejected)
                    .with_authentication_results(auth_results.to_string())
                    .with_headers(std::str::from_utf8(message.raw_headers()).unwrap_or_default());

                // Report the first failed signature
                let dkim_failed = if let (
                    dmarc::Report::Dkim
                    | dmarc::Report::DkimSpf
                    | dmarc::Report::All
                    | dmarc::Report::Any,
                    Some(signature),
                ) = (
                    &report_options,
                    dkim_output.iter().find_map(|o| {
                        let s = o.signature()?;
                        if !matches!(o.result(), DkimResult::Pass) {
                            Some(s)
                        } else {
                            None
                        }
                    }),
                ) {
                    auth_failure = auth_failure
                        .with_dkim_domain(signature.domain())
                        .with_dkim_selector(signature.selector())
                        .with_dkim_identity(signature.identity());
                    true
                } else {
                    false
                };

                // Report SPF failure
                let spf_failed = if let (
                    dmarc::Report::Spf
                    | dmarc::Report::DkimSpf
                    | dmarc::Report::All
                    | dmarc::Report::Any,
                    Some(output),
                ) = (
                    &report_options,
                    self.data
                        .spf_ehlo
                        .as_ref()
                        .and_then(|s| {
                            if s.result() != SpfResult::Pass {
                                s.into()
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            self.data.spf_mail_from.as_ref().and_then(|s| {
                                if s.result() != SpfResult::Pass {
                                    s.into()
                                } else {
                                    None
                                }
                            })
                        }),
                ) {
                    auth_failure =
                        auth_failure.with_spf_dns(format!("txt : {} : v=SPF1", output.domain()));
                    // TODO use DNS record
                    true
                } else {
                    false
                };

                auth_failure
                    .with_identity_alignment(if dkim_failed && spf_failed {
                        IdentityAlignment::DkimSpf
                    } else if dkim_failed {
                        IdentityAlignment::Dkim
                    } else {
                        IdentityAlignment::Spf
                    })
                    .write_rfc5322(
                        (
                            self.server
                                .eval_if(&config.name, self, self.data.session_id)
                                .await
                                .unwrap_or_else(|| "Mail Delivery Subsystem".to_compact_string())
                                .as_str(),
                            from_addr.as_str(),
                        ),
                        &rcpts.join(", "),
                        &self
                            .server
                            .eval_if(&config.subject, self, self.data.session_id)
                            .await
                            .unwrap_or_else(|| "DMARC Report".to_compact_string()),
                        &mut report,
                    )
                    .ok();

                trc::event!(
                    OutgoingReport(OutgoingReportEvent::DmarcReport),
                    SpanId = self.data.session_id,
                    From = from_addr.to_string(),
                    To = rcpts
                        .iter()
                        .map(|a| trc::Value::String(a.to_compact_string()))
                        .collect::<Vec<_>>(),
                );

                // Send report
                self.server
                    .send_report(
                        &from_addr,
                        rcpts.into_iter(),
                        report,
                        &config.sign,
                        true,
                        self.data.session_id,
                    )
                    .await;
            } else {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::DmarcRateLimited),
                    SpanId = self.data.session_id,
                    Limit = vec![
                        trc::Value::from(failure_rate.count),
                        trc::Value::from(failure_rate.period.into_inner())
                    ],
                );
            }
        }

        // Send aggregate reports
        let interval = self
            .server
            .eval_if(
                &self.server.core.smtp.report.dmarc_aggregate.send,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(AggregateFrequency::Never);

        if matches!(interval, AggregateFrequency::Never) || dmarc_record.rua().is_empty() {
            return;
        }

        // Create DMARC report record
        let mut report_record = Record::new()
            .with_dmarc_output(&dmarc_output)
            .with_dkim_output(dkim_output)
            .with_source_ip(self.data.remote_ip)
            .with_header_from(message.from().domain_part())
            .with_envelope_from(
                self.data
                    .mail_from
                    .as_ref()
                    .map(|mf| mf.domain.as_str())
                    .unwrap_or_else(|| self.data.helo_domain.as_str()),
            );
        if let Some(spf_ehlo) = &self.data.spf_ehlo {
            report_record = report_record.with_spf_output(spf_ehlo, SPFDomainScope::Helo);
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            report_record = report_record.with_spf_output(spf_mail_from, SPFDomainScope::MailFrom);
        }
        if let Some(arc_output) = arc_output {
            report_record = report_record.with_arc_output(arc_output);
        }

        // Submit DMARC report event
        self.server
            .schedule_report(DmarcEvent {
                domain: dmarc_output.into_domain(),
                report_record,
                dmarc_record,
                interval,
                span_id: self.data.session_id,
            })
            .await;
    }
}

pub trait DmarcReporting: Sync + Send {
    fn send_dmarc_aggregate_report(
        &self,
        report_id: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;
    fn schedule_dmarc(&self, event: Box<DmarcEvent>) -> impl Future<Output = ()> + Send;
}

impl DmarcReporting for Server {
    async fn send_dmarc_aggregate_report(&self, item_id: u64) -> trc::Result<()> {
        let object_id = ObjectType::DmarcInternalReport.to_id();
        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });

        let Some(report) = self
            .store()
            .get_value::<DmarcInternalReport>(ValueKey::from(key.clone()))
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
            key: KeySerializer::new(report.domain.len() + U64_LEN)
                .write(&report.domain)
                .write(report.policy_identifier)
                .finalize(),
        });
        self.core
            .storage
            .data
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        let span_id = self.inner.data.span_id_gen.generate();
        let event_from = report.report.date_range_begin.timestamp() as u64;
        let event_to = report.report.date_range_end.timestamp() as u64;

        trc::event!(
            OutgoingReport(OutgoingReportEvent::DmarcAggregateReport),
            SpanId = span_id,
            ReportId = event_from,
            Domain = report.domain.clone(),
            RangeFrom = trc::Value::Timestamp(event_from),
            RangeTo = trc::Value::Timestamp(event_to),
        );

        // Verify external reporting addresses
        let rua = match self
            .core
            .smtp
            .resolvers
            .dns
            .verify_dmarc_report_address(
                &report.domain,
                &report.rua,
                Some(&self.inner.cache.dns_txt),
            )
            .await
        {
            Some(rcpts) => {
                if !rcpts.is_empty() {
                    rcpts
                } else {
                    trc::event!(
                        OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
                        SpanId = span_id,
                        Url = report
                            .rua
                            .into_iter()
                            .map(|u| trc::Value::String(u.into()))
                            .collect::<Vec<_>>(),
                    );

                    return Ok(());
                }
            }
            None => {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
                    SpanId = span_id,
                    Url = report
                        .rua
                        .into_iter()
                        .map(|u| trc::Value::String(u.into()))
                        .collect::<Vec<_>>(),
                );

                return Ok(());
            }
        };

        // Serialize report
        let config = &self.core.smtp.report.dmarc_aggregate;
        let from_addr = self
            .eval_if(
                &config.address,
                &RecipientDomain::new(report.domain.as_str()),
                span_id,
            )
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_compact_string());
        let mut message = Vec::with_capacity(2048);
        let _ = mail_auth::report::Report::from(report.report).write_rfc5322(
            &self
                .eval_if(
                    &self.core.smtp.report.submitter,
                    &RecipientDomain::new(report.domain.as_str()),
                    span_id,
                )
                .await
                .unwrap_or_else(|| "localhost".to_compact_string()),
            (
                self.eval_if(
                    &config.name,
                    &RecipientDomain::new(report.domain.as_str()),
                    span_id,
                )
                .await
                .unwrap_or_else(|| "Mail Delivery Subsystem".to_compact_string())
                .as_str(),
                from_addr.as_str(),
            ),
            rua.iter().map(|a| a.as_str()),
            &mut message,
        );

        // Send report
        self.send_report(
            &from_addr,
            rua.iter(),
            message,
            &config.sign,
            false,
            span_id,
        )
        .await;

        Ok(())
    }

    async fn schedule_dmarc(&self, event: Box<DmarcEvent>) {
        let object_id = ObjectType::DmarcInternalReport.to_id();
        let policy_hash = event.dmarc_record.to_hash();
        let pk = ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: object_id.into(),
            index_id: Property::Domain.to_id(),
            key: KeySerializer::new(event.domain.len() + U64_LEN)
                .write(&event.domain)
                .write(policy_hash)
                .finalize(),
        });
        let mut rety_count = 0;

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
                        .get_value::<DmarcInternalReport>(ValueKey::from(ValueClass::Registry(
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
                                Details = "Failed to find DMARC report for domain"
                            );

                            return;
                        }
                        Err(err) => {
                            trc::error!(
                                err.caused_by(trc::location!())
                                    .details("Failed to query registry for DMARC report")
                            );
                            return;
                        }
                    }
                }
                Ok(None) => None,
                Err(err) => {
                    trc::error!(
                        err.caused_by(trc::location!())
                            .details("Failed to query registry for DMARC report")
                    );
                    return;
                }
            };

            // Create report if missing
            let config = &self.core.smtp.report.dmarc_aggregate;
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
                            object_id: ObjectId::new(
                                ObjectType::DmarcInternalReport,
                                item_id.into(),
                            ),
                            version: 0,
                        }
                        .serialize(),
                    )
                    .schedule_task_with_id(
                        item_id,
                        Task::DmarcReport(TaskDmarcReport {
                            report_id: item_id.into(),
                            status: TaskStatus::at(deliver_at),
                        }),
                    );

                let created_at = UTCDateTime::now();
                let deliver_at = UTCDateTime::from_timestamp(deliver_at);
                let policy =
                    PolicyPublished::from_record(event.domain.clone(), &event.dmarc_record);
                (
                    item_id,
                    DmarcInternalReport {
                        created_at,
                        deliver_at,
                        domain: event.domain.clone(),
                        report: DmarcReport {
                            report_id: format!("{}_{policy_hash}", created_at.timestamp()),
                            date_range_begin: created_at,
                            date_range_end: deliver_at,
                            email: self
                                .eval_if(
                                    &config.address,
                                    &RecipientDomain::new(event.domain.as_str()),
                                    event.span_id,
                                )
                                .await
                                .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string()),
                            extra_contact_info: self
                                .eval_if::<String, _>(
                                    &config.contact_info,
                                    &RecipientDomain::new(event.domain.as_str()),
                                    event.span_id,
                                )
                                .await,
                            org_name: self
                                .eval_if::<String, _>(
                                    &config.org_name,
                                    &RecipientDomain::new(event.domain.as_str()),
                                    event.span_id,
                                )
                                .await
                                .unwrap_or_default(),
                            policy_adkim: policy.adkim.into(),
                            policy_aspf: policy.aspf.into(),
                            policy_disposition: policy.p.into(),
                            policy_domain: policy.domain,
                            policy_failure_reporting_options: match event.dmarc_record.fo {
                                dmarc::Report::All => vec![FailureReportingOption::All],
                                dmarc::Report::Any => vec![FailureReportingOption::Any],
                                dmarc::Report::Dkim => vec![FailureReportingOption::DkimFailure],
                                dmarc::Report::Spf => vec![FailureReportingOption::SpfFailure],
                                dmarc::Report::DkimSpf => vec![
                                    FailureReportingOption::DkimFailure,
                                    FailureReportingOption::SpfFailure,
                                ],
                            },
                            policy_subdomain_disposition: policy.sp.into(),
                            policy_testing_mode: policy.testing,
                            policy_version: None,
                            version: 1.0.into(),
                            ..Default::default()
                        },
                        policy_identifier: policy_hash,
                        rua: event
                            .dmarc_record
                            .rua()
                            .iter()
                            .map(|u| u.uri.clone())
                            .collect(),
                    },
                )
            };

            // Add record
            let mut record = DmarcReportRecord::from(event.report_record.clone());
            if let Some(idx) = report.report.records.iter().position(|d| d == &record) {
                report.report.records[idx].count += 1;
            } else {
                record.count = 1;
                report.report.records.push(record);
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
                            .details("Failed to write DMARC report")
                    );
                    break;
                }
            }
        }
    }
}
