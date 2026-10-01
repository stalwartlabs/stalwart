/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AggregateTimestamp;
use crate::{
    core::Session,
    queue::RecipientDomain,
    reporting::{ReportAddress, index::InternalReportIndex, send::MtaReportSend},
};
use common::{
    Server,
    config::smtp::report::AggregateFrequency,
    expr::Bump,
    ipc::{DmarcEvent, ToHash},
    network::SessionStream,
};
use compact_str::ToCompactString;
use mail_auth::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    DmarcResult, SpfResult,
    dkim2::Dkim2Output,
    dmarc::{self, FailureOptions},
    report::{
        ReportEnvelope,
        arf::{AuthFailureType, FeedbackReport, IdentityAlignment},
        dmarc::{AggregateReport, PolicyPublished, Record, SpfScope},
    },
};
use registry::{
    schema::{
        enums::FailureReportingOption,
        prelude::{ObjectType, Property},
        structs::{DmarcInternalReport, DmarcReport, DmarcReportRecord, Rate},
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, map::Map},
};
use std::{borrow::Cow, future::Future, sync::Arc};
use store::{
    Deserialize, U64_LEN, ValueKey,
    registry::ObjectIdVersioned,
    write::{BatchBuilder, MergeResult, RegistryClass, ValueClass, key::KeySerializer},
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
        dkim2_output: Option<&Dkim2Output<'_>>,
        arc_output: &Option<ArcOutput<'_>>,
    ) {
        let Some(dmarc_record) = dmarc_output.record().cloned() else {
            return;
        };
        let config = &self.server.core.smtp.report.dmarc;
        let mut arena = Bump::new();

        if self
            .server
            .is_local_report_domain(dmarc_output.domain(), self.data.session_id)
            .await
        {
            return;
        }

        // Send failure report. RFC 9991 Section 2: report generators MUST NOT
        // honor "ruf" for policy records published with "psd=y".
        if !matches!(dmarc_record.psd, dmarc::Psd::Yes)
            && let (Some(failure_rate), Some(report_options)) = (
                self.server
                    .eval_if::<Rate, _>(&config.send, self, &mut arena, self.data.session_id)
                    .await,
                dmarc_output.failure_report(),
            )
        {
            // Verify that any external reporting addresses are authorized
            let rcpts = match self
                .server
                .core
                .smtp
                .resolvers
                .dns
                .authorized_report_addresses(
                    self.server
                        .inner
                        .cache
                        .build_auth_parameters((dmarc_output.domain(), dmarc_record.ruf())),
                )
                .await
            {
                Ok(rcpts) => {
                    if !rcpts.is_empty() {
                        let mut new_rcpts = Vec::with_capacity(rcpts.len());

                        for rcpt in rcpts {
                            if ReportAddress::checked(rcpt.uri(), self.data.session_id).is_some() {
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
                Err(_) => {
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

            if !rcpts.is_empty() {
                let from_addr = self
                    .server
                    .eval_if(&config.address, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_compact_string());
                let mut auth_failure = FeedbackReport {
                    authentication_results: vec![auth_results.to_string().into()],
                    headers: Some(
                        std::str::from_utf8(message.raw_headers())
                            .unwrap_or_default()
                            .into(),
                    ),
                    ..self.new_auth_failure(AuthFailureType::Dmarc, rejected)
                };

                let dkim_aligned = matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
                let spf_aligned = matches!(dmarc_output.spf_result(), DmarcResult::Pass);

                // Report the first failed signature
                if let (
                    FailureOptions::Dkim
                    | FailureOptions::DkimSpf
                    | FailureOptions::All
                    | FailureOptions::Any,
                    Some(signature),
                ) = (
                    &report_options,
                    if !dkim_aligned {
                        dkim_output
                            .iter()
                            .find_map(|o| {
                                let s = o.signature()?;
                                if !matches!(o.result(), DkimResult::Pass) {
                                    Some(s)
                                } else {
                                    None
                                }
                            })
                            .or_else(|| dkim_output.iter().find_map(|o| o.signature()))
                    } else {
                        None
                    },
                ) {
                    auth_failure.dkim_domain = Some(signature.d.as_str().into());
                    auth_failure.dkim_selector = Some(signature.s.as_str().into());
                    auth_failure.dkim_identity = Some(signature.identity().into());
                }

                // Report SPF failure
                if let (
                    FailureOptions::Spf
                    | FailureOptions::DkimSpf
                    | FailureOptions::All
                    | FailureOptions::Any,
                    Some(output),
                ) = (
                    &report_options,
                    if !spf_aligned {
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
                            })
                            .or(self.data.spf_mail_from.as_ref())
                    } else {
                        None
                    },
                ) {
                    auth_failure.spf_dns =
                        Some(format!("txt : {} : v=SPF1", output.domain()).into());
                    // TODO use DNS record
                }

                auth_failure.identity_alignment = match (dkim_aligned, spf_aligned) {
                    (false, false) => IdentityAlignment::DkimSpf,
                    (false, true) => IdentityAlignment::Dkim,
                    (true, false) => IdentityAlignment::Spf,
                    (true, true) => IdentityAlignment::None,
                };
                let from_name = self
                    .server
                    .eval_if(&config.name, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "Mail Delivery Subsystem".to_compact_string());
                let subject = self
                    .server
                    .eval_if(&config.subject, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "DMARC Report".to_compact_string());
                let write_report = |to| {
                    let envelope = ReportEnvelope {
                        from: (from_name.as_str(), from_addr.as_str()).into(),
                        to,
                        submitter: &self.hostname,
                        report_domain: "",
                        subject: Some(&subject),
                    };
                    let mut report = Vec::with_capacity(128);
                    auth_failure
                        .write_rfc5322(&envelope, &mut report)
                        .map(|_| (report, envelope.to))
                };
                let report = match write_report(rcpts) {
                    Ok((report, validated)) => {
                        let mut allowed = Vec::with_capacity(validated.len());
                        for rcpt in &validated {
                            if self.throttle_rcpt(rcpt, &failure_rate, "dmarc").await {
                                allowed.push(*rcpt);
                            }
                        }
                        match allowed.len() {
                            0 => None,
                            len if len == validated.len() => Some(Ok((report, allowed))),
                            _ => Some(write_report(allowed)),
                        }
                    }
                    Err(err) => Some(Err(err)),
                };
                match report {
                    Some(Ok((report, rcpts))) => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::DmarcReport),
                            SpanId = self.data.session_id,
                            From = from_addr.clone(),
                            To = rcpts
                                .iter()
                                .map(|a| trc::Value::String(a.to_compact_string()))
                                .collect::<Vec<_>>(),
                        );

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
                    }
                    Some(Err(err)) => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::SubmissionError),
                            SpanId = self.data.session_id,
                            Reason = err.to_string(),
                        );
                    }
                    None => {
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
                &mut arena,
                self.data.session_id,
            )
            .await
            .unwrap_or(AggregateFrequency::Never);

        if matches!(interval, AggregateFrequency::Never) || dmarc_record.rua().is_empty() {
            return;
        }

        // Report the same identifier forms that were used for alignment
        let message_from = message.first_from_address();
        let header_from = message_from.domain_part();
        let header_from = header_from
            .to_ascii_domain()
            .unwrap_or(Cow::Borrowed(header_from));
        let envelope_from = self
            .data
            .mail_from
            .as_ref()
            .map(|mf| mf.domain.as_str())
            .unwrap_or_else(|| self.data.helo_domain.as_str());
        let envelope_from = envelope_from
            .to_ascii_domain()
            .unwrap_or(Cow::Borrowed(envelope_from));

        // Create DMARC report record
        let mut report_record = Record::default()
            .with_dmarc_output(&dmarc_output)
            .with_dkim_output(dkim_output);
        report_record.row.source_ip = Some(self.data.remote_ip);
        report_record.identifiers.header_from = header_from.into_owned();
        report_record.identifiers.envelope_from = envelope_from.into_owned();
        if let Some(dkim2_output) = dkim2_output {
            report_record = report_record.with_dkim2_output(dkim2_output);
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            report_record = report_record.with_spf_output(spf_mail_from, SpfScope::MailFrom);
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
        self.store()
            .write_batch(&mut batch)
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
            .authorized_report_addresses(
                self.inner
                    .cache
                    .build_auth_parameters((report.domain.as_str(), report.rua.as_slice())),
            )
            .await
        {
            Ok(rcpts) => {
                let rcpts = rcpts
                    .into_iter()
                    .filter(|rcpt| ReportAddress::checked(rcpt.as_str(), span_id).is_some())
                    .collect::<Vec<_>>();
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
            Err(_) => {
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
        let mut arena = Bump::new();
        let from_addr = self
            .eval_if(
                &config.address,
                &RecipientDomain::new(report.domain.as_str()),
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_compact_string());
        let submitter = self
            .eval_if(
                &self.core.smtp.report.submitter,
                &RecipientDomain::new(report.domain.as_str()),
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| "localhost".to_compact_string());
        let from_name = self
            .eval_if(
                &config.name,
                &RecipientDomain::new(report.domain.as_str()),
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| "Mail Delivery Subsystem".to_compact_string());
        let mut message = Vec::with_capacity(2048);
        if let Err(err) = AggregateReport::from(report.report).write_rfc5322(
            &ReportEnvelope {
                from: (from_name.as_str(), from_addr.as_str()).into(),
                to: rua.iter().map(|a| a.as_str()).collect(),
                submitter: &submitter,
                report_domain: "",
                subject: None,
            },
            &mut message,
        ) {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::SubmissionError),
                SpanId = span_id,
                Reason = err.to_string(),
            );
            return Ok(());
        }

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
        let DmarcEvent {
            domain,
            report_record,
            dmarc_record,
            interval,
            span_id,
        } = *event;
        let object_id = ObjectType::DmarcInternalReport.to_id();
        let policy_hash = dmarc_record.to_hash();
        let pk = ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: object_id.into(),
            index_id: Property::Domain.to_id(),
            key: KeySerializer::new(domain.len() + U64_LEN)
                .write(&domain)
                .write(policy_hash)
                .finalize(),
        });
        let record = Arc::new(DmarcReportRecord::from(report_record));
        let mut rety_count = 0;
        let mut arena = Bump::new();

        loop {
            // Find the report by domain name
            let mut batch = BatchBuilder::new();
            let object_id_v = match self
                .store()
                .get_value::<ObjectIdVersioned>(ValueKey::from(pk.clone()))
                .await
            {
                Ok(object_id_v) => object_id_v,
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
            let max_report_size = self
                .eval_if(
                    &config.max_size,
                    &RecipientDomain::new(&domain),
                    &mut arena,
                    span_id,
                )
                .await
                .unwrap_or(5 * 1024 * 1024);

            let (item_id, mut report) = if let Some(object_id_v) = object_id_v {
                // Merge the record into the stored report
                let item_id = object_id_v.object_id.id().id();
                let record = record.clone();
                let domain = domain.clone();

                batch.merge_fnc(
                    ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                    move |_, bytes| {
                        let Some(bytes) = bytes else {
                            return Err(trc::StoreEvent::AssertValueFailed
                                .into_err()
                                .details("DMARC report was delivered concurrently.")
                                .caused_by(trc::location!()));
                        };

                        let mut report = DmarcInternalReport::deserialize(bytes)?;
                        add_dmarc_record(&mut report, &record);

                        let report_bytes = report.to_pickled_vec();
                        if max_report_size != 0 && report_bytes.len() > max_report_size {
                            trc::event!(
                                OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
                                SpanId = span_id,
                                Domain = domain.clone(),
                                Details = report_bytes.len(),
                                Limit = max_report_size,
                            );

                            return Ok(MergeResult::Skip);
                        }

                        Ok(MergeResult::Update(report_bytes))
                    },
                );

                match self.core.storage.data.write_batch(&mut batch).await {
                    Ok(_) => return,
                    Err(err) if err.is_assertion_failure() && rety_count < 3 => {
                        rety_count += 1;
                        continue;
                    }
                    Err(err) => {
                        trc::error!(
                            err.caused_by(trc::location!())
                                .details("Failed to write DMARC report")
                        );
                        return;
                    }
                }
            } else {
                let item_id = self.inner.data.queue_id_gen.generate();
                let date_range_begin = UTCDateTime::now();
                let date_range_end = UTCDateTime::from_timestamp(
                    date_range_begin.timestamp() + interval.as_secs() as i64,
                );
                let policy = PolicyPublished::from_record(domain.clone(), &dmarc_record);

                let report = DmarcInternalReport {
                    created_at: date_range_begin,
                    deliver_at: date_range_end,
                    domain: domain.clone(),
                    report: DmarcReport {
                        report_id: format!("{}_{policy_hash}", date_range_begin.timestamp()),
                        date_range_begin,
                        date_range_end,
                        email: self
                            .eval_if(
                                &config.address,
                                &RecipientDomain::new(domain.as_str()),
                                &mut arena,
                                span_id,
                            )
                            .await
                            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string()),
                        extra_contact_info: self
                            .eval_if::<String, _>(
                                &config.contact_info,
                                &RecipientDomain::new(domain.as_str()),
                                &mut arena,
                                span_id,
                            )
                            .await,
                        org_name: self
                            .eval_if::<String, _>(
                                &config.org_name,
                                &RecipientDomain::new(domain.as_str()),
                                &mut arena,
                                span_id,
                            )
                            .await
                            .unwrap_or_default(),
                        policy_adkim: policy.adkim.into(),
                        policy_aspf: policy.aspf.into(),
                        policy_disposition: policy.p.into(),
                        policy_domain: policy.domain,
                        policy_failure_reporting_options: match dmarc_record.fo {
                            FailureOptions::All => vec![FailureReportingOption::All],
                            FailureOptions::Any => vec![FailureReportingOption::Any],
                            FailureOptions::Dkim => vec![FailureReportingOption::DkimFailure],
                            FailureOptions::Spf => vec![FailureReportingOption::SpfFailure],
                            FailureOptions::DkimSpf => vec![
                                FailureReportingOption::DkimFailure,
                                FailureReportingOption::SpfFailure,
                            ],
                        }
                        .into(),
                        policy_subdomain_disposition: policy.sp.into(),
                        policy_np: policy.np.into(),
                        policy_discovery_method: policy.discovery_method.into(),
                        policy_testing_mode: policy.testing,
                        policy_version: None,
                        version: 1.0.into(),
                        ..Default::default()
                    },
                    policy_identifier: policy_hash,
                    rua: Map::new(dmarc_record.rua().iter().map(|u| u.uri.clone()).collect()),
                };

                report.write_ops(&mut batch, item_id, true);

                (item_id, report)
            };

            // Add record
            add_dmarc_record(&mut report, &record);

            // Write entry
            let report_bytes = report.to_pickled_vec();
            if max_report_size != 0 && report_bytes.len() > max_report_size {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
                    SpanId = span_id,
                    Domain = domain.clone(),
                    Details = report_bytes.len(),
                    Limit = max_report_size,
                );
                return;
            }

            batch.set(
                ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                report_bytes,
            );

            match self.core.storage.data.write_batch(&mut batch).await {
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

fn add_dmarc_record(report: &mut DmarcInternalReport, record: &DmarcReportRecord) {
    if let Some(existing) = report
        .report
        .records
        .0
        .inner
        .iter_mut()
        .find(|d| d.value.eq_except_count(record))
    {
        existing.value.count += 1;
    } else {
        let mut record = record.clone();
        record.count = 1;
        report.report.records.push(record);
    }
}
