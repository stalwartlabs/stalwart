/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use ahash::AHashMap;
use common::USER_AGENT;
use compact_str::{CompactString, format_compact};
use mail_auth::report::{
    arf::{AuthFailureType, DeliveryResult, FeedbackReport, FeedbackType},
    dmarc::{AggregateReport, Disposition, DmarcStatus},
    tlsrpt::TlsReport,
};
use std::{collections::hash_map::Entry, time::SystemTime};
use store::write::now;
use tokio::io::{AsyncRead, AsyncWrite};
use trc::IncomingReportEvent;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn new_auth_failure(&self, ft: AuthFailureType, rejected: bool) -> FeedbackReport<'_> {
        FeedbackReport {
            auth_failure: ft,
            arrival_date: Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as i64,
            ),
            source_ip: Some(self.data.remote_ip),
            reporting_mta: Some(self.hostname.as_str().into()),
            user_agent: Some(USER_AGENT.into()),
            delivery_result: if rejected {
                DeliveryResult::Reject
            } else {
                DeliveryResult::Unspecified
            },
            ..FeedbackReport::new(FeedbackType::AuthFailure)
        }
    }

    pub fn is_report(&self) -> bool {
        let analysis = &self.server.core.smtp.report.analysis;

        self.data
            .rcpt_to
            .iter()
            .any(|addr| analysis.is_report_address(addr.report_address()))
    }
}

pub(crate) trait LogReport {
    fn log(&self);
}

impl LogReport for AggregateReport {
    fn log(&self) {
        let mut dmarc_pass = 0;
        let mut dmarc_quarantine = 0;
        let mut dmarc_reject = 0;
        let mut dmarc_none = 0;
        let mut dkim_pass = 0;
        let mut dkim_fail = 0;
        let mut dkim_none = 0;
        let mut spf_pass = 0;
        let mut spf_fail = 0;
        let mut spf_none = 0;

        for record in &self.records {
            let count = std::cmp::min(record.row.count, 1);
            let evaluated = &record.row.policy_evaluated;

            match evaluated.disposition {
                Disposition::Pass => {
                    dmarc_pass += count;
                }
                Disposition::Quarantine => {
                    dmarc_quarantine += count;
                }
                Disposition::Reject => {
                    dmarc_reject += count;
                }
                Disposition::None | Disposition::Unspecified => {
                    dmarc_none += count;
                }
            }
            match evaluated.dkim {
                DmarcStatus::Pass => {
                    dkim_pass += count;
                }
                DmarcStatus::Fail => {
                    dkim_fail += count;
                }
                DmarcStatus::Unspecified => {
                    dkim_none += count;
                }
            }
            match evaluated.spf {
                DmarcStatus::Pass => {
                    spf_pass += count;
                }
                DmarcStatus::Fail => {
                    spf_fail += count;
                }
                DmarcStatus::Unspecified => {
                    spf_none += count;
                }
            }
        }

        trc::event!(
            IncomingReport(
                if (dmarc_reject + dmarc_quarantine + dkim_fail + spf_fail) > 0 {
                    IncomingReportEvent::DmarcReportWithWarnings
                } else {
                    IncomingReportEvent::DmarcReport
                }
            ),
            RangeFrom = trc::Value::Timestamp(self.report_metadata.date_range.begin),
            RangeTo = trc::Value::Timestamp(self.report_metadata.date_range.end),
            Domain = CompactString::from(&self.policy_published.domain),
            From = CompactString::from(&self.report_metadata.email),
            Id = CompactString::from(&self.report_metadata.report_id),
            DmarcPass = dmarc_pass,
            DmarcQuarantine = dmarc_quarantine,
            DmarcReject = dmarc_reject,
            DmarcNone = dmarc_none,
            DkimPass = dkim_pass,
            DkimFail = dkim_fail,
            DkimNone = dkim_none,
            SpfPass = spf_pass,
            SpfFail = spf_fail,
            SpfNone = spf_none,
        );
    }
}

impl LogReport for TlsReport {
    fn log(&self) {
        for policy in self.policies.iter().take(5) {
            let mut details = AHashMap::with_capacity(policy.failure_details.len());
            for failure in &policy.failure_details {
                let num_failures = std::cmp::min(1, failure.failed_session_count);
                match details.entry(failure.result_type) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += num_failures;
                    }
                    Entry::Vacant(e) => {
                        e.insert(num_failures);
                    }
                }
            }

            trc::event!(
                IncomingReport(if policy.summary.failed_sessions > 0 {
                    IncomingReportEvent::TlsReportWithWarnings
                } else {
                    IncomingReportEvent::TlsReport
                }),
                RangeFrom =
                    trc::Value::Timestamp(self.date_range.start_datetime.to_timestamp() as u64),
                RangeTo = trc::Value::Timestamp(self.date_range.end_datetime.to_timestamp() as u64),
                Domain = policy.policy.policy_domain.clone(),
                From = CompactString::from(self.contact_info.as_deref().unwrap_or_default()),
                Id = self.report_id.clone(),
                Policy = format_compact!("{:?}", policy.policy.policy_type),
                TotalSuccesses = policy.summary.successful_sessions,
                TotalFailures = policy.summary.failed_sessions,
                Details = format_compact!("{details:?}"),
            );
        }
    }
}

impl LogReport for FeedbackReport<'_> {
    fn log(&self) {
        trc::event!(
            IncomingReport(match self.feedback_type {
                FeedbackType::Abuse => IncomingReportEvent::AbuseReport,
                FeedbackType::AuthFailure => IncomingReportEvent::AuthFailureReport,
                FeedbackType::Fraud => IncomingReportEvent::FraudReport,
                FeedbackType::NotSpam => IncomingReportEvent::NotSpamReport,
                FeedbackType::Other => IncomingReportEvent::OtherReport,
                FeedbackType::Virus => IncomingReportEvent::VirusReport,
            }),
            RangeFrom = trc::Value::Timestamp(
                self.arrival_date
                    .map(|d| d as u64)
                    .unwrap_or_else(|| { now() })
            ),
            Domain = self
                .reported_domains
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
            Hostname = self
                .reporting_mta
                .as_deref()
                .map(|d| trc::Value::String(d.into())),
            Url = self
                .reported_uris
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
            RemoteIp = self.source_ip,
            Total = self.incidents,
            Result = format_compact!("{:?}", self.delivery_result),
            Details = self
                .authentication_results
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
        );
    }
}
