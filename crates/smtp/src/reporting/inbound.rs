/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use ahash::AHashMap;
use common::{USER_AGENT, config::smtp::report::AddressMatch};
use mail_auth::report::{
    ActionDisposition, AuthFailureType, DeliveryResult, DmarcResult, Feedback, FeedbackType,
    Report, tlsrpt::TlsReport,
};
use std::{collections::hash_map::Entry, time::SystemTime};
use store::write::now;
use tokio::io::{AsyncRead, AsyncWrite};
use trc::IncomingReportEvent;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn new_auth_failure(&self, ft: AuthFailureType, rejected: bool) -> Feedback<'_> {
        Feedback::new(FeedbackType::AuthFailure)
            .with_auth_failure(ft)
            .with_arrival_date(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as i64,
            )
            .with_source_ip(self.data.remote_ip)
            .with_reporting_mta(&self.hostname)
            .with_user_agent(USER_AGENT)
            .with_delivery_result(if rejected {
                DeliveryResult::Reject
            } else {
                DeliveryResult::Unspecified
            })
    }

    pub fn is_report(&self) -> bool {
        for addr_match in &self.server.core.smtp.report.analysis.addresses {
            for addr in &self.data.rcpt_to {
                let rcpt_addr = addr
                    .dsn_info
                    .as_ref()
                    .and_then(|v| v.strip_prefix("rfc822;"))
                    .unwrap_or(&addr.address_lcase);

                match addr_match {
                    AddressMatch::StartsWith(prefix) if rcpt_addr.starts_with(prefix) => {
                        return true;
                    }
                    AddressMatch::EndsWith(suffix) if rcpt_addr.ends_with(suffix) => {
                        return true;
                    }
                    AddressMatch::Equals(value) if rcpt_addr.eq(value) => return true,
                    _ => (),
                }
            }
        }

        false
    }
}

pub(crate) trait LogReport {
    fn log(&self);
}

impl LogReport for Report {
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

        for record in self.records() {
            let count = std::cmp::min(record.count(), 1);

            match record.action_disposition() {
                ActionDisposition::Pass => {
                    dmarc_pass += count;
                }
                ActionDisposition::Quarantine => {
                    dmarc_quarantine += count;
                }
                ActionDisposition::Reject => {
                    dmarc_reject += count;
                }
                ActionDisposition::None | ActionDisposition::Unspecified => {
                    dmarc_none += count;
                }
            }
            match record.dmarc_dkim_result() {
                DmarcResult::Pass => {
                    dkim_pass += count;
                }
                DmarcResult::Fail => {
                    dkim_fail += count;
                }
                DmarcResult::Unspecified => {
                    dkim_none += count;
                }
            }
            match record.dmarc_spf_result() {
                DmarcResult::Pass => {
                    spf_pass += count;
                }
                DmarcResult::Fail => {
                    spf_fail += count;
                }
                DmarcResult::Unspecified => {
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
            RangeFrom = trc::Value::Timestamp(self.date_range_begin()),
            RangeTo = trc::Value::Timestamp(self.date_range_end()),
            Domain = self.domain().to_string(),
            From = self.email().to_string(),
            Id = self.report_id().to_string(),
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
                IncomingReport(if policy.summary.total_failure > 0 {
                    IncomingReportEvent::TlsReportWithWarnings
                } else {
                    IncomingReportEvent::TlsReport
                }),
                RangeFrom =
                    trc::Value::Timestamp(self.date_range.start_datetime.to_timestamp() as u64),
                RangeTo = trc::Value::Timestamp(self.date_range.end_datetime.to_timestamp() as u64),
                Domain = policy.policy.policy_domain.clone(),
                From = self.contact_info.as_deref().unwrap_or_default().to_string(),
                Id = self.report_id.clone(),
                Policy = format!("{:?}", policy.policy.policy_type),
                TotalSuccesses = policy.summary.total_success,
                TotalFailures = policy.summary.total_failure,
                Details = format!("{details:?}"),
            );
        }
    }
}

impl LogReport for Feedback<'_> {
    fn log(&self) {
        trc::event!(
            IncomingReport(match self.feedback_type() {
                mail_auth::report::FeedbackType::Abuse => IncomingReportEvent::AbuseReport,
                mail_auth::report::FeedbackType::AuthFailure =>
                    IncomingReportEvent::AuthFailureReport,
                mail_auth::report::FeedbackType::Fraud => IncomingReportEvent::FraudReport,
                mail_auth::report::FeedbackType::NotSpam => IncomingReportEvent::NotSpamReport,
                mail_auth::report::FeedbackType::Other => IncomingReportEvent::OtherReport,
                mail_auth::report::FeedbackType::Virus => IncomingReportEvent::VirusReport,
            }),
            RangeFrom = trc::Value::Timestamp(
                self.arrival_date()
                    .map(|d| d as u64)
                    .unwrap_or_else(|| { now() })
            ),
            Domain = self
                .reported_domain()
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
            Hostname = self.reporting_mta().map(|d| trc::Value::String(d.into())),
            Url = self
                .reported_uri()
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
            RemoteIp = self.source_ip(),
            Total = self.incidents(),
            Result = format!("{:?}", self.delivery_result()),
            Details = self
                .authentication_results()
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
        );
    }
}
