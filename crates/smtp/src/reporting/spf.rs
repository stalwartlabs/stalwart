/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::Session,
    reporting::{ReportAddress, send::MtaReportSend},
};
use common::network::SessionStream;
use compact_str::CompactString;
use mail_auth::{
    AuthenticationResults, SpfOutput,
    report::{
        ReportEnvelope,
        arf::{AuthFailureType, FeedbackReport},
    },
    spf::verify::SpfParameters,
};
use registry::schema::structs::Rate;
use trc::OutgoingReportEvent;

impl<T: SessionStream> Session<T> {
    pub async fn send_spf_report(
        &self,
        rcpt: &str,
        rate: &Rate,
        rejected: bool,
        output: &SpfOutput,
    ) {
        if ReportAddress::checked(rcpt, self.data.session_id).is_none() {
            return;
        }

        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "spf").await {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::SpfRateLimited),
                SpanId = self.data.session_id,
                To = CompactString::from(rcpt),
                Limit = vec![
                    trc::Value::from(rate.count),
                    trc::Value::from(rate.period.into_inner())
                ],
            );

            return;
        }

        // Generate report
        let config = &self.server.core.smtp.report.spf;
        let from_addr = self
            .server
            .eval_if(&config.address, self, self.data.session_id)
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let from_name = self
            .server
            .eval_if(&config.name, self, self.data.session_id)
            .await
            .unwrap_or_else(|| "Mailer Daemon".to_string());
        let subject = self
            .server
            .eval_if(&config.subject, self, self.data.session_id)
            .await
            .unwrap_or_else(|| "SPF Report".to_string());
        let spf_params = if let Some(mail_from) = &self.data.mail_from {
            SpfParameters::mail_from(
                self.data.remote_ip,
                &self.data.helo_domain,
                &self.hostname,
                &mail_from.address,
            )
        } else {
            SpfParameters::helo(self.data.remote_ip, &self.data.helo_domain, &self.hostname)
        };
        let mut report = Vec::with_capacity(128);
        if let Err(err) = (FeedbackReport {
            authentication_results: vec![
                AuthenticationResults::new(&self.hostname)
                    .with_spf_result(output, &spf_params)
                    .to_string()
                    .into(),
            ],
            spf_dns: Some(format!("txt : {} : v=SPF1", output.domain()).into()),
            ..self.new_auth_failure(AuthFailureType::Spf, rejected)
        })
        .write_rfc5322(
            &ReportEnvelope {
                from: (from_name.as_str(), from_addr.as_str()).into(),
                to: vec![rcpt],
                submitter: &self.hostname,
                report_domain: "",
                subject: Some(&subject),
            },
            &mut report,
        ) {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::SubmissionError),
                SpanId = self.data.session_id,
                To = CompactString::from(rcpt),
                Reason = err.to_string(),
            );
            return;
        }

        trc::event!(
            OutgoingReport(OutgoingReportEvent::SpfReport),
            SpanId = self.data.session_id,
            To = CompactString::from(rcpt),
            From = CompactString::from(&from_addr),
        );

        // Send report
        self.server
            .send_report(
                &from_addr,
                [rcpt].into_iter(),
                report,
                &config.sign,
                true,
                self.data.session_id,
            )
            .await;
    }
}
