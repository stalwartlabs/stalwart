/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::Session,
    reporting::{ReportAddress, send::MtaReportSend},
};
use common::{expr::Bump, network::SessionStream};
use compact_str::CompactString;
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DkimOutput,
    report::{ReportEnvelope, arf::FeedbackReport},
};
use registry::schema::structs::Rate;
use trc::OutgoingReportEvent;

impl<T: SessionStream> Session<T> {
    pub async fn send_dkim_report(
        &self,
        rcpt: &str,
        message: &AuthenticatedMessage<'_>,
        rate: &Rate,
        rejected: bool,
        output: &DkimOutput<'_>,
    ) {
        if ReportAddress::checked(rcpt, self.data.session_id).is_none() {
            return;
        }

        // Generate report
        let signature = if let Some(signature) = output.signature() {
            signature
        } else {
            return;
        };

        if self
            .server
            .is_local_report_domain(&signature.d, self.data.session_id)
            .await
        {
            return;
        }

        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "dkim").await {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::DkimRateLimited),
                SpanId = self.data.session_id,
                To = CompactString::from(rcpt),
                Limit = vec![
                    trc::Value::from(rate.count),
                    trc::Value::from(rate.period.into_inner())
                ],
            );

            return;
        }

        let config = &self.server.core.smtp.report.dkim;
        let mut arena = Bump::new();
        let from_addr = self
            .server
            .eval_if(&config.address, self, &mut arena, self.data.session_id)
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let from_name = self
            .server
            .eval_if(&config.name, self, &mut arena, self.data.session_id)
            .await
            .unwrap_or_else(|| "Mail Delivery Subsystem".to_string());
        let subject = self
            .server
            .eval_if(&config.subject, self, &mut arena, self.data.session_id)
            .await
            .unwrap_or_else(|| "DKIM Report".to_string());
        let mut report = Vec::with_capacity(128);
        if let Err(err) = (FeedbackReport {
            authentication_results: vec![
                AuthenticationResults::new(&self.hostname)
                    .with_dkim_result(output, message.first_from_address())
                    .to_string()
                    .into(),
            ],
            dkim_domain: Some(signature.d.as_str().into()),
            dkim_selector: Some(signature.s.as_str().into()),
            dkim_identity: Some(signature.identity().into()),
            headers: Some(
                std::str::from_utf8(message.raw_headers())
                    .unwrap_or_default()
                    .into(),
            ),
            ..self.new_auth_failure(output.result().into(), rejected)
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
            OutgoingReport(OutgoingReportEvent::DkimReport),
            SpanId = self.data.session_id,
            From = CompactString::from(&from_addr),
            To = CompactString::from(rcpt),
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
