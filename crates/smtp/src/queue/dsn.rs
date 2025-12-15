/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::spool::SmtpSpool;
use super::{
    Error, ErrorDetails, HostResponse, Message, MessageSource, QueueEnvelope, RCPT_DSN_SENT,
    Recipient, Status,
};
use crate::queue::{MessageWrapper, UnexpectedResponse};
use crate::reporting::SmtpReporting;
use common::Server;
use mail_builder::MessageBuilder;
use mail_builder::headers::HeaderType;
use mail_builder::headers::content_type::ContentType;
use mail_builder::mime::{BodyPart, MimePart, make_boundary};
use mail_parser::DateTime;
use smtp_proto::{
    RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, Response,
};
use std::fmt::Write;
use std::future::Future;
use store::write::now;

pub trait SendDsn: Sync + Send {
    fn send_dsn(&self, message: &mut MessageWrapper) -> impl Future<Output = ()> + Send;
    fn log_dsn(&self, message: &MessageWrapper) -> impl Future<Output = ()> + Send;
}

impl SendDsn for Server {
    async fn send_dsn(&self, message: &mut MessageWrapper) {
        // Send DSN events
        self.log_dsn(message).await;

        if !message.message.return_path.is_empty() {
            // Build DSN
            if let Some(dsn) = message.build_dsn(self).await {
                let mut dsn_message = self.new_message("", message.span_id);
                dsn_message
                    .add_recipient(message.message.return_path.as_ref(), self)
                    .await;

                // Sign message
                let signature = self
                    .sign_message(message, &self.core.smtp.queue.dsn.sign, &dsn)
                    .await;

                // Queue DSN
                dsn_message
                    .queue(
                        signature.as_deref(),
                        &dsn,
                        message.span_id,
                        self,
                        MessageSource::Dsn,
                    )
                    .await;
            }
        } else {
            // Handle double bounce
            message.handle_double_bounce();
        }
    }

    async fn log_dsn(&self, message: &MessageWrapper) {
        let now = now();

        for rcpt in &message.message.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT) {
                continue;
            }

            match &rcpt.status {
                Status::Completed(response) => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::DsnSuccess),
                        SpanId = message.span_id,
                        To = rcpt.address.clone(),
                        Hostname = response.hostname.clone(),
                        Code = response.response.code,
                        Details = response.response.message.to_string(),
                    );
                }
                Status::TemporaryFailure(response) if rcpt.notify.due <= now => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::DsnTempFail),
                        SpanId = message.span_id,
                        To = rcpt.address.clone(),
                        Hostname = response.entity.clone(),
                        Details = response.details.to_string(),
                        NextRetry = trc::Value::Timestamp(rcpt.retry.due),
                        Expires = rcpt
                            .expiration_time(message.message.created)
                            .map(trc::Value::Timestamp),
                        Total = rcpt.retry.inner,
                    );
                }
                Status::PermanentFailure(response) => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::DsnPermFail),
                        SpanId = message.span_id,
                        To = rcpt.address.clone(),
                        Hostname = response.entity.clone(),
                        Details = response.details.to_string(),
                        Total = rcpt.retry.inner,
                    );
                }
                Status::Scheduled if rcpt.notify.due <= now => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::DsnTempFail),
                        SpanId = message.span_id,
                        To = rcpt.address.clone(),
                        Details = "Concurrency limited",
                        NextRetry = trc::Value::Timestamp(rcpt.retry.due),
                        Expires = rcpt
                            .expiration_time(message.message.created)
                            .map(trc::Value::Timestamp),
                        Total = rcpt.retry.inner,
                    );
                }
                _ => continue,
            }
        }
    }
}

const MAX_HEADER_SIZE: usize = 4096;

impl MessageWrapper {
    pub async fn build_dsn(&mut self, server: &Server) -> Option<Vec<u8>> {
        let config = &server.core.smtp.queue;
        let now = now();

        let mut txt_success = String::new();
        let mut txt_delay = String::new();
        let mut txt_failed = String::new();
        let mut dsn = String::new();

        for rcpt in &mut self.message.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                continue;
            }
            match &rcpt.status {
                Status::Completed(response) => {
                    rcpt.flags |= RCPT_DSN_SENT;
                    if !rcpt.has_flag(RCPT_NOTIFY_SUCCESS) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_success);
                }
                Status::TemporaryFailure(response)
                    if rcpt.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                {
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    rcpt.write_dsn_will_retry_until(self.message.created, &mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_delay);
                }
                Status::PermanentFailure(response) => {
                    rcpt.flags |= RCPT_DSN_SENT;
                    if !rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_failed);
                }
                Status::Scheduled if rcpt.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) => {
                    // This case should not happen under normal circumstances
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    rcpt.write_dsn_will_retry_until(self.message.created, &mut dsn);
                    ErrorDetails {
                        entity: "localhost".into(),
                        details: Error::ConcurrencyLimited,
                    }
                    .write_dsn_text(&rcpt.address, &mut txt_delay);
                }
                _ => continue,
            }

            dsn.push_str("\r\n");
        }

        // Build text response
        let txt_len = txt_success.len() + txt_delay.len() + txt_failed.len();
        if txt_len == 0 {
            return None;
        }

        let has_success = !txt_success.is_empty();
        let has_delay = !txt_delay.is_empty();
        let has_failure = !txt_failed.is_empty();

        let mut txt = String::with_capacity(txt_len + 128);
        let (subject, is_mixed) = if has_success && !has_delay && !has_failure {
            txt.push_str(
                "Your message has been successfully delivered to the following recipients:\r\n\r\n",
            );
            ("Successfully delivered message", false)
        } else if has_delay && !has_success && !has_failure {
            txt.push_str("There was a temporary problem delivering your message to the following recipients:\r\n\r\n");
            ("Warning: Delay in message delivery", false)
        } else if has_failure && !has_success && !has_delay {
            txt.push_str(
                "Your message could not be delivered to the following recipients:\r\n\r\n",
            );
            ("Failed to deliver message", false)
        } else if has_success {
            txt.push_str("Your message has been partially delivered:\r\n\r\n");
            ("Partially delivered message", true)
        } else {
            txt.push_str("Your message could not be delivered to some recipients:\r\n\r\n");
            (
                "Warning: Temporary and permanent failures during message delivery",
                true,
            )
        };

        if has_success {
            if is_mixed {
                txt.push_str(
                    "    ----- Delivery to the following addresses was successful -----\r\n",
                );
            }

            txt.push_str(&txt_success);
            txt.push_str("\r\n");
        }

        if has_delay {
            if is_mixed {
                txt.push_str(
                    "    ----- There was a temporary problem delivering to these addresses -----\r\n",
                );
            }
            txt.push_str(&txt_delay);
            txt.push_str("\r\n");
        }

        if has_failure {
            if is_mixed {
                txt.push_str("    ----- Delivery to the following addresses failed -----\r\n");
            }
            txt.push_str(&txt_failed);
            txt.push_str("\r\n");
        }

        // Update next delay notification time
        if has_delay {
            let mut changes = Vec::new();
            for (rcpt_idx, rcpt) in self.message.recipients.iter().enumerate() {
                if matches!(
                    &rcpt.status,
                    Status::TemporaryFailure(_) | Status::Scheduled
                ) && rcpt.notify.due <= now
                {
                    let envelope = QueueEnvelope::new(&self.message, rcpt);

                    let queue_id = server
                        .eval_if::<String, _>(
                            &server.core.smtp.queue.queue,
                            &envelope,
                            self.span_id,
                        )
                        .await
                        .unwrap_or_else(|| "default".to_string());
                    let queue = server.get_queue_or_default(&queue_id, self.span_id);

                    if let Some(next_notify) =
                        queue.notify.get((rcpt.notify.inner + 1) as usize).copied()
                    {
                        changes.push((rcpt_idx, 1, now + next_notify));
                    } else {
                        changes.push((rcpt_idx, 0, u64::MAX));
                    }
                }
            }

            for (rcpt_idx, inner, due) in changes {
                let rcpt = &mut self.message.recipients[rcpt_idx];
                rcpt.notify.inner += inner;
                rcpt.notify.due = due;
            }
        }

        // Obtain hostname and sender addresses
        let from_name = server
            .eval_if(&config.dsn.name, &self.message, self.span_id)
            .await
            .unwrap_or_else(|| String::from("Mail Delivery Subsystem"));
        let from_addr = server
            .eval_if(&config.dsn.address, &self.message, self.span_id)
            .await
            .unwrap_or_else(|| String::from("MAILER-DAEMON@localhost"));
        let reporting_mta = server
            .eval_if(
                &server.core.smtp.report.submitter,
                &self.message,
                self.span_id,
            )
            .await
            .unwrap_or_else(|| String::from("localhost"));

        // Prepare DSN
        let mut dsn_header = String::with_capacity(dsn.len() + 128);
        self.message
            .write_dsn_headers(&mut dsn_header, &reporting_mta);
        let dsn = dsn_header + dsn.as_str();

        // Fetch up to MAX_HEADER_SIZE bytes of message headers
        let headers = match server
            .blob_store()
            .get_blob(self.message.blob_hash.as_slice(), 0..MAX_HEADER_SIZE)
            .await
        {
            Ok(Some(mut buf)) => {
                let mut prev_ch = 0;
                let mut last_lf = buf.len();
                for (pos, &ch) in buf.iter().enumerate() {
                    match ch {
                        b'\n' => {
                            last_lf = pos + 1;
                            if prev_ch != b'\n' {
                                prev_ch = ch;
                            } else {
                                break;
                            }
                        }
                        b'\r' => (),
                        0 => break,
                        _ => {
                            prev_ch = ch;
                        }
                    }
                }
                if last_lf < MAX_HEADER_SIZE {
                    buf.truncate(last_lf);
                }
                String::from_utf8(buf).unwrap_or_default()
            }
            Ok(None) => {
                trc::event!(
                    Queue(trc::QueueEvent::BlobNotFound),
                    SpanId = self.span_id,
                    BlobId = self.message.blob_hash.to_hex(),
                    CausedBy = trc::location!()
                );

                String::new()
            }
            Err(err) => {
                trc::error!(
                    err.span_id(self.span_id)
                        .details("Failed to fetch blobId")
                        .caused_by(trc::location!())
                );

                String::new()
            }
        };

        // Build message
        MessageBuilder::new()
            .from((from_name.as_str(), from_addr.as_str()))
            .header(
                "To",
                HeaderType::Text(self.message.return_path.as_ref().into()),
            )
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("<{}@{}>", make_boundary("."), reporting_mta))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
                BodyPart::Multipart(vec![
                    MimePart::new(ContentType::new("text/plain"), BodyPart::Text(txt.into())),
                    MimePart::new(
                        ContentType::new("message/delivery-status"),
                        BodyPart::Text(dsn.into()),
                    ),
                    MimePart::new(
                        ContentType::new("message/rfc822"),
                        BodyPart::Text(headers.into()),
                    ),
                ]),
            ))
            .write_to_vec()
            .unwrap_or_default()
            .into()
    }

    fn handle_double_bounce(&mut self) {
        let mut is_double_bounce = Vec::with_capacity(0);
        let now = now();

        for rcpt in &mut self.message.recipients {
            if !rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER)
                && let Status::PermanentFailure(err) = &rcpt.status
            {
                rcpt.flags |= RCPT_DSN_SENT;
                let mut dsn = String::new();
                err.write_dsn_text(&rcpt.address, &mut dsn);
                is_double_bounce.push(dsn);
            }

            if rcpt.notify.due <= now {
                rcpt.notify.due = rcpt
                    .expiration_time(self.message.created)
                    .map(|d| d + 10)
                    .unwrap_or(u64::MAX);
            }
        }

        if !is_double_bounce.is_empty() {
            trc::event!(
                Delivery(trc::DeliveryEvent::DoubleBounce),
                SpanId = self.span_id,
                To = is_double_bounce
            );
        }
    }
}

impl HostResponse<Box<str>> {
    fn write_dsn_text(&self, addr: &str, dsn: &mut String) {
        let _ = write!(
            dsn,
            "<{}> (delivered to '{}' with code {} ({}.{}.{}) '",
            addr,
            self.hostname,
            self.response.code,
            self.response.esc[0],
            self.response.esc[1],
            self.response.esc[2]
        );
        self.response.write_response(dsn);
        dsn.push_str("')\r\n");
    }
}

impl UnexpectedResponse {
    fn write_dsn_text(&self, host: &str, addr: &str, dsn: &mut String) {
        let _ = write!(dsn, "<{addr}> (host '{host}' rejected ");

        if !self.command.is_empty() {
            let _ = write!(dsn, "command '{}'", self.command);
        } else {
            dsn.push_str("transaction");
        }

        let _ = write!(
            dsn,
            " with code {} ({}.{}.{}) '",
            self.response.code, self.response.esc[0], self.response.esc[1], self.response.esc[2]
        );
        self.response.write_response(dsn);
        dsn.push_str("')\r\n");
    }
}

impl ErrorDetails {
    fn write_dsn_text(&self, addr: &str, dsn: &mut String) {
        let entity = self.entity.as_ref();
        match &self.details {
            Error::UnexpectedResponse(response) => {
                response.write_dsn_text(entity, addr, dsn);
            }
            Error::DnsError(err) => {
                let _ = write!(dsn, "<{addr}> (failed to lookup '{entity}': {err})\r\n",);
            }
            Error::ConnectionError(details) => {
                let _ = write!(
                    dsn,
                    "<{addr}> (connection to '{entity}' failed: {details})\r\n",
                );
            }
            Error::TlsError(details) => {
                let _ = write!(dsn, "<{addr}> (TLS error from '{entity}': {details})\r\n",);
            }
            Error::DaneError(details) => {
                let _ = write!(
                    dsn,
                    "<{addr}> (DANE failed to authenticate '{entity}': {details})\r\n",
                );
            }
            Error::MtaStsError(details) => {
                let _ = write!(
                    dsn,
                    "<{addr}> (MTA-STS failed to authenticate '{entity}': {details})\r\n",
                );
            }
            Error::RateLimited => {
                let _ = write!(dsn, "<{addr}> (rate limited)\r\n");
            }
            Error::ConcurrencyLimited => {
                let _ = write!(
                    dsn,
                    "<{addr}> (too many concurrent connections to remote server)\r\n",
                );
            }
            Error::Io(err) => {
                let _ = write!(dsn, "<{addr}> (queue error: {err})\r\n");
            }
        }
    }
}

impl Message {
    fn write_dsn_headers(&self, dsn: &mut String, reporting_mta: &str) {
        let _ = write!(dsn, "Reporting-MTA: dns;{reporting_mta}\r\n");
        dsn.push_str("Arrival-Date: ");
        dsn.push_str(&DateTime::from_timestamp(self.created as i64).to_rfc822());
        dsn.push_str("\r\n");
        if let Some(env_id) = &self.env_id {
            let _ = write!(dsn, "Original-Envelope-Id: {env_id}\r\n");
        }
        dsn.push_str("\r\n");
    }
}

impl Recipient {
    fn write_dsn(&self, dsn: &mut String) {
        if let Some(orcpt) = &self.orcpt {
            let _ = write!(dsn, "Original-Recipient: rfc822;{orcpt}\r\n");
        }
        let _ = write!(dsn, "Final-Recipient: rfc822;{}\r\n", self.address);
    }

    fn write_dsn_will_retry_until(&self, created: u64, dsn: &mut String) {
        if let Some(expires) = self.expiration_time(created)
            && expires > now()
        {
            dsn.push_str("Will-Retry-Until: ");
            dsn.push_str(&DateTime::from_timestamp(expires as i64).to_rfc822());
            dsn.push_str("\r\n");
        }
    }
}

impl<T, E> Status<T, E> {
    pub fn into_permanent(self) -> Self {
        match self {
            Status::TemporaryFailure(v) => Status::PermanentFailure(v),
            v => v,
        }
    }

    pub fn into_temporary(self) -> Self {
        match self {
            Status::PermanentFailure(err) => Status::TemporaryFailure(err),
            other => other,
        }
    }

    pub fn is_permanent(&self) -> bool {
        matches!(self, Status::PermanentFailure(_))
    }

    fn write_dsn_action(&self, dsn: &mut String) {
        dsn.push_str("Action: ");
        dsn.push_str(match self {
            Status::Completed(_) => "delivered",
            Status::PermanentFailure(_) => "failed",
            Status::TemporaryFailure(_) | Status::Scheduled => "delayed",
        });
        dsn.push_str("\r\n");
    }
}

impl Status<HostResponse<Box<str>>, ErrorDetails> {
    fn write_dsn(&self, dsn: &mut String) {
        self.write_dsn_action(dsn);
        self.write_dsn_status(dsn);
        self.write_dsn_diagnostic(dsn);
        self.write_dsn_remote_mta(dsn);
    }

    fn write_dsn_status(&self, dsn: &mut String) {
        dsn.push_str("Status: ");
        match self {
            Status::Completed(response) => {
                response.response.write_dsn_status(dsn);
            }
            Status::TemporaryFailure(err) | Status::PermanentFailure(err) => {
                if let Error::UnexpectedResponse(response) = &err.details {
                    response.response.write_dsn_status(dsn);
                } else {
                    dsn.push_str(if matches!(self, Status::PermanentFailure(_)) {
                        "5.0.0"
                    } else {
                        "4.0.0"
                    });
                }
            }
            Status::Scheduled => {
                dsn.push_str("4.0.0");
            }
        }
        dsn.push_str("\r\n");
    }

    fn write_dsn_remote_mta(&self, dsn: &mut String) {
        match self {
            Status::Completed(response) => {
                dsn.push_str("Remote-MTA: dns;");
                dsn.push_str(&response.hostname);
                dsn.push_str("\r\n");
            }
            Status::TemporaryFailure(err) | Status::PermanentFailure(err) => match &err.details {
                Error::UnexpectedResponse(_)
                | Error::ConnectionError(_)
                | Error::TlsError(_)
                | Error::DaneError(_) => {
                    dsn.push_str("Remote-MTA: dns;");
                    dsn.push_str(&err.entity);
                    dsn.push_str("\r\n");
                }
                _ => (),
            },
            Status::Scheduled => (),
        }
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        if let Status::PermanentFailure(err) | Status::TemporaryFailure(err) = self
            && let Error::UnexpectedResponse(response) = &err.details
        {
            response.response.write_dsn_diagnostic(dsn);
        }
    }
}

impl WriteDsn for Response<Box<str>> {
    fn write_dsn_status(&self, dsn: &mut String) {
        if self.esc[0] > 0 {
            let _ = write!(dsn, "{}.{}.{}", self.esc[0], self.esc[1], self.esc[2]);
        } else {
            let _ = write!(
                dsn,
                "{}.{}.{}",
                self.code / 100,
                (self.code / 10) % 10,
                self.code % 10
            );
        }
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        let _ = write!(dsn, "Diagnostic-Code: smtp;{} ", self.code);
        self.write_response(dsn);
        dsn.push_str("\r\n");
    }

    fn write_response(&self, dsn: &mut String) {
        for ch in self.message.chars() {
            if ch != '\n' && ch != '\r' {
                dsn.push(ch);
            }
        }
    }
}

trait WriteDsn {
    fn write_dsn_status(&self, dsn: &mut String);
    fn write_dsn_diagnostic(&self, dsn: &mut String);
    fn write_response(&self, dsn: &mut String);
}
