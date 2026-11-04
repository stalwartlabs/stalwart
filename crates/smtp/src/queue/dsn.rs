/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::spool::SmtpSpool;
use super::{
    Error, ErrorDetails, FROM_DKIM2_SIGNED, HostResponse, Message, MessageSource, QueueEnvelope,
    RCPT_DSN_SENT, Recipient, Status,
};
use crate::inbound::dkim::has_dkim2_headers;
use crate::queue::quota::HasQueueQuota;
use crate::queue::spool::{DSN_RETRY, QueueOutcome, QueueParams};
use crate::queue::{MessageWrapper, UnexpectedResponse, eval_strategy};
use common::{Server, config::smtp::auth::DkimSigners, expr::Bump};
use compact_str::{CompactString, ToCompactString};
use email::message::delivery::ORCPT_ADDR_TYPE;
use mail_auth::AuthenticatedMessage;
use mail_auth::dkim2::ChainBinding;
use mail_builder::MessageBuilder;
use mail_builder::headers::HeaderType;
use mail_builder::headers::content_type::ContentType;
use mail_builder::mime::{BodyPart, MimePart, make_boundary};
use mail_parser::DateTime;
use smtp_proto::{
    RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, Response,
};
use std::borrow::Cow;
use std::fmt::Write;
use std::future::Future;
use std::sync::Arc;
use store::write::now;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnStatus {
    Completed,
    Deferred,
}

pub trait SendDsn: Sync + Send {
    fn send_dsn(&self, message: &mut MessageWrapper) -> impl Future<Output = DsnStatus> + Send;
    fn log_dsn(&self, message: &MessageWrapper) -> impl Future<Output = ()> + Send;
}

pub(crate) trait PropagateDsn: Sync + Send {
    fn propagate_dkim2_dsn(
        &self,
        parsed_dsn: &mail_parser::Message<'_>,
        returned: &AuthenticatedMessage<'_>,
        session_id: u64,
    ) -> impl Future<Output = Option<QueueOutcome>> + Send;

    fn own_dkim2_hops(
        &self,
        message: &AuthenticatedMessage<'_>,
    ) -> impl Future<Output = usize> + Send;

    fn dsn_signers(
        &self,
        resolver: &Message,
        returned: Option<&AuthenticatedMessage<'_>>,
        recipients: Option<&[Recipient]>,
        span_id: u64,
    ) -> impl Future<Output = DsnSigning> + Send;

    fn load_dsn_signers(
        &self,
        domain: &str,
        span_id: u64,
    ) -> impl Future<Output = Option<Arc<DkimSigners>>> + Send;

    fn build_forwarded_dsn(
        &self,
        delivery_status: &str,
        arrival_headers: &[u8],
        resolver: Option<&Message>,
        span_id: u64,
    ) -> impl Future<Output = Option<ForwardedDsn>> + Send;
}

impl SendDsn for Server {
    async fn send_dsn(&self, message: &mut MessageWrapper) -> DsnStatus {
        // Send DSN events
        self.log_dsn(message).await;

        let mut status = DsnStatus::Completed;

        if !message.message.return_path.is_empty() {
            // Build DSN
            if let Some(report) = message.dsn_report() {
                let returned = message.returned_part(self).await;
                let outcome = match message.forwarded_dsn(self, &report, &returned).await {
                    Some(outcome) => Some(outcome),
                    None => message.local_dsn(self, report, returned).await,
                };
                match outcome {
                    Some(QueueOutcome::Queued) | None => message.mark_dsn_sent(),
                    Some(_) => status = DsnStatus::Deferred,
                }
            } else {
                message.mark_dsn_sent();
            }
        } else {
            // Handle double bounce
            message.handle_double_bounce();
        }

        // Update next DSN notify times
        message.update_next_dsn(self, status).await;

        status
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
                        Details = CompactString::from(&*response.response.message),
                    );
                }
                Status::TemporaryFailure(response) if rcpt.notify.due <= now => {
                    trc::event!(
                        Delivery(trc::DeliveryEvent::DsnTempFail),
                        SpanId = message.span_id,
                        To = rcpt.address.clone(),
                        Hostname = response.entity.clone(),
                        Details = response.details.to_compact_string(),
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
                        Details = response.details.to_compact_string(),
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

impl PropagateDsn for Server {
    async fn propagate_dkim2_dsn(
        &self,
        parsed_dsn: &mail_parser::Message<'_>,
        returned: &AuthenticatedMessage<'_>,
        session_id: u64,
    ) -> Option<QueueOutcome> {
        let hops = self.own_dkim2_hops(returned).await;
        if hops == 0 || hops == returned.dkim2_signatures().len() {
            return None;
        }
        let arrival_headers = returned.dkim2_arrival_headers(hops);
        let delivery_status = parsed_dsn
            .root_part()
            .children()
            .find(|part| part.is_content_type("message", "delivery-status"))?
            .decoded();
        let delivery_status = std::str::from_utf8(&delivery_status).ok()?;
        let ForwardedDsn {
            message,
            raw,
            signing,
            return_path,
        } = self
            .build_forwarded_dsn(delivery_status, &arrival_headers, None, session_id)
            .await?;
        let quotas = self.queue_quotas(&message).await;
        let outcome = message
            .queue(signing.apply(QueueParams::new(&raw, session_id, self).with_quotas(quotas)))
            .await;
        if outcome == QueueOutcome::Queued {
            trc::event!(
                Dkim2(trc::Dkim2Event::DsnPropagated),
                SpanId = session_id,
                To = return_path,
            );
        }
        Some(outcome)
    }

    async fn own_dkim2_hops(&self, message: &AuthenticatedMessage<'_>) -> usize {
        let mut hops = 0;
        for signature in message.dkim2_signatures().iter().rev() {
            match self.domain(&signature.header.d).await {
                Ok(Some(_)) => hops += 1,
                _ => break,
            }
        }
        hops
    }

    async fn dsn_signers(
        &self,
        resolver: &Message,
        returned: Option<&AuthenticatedMessage<'_>>,
        recipients: Option<&[Recipient]>,
        span_id: u64,
    ) -> DsnSigning {
        let mut arena = Bump::new();
        let Some(configured) = self
            .eval_if::<String, _>(
                &self.core.smtp.queue.dsn.sign,
                resolver,
                &mut arena,
                span_id,
            )
            .await
        else {
            return DsnSigning::Configured(None);
        };
        let Some(returned) = returned.filter(|returned| {
            !returned.dkim2_signatures().is_empty() && !returned.dkim2_dsn_aligned(&configured)
        }) else {
            return DsnSigning::Configured(self.load_dsn_signers(&configured, span_id).await);
        };

        let mut tried: Vec<&str> = Vec::with_capacity(MAX_DSN_DOMAINS);
        for domain in returned.dkim2_dsn_domains() {
            if tried.len() == MAX_DSN_DOMAINS {
                break;
            }
            if configured.eq_ignore_ascii_case(domain)
                || tried.iter().any(|tried| tried.eq_ignore_ascii_case(domain))
            {
                continue;
            }
            tried.push(domain);
            if recipients.is_some_and(|recipients| {
                !recipients
                    .iter()
                    .any(|rcpt| is_same_or_subdomain(rcpt.domain_part(), domain))
            }) {
                continue;
            }
            if let Some(signers) = self.load_dsn_signers(domain, span_id).await
                && signers.dkim2.is_some()
            {
                return DsnSigning::Aligned {
                    signers,
                    domain: domain.into(),
                };
            }
        }

        let signers = self.load_dsn_signers(&configured, span_id).await;
        trc::event!(
            Dkim2(trc::Dkim2Event::DsnNotAligned),
            SpanId = span_id,
            Domain = configured,
        );
        DsnSigning::Dkim1Only(signers)
    }

    async fn load_dsn_signers(&self, domain: &str, span_id: u64) -> Option<Arc<DkimSigners>> {
        self.dkim_signers(domain).await.unwrap_or_else(|err| {
            trc::error!(
                err.span_id(span_id)
                    .details("Failed to retrieve DKIM signers")
            );
            None
        })
    }

    async fn build_forwarded_dsn(
        &self,
        delivery_status: &str,
        arrival_headers: &[u8],
        resolver: Option<&Message>,
        span_id: u64,
    ) -> Option<ForwardedDsn> {
        let arrival = AuthenticatedMessage::parse(arrival_headers)?;
        let return_path = strip_brackets(arrival.dkim2_return_path()?);
        let arrival_rcpts = arrival
            .dkim2_signatures()
            .last()
            .map_or(&[][..], |signature| match &signature.header.chain {
                ChainBinding::Envelope { rcpt_to, .. } => rcpt_to.as_slice(),
                ChainBinding::NextDomain(_) => &[][..],
            });

        let mut message = self.new_message("", MessageSource::Dsn, span_id);
        message.expand_and_add_recipient(return_path, self).await;
        let resolver = resolver.unwrap_or(&message.message);
        let signing = self
            .dsn_signers(resolver, Some(&arrival), None, span_id)
            .await;

        let config = &self.core.smtp.queue;
        let mut arena = Bump::new();
        let from_name = self
            .eval_if(&config.dsn.name, resolver, &mut arena, span_id)
            .await
            .unwrap_or_else(|| String::from("Mail Delivery Subsystem"));
        let from_addr = self
            .eval_if(&config.dsn.address, resolver, &mut arena, span_id)
            .await
            .unwrap_or_else(|| String::from("MAILER-DAEMON@localhost"));
        let from_addr = aligned_from(from_addr, signing.aligned_domain());
        let reporting_mta = self
            .eval_if(
                &self.core.smtp.report.submitter,
                resolver,
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| String::from("localhost"));

        let status = rewrite_delivery_status(delivery_status, &reporting_mta, arrival_rcpts)?;
        let txt = format!(
            "This is the mail system at host {reporting_mta}.\r\n\r\n\
             A message you sent was forwarded by this system and could not be\r\n\
             delivered from there. Details about the forwarding destination\r\n\
             have been removed from this report.\r\n"
        );

        let raw = MessageBuilder::new()
            .from((from_name.as_str(), from_addr.as_str()))
            .header("To", HeaderType::Text(return_path.into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("{}@{}", make_boundary("."), reporting_mta))
            .subject("Delivery Status Notification")
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
                BodyPart::Multipart(vec![
                    MimePart::new(ContentType::new("text/plain"), BodyPart::Text(txt.into())),
                    MimePart::new(
                        ContentType::new("message/delivery-status"),
                        BodyPart::Text(status.into()),
                    ),
                    rfc822_headers_part(arrival_headers.into()),
                ]),
            ))
            .write_to_vec()
            .ok()?;

        Some(ForwardedDsn {
            message,
            raw,
            signing,
            return_path: return_path.into(),
        })
    }
}

const MAX_HEADER_SIZE: usize = 4096;
const MAX_DKIM2_HEADER_SIZE: usize = 1024 * 1024;
const MAX_DSN_DOMAINS: usize = 8;

pub(crate) enum ReturnedPart {
    Headers(Vec<u8>),
    Dkim2Headers { headers: Vec<u8>, forwarded: bool },
}

struct DsnReport {
    subject: &'static str,
    txt: String,
    status: String,
}

pub(crate) enum DsnSigning {
    Configured(Option<Arc<DkimSigners>>),
    Aligned {
        signers: Arc<DkimSigners>,
        domain: Box<str>,
    },
    Dkim1Only(Option<Arc<DkimSigners>>),
}

pub(crate) struct ForwardedDsn {
    message: MessageWrapper,
    raw: Vec<u8>,
    signing: DsnSigning,
    return_path: CompactString,
}

impl ReturnedPart {
    pub fn dkim2(&self) -> Option<AuthenticatedMessage<'_>> {
        match self {
            ReturnedPart::Dkim2Headers { headers, .. } => AuthenticatedMessage::parse(headers),
            ReturnedPart::Headers(_) => None,
        }
    }

    fn into_mime_part(self) -> MimePart<'static> {
        match self {
            ReturnedPart::Headers(headers) => MimePart::new(
                ContentType::new("message/rfc822"),
                BodyPart::Text(String::from_utf8(headers).unwrap_or_default().into()),
            ),
            ReturnedPart::Dkim2Headers { headers, .. } => rfc822_headers_part(headers.into()),
        }
    }
}

impl DsnSigning {
    fn aligned_domain(&self) -> Option<&str> {
        match self {
            DsnSigning::Aligned { domain, .. } => Some(domain),
            DsnSigning::Configured(_) | DsnSigning::Dkim1Only(_) => None,
        }
    }

    fn apply<'x, 'y>(self, params: QueueParams<'x, 'y>) -> QueueParams<'x, 'y> {
        match self {
            DsnSigning::Configured(signers) => params.with_dkim_signers(signers),
            DsnSigning::Aligned { signers, .. } => params.with_dkim_signers(Some(signers)),
            DsnSigning::Dkim1Only(signers) => params.with_dkim_signers(signers).with_dkim1_only(),
        }
    }
}

impl MessageWrapper {
    async fn returned_part(&self, server: &Server) -> ReturnedPart {
        let mut buf = match server
            .get_blob(self.message.blob_hash.as_slice(), 0..MAX_DKIM2_HEADER_SIZE)
            .await
        {
            Ok(Some(buf)) => buf,
            Ok(None) => {
                trc::event!(
                    Queue(trc::QueueEvent::BlobNotFound),
                    SpanId = self.span_id,
                    BlobId = self.message.blob_hash.to_hex(),
                    CausedBy = trc::location!()
                );
                return ReturnedPart::Headers(Vec::new());
            }
            Err(err) => {
                trc::error!(
                    err.span_id(self.span_id)
                        .details("Failed to fetch blobId")
                        .caused_by(trc::location!())
                );
                return ReturnedPart::Headers(Vec::new());
            }
        };

        buf.truncate(header_block_len(&buf));
        if has_dkim2_headers(&buf)
            && let Some(message) = AuthenticatedMessage::parse(&buf)
        {
            let hops = self.queued_dkim2_hops(server, &message).await;
            let forwarded = self.message.flags & FROM_DKIM2_SIGNED != 0
                && hops < message.dkim2_signatures().len()
                && self.has_only_remote_recipients(server).await;
            return ReturnedPart::Dkim2Headers {
                headers: message.dkim2_arrival_headers(hops),
                forwarded,
            };
        }

        buf.truncate(MAX_HEADER_SIZE);
        let len = header_block_len(&buf);
        if len < MAX_HEADER_SIZE {
            buf.truncate(len);
        }
        ReturnedPart::Headers(buf)
    }

    async fn queued_dkim2_hops(
        &self,
        server: &Server,
        message: &AuthenticatedMessage<'_>,
    ) -> usize {
        let prepended = message
            .headers()
            .iter()
            .take_while(|(name, _)| is_signing_field(name))
            .filter(|(name, _)| name.eq_ignore_ascii_case(b"DKIM2-Signature"))
            .count();
        let mut hops = 0;
        for signature in message.dkim2_signatures().iter().rev().take(prepended) {
            let is_ours = matches!(&signature.header.chain, ChainBinding::Envelope { mail_from, .. }
                if strip_brackets(mail_from).eq_ignore_ascii_case(&self.message.return_path))
                && matches!(server.domain(&signature.header.d).await, Ok(Some(_)));
            if !is_ours {
                break;
            }
            hops += 1;
        }
        hops
    }

    async fn has_only_remote_recipients(&self, server: &Server) -> bool {
        for rcpt in &self.message.recipients {
            if !matches!(server.domain(rcpt.domain_part()).await, Ok(None)) {
                return false;
            }
        }
        true
    }

    fn dsn_report(&self) -> Option<DsnReport> {
        let now = now();

        let mut txt_success = String::new();
        let mut txt_delay = String::new();
        let mut txt_failed = String::new();
        let mut dsn = String::new();

        for rcpt in &self.message.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                continue;
            }
            match &rcpt.status {
                Status::Completed(response) => {
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

        Some(DsnReport {
            subject,
            txt,
            status: dsn,
        })
    }

    async fn forwarded_dsn(
        &self,
        server: &Server,
        report: &DsnReport,
        returned: &ReturnedPart,
    ) -> Option<QueueOutcome> {
        let ReturnedPart::Dkim2Headers {
            headers,
            forwarded: true,
        } = returned
        else {
            return None;
        };
        let mut status = String::with_capacity(report.status.len() + 128);
        self.message.write_dsn_headers(&mut status, "localhost");
        status.push_str(&report.status);
        let ForwardedDsn {
            message,
            raw,
            signing,
            return_path,
        } = server
            .build_forwarded_dsn(&status, headers, Some(&self.message), self.span_id)
            .await?;
        let outcome = message
            .queue(signing.apply(QueueParams::new(&raw, self.span_id, server)))
            .await;
        if outcome == QueueOutcome::Queued {
            trc::event!(
                Dkim2(trc::Dkim2Event::DsnPropagated),
                SpanId = self.span_id,
                To = return_path,
            );
        }
        Some(outcome)
    }

    async fn local_dsn(
        &self,
        server: &Server,
        report: DsnReport,
        returned: ReturnedPart,
    ) -> Option<QueueOutcome> {
        let signing = server
            .dsn_signers(
                &self.message,
                returned.dkim2().as_ref(),
                Some(&self.message.recipients),
                self.span_id,
            )
            .await;
        let dsn = self
            .build_dsn(server, report, returned, signing.aligned_domain())
            .await?;
        let mut dsn_message = server.new_message("", MessageSource::Dsn, self.span_id);
        dsn_message
            .expand_and_add_recipient(self.message.return_path.as_ref(), server)
            .await;
        Some(
            dsn_message
                .queue(signing.apply(QueueParams::new(&dsn, self.span_id, server)))
                .await,
        )
    }

    async fn build_dsn(
        &self,
        server: &Server,
        report: DsnReport,
        returned: ReturnedPart,
        aligned_domain: Option<&str>,
    ) -> Option<Vec<u8>> {
        let config = &server.core.smtp.queue;
        let DsnReport {
            subject,
            txt,
            status: dsn,
        } = report;

        // Obtain hostname and sender addresses
        let mut arena = Bump::new();
        let from_name = server
            .eval_if(&config.dsn.name, &self.message, &mut arena, self.span_id)
            .await
            .unwrap_or_else(|| String::from("Mail Delivery Subsystem"));
        let from_addr = server
            .eval_if(&config.dsn.address, &self.message, &mut arena, self.span_id)
            .await
            .unwrap_or_else(|| String::from("MAILER-DAEMON@localhost"));
        let from_addr = aligned_from(from_addr, aligned_domain);
        let reporting_mta = server
            .eval_if(
                &server.core.smtp.report.submitter,
                &self.message,
                &mut arena,
                self.span_id,
            )
            .await
            .unwrap_or_else(|| String::from("localhost"));

        // Prepare DSN
        let mut dsn_header = String::with_capacity(dsn.len() + 128);
        self.message
            .write_dsn_headers(&mut dsn_header, &reporting_mta);
        let dsn = dsn_header + dsn.as_str();

        // Build message
        MessageBuilder::new()
            .from((from_name.as_str(), from_addr.as_str()))
            .header(
                "To",
                HeaderType::Text(self.message.return_path.as_ref().into()),
            )
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("{}@{}", make_boundary("."), reporting_mta))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
                BodyPart::Multipart(vec![
                    MimePart::new(ContentType::new("text/plain"), BodyPart::Text(txt.into())),
                    MimePart::new(
                        ContentType::new("message/delivery-status"),
                        BodyPart::Text(dsn.into()),
                    ),
                    returned.into_mime_part(),
                ]),
            ))
            .write_to_vec()
            .unwrap_or_default()
            .into()
    }

    pub async fn update_next_dsn(&mut self, server: &Server, status: DsnStatus) {
        let now = now();
        let mut notify_changes = Vec::new();
        let mut arena = Bump::new();
        for (rcpt_idx, rcpt) in self.message.recipients.iter().enumerate() {
            if matches!(
                &rcpt.status,
                Status::TemporaryFailure(_) | Status::Scheduled
            ) && rcpt.notify.due <= now
            {
                if status == DsnStatus::Deferred {
                    notify_changes.push((rcpt_idx, 0, now + DSN_RETRY));
                    continue;
                }

                let envelope = QueueEnvelope::new(&self.message, rcpt);

                let queue = eval_strategy(
                    server,
                    &server.core.smtp.queue.queue,
                    &envelope,
                    &mut arena,
                    self.span_id,
                    Server::get_queue_or_default,
                )
                .await;

                if let Some(next_notify) =
                    queue.notify.get((rcpt.notify.inner + 1) as usize).copied()
                {
                    notify_changes.push((rcpt_idx, 1, now + next_notify));
                } else {
                    notify_changes.push((rcpt_idx, 0, u64::MAX));
                }
            }
        }

        for (rcpt_idx, inner, due) in notify_changes {
            let rcpt = &mut self.message.recipients[rcpt_idx];
            rcpt.notify.inner += inner;
            rcpt.notify.due = due;
        }
    }

    fn mark_dsn_sent(&mut self) {
        for rcpt in &mut self.message.recipients {
            if !rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER)
                && matches!(
                    rcpt.status,
                    Status::Completed(_) | Status::PermanentFailure(_)
                )
            {
                rcpt.flags |= RCPT_DSN_SENT;
            }
        }
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
            Error::EncryptionError(details) => {
                let _ = write!(dsn, "<{addr}> (Encryption required: {details})\r\n");
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
            let _ = write!(dsn, "Original-Recipient: {ORCPT_ADDR_TYPE}{orcpt}\r\n");
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
            Status::TemporaryFailure(err) | Status::PermanentFailure(err) => match &err.details {
                Error::UnexpectedResponse(response) => {
                    response.response.write_dsn_status(dsn);
                }
                Error::EncryptionError(_) => {
                    dsn.push_str(if matches!(self, Status::PermanentFailure(_)) {
                        "5.7.5"
                    } else {
                        "4.7.5"
                    });
                }
                _ => {
                    dsn.push_str(if matches!(self, Status::PermanentFailure(_)) {
                        "5.0.0"
                    } else {
                        "4.0.0"
                    });
                }
            },
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

fn rewrite_delivery_status(
    original: &str,
    reporting_mta: &str,
    arrival_rcpts: &[String],
) -> Option<String> {
    let original = original.replace("\r\n", "\n");
    let mut blocks = original.split("\n\n");
    let mut out = String::with_capacity(256);
    let _ = write!(out, "Reporting-MTA: dns;{reporting_mta}\r\n");
    if let Some(envelope_id) = blocks.next().and_then(|block| {
        unfolded_fields(block)
            .find(|(name, _)| name.eq_ignore_ascii_case("original-envelope-id"))
            .map(|(_, value)| value)
            .filter(|value| is_envelope_id(value))
    }) {
        let _ = write!(out, "Original-Envelope-Id: {envelope_id}\r\n");
    }

    let mut written: Vec<&str> = Vec::with_capacity(arrival_rcpts.len());
    for block in blocks {
        if written.len() == arrival_rcpts.len() {
            break;
        }
        let mut action = None;
        let mut status = None;
        let mut orcpt = None;
        for (name, value) in unfolded_fields(block) {
            hashify::fnc_map_ignore_case!(name.as_bytes(),
                "action" => { action = Some(value); },
                "status" => { status = Some(value); },
                "original-recipient" => { orcpt = Some(value); },
                _ => {}
            );
        }
        let (Some(action), Some(status)) = (
            action.filter(|action| {
                hashify::set_ignore_case!(
                    action.as_bytes(),
                    "failed",
                    "delayed",
                    "delivered",
                    "relayed",
                    "expanded"
                )
            }),
            status
                .as_deref()
                .and_then(|status| status.split_ascii_whitespace().next())
                .filter(|status| is_status_code(status)),
        ) else {
            continue;
        };
        let orcpt = orcpt
            .as_deref()
            .and_then(|orcpt| orcpt.split_once(';'))
            .map(|(_, addr)| addr.trim());
        let Some(recipient) = orcpt
            .and_then(|orcpt| {
                arrival_rcpts
                    .iter()
                    .map(|rcpt| strip_brackets(rcpt))
                    .find(|rcpt| rcpt.eq_ignore_ascii_case(orcpt))
            })
            .or_else(|| arrival_rcpts.first().map(|rcpt| strip_brackets(rcpt)))
        else {
            continue;
        };
        if written
            .iter()
            .any(|written| written.eq_ignore_ascii_case(recipient))
        {
            continue;
        }
        written.push(recipient);
        let _ = write!(
            out,
            "\r\nFinal-Recipient: rfc822;{recipient}\r\nAction: {action}\r\nStatus: {status}\r\n"
        );
    }
    (!written.is_empty()).then_some(out)
}

fn unfolded_fields(block: &str) -> impl Iterator<Item = (&str, Cow<'_, str>)> {
    let mut lines = block.lines().peekable();
    std::iter::from_fn(move || {
        loop {
            let Some((name, value)) = lines.next()?.split_once(':') else {
                continue;
            };
            let mut value = Cow::Borrowed(value.trim());
            while let Some(continuation) = lines.next_if(|line| line.starts_with([' ', '\t'])) {
                let value = value.to_mut();
                value.push(' ');
                value.push_str(continuation.trim());
            }
            return Some((name.trim(), value));
        }
    })
}

fn is_status_code(status: &str) -> bool {
    let mut parts = status.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("2" | "4" | "5"), Some(subject), Some(detail), None)
            if [subject, detail].iter().all(|part| {
                (1..=3).contains(&part.len()) && part.bytes().all(|ch| ch.is_ascii_digit())
            })
    )
}

fn is_envelope_id(value: &str) -> bool {
    (1..=100).contains(&value.len()) && value.bytes().all(|ch| ch.is_ascii_graphic())
}

fn is_signing_field(name: &[u8]) -> bool {
    hashify::set_ignore_case!(
        name,
        "DKIM-Signature",
        "DKIM2-Signature",
        "Message-Instance"
    )
}

fn is_same_or_subdomain(domain: &str, parent: &str) -> bool {
    domain.eq_ignore_ascii_case(parent)
        || domain
            .len()
            .checked_sub(parent.len() + 1)
            .and_then(|start| domain.get(start..))
            .and_then(|suffix| suffix.strip_prefix('.'))
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(parent))
}

fn strip_brackets(address: &str) -> &str {
    address.trim_start_matches('<').trim_end_matches('>')
}

fn rfc822_headers_part(headers: Cow<'_, [u8]>) -> MimePart<'_> {
    let encoding = if headers.is_ascii() { "7bit" } else { "8bit" };
    MimePart::new(
        ContentType::new("text/rfc822-headers"),
        BodyPart::Binary(headers),
    )
    .transfer_encoding(encoding)
}

fn aligned_from(from_addr: String, aligned_domain: Option<&str>) -> String {
    match (aligned_domain, from_addr.rsplit_once('@')) {
        (Some(domain), Some((local, _))) => format!("{local}@{domain}"),
        _ => from_addr,
    }
}

fn header_block_len(buf: &[u8]) -> usize {
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
    last_lf
}
