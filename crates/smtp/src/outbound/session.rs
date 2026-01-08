/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::client::SmtpClient;
use crate::outbound::DeliveryResult;
use crate::outbound::client::{BoxResponse, from_error_status, from_mail_send_error};
use crate::queue::{Error, MessageWrapper, Recipient, Status};
use crate::queue::{ErrorDetails, HostResponse, UnexpectedResponse};
use common::Server;
use common::config::smtp::queue::ConnectionStrategy;
use mail_send::Credentials;
use smtp_proto::{
    EXT_CHUNKING, EXT_DSN, EXT_REQUIRE_TLS, EXT_SIZE, EXT_SMTP_UTF8, EhloResponse, MAIL_REQUIRETLS,
    MAIL_RET_FULL, MAIL_RET_HDRS, MAIL_SMTPUTF8, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE,
    RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, Severity,
};
use std::{fmt::Write, time::Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use trc::DeliveryEvent;

pub struct SessionParams<'x> {
    pub server: &'x Server,
    pub hostname: &'x str,
    pub credentials: Option<&'x Credentials<String>>,
    pub capabilities: Option<EhloResponse<String>>,
    pub is_smtp: bool,
    pub local_hostname: &'x str,
    pub conn_strategy: &'x ConnectionStrategy,
    pub session_id: u64,
}

impl MessageWrapper {
    pub(super) async fn deliver<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut smtp_client: SmtpClient<T>,
        rcpt_idxs: Vec<usize>,
        statuses: &mut Vec<DeliveryResult>,
        mut params: SessionParams<'_>,
    ) {
        // Obtain capabilities
        let time = Instant::now();
        let capabilities = if let Some(capabilities) = params.capabilities.take() {
            capabilities
        } else {
            match smtp_client.say_helo(&params).await {
                Ok(capabilities) => {
                    trc::event!(
                        Delivery(DeliveryEvent::Ehlo),
                        SpanId = params.session_id,
                        Hostname = params.hostname.to_string(),
                        Details = capabilities.capabilities(),
                        Elapsed = time.elapsed(),
                    );

                    capabilities
                }
                Err(status) => {
                    trc::event!(
                        Delivery(DeliveryEvent::EhloRejected),
                        SpanId = params.session_id,
                        Hostname = params.hostname.to_string(),
                        CausedBy = from_error_status(&status),
                        Elapsed = time.elapsed(),
                    );
                    smtp_client.quit().await;
                    statuses.push(DeliveryResult::domain(status, rcpt_idxs));
                    return;
                }
            }
        };

        // Authenticate
        if let Some(credentials) = params.credentials {
            let time = Instant::now();
            if let Err(err) = smtp_client.authenticate(credentials, &capabilities).await {
                trc::event!(
                    Delivery(DeliveryEvent::AuthFailed),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    CausedBy = from_mail_send_error(&err),
                    Elapsed = time.elapsed(),
                );

                smtp_client.quit().await;
                statuses.push(DeliveryResult::domain(
                    Status::from_smtp_error(params.hostname, "AUTH ...", err),
                    rcpt_idxs,
                ));
                return;
            }

            trc::event!(
                Delivery(DeliveryEvent::Auth),
                SpanId = params.session_id,
                Hostname = params.hostname.to_string(),
                Elapsed = time.elapsed(),
            );

            // Refresh capabilities
            // Disabled as some SMTP servers deauthenticate after EHLO
            /*capabilities = match say_helo(&mut smtp_client, &params).await {
                Ok(capabilities) => capabilities,
                Err(status) => {
                    trc::event!(

                        context = "ehlo",
                        event = "rejected",
                        mx = &params.hostname,
                        reason = %status,
                    );
                    smtp_client.quit().await;
                    return status;
                }
            };*/
        }

        // MAIL FROM
        let time = Instant::now();
        smtp_client.timeout = params.conn_strategy.timeout_mail;
        let cmd = self.build_mail_from(&capabilities);
        match smtp_client.cmd(cmd.as_bytes()).await.and_then(|r| {
            if r.is_positive_completion() {
                Ok(r)
            } else {
                Err(mail_send::Error::UnexpectedReply(r))
            }
        }) {
            Ok(response) => {
                trc::event!(
                    Delivery(DeliveryEvent::MailFrom),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    From = self.message.return_path.to_string(),
                    Code = response.code,
                    Details = response.message.to_string(),
                    Elapsed = time.elapsed(),
                );
            }
            Err(err) => {
                trc::event!(
                    Delivery(DeliveryEvent::MailFromRejected),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    CausedBy = from_mail_send_error(&err),
                    Elapsed = time.elapsed(),
                );

                smtp_client.quit().await;
                statuses.push(DeliveryResult::domain(
                    Status::from_smtp_error(params.hostname, &cmd, err),
                    rcpt_idxs,
                ));
                return;
            }
        }

        // RCPT TO
        let mut accepted_rcpts = Vec::new();
        smtp_client.timeout = params.conn_strategy.timeout_rcpt;
        for rcpt_idx in &rcpt_idxs {
            let time = Instant::now();
            let rcpt = &self.message.recipients[*rcpt_idx];
            if matches!(
                &rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                continue;
            }

            let cmd = self.build_rcpt_to(rcpt, &capabilities);
            match smtp_client.cmd(cmd.as_bytes()).await {
                Ok(response) => match response.severity() {
                    Severity::PositiveCompletion => {
                        trc::event!(
                            Delivery(DeliveryEvent::RcptTo),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            To = rcpt.address().to_string(),
                            Code = response.code,
                            Details = response.message.to_string(),
                            Elapsed = time.elapsed(),
                        );

                        accepted_rcpts.push((
                            rcpt,
                            rcpt_idx,
                            Status::Completed(HostResponse {
                                hostname: params.hostname.into(),
                                response: response.into_box(),
                            }),
                        ));
                    }
                    severity => {
                        trc::event!(
                            Delivery(DeliveryEvent::RcptToRejected),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            To = rcpt.address().to_string(),
                            Code = response.code,
                            Details = response.message.to_string(),
                            Elapsed = time.elapsed(),
                        );

                        let response = ErrorDetails {
                            entity: params.hostname.into(),
                            details: Error::UnexpectedResponse(UnexpectedResponse {
                                command: cmd.trim().into(),
                                response: response.into_box(),
                            }),
                        };
                        statuses.push(DeliveryResult::account(
                            if severity == Severity::PermanentNegativeCompletion {
                                Status::PermanentFailure(response)
                            } else {
                                Status::TemporaryFailure(response)
                            },
                            *rcpt_idx,
                        ));
                    }
                },
                Err(err) => {
                    trc::event!(
                        Delivery(DeliveryEvent::RcptToFailed),
                        SpanId = params.session_id,
                        Hostname = params.hostname.to_string(),
                        To = rcpt.address().to_string(),
                        CausedBy = from_mail_send_error(&err),
                        Elapsed = time.elapsed(),
                    );

                    // Something went wrong, abort.
                    smtp_client.quit().await;
                    statuses.push(DeliveryResult::domain(
                        Status::from_smtp_error(params.hostname, "", err),
                        rcpt_idxs,
                    ));
                    return;
                }
            }
        }

        // Send message
        if !accepted_rcpts.is_empty() {
            let time = Instant::now();
            let bdat_cmd = capabilities
                .has_capability(EXT_CHUNKING)
                .then(|| format!("BDAT {} LAST\r\n", self.message.size));

            if let Err(status) = smtp_client.send_message(self, &bdat_cmd, &params).await {
                trc::event!(
                    Delivery(DeliveryEvent::MessageRejected),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    CausedBy = from_error_status(&status),
                    Elapsed = time.elapsed(),
                );

                smtp_client.quit().await;
                statuses.push(DeliveryResult::domain(status, rcpt_idxs));
                return;
            }

            if params.is_smtp {
                // Handle SMTP response
                match smtp_client
                    .read_smtp_data_response(params.hostname, &bdat_cmd)
                    .await
                {
                    Ok(response) => {
                        // Mark recipients as delivered
                        if response.code() == 250 {
                            for (rcpt, rcpt_idx, status) in accepted_rcpts {
                                trc::event!(
                                    Delivery(DeliveryEvent::Delivered),
                                    SpanId = params.session_id,
                                    Hostname = params.hostname.to_string(),
                                    To = rcpt.address().to_string(),
                                    Code = response.code,
                                    Details = response.message.to_string(),
                                    Elapsed = time.elapsed(),
                                );

                                statuses.push(DeliveryResult::account(status, *rcpt_idx));
                            }
                        } else {
                            trc::event!(
                                Delivery(DeliveryEvent::MessageRejected),
                                SpanId = params.session_id,
                                Hostname = params.hostname.to_string(),
                                Code = response.code,
                                Details = response.message.to_string(),
                                Elapsed = time.elapsed(),
                            );

                            smtp_client.quit().await;
                            statuses.push(DeliveryResult::domain(
                                Status::from_smtp_error(
                                    params.hostname,
                                    bdat_cmd.as_deref().unwrap_or("DATA"),
                                    mail_send::Error::UnexpectedReply(response),
                                ),
                                rcpt_idxs,
                            ));
                            return;
                        }
                    }
                    Err(status) => {
                        trc::event!(
                            Delivery(DeliveryEvent::MessageRejected),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            CausedBy = from_error_status(&status),
                            Elapsed = time.elapsed(),
                        );

                        smtp_client.quit().await;
                        statuses.push(DeliveryResult::domain(status, rcpt_idxs));
                        return;
                    }
                }
            } else {
                // Handle LMTP responses
                match smtp_client
                    .read_lmtp_data_response(params.hostname, accepted_rcpts.len())
                    .await
                {
                    Ok(responses) => {
                        for ((rcpt, rcpt_idx, _), response) in
                            accepted_rcpts.into_iter().zip(responses)
                        {
                            let status: Status<HostResponse<Box<str>>, ErrorDetails> =
                                match response.severity() {
                                    Severity::PositiveCompletion => {
                                        trc::event!(
                                            Delivery(DeliveryEvent::Delivered),
                                            SpanId = params.session_id,
                                            Hostname = params.hostname.to_string(),
                                            To = rcpt.address().to_string(),
                                            Code = response.code,
                                            Details = response.message.to_string(),
                                            Elapsed = time.elapsed(),
                                        );

                                        Status::Completed(HostResponse {
                                            hostname: params.hostname.into(),
                                            response,
                                        })
                                    }
                                    severity => {
                                        trc::event!(
                                            Delivery(DeliveryEvent::RcptToRejected),
                                            SpanId = params.session_id,
                                            Hostname = params.hostname.to_string(),
                                            To = rcpt.address().to_string(),
                                            Code = response.code,
                                            Details = response.message.to_string(),
                                            Elapsed = time.elapsed(),
                                        );

                                        let response = ErrorDetails {
                                            entity: params.hostname.into(),
                                            details: Error::UnexpectedResponse(
                                                UnexpectedResponse {
                                                    command: bdat_cmd
                                                        .as_deref()
                                                        .unwrap_or("DATA")
                                                        .into(),
                                                    response,
                                                },
                                            ),
                                        };
                                        if severity == Severity::PermanentNegativeCompletion {
                                            Status::PermanentFailure(response)
                                        } else {
                                            Status::TemporaryFailure(response)
                                        }
                                    }
                                };

                            statuses.push(DeliveryResult::account(status, *rcpt_idx));
                        }
                    }
                    Err(status) => {
                        trc::event!(
                            Delivery(DeliveryEvent::MessageRejected),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            CausedBy = from_error_status(&status),
                            Elapsed = time.elapsed(),
                        );

                        smtp_client.quit().await;
                        statuses.push(DeliveryResult::domain(status, rcpt_idxs));
                        return;
                    }
                }
            }
        }

        smtp_client.quit().await;
    }

    fn build_mail_from(&self, capabilities: &EhloResponse<String>) -> String {
        let mut mail_from = String::with_capacity(self.message.return_path.len() + 60);
        let _ = write!(mail_from, "MAIL FROM:<{}>", self.message.return_path);
        if capabilities.has_capability(EXT_SIZE) {
            let _ = write!(mail_from, " SIZE={}", self.message.size);
        }
        if self.has_flag(MAIL_REQUIRETLS) & capabilities.has_capability(EXT_REQUIRE_TLS) {
            mail_from.push_str(" REQUIRETLS");
        }
        if self.has_flag(MAIL_SMTPUTF8) & capabilities.has_capability(EXT_SMTP_UTF8) {
            mail_from.push_str(" SMTPUTF8");
        }
        if capabilities.has_capability(EXT_DSN) {
            if self.has_flag(MAIL_RET_FULL) {
                mail_from.push_str(" RET=FULL");
            } else if self.has_flag(MAIL_RET_HDRS) {
                mail_from.push_str(" RET=HDRS");
            }
            if let Some(env_id) = &self.message.env_id {
                let _ = write!(mail_from, " ENVID={env_id}");
            }
        }

        mail_from.push_str("\r\n");
        mail_from
    }

    fn build_rcpt_to(&self, rcpt: &Recipient, capabilities: &EhloResponse<String>) -> String {
        let mut rcpt_to = String::with_capacity(rcpt.address().len() + 60);
        let _ = write!(rcpt_to, "RCPT TO:<{}>", rcpt.address());
        if capabilities.has_capability(EXT_DSN) {
            if rcpt.has_flag(RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY) {
                rcpt_to.push_str(" NOTIFY=");
                let mut add_comma = if rcpt.has_flag(RCPT_NOTIFY_SUCCESS) {
                    rcpt_to.push_str("SUCCESS");
                    true
                } else {
                    false
                };
                if rcpt.has_flag(RCPT_NOTIFY_DELAY) {
                    if add_comma {
                        rcpt_to.push(',');
                    } else {
                        add_comma = true;
                    }
                    rcpt_to.push_str("DELAY");
                }
                if rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                    if add_comma {
                        rcpt_to.push(',');
                    }
                    rcpt_to.push_str("FAILURE");
                }
            } else if rcpt.has_flag(RCPT_NOTIFY_NEVER) {
                rcpt_to.push_str(" NOTIFY=NEVER");
            }
        }
        rcpt_to.push_str("\r\n");
        rcpt_to
    }

    #[inline(always)]
    pub fn has_flag(&self, flag: u64) -> bool {
        (self.message.flags & flag) != 0
    }
}

impl Recipient {
    #[inline(always)]
    pub fn has_flag(&self, flag: u64) -> bool {
        (self.flags & flag) != 0
    }
}
