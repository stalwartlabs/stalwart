/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Action, Error, Macros, Modification};
use crate::{
    core::{Session, SessionAddress, SessionData},
    inbound::{FilterResponse, milter::MilterClient},
    queue::QueueId,
};
use common::{
    DAEMON_NAME,
    config::smtp::session::{Milter, Stage},
    expr::Bump,
    network::SessionStream,
};
use compact_str::ToCompactString;
use mail_auth::AuthenticatedMessage;
use smtp_proto::{IntoString, request::parser::Rfc5321Parser};
use std::{borrow::Cow, time::Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use trc::MilterEvent;
use utils::DomainPart;

enum Rejection {
    Action(Action),
    Error(Error),
}

impl<T: SessionStream> Session<T> {
    pub async fn run_milters(
        &self,
        stage: Stage,
        message: Option<&AuthenticatedMessage<'_>>,
        queue_id: Option<QueueId>,
    ) -> Result<Vec<Modification>, FilterResponse> {
        let milters = &self.server.core.smtp.session.milters;
        if milters.is_empty() {
            return Ok(Vec::new());
        }

        let mut modifications = Vec::new();
        let mut arena = Bump::new();
        for milter in milters {
            if !milter.run_on_stage.contains(&stage)
                || !self
                    .server
                    .eval_if(&milter.enable, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or(false)
            {
                continue;
            }

            let time = Instant::now();
            match self.connect_and_run(milter, message).await {
                Ok(new_modifications) => {
                    trc::event!(
                        Milter(MilterEvent::ActionAccept),
                        SpanId = self.data.session_id,
                        Name = milter.id.to_compact_string(),
                        Elapsed = time.elapsed(),
                    );

                    if !modifications.is_empty() {
                        // The message body can only be replaced once, so we need to remove
                        // any previous replacements.
                        if new_modifications
                            .iter()
                            .any(|m| matches!(m, Modification::ReplaceBody { .. }))
                        {
                            modifications
                                .retain(|m| !matches!(m, Modification::ReplaceBody { .. }));
                        }
                        modifications.extend(new_modifications);
                    } else {
                        modifications = new_modifications;
                    }
                }
                Err(Rejection::Action(action)) => {
                    trc::event!(
                        Milter(match &action {
                            Action::Discard => MilterEvent::ActionDiscard,
                            Action::Reject => MilterEvent::ActionReject,
                            Action::TempFail => MilterEvent::ActionTempFail,
                            Action::ReplyCode { .. } => {
                                MilterEvent::ActionReplyCode
                            }
                            Action::Shutdown => MilterEvent::ActionShutdown,
                            Action::ConnectionFailure => MilterEvent::ActionConnectionFailure,
                            Action::Accept | Action::Continue => unreachable!(),
                        }),
                        SpanId = self.data.session_id,
                        QueueId = queue_id,
                        Name = milter.id.to_compact_string(),
                        Elapsed = time.elapsed(),
                    );

                    return Err(match action {
                        Action::Discard => FilterResponse::accept(),
                        Action::Reject => FilterResponse::reject(),
                        Action::TempFail => FilterResponse::temp_fail(),
                        Action::ReplyCode { code, text } => {
                            let mut response = Vec::with_capacity(text.len() + 6);
                            response.extend_from_slice(code.as_slice());
                            response.push(b' ');
                            response.extend_from_slice(text.as_bytes());
                            if !text.ends_with('\n') {
                                response.extend_from_slice(b"\r\n");
                            }
                            FilterResponse {
                                message: response.into_string().into(),
                                disconnect: false,
                            }
                        }
                        Action::Shutdown => FilterResponse::shutdown(),
                        Action::ConnectionFailure => FilterResponse::default().disconnect(),
                        Action::Accept | Action::Continue => unreachable!(),
                    });
                }
                Err(Rejection::Error(err)) => {
                    let (code, details) = match err {
                        Error::Io(details) => (
                            MilterEvent::IoError,
                            trc::Value::from(details.to_compact_string()),
                        ),
                        Error::FrameTooLarge(size) => {
                            (MilterEvent::FrameTooLarge, trc::Value::from(size))
                        }
                        Error::FrameInvalid(bytes) => {
                            (MilterEvent::FrameInvalid, trc::Value::from(bytes))
                        }
                        Error::Unexpected(response) => (
                            MilterEvent::UnexpectedResponse,
                            trc::Value::from(response.to_compact_string()),
                        ),
                        Error::Timeout => (MilterEvent::Timeout, trc::Value::None),
                        Error::TLSInvalidName => (MilterEvent::TlsInvalidName, trc::Value::None),
                        Error::Disconnected => (MilterEvent::Disconnected, trc::Value::None),
                    };

                    trc::event!(
                        Milter(code),
                        SpanId = self.data.session_id,
                        Name = milter.id.to_compact_string(),
                        Details = details,
                        Elapsed = time.elapsed(),
                    );

                    if milter.tempfail_on_error {
                        return Err(FilterResponse::server_failure());
                    }
                }
            }
        }

        Ok(modifications)
    }

    async fn connect_and_run(
        &self,
        milter: &Milter,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Vec<Modification>, Rejection> {
        // Build client
        let client = MilterClient::connect(milter, self.data.session_id).await?;
        if !milter.tls {
            self.run(client, message).await
        } else {
            self.run(
                client
                    .into_tls(
                        if !milter.tls_allow_invalid_certs {
                            &self.server.inner.data.smtp_connectors.pki_verify
                        } else {
                            &self.server.inner.data.smtp_connectors.dummy_verify
                        },
                        &milter.hostname,
                    )
                    .await?,
                message,
            )
            .await
        }
    }

    async fn run<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut client: MilterClient<S>,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Vec<Modification>, Rejection> {
        // Option negotiation
        client.init().await?;

        // Connect stage
        let client_ptr = self
            .data
            .iprev
            .as_ref()
            .and_then(|ip_rev| ip_rev.ptr.as_ref())
            .and_then(|ptrs| ptrs.first())
            .map(|s| s.as_ref());
        client
            .connection(
                client_ptr.unwrap_or(self.data.helo_domain.as_str()),
                self.data.remote_ip,
                self.data.remote_port,
                Macros::new()
                    .with_daemon_name(DAEMON_NAME)
                    .with_local_hostname(&self.hostname)
                    .with_client_address(self.data.remote_ip)
                    .with_client_port(self.data.remote_port)
                    .with_client_ptr(client_ptr.unwrap_or("unknown")),
            )
            .await?
            .assert_continue()?;

        // EHLO/HELO
        if !self.data.helo_domain.is_empty() {
            let (tls_version, tls_cipher) = self.stream.tls_version_and_cipher();
            client
                .helo(
                    &self.data.helo_domain,
                    Macros::new()
                        .with_cipher(tls_cipher.as_ref())
                        .with_tls_version(tls_version.as_ref()),
                )
                .await?
                .assert_continue()?;
        }

        // Mail from
        if let Some(mail_from) = &self.data.mail_from {
            let addr = &mail_from.address_lcase;
            client
                .mail_from(
                    &format!("<{addr}>"),
                    None::<&[&str]>,
                    if let Some(name) = self.authenticated_as() {
                        Macros::new()
                            .with_mail_address(addr)
                            .with_sasl_login_name(name)
                    } else {
                        Macros::new().with_mail_address(addr)
                    },
                )
                .await?
                .assert_continue()?;

            // Rcpt to
            for rcpt in &self.data.rcpt_to {
                client
                    .rcpt_to(
                        &format!("<{}>", rcpt.address_lcase),
                        None::<&[&str]>,
                        Macros::new().with_rcpt_address(&rcpt.address_lcase),
                    )
                    .await?
                    .assert_continue()?;
            }
        }

        if let Some(message) = message {
            // Data
            client.data().await?.assert_continue()?;

            // Headers
            client
                .headers(message.headers().iter().copied())
                .await?
                .assert_continue()?;

            // Message body
            let (action, modifications) = client.body(message.raw_body()).await?;
            action.assert_continue()?;

            // Quit
            let _ = client.quit().await;

            // Return modifications
            Ok(modifications)
        } else {
            // Quit
            let _ = client.quit().await;

            Ok(Vec::new())
        }
    }
}

impl SessionData {
    pub fn apply_milter_modifications(
        &mut self,
        modifications: Vec<Modification>,
        message: &AuthenticatedMessage<'_>,
    ) -> Option<Vec<u8>> {
        let mut body = Vec::new();
        let mut headers = None;
        let original_headers = || {
            message
                .headers()
                .iter()
                .map(|(name, value)| (Cow::Borrowed(*name), Cow::Borrowed(*value)))
                .collect::<Vec<_>>()
        };

        for modification in modifications {
            match modification {
                Modification::ChangeFrom { sender, mut args } => {
                    // Change sender
                    let sender = strip_brackets(&sender);
                    let address_lcase = sender.to_lowercase();
                    let mut mail_from = SessionAddress {
                        domain: address_lcase.domain_part().into(),
                        address_lcase,
                        address: sender,
                        flags: 0,
                        dsn_info: None,
                    };
                    if !args.is_empty() {
                        args.push('\n');
                        match Rfc5321Parser::new(&mut args.as_bytes().iter())
                            .mail_from_parameters(Cow::Borrowed(""))
                        {
                            Ok(addr) => {
                                mail_from.flags = addr.flags;
                                mail_from.dsn_info = addr.env_id.map(|e| e.into_owned());
                            }
                            Err(err) => {
                                trc::event!(
                                    Milter(MilterEvent::ParseError),
                                    SpanId = self.session_id,
                                    Details = "Failed to parse milter mailFrom parameters",
                                    Reason = err.to_compact_string(),
                                );
                            }
                        }
                    }
                    self.mail_from = Some(mail_from);
                }
                Modification::AddRcpt {
                    recipient,
                    mut args,
                } => {
                    // Add recipient
                    let recipient = strip_brackets(&recipient);
                    if recipient.contains('@') {
                        let address_lcase = recipient.to_lowercase();
                        let mut rcpt = SessionAddress {
                            domain: address_lcase.domain_part().into(),
                            address_lcase,
                            address: recipient,
                            flags: 0,
                            dsn_info: None,
                        };
                        if !args.is_empty() {
                            args.push('\n');
                            match Rfc5321Parser::new(&mut args.as_bytes().iter())
                                .rcpt_to_parameters(Cow::Borrowed(""))
                            {
                                Ok(addr) => {
                                    rcpt.flags = addr.flags;
                                    rcpt.dsn_info = addr.orcpt.map(|e| e.into_owned());
                                }
                                Err(err) => {
                                    trc::event!(
                                        Milter(MilterEvent::ParseError),
                                        SpanId = self.session_id,
                                        Details = "Failed to parse milter rcptTo parameters",
                                        Reason = err.to_compact_string(),
                                    );
                                }
                            }
                        }

                        if !self.rcpt_to.contains(&rcpt) {
                            self.rcpt_to.push(rcpt);
                        }
                    }
                }
                Modification::DeleteRcpt { recipient } => {
                    let recipient = strip_brackets(&recipient);
                    self.rcpt_to.retain(|r| r.address_lcase != recipient);
                }
                Modification::ReplaceBody { value } => {
                    if body.is_empty() {
                        body = value;
                    } else {
                        body.extend(value);
                    }
                }
                Modification::AddHeader { name, value } => {
                    headers.get_or_insert_with(original_headers).push((
                        Cow::Owned(name.into_bytes()),
                        Cow::Owned(milter_header_value(&value)),
                    ));
                }
                Modification::InsertHeader { index, name, value } => {
                    let headers = headers.get_or_insert_with(original_headers);
                    let pos = usize::try_from(index)
                        .unwrap_or(usize::MAX)
                        .min(headers.len());
                    headers.insert(
                        pos,
                        (
                            Cow::Owned(name.into_bytes()),
                            Cow::Owned(milter_header_value(&value)),
                        ),
                    );
                }
                Modification::ChangeHeader { index, name, value } => {
                    let headers = headers.get_or_insert_with(original_headers);
                    let occurrence = usize::try_from(index).unwrap_or(usize::MAX).max(1);
                    let pos = headers
                        .iter()
                        .enumerate()
                        .filter(|(_, (header, _))| header.eq_ignore_ascii_case(name.as_bytes()))
                        .nth(occurrence - 1)
                        .map(|(pos, _)| pos);
                    match pos {
                        Some(pos) if value.is_empty() => {
                            headers.remove(pos);
                        }
                        Some(pos) => {
                            if let Some((_, header_value)) = headers.get_mut(pos) {
                                *header_value = Cow::Owned(milter_header_value(&value));
                            }
                        }
                        None if !value.is_empty() => {
                            headers.push((
                                Cow::Owned(name.into_bytes()),
                                Cow::Owned(milter_header_value(&value)),
                            ));
                        }
                        None => {}
                    }
                }
                Modification::Quarantine { reason } => {
                    headers.get_or_insert_with(original_headers).insert(
                        0,
                        (
                            Cow::Borrowed(b"X-Quarantine"),
                            Cow::Owned(milter_header_value(reason.as_bytes())),
                        ),
                    );
                }
            }
        }

        let Some(headers) = headers else {
            return if !body.is_empty() {
                let mut new_message = Vec::with_capacity(body.len() + message.raw_headers().len());
                new_message.extend_from_slice(message.raw_headers());
                new_message.extend(body);
                Some(new_message)
            } else {
                None
            };
        };

        let new_body = if !body.is_empty() {
            &body[..]
        } else {
            message.raw_body()
        };
        let mut new_message = Vec::with_capacity(
            new_body.len()
                + headers
                    .iter()
                    .map(|(name, value)| name.len() + value.len() + 3)
                    .sum::<usize>()
                + 2,
        );
        for (name, value) in headers {
            new_message.extend_from_slice(&name);
            new_message.push(b':');
            new_message.extend_from_slice(&value);
            if !value.ends_with(b"\n") {
                new_message.extend_from_slice(b"\r\n");
            }
        }
        new_message.extend_from_slice(b"\r\n");
        new_message.extend_from_slice(new_body);
        Some(new_message)
    }
}

fn milter_header_value(value: &[u8]) -> Vec<u8> {
    let mut value = value;
    while let [rest @ .., b'\r' | b'\n'] = value {
        value = rest;
    }
    let mut out = Vec::with_capacity(value.len() + 4);
    if !matches!(value.first(), Some(b' ' | b'\t')) {
        out.push(b' ');
    }
    let mut lines = value
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    if let Some(first) = lines.next() {
        out.extend_from_slice(first);
    }
    for line in lines.filter(|line| !line.is_empty()) {
        out.extend_from_slice(b"\r\n");
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            out.push(b'\t');
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(b"\r\n");
    out
}

impl Action {
    fn assert_continue(self) -> Result<(), Rejection> {
        match self {
            Action::Continue | Action::Accept => Ok(()),
            action => Err(Rejection::Action(action)),
        }
    }
}

impl From<Error> for Rejection {
    fn from(err: Error) -> Self {
        Rejection::Error(err)
    }
}

fn strip_brackets(addr: &str) -> String {
    let addr = addr.trim();
    if let Some(addr) = addr.strip_prefix('<') {
        if let Some((addr, _)) = addr.rsplit_once('>') {
            addr.trim().into()
        } else {
            addr.trim().into()
        }
    } else {
        addr.into()
    }
}
