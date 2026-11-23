/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::action_vacation::{MAX_SUBJECT_LEN, header_safe};
use crate::runtime::platform;
use crate::{
    Context, Importance, Sieve,
    bytecode::ops,
    compiler::grammar::actions::action_redirect::{ByTime, Notify, Ret},
    runtime::{
        RuntimeError, Variable,
        handler::{Action, MessageSource, Recipient},
    },
};
use mail_builder::headers::date::Date;
use mail_parser::HeaderName;
use std::borrow::Cow;

const DEFAULT_IMPORTANCE_HEADERS: (&str, &str) = ("Normal", "3 (Normal)");

impl<'x> Context<'x> {
    pub(crate) fn exec_notify(
        &mut self,
        script: &'x Sieve<'x>,
        notify: &ops::Notify,
    ) -> Result<(), RuntimeError> {
        for header in self.root_headers() {
            if header.is_named(&HeaderName::AutoSubmitted)
                && header
                    .value()
                    .as_text()
                    .is_none_or(|v| !v.eq_ignore_ascii_case("no"))
            {
                return Ok(());
            }
        }

        let uri = self.eval_str(script, notify.method)?;
        let Some((scheme, params)) = parse_uri(uri) else {
            return Ok(());
        };

        let has_fcc = notify.fcc.present;
        let is_mailto = scheme.eq_ignore_ascii_case("mailto")
            && self.num_out_messages < self.runtime.max_out_messages;
        let from = self.eval_opt(script, notify.from)?;
        let importance = self.eval_opt(script, notify.importance)?;
        let notify_message = self
            .eval_opt(script, notify.message)?
            .map(|m| m.into_string());

        if is_mailto || has_fcc {
            let params = if is_mailto {
                let Some(params) = parse_mailto(params) else {
                    return Ok(());
                };
                params
            } else {
                MailtoMessage::default()
            };
            let from = self.notify_from(from.as_ref());
            let importance_headers = importance.as_ref().map_or(DEFAULT_IMPORTANCE_HEADERS, |i| {
                lookup_importance_headers(i.to_string().as_ref())
                    .unwrap_or(DEFAULT_IMPORTANCE_HEADERS)
            });
            let message = self.build_notify_message(
                &params,
                &from,
                notify_message.as_deref(),
                importance_headers,
            );

            self.last_message_id += 1;
            self.actions.push(Action::CreatedMessage {
                message_id: self.last_message_id,
                message,
            });

            if is_mailto {
                let recipients = params
                    .to
                    .iter()
                    .chain(params.cc.iter())
                    .chain(params.bcc.iter())
                    .map(|addr| {
                        self.alloc_str(
                            addr.rsplit_once('<')
                                .and_then(|(_, addr)| addr.rsplit_once('>'))
                                .map_or(addr.as_str(), |(addr, _)| addr),
                        )
                    })
                    .collect();
                self.actions.push(Action::SendMessage {
                    source: MessageSource::Notification,
                    recipient: Recipient::Group(recipients),
                    notify: Notify::Never,
                    return_of_content: Ret::Default,
                    by_time: ByTime::None,
                    message_id: self.last_message_id,
                });
            }
        }

        if !is_mailto {
            let options = self.eval_strings(script, notify.options)?;
            let action = Action::Notify {
                from: from.map(|f| self.intern_cow(f.into_string())),
                importance: importance.map_or(Importance::Normal, |i| {
                    lookup_importance(i.to_string().as_ref()).unwrap_or(Importance::Normal)
                }),
                options: self.alloc_strs(&options),
                message: match notify_message {
                    Some(message) => self.intern_cow(message),
                    None => self.subject_str().unwrap_or_default(),
                },
                method: uri,
            };
            self.actions.push(action);
            self.num_out_messages += 1;
        }

        if has_fcc {
            let fcc = &notify.fcc;
            let action = Action::FileInto {
                folder: self.eval_str(script, fcc.mailbox)?,
                flags: self.get_local_flags(script, fcc.flags)?,
                mailbox_id: self.eval_opt_str(script, fcc.mailbox_id)?,
                special_use: self.eval_opt_str(script, fcc.special_use)?,
                create: fcc.create,
                message_id: self.last_message_id,
            };
            self.actions.push(action);
        }
        Ok(())
    }

    fn subject_str(&self) -> Option<&'x str> {
        self.root_text(&HeaderName::Subject)
    }

    fn notify_from<'a>(&self, from: Option<&'a Variable<'x>>) -> Cow<'a, str> {
        if let Some(from) = from {
            let from = from.to_string();
            if from
                .to_ascii_lowercase()
                .contains(&self.user_address.to_ascii_lowercase())
            {
                return header_safe(from, self.runtime.max_header_size);
            }
        }
        self.user_from_field().into()
    }

    fn build_notify_message(
        &self,
        params: &MailtoMessage,
        from: &str,
        notify_message: Option<&str>,
        (importance, priority): (&str, &str),
    ) -> Vec<u8> {
        let message_len = params
            .to
            .iter()
            .chain(params.cc.iter())
            .map(|a| a.len() + 4)
            .sum::<usize>()
            + params
                .headers
                .iter()
                .map(|(h, v)| h.as_str().len() + v.len() + 4)
                .sum::<usize>()
            + params.body.as_ref().map_or(0, |b| b.len())
            + notify_message.map_or(0, |b| b.len())
            + from.len()
            + 200;

        let mut message = Vec::with_capacity(message_len);
        message.extend_from_slice(b"From: ");
        message.extend_from_slice(from.as_bytes());
        message.extend_from_slice(b"\r\n");

        for (header, addresses) in [("To: ", &params.to), ("Cc: ", &params.cc)] {
            if !addresses.is_empty() {
                message.extend_from_slice(header.as_bytes());
                for (pos, address) in addresses.iter().enumerate() {
                    if pos > 0 {
                        message.extend_from_slice(b", ");
                    }
                    if !address.contains('<') {
                        message.push(b'<');
                    }
                    message.extend_from_slice(address.as_bytes());
                    if !address.contains('<') {
                        message.push(b'>');
                    }
                }
                message.extend_from_slice(b"\r\n");
            }
        }

        let mut has_subject = None;
        for (header, value) in &params.headers {
            match header {
                HeaderName::Subject => {
                    has_subject = value.into();
                }
                HeaderName::From
                | HeaderName::Date
                | HeaderName::MessageId
                | HeaderName::AutoSubmitted
                | HeaderName::Received
                | HeaderName::ReturnPath
                | HeaderName::MimeVersion
                | HeaderName::ContentType
                | HeaderName::ContentTransferEncoding
                | HeaderName::ContentDisposition
                | HeaderName::ContentDescription
                | HeaderName::ContentId
                | HeaderName::ContentLanguage
                | HeaderName::ContentLocation
                | HeaderName::ResentTo
                | HeaderName::ResentFrom
                | HeaderName::ResentBcc
                | HeaderName::ResentCc
                | HeaderName::ResentSender
                | HeaderName::ResentDate
                | HeaderName::ResentMessageId => (),
                _ => {
                    message.extend_from_slice(header.as_str().as_bytes());
                    message.extend_from_slice(b": ");
                    message.extend_from_slice(value.as_bytes());
                    message.extend_from_slice(b"\r\n");
                }
            }
        }

        message.extend_from_slice(b"Date: ");
        message.extend_from_slice(Date::new(self.current_time).to_rfc822().as_bytes());
        message.extend_from_slice(b"\r\n");

        message.extend_from_slice(b"Message-ID: ");
        platform::write_message_id(&mut message, &self.runtime.local_hostname);
        message.extend_from_slice(b"\r\n");

        message.extend_from_slice(b"Importance: ");
        message.extend_from_slice(importance.as_bytes());
        message.extend_from_slice(b"\r\n");

        message.extend_from_slice(b"X-Priority: ");
        message.extend_from_slice(priority.as_bytes());
        message.extend_from_slice(b"\r\n");

        message.extend_from_slice(b"Subject: ");
        let subject = if let Some(subject) = has_subject {
            subject.as_str()
        } else if let Some(subject) = notify_message {
            subject
        } else {
            self.message.subject().unwrap_or_default()
        };
        let mut iter = subject
            .chars()
            .filter(|ch| !matches!(ch, '\r' | '\n'))
            .enumerate();
        let mut buf = [0; 4];
        #[allow(clippy::while_let_on_iterator)]
        while let Some((pos, char)) = iter.next() {
            if pos < MAX_SUBJECT_LEN {
                message.extend_from_slice(char.encode_utf8(&mut buf).as_bytes());
            } else {
                break;
            }
        }
        if iter.next().is_some() {
            message.extend_from_slice('…'.encode_utf8(&mut buf).as_bytes());
        }
        message.extend_from_slice(b"\r\n");

        message.extend_from_slice(b"Auto-Submitted: auto-notified\r\n");
        message.extend_from_slice(b"X-Sieve: yes\r\n");
        message.extend_from_slice(b"Content-type: text/plain; charset=utf-8\r\n\r\n");
        if let Some(body) = &params.body {
            message.extend_from_slice(body.as_bytes());
        } else if let Some(subject) = notify_message {
            message.extend_from_slice(subject.as_bytes());
        } else if let Some(subject) = self.message.subject() {
            message.extend_from_slice(subject.as_bytes());
        }
        message
    }
}

pub fn validate_from(addr: &str) -> bool {
    let mut has_at = false;
    let mut has_dot = false;
    let mut in_quote = false;
    let mut in_angle = false;
    let mut last_ch = 0;

    for &ch in addr.as_bytes().iter() {
        match ch {
            b'\"' if last_ch != b'\\' => {
                in_quote = !in_quote;
            }
            b'<' if !in_quote => {
                if !in_angle {
                    in_angle = true;
                    has_at = false;
                    has_dot = false;
                } else {
                    return false;
                }
            }
            b'>' if !in_quote => {
                if in_angle {
                    in_angle = false;
                } else {
                    return false;
                }
            }
            b'@' if !in_quote => {
                if !has_at && last_ch.is_ascii_alphanumeric() {
                    has_at = true;
                } else {
                    return false;
                }
            }
            b'.' if !in_quote && has_at => {
                has_dot = true;
            }
            _ => (),
        }
        last_ch = ch;
    }

    has_dot && has_at && !in_angle
}

pub fn validate_uri(uri: &str) -> Option<&str> {
    let (scheme, uri) = parse_uri(uri)?;
    if scheme.eq_ignore_ascii_case("mailto") {
        parse_mailto(uri)?;
        scheme.into()
    } else if ["xmpp", "tel", "http", "https"].contains(&scheme) {
        scheme.into()
    } else {
        None
    }
}

pub(crate) fn parse_uri(uri: &str) -> Option<(&str, &str)> {
    let (scheme, uri) = uri.split_once(':')?;

    if !uri.is_empty() {
        Some((scheme, uri))
    } else {
        None
    }
}

pub enum Mailto {
    Header(HeaderName<'static>),
    Body,
    Other(String),
}

enum State {
    Address((HeaderName<'static>, bool)),
    ParamName,
    ParamValue(Mailto),
}

#[derive(Default)]
struct MailtoMessage {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    body: Option<String>,
    headers: Vec<(HeaderName<'static>, String)>,
}

fn parse_mailto(uri: &str) -> Option<MailtoMessage> {
    let mut params = MailtoMessage::default();

    let mut state = State::Address((HeaderName::To, false));
    let mut buf = Vec::new();
    let uri_ = uri.as_bytes();
    let mut iter = uri_.iter();
    let mut has_addresses = false;

    while let Some(&ch) = iter.next() {
        match ch {
            b'%' => {
                let hex1 = hex_value(*iter.next()?);
                let hex2 = hex_value(*iter.next()?);
                if let (Some(hex1), Some(hex2)) = (hex1, hex2) {
                    let ch = (hex1 << 4) | hex2;

                    match &state {
                        State::Address(_) if matches!(ch, b'\r' | b'\n') => {
                            return None;
                        }
                        State::Address((header, has_at)) => match ch {
                            b',' => {
                                if *has_at {
                                    insert_address(
                                        &mut params,
                                        header.clone(),
                                        String::from_utf8(std::mem::take(&mut buf)).ok()?,
                                    );
                                    has_addresses = true;
                                    state = State::Address((header.clone(), false));
                                } else {
                                    return None;
                                }
                            }
                            b'@' => {
                                if !*has_at {
                                    state = State::Address((header.clone(), true));
                                    buf.push(ch);
                                } else {
                                    return None;
                                }
                            }
                            _ => {
                                buf.push(ch);
                            }
                        },
                        State::ParamName if !ch.is_ascii_alphanumeric() && !b"-_".contains(&ch) => {
                            return None;
                        }
                        State::ParamValue(Mailto::Header(_) | Mailto::Other(_))
                            if matches!(ch, b'\r' | b'\n') => {}
                        _ => buf.push(ch),
                    }
                } else {
                    return None;
                }
            }
            b',' => match &state {
                State::Address((header, true)) => {
                    insert_address(
                        &mut params,
                        header.clone(),
                        String::from_utf8(std::mem::take(&mut buf)).ok()?,
                    );
                    state = State::Address((header.clone(), false));
                    has_addresses = true;
                }
                State::ParamValue(_) => buf.push(ch),
                _ => return None,
            },
            b'?' => match &state {
                State::Address((header, has_at)) if *has_at || buf.is_empty() => {
                    if !buf.is_empty() {
                        insert_address(
                            &mut params,
                            header.clone(),
                            String::from_utf8(std::mem::take(&mut buf)).ok()?,
                        );
                        has_addresses = true;
                    }
                    state = State::ParamName;
                }
                State::ParamValue(_) => buf.push(ch),
                _ => return None,
            },
            b'@' => match &state {
                State::Address((header, false)) if !buf.is_empty() => {
                    buf.push(ch);
                    state = State::Address((header.clone(), true));
                }
                State::ParamName | State::ParamValue(_) => buf.push(ch),
                _ => return None,
            },
            b'=' => match &state {
                State::ParamName if !buf.is_empty() => {
                    let param = String::from_utf8(std::mem::take(&mut buf)).ok()?;
                    state = HeaderName::parse(param)
                        .map(|hdr| match hdr {
                            HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                                State::Address((hdr, false))
                            }
                            HeaderName::Other(param) => {
                                if param.eq_ignore_ascii_case("body") {
                                    State::ParamValue(Mailto::Body)
                                } else {
                                    State::ParamValue(Mailto::Other(param.into_owned()))
                                }
                            }
                            _ => State::ParamValue(Mailto::Header(hdr)),
                        })
                        .unwrap_or_else(|| State::ParamValue(Mailto::Other(String::new())));
                }
                State::ParamValue(_) => buf.push(ch),
                _ => return None,
            },
            b'&' => match state {
                State::Address((header, true)) => {
                    if !buf.is_empty() {
                        insert_address(
                            &mut params,
                            header,
                            String::from_utf8(std::mem::take(&mut buf)).ok()?,
                        );
                    }
                    state = State::ParamName;
                }
                State::ParamValue(param) => {
                    if !buf.is_empty() {
                        let value = String::from_utf8(std::mem::take(&mut buf)).ok()?;
                        match param {
                            Mailto::Header(header) => params.headers.push((header, value)),
                            Mailto::Body => params.body = value.into(),
                            Mailto::Other(header) => params.headers.push((header.into(), value)),
                        }
                    }
                    state = State::ParamName;
                }
                _ => return None,
            },
            _ => match &state {
                State::ParamName => {
                    if ch.is_ascii_alphanumeric() || b"-_".contains(&ch) {
                        buf.push(ch);
                    } else {
                        return None;
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        buf.push(ch);
                    }
                }
            },
        }
    }

    if !buf.is_empty() {
        let value = String::from_utf8(std::mem::take(&mut buf)).ok()?;
        match state {
            State::Address((header, true)) => {
                insert_address(&mut params, header, value);
                has_addresses = true;
            }
            State::ParamName => {
                params
                    .headers
                    .push((HeaderName::Other(value.into()), String::new()));
            }
            State::ParamValue(param) => match param {
                Mailto::Header(header) => params.headers.push((header, value)),
                Mailto::Body => params.body = value.into(),
                Mailto::Other(header) => params
                    .headers
                    .push((HeaderName::Other(header.into()), value)),
            },
            _ => return None,
        }
    }

    if has_addresses { Some(params) } else { None }
}

#[inline(always)]
fn insert_address(params: &mut MailtoMessage, name: HeaderName, value: String) {
    if !params
        .to
        .iter()
        .chain(params.cc.iter())
        .chain(params.bcc.iter())
        .any(|v| v.eq_ignore_ascii_case(&value))
    {
        match name {
            HeaderName::To => {
                params.to.push(value);
            }
            HeaderName::Cc => {
                params.cc.push(value);
            }
            HeaderName::Bcc => {
                params.bcc.push(value);
            }
            _ => (),
        }
    }
}

fn lookup_importance(input: &str) -> Option<Importance> {
    hashify::map!(
        input.as_bytes(), Importance,
        "1" => Importance::High,
        "3" => Importance::Low,
    )
    .copied()
}

fn lookup_importance_headers(input: &str) -> Option<(&'static str, &'static str)> {
    hashify::map!(
        input.as_bytes(), (&'static str, &'static str),
        "1" => ("High", "1 (High)"),
        "3" => ("Low", "5 (Low)"),
    )
    .copied()
}

fn hex_value(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}
