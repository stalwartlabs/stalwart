/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::{
    MessageSource,
    quota::HasQueueQuota,
    spool::{QueueParams, SmtpSpool},
};
use common::{
    Server,
    config::smtp::queue::QueueExpiry,
    scripts::{ScriptModification, plugins::PluginContext},
};
use mail_parser::{Encoding, Message, MessagePart, PartType};
use sieve::{
    Arena, Context, Handler, Input, Mailbox, MatchAs, MessageSource as SieveMessageSource,
    Recipient, Reply, Sieve, SieveAction, Status,
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, Ret},
    runtime::{RuntimeError, Script, Variable},
};
use smtp_proto::{MAIL_BY_TRACE, MAIL_RET_FULL, MAIL_RET_HDRS};
use std::{borrow::Cow, future::Future, time::Instant};
use trc::SieveEvent;

use super::{ScriptParameters, ScriptResult, notify_flags};

const IMPLICIT_KEEP: usize = usize::MAX;
const DISCARD: usize = usize::MAX - 1;

pub trait RunScript: Sync + Send {
    fn run_script(
        &self,
        script_id: String,
        script: &Sieve<'_>,
        params: ScriptParameters<'_>,
    ) -> impl Future<Output = ScriptResult> + Send;
}

struct SmtpHandler<'x> {
    server: &'x Server,
    script_id: &'x str,
    session_id: u64,
    modifications: Vec<ScriptModification>,
    messages: Vec<Vec<u8>>,
    reject_reason: Option<String>,
    keep_id: usize,
    pending: Option<PendingWork<'x>>,
}

enum PendingWork<'x> {
    ListContains {
        lists: Vec<String>,
        values: Vec<String>,
        match_as: MatchAs,
    },
    Function {
        id: u32,
        arguments: Vec<Variable<'x>>,
    },
    SendMessage {
        source: SieveMessageSource,
        recipients: Vec<String>,
        notify: Notify,
        return_of_content: Ret,
        by_time: ByTime<i64>,
        message_id: usize,
    },
}

impl<'x> Handler<'x> for SmtpHandler<'x> {
    fn mailbox_exists(&mut self, _: &Context<'x>, _: &[Mailbox<'_>], _: &[&str]) -> Reply<bool> {
        Reply::Error(RuntimeError::CapabilityNotSupported("mailbox".into()))
    }

    fn duplicate_id(&mut self, _: &Context<'x>, _: &str, _: u64, _: bool) -> Reply<bool> {
        Reply::Error(RuntimeError::CapabilityNotSupported("duplicate".into()))
    }

    fn include_script(
        &mut self,
        _: &Context<'x>,
        name: Script<'_>,
        optional: bool,
    ) -> Reply<Option<&'x Sieve<'x>>> {
        match self.server.core.sieve.trusted_script(name.name()) {
            Some(script) => Reply::Ready(Some(script)),
            None => {
                if !optional {
                    trc::event!(
                        Sieve(SieveEvent::ScriptNotFound),
                        Id = self.script_id.to_string(),
                        SpanId = self.session_id,
                        Details = name.name().to_string(),
                    );
                }

                Reply::Ready(None)
            }
        }
    }

    fn list_contains(
        &mut self,
        _: &Context<'x>,
        lists: &[&str],
        values: &[&str],
        match_as: MatchAs,
    ) -> Reply<bool> {
        self.pending = Some(PendingWork::ListContains {
            lists: lists.iter().map(|list| list.to_string()).collect(),
            values: values.iter().map(|value| value.to_string()).collect(),
            match_as,
        });

        Reply::Pending
    }

    fn function(
        &mut self,
        _: &Context<'x>,
        id: u32,
        arguments: &[Variable<'x>],
    ) -> Reply<Variable<'x>> {
        self.pending = Some(PendingWork::Function {
            id,
            arguments: arguments.to_vec(),
        });

        Reply::Pending
    }

    fn action(&mut self, _: &Context<'x>, action: SieveAction<'_>) -> Reply<()> {
        match action {
            SieveAction::Keep { message_id, .. } => {
                self.keep_id = message_id;
            }
            SieveAction::Discard => {
                self.keep_id = DISCARD;
            }
            SieveAction::Reject { reason, .. } => {
                self.reject_reason = reason.to_string().into();
            }
            SieveAction::CreatedMessage { message, .. } => {
                self.messages.push(message);
            }
            SieveAction::SetEnvelope { envelope, value } => {
                self.modifications.push(ScriptModification::SetEnvelope {
                    name: envelope,
                    value: value.to_string(),
                });
            }
            SieveAction::SendMessage {
                source,
                recipient,
                notify,
                return_of_content,
                by_time,
                message_id,
            } => {
                let recipients = match recipient {
                    Recipient::Address(rcpt) => vec![rcpt.to_string()],
                    Recipient::Group(rcpts) => rcpts.iter().map(|rcpt| rcpt.to_string()).collect(),
                    Recipient::List(list) => {
                        trc::event!(
                            Sieve(SieveEvent::NotSupported),
                            Id = self.script_id.to_string(),
                            SpanId = self.session_id,
                            Details = list.to_string(),
                            Reason = "Sending to lists is not supported.",
                        );

                        Vec::new()
                    }
                };

                self.pending = Some(PendingWork::SendMessage {
                    source,
                    recipients,
                    notify,
                    return_of_content,
                    by_time,
                    message_id,
                });

                return Reply::Pending;
            }
            action => {
                let capability = if matches!(action, SieveAction::FileInto { .. }) {
                    "fileinto"
                } else {
                    "enotify"
                };
                trc::event!(
                    Sieve(SieveEvent::NotSupported),
                    Id = self.script_id.to_string(),
                    SpanId = self.session_id,
                    Reason = "Unsupported action",
                    Details = format!("{action:?}"),
                );
                return Reply::Error(RuntimeError::CapabilityNotSupported(capability.into()));
            }
        }

        Reply::Ready(())
    }
}

impl RunScript for Server {
    async fn run_script(
        &self,
        script_id: String,
        script: &Sieve<'_>,
        mut params: ScriptParameters<'_>,
    ) -> ScriptResult {
        // Create filter instance
        let time = Instant::now();
        let session_id = params.session_id;
        let mut arena = Arena::new();
        let mut ctx = self
            .core
            .sieve
            .trusted_runtime
            .filter_parsed(
                params.message.take().unwrap_or_else(|| Message {
                    parts: vec![MessagePart {
                        headers: vec![],
                        is_encoding_problem: false,
                        body: PartType::Text("".into()),
                        encoding: Encoding::None,
                        offset_header: 0,
                        offset_body: 0,
                        offset_end: 0,
                    }],
                    raw_message: b""[..].into(),
                    ..Default::default()
                }),
                script,
                &mut arena,
            )
            .with_vars_env(std::mem::take(&mut params.variables))
            .with_envelope_list(std::mem::take(&mut params.envelope))
            .with_user_address(&params.from_addr)
            .with_user_full_name(&params.from_name);
        if let Some(spam_status) = params.spam_status {
            ctx.set_spam_status(spam_status);
        }

        let mut handler = SmtpHandler {
            server: self,
            script_id: script_id.as_str(),
            session_id,
            modifications: Vec::new(),
            messages: Vec::new(),
            reject_reason: None,
            keep_id: IMPLICIT_KEEP,
            pending: None,
        };

        // Start event loop
        loop {
            match ctx.run(&mut handler) {
                Ok(Status::Finished) => break,
                Ok(Status::Pending) => {
                    let input = match handler.pending.take() {
                        Some(PendingWork::ListContains {
                            lists,
                            values,
                            match_as,
                        }) => {
                            let mut contains = false;

                            'outer: for list in lists {
                                let Some(store) = self.get_lookup_store(&list) else {
                                    trc::event!(
                                        Sieve(SieveEvent::ListNotFound),
                                        Id = script_id.clone(),
                                        SpanId = session_id,
                                        Details = list,
                                    );

                                    continue;
                                };

                                for value in &values {
                                    let key = if matches!(match_as, MatchAs::Lowercase) {
                                        Cow::Owned(value.to_lowercase())
                                    } else {
                                        Cow::Borrowed(value.as_str())
                                    };

                                    if let Ok(true) = store.key_exists(key).await {
                                        contains = true;
                                        break 'outer;
                                    }
                                }
                            }

                            Input::Bool(contains)
                        }
                        Some(PendingWork::Function { id, arguments }) => {
                            self.core
                                .run_plugin(
                                    id,
                                    PluginContext {
                                        session_id,
                                        server: self,
                                        message: ctx.message(),
                                        modifications: &mut handler.modifications,
                                        access_token: params.access_token,
                                        arguments,
                                    },
                                )
                                .await
                        }
                        Some(PendingWork::SendMessage {
                            source,
                            recipients,
                            notify,
                            return_of_content,
                            by_time,
                            message_id,
                        }) => {
                            self.queue_sieve_message(
                                &handler.messages,
                                ctx.message().raw_message(),
                                &params,
                                &script_id,
                                source,
                                recipients,
                                notify,
                                return_of_content,
                                by_time,
                                message_id,
                            )
                            .await;

                            Input::Continue
                        }
                        None => Input::Continue,
                    };

                    ctx.resume(input);
                }
                Err(err) => {
                    trc::event!(
                        Sieve(SieveEvent::RuntimeError),
                        Id = script_id.clone(),
                        SpanId = session_id,
                        Reason = err.to_string(),
                    );

                    break;
                }
            }
        }

        let SmtpHandler {
            modifications,
            messages,
            reject_reason,
            keep_id,
            ..
        } = handler;

        // Keep id
        // 0 = use original message
        // IMPLICIT_KEEP = implicit keep
        // DISCARD = discard message

        if keep_id == 0 {
            trc::event!(
                Sieve(SieveEvent::ActionAccept),
                SpanId = session_id,
                Id = script_id,
                Elapsed = time.elapsed(),
            );

            ScriptResult::Accept { modifications }
        } else if let Some(mut reject_reason) = reject_reason {
            trc::event!(
                Sieve(SieveEvent::ActionReject),
                Id = script_id,
                SpanId = session_id,
                Details = reject_reason.clone(),
                Elapsed = time.elapsed(),
            );

            if !reject_reason.ends_with('\n') {
                reject_reason.push_str("\r\n");
            }
            let mut reject_bytes = reject_reason.as_bytes().iter();
            if matches!(reject_bytes.next(), Some(ch) if ch.is_ascii_digit())
                && matches!(reject_bytes.next(), Some(ch) if ch.is_ascii_digit())
                && matches!(reject_bytes.next(), Some(ch) if ch.is_ascii_digit())
                && matches!(reject_bytes.next(), Some(ch) if ch == &b' ' )
            {
                ScriptResult::Reject(reject_reason)
            } else {
                ScriptResult::Reject(format!("503 5.5.3 {reject_reason}"))
            }
        } else if keep_id != DISCARD {
            if let Some(message) = messages.into_iter().nth(keep_id - 1) {
                trc::event!(
                    Sieve(SieveEvent::ActionAccept),
                    SpanId = session_id,
                    Id = script_id,
                    Elapsed = time.elapsed(),
                );

                ScriptResult::Replace {
                    message,
                    modifications,
                }
            } else {
                trc::event!(
                    Sieve(SieveEvent::ActionAcceptReplace),
                    SpanId = session_id,
                    Id = script_id,
                    Elapsed = time.elapsed(),
                );

                ScriptResult::Accept { modifications }
            }
        } else {
            trc::event!(
                Sieve(SieveEvent::ActionDiscard),
                SpanId = session_id,
                Id = script_id,
                Elapsed = time.elapsed()
            );

            ScriptResult::Discard
        }
    }
}

trait QueueSieveMessage {
    #[allow(clippy::too_many_arguments)]
    fn queue_sieve_message(
        &self,
        messages: &[Vec<u8>],
        original_raw_message: &[u8],
        params: &ScriptParameters<'_>,
        script_id: &str,
        source: SieveMessageSource,
        recipients: Vec<String>,
        notify: Notify,
        return_of_content: Ret,
        by_time: ByTime<i64>,
        message_id: usize,
    ) -> impl Future<Output = ()> + Send;
}

impl QueueSieveMessage for Server {
    async fn queue_sieve_message(
        &self,
        messages: &[Vec<u8>],
        original_raw_message: &[u8],
        params: &ScriptParameters<'_>,
        script_id: &str,
        source: SieveMessageSource,
        recipients: Vec<String>,
        notify: Notify,
        return_of_content: Ret,
        by_time: ByTime<i64>,
        message_id: usize,
    ) {
        let session_id = params.session_id;

        // Build message
        let return_path = if source == SieveMessageSource::Vacation {
            ""
        } else {
            params.return_path.as_str()
        };
        let mut message = self.new_message(return_path, MessageSource::Autogenerated, session_id);
        for rcpt in recipients {
            message.expand_and_add_recipient(rcpt, self).await;
        }

        // Set notify flags
        let flags = notify_flags(&notify);
        if flags > 0 {
            for rcpt in &mut message.message.recipients {
                rcpt.flags |= flags;
            }
        }

        // Set ByTime flags
        match by_time {
            ByTime::Relative {
                rlimit,
                mode,
                trace,
            } => {
                if trace {
                    message.message.flags |= MAIL_BY_TRACE;
                }
                match mode {
                    ByMode::Notify | ByMode::Return => {
                        for domain in &mut message.message.recipients {
                            domain.notify.due += rlimit;
                        }
                    }
                    ByMode::Default => (),
                }
            }
            ByTime::Absolute {
                alimit,
                mode,
                trace,
            } => {
                if trace {
                    message.message.flags |= MAIL_BY_TRACE;
                }
                match mode {
                    ByMode::Notify => {
                        for domain in &mut message.message.recipients {
                            domain.notify.due = alimit as u64;
                        }
                    }
                    ByMode::Return => {
                        let expires = (alimit as u64).saturating_sub(message.message.created);
                        if expires > 0 {
                            for domain in &mut message.message.recipients {
                                domain.expires = QueueExpiry::Ttl(expires);
                            }
                        }
                    }
                    ByMode::Default => (),
                }
            }
            ByTime::None => (),
        };

        // Set ret
        match return_of_content {
            Ret::Full => {
                message.message.flags |= MAIL_RET_FULL;
            }
            Ret::Hdrs => {
                message.message.flags |= MAIL_RET_HDRS;
            }
            Ret::Default => (),
        }

        // Queue message
        let is_forward = message_id == 0;
        let raw_message = if !is_forward {
            messages.get(message_id - 1).map(|m| m.as_slice())
        } else {
            original_raw_message.into()
        };
        let Some(raw_message) = raw_message.filter(|m| !m.is_empty()) else {
            return;
        };

        let Some(metadata) = self.has_quota(&mut message).await else {
            trc::event!(
                Sieve(SieveEvent::QuotaExceeded),
                SpanId = session_id,
                Id = script_id.to_string(),
                From = message.message.return_path,
                To = message
                    .message
                    .recipients
                    .into_iter()
                    .map(|r| trc::Value::from(r.address().to_string()))
                    .collect::<Vec<_>>(),
            );

            return;
        };

        let dkim_signers = match &params.sign_domain {
            Some(sign_domain) => match self.dkim_signers(sign_domain).await {
                Ok(signers) => signers,
                Err(err) => {
                    trc::error!(
                        err.details("Failed to obtain DKIM signers")
                            .caused_by(trc::location!())
                    );

                    None
                }
            },
            None => None,
        };

        message
            .queue(
                QueueParams::new(raw_message, session_id, self)
                    .with_dkim_signers(dkim_signers)
                    .with_raw_headers_opt(params.headers.filter(|_| is_forward))
                    .with_original_raw_message(original_raw_message)
                    .with_metadata(metadata),
            )
            .await;
    }
}
