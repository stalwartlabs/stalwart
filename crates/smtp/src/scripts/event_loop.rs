/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::{
    MessageSource,
    quota::HasQueueQuota,
    spool::{QueueOutcome, QueueParams, SmtpSpool},
};
use common::{
    Server,
    config::smtp::queue::QueueExpiry,
    scripts::{ScriptModification, plugins::PluginContext},
};
use compact_str::{CompactString, ToCompactString, format_compact};
use mail_parser::Message;
use sieve::{
    Arena, Context, Handler, Input, Mailbox, MatchAs, MessageSource as SieveMessageSource,
    Recipient, Reply, Sieve, SieveAction, Status,
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, Ret},
    runtime::{RuntimeError, Script, Variable},
};
use smtp_proto::{MAIL_BY_TRACE, MAIL_RET_FULL, MAIL_RET_HDRS};
use std::{future::Future, time::Instant};
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
    },
    Function {
        id: u32,
        arguments: Vec<Variable<'x>>,
    },
    SendMessage(SieveSend),
}

struct SieveSend {
    source: SieveMessageSource,
    recipients: Vec<String>,
    notify: Notify,
    return_of_content: Ret,
    by_time: ByTime<i64>,
    message_id: usize,
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
                        Script = CompactString::from(self.script_id),
                        SpanId = self.session_id,
                        Details = CompactString::from(name.name()),
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
        let lowercase = matches!(match_as, MatchAs::Lowercase);
        self.pending = Some(PendingWork::ListContains {
            lists: lists.iter().map(|list| list.to_string()).collect(),
            values: values
                .iter()
                .map(|value| {
                    if lowercase {
                        value.to_lowercase()
                    } else {
                        value.to_string()
                    }
                })
                .collect(),
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
                            Script = CompactString::from(self.script_id),
                            SpanId = self.session_id,
                            Name = CompactString::from(list),
                            Reason = "Sending to lists is not supported.",
                        );

                        Vec::new()
                    }
                };

                self.pending = Some(PendingWork::SendMessage(SieveSend {
                    source,
                    recipients,
                    notify,
                    return_of_content,
                    by_time,
                    message_id,
                }));

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
                    Script = CompactString::from(self.script_id),
                    SpanId = self.session_id,
                    Reason = "Unsupported action",
                    Details = format_compact!("{action:?}"),
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
        let empty;
        let message = match params.message.take() {
            Some(message) => message,
            None => {
                empty = Message::default();
                &empty
            }
        };
        let mut arena = Arena::new();
        let mut ctx = self
            .core
            .sieve
            .trusted_runtime
            .filter_parsed(message, script, &mut arena)
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
        let mut first_redirect = None;
        let mut more_redirects = Vec::new();
        let mut redirect_copies = 0;
        loop {
            match ctx.run(&mut handler) {
                Ok(Status::Finished) => break,
                Ok(Status::Pending) => {
                    let input = match handler.pending.take() {
                        Some(PendingWork::ListContains { lists, values }) => {
                            let mut contains = false;

                            'outer: for list in lists {
                                let Some(store) = self.get_lookup_store(&list) else {
                                    trc::event!(
                                        Sieve(SieveEvent::ListNotFound),
                                        Script = script_id.clone(),
                                        SpanId = session_id,
                                        Name = list,
                                    );

                                    continue;
                                };

                                for value in &values {
                                    if let Ok(true) = store.key_exists(value.as_str()).await {
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
                        Some(PendingWork::SendMessage(send))
                            if send.source == SieveMessageSource::Redirect =>
                        {
                            redirect_copies += send.recipients.len();
                            if first_redirect.is_none() {
                                first_redirect = Some(send);
                            } else {
                                more_redirects.push(send);
                            }

                            Input::Continue
                        }
                        Some(PendingWork::SendMessage(send)) => {
                            self.queue_sieve_message(
                                &handler.messages,
                                ctx.message().raw(),
                                &params,
                                &script_id,
                                send,
                                false,
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
                        Script = script_id.clone(),
                        SpanId = session_id,
                        Reason = err.to_compact_string(),
                    );

                    break;
                }
            }
        }

        let redirected = redirect_copies > 0;
        if first_redirect.is_some() {
            let kept = handler.keep_id == 0
                || (handler.keep_id != DISCARD && handler.reject_reason.is_none());
            let exploded = redirect_copies + usize::from(kept) > 1;
            for send in first_redirect.into_iter().chain(more_redirects) {
                self.queue_sieve_message(
                    &handler.messages,
                    ctx.message().raw(),
                    &params,
                    &script_id,
                    send,
                    exploded,
                )
                .await;
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
                Script = script_id,
                Elapsed = time.elapsed(),
            );

            ScriptResult::Accept {
                modifications,
                redirected,
            }
        } else if let Some(mut reject_reason) = reject_reason {
            trc::event!(
                Sieve(SieveEvent::ActionReject),
                Script = script_id,
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
                    Script = script_id,
                    Elapsed = time.elapsed(),
                );

                ScriptResult::Replace {
                    message,
                    modifications,
                    redirected,
                }
            } else {
                trc::event!(
                    Sieve(SieveEvent::ActionAcceptReplace),
                    SpanId = session_id,
                    Script = script_id,
                    Elapsed = time.elapsed(),
                );

                ScriptResult::Accept {
                    modifications,
                    redirected,
                }
            }
        } else {
            trc::event!(
                Sieve(SieveEvent::ActionDiscard),
                SpanId = session_id,
                Script = script_id,
                Elapsed = time.elapsed()
            );

            ScriptResult::Discard
        }
    }
}

trait QueueSieveMessage {
    fn queue_sieve_message(
        &self,
        messages: &[Vec<u8>],
        original_raw_message: &[u8],
        params: &ScriptParameters<'_>,
        script_id: &str,
        send: SieveSend,
        exploded: bool,
    ) -> impl Future<Output = ()> + Send;
}

impl QueueSieveMessage for Server {
    async fn queue_sieve_message(
        &self,
        messages: &[Vec<u8>],
        original_raw_message: &[u8],
        params: &ScriptParameters<'_>,
        script_id: &str,
        send: SieveSend,
        exploded: bool,
    ) {
        let SieveSend {
            source,
            recipients,
            notify,
            return_of_content,
            by_time,
            message_id,
        } = send;
        let session_id = params.session_id;
        let is_redirect = source == SieveMessageSource::Redirect;

        // Build message
        let return_path = if source == SieveMessageSource::Vacation {
            ""
        } else {
            params.return_path.as_str()
        };
        let mut message = self.new_message(return_path, MessageSource::Autogenerated, session_id);
        for rcpt in &recipients {
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

        let quotas = self.queue_quotas(&message).await;

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

        let (dkim2_verified, verified_message) =
            params.dkim2_verified.filter(|_| is_redirect).unzip();
        let queue_params = QueueParams::new(raw_message, session_id, self)
            .with_dkim_signers(dkim_signers)
            .with_raw_headers_opt(params.headers.filter(|_| is_forward))
            .with_original_raw_message(original_raw_message)
            .with_dkim2_verified(dkim2_verified)
            .with_exploded(exploded)
            .with_quotas(quotas);
        match message
            .queue(match verified_message {
                Some(verified_message) => {
                    queue_params.with_original_authenticated_message(verified_message)
                }
                None => queue_params,
            })
            .await
        {
            QueueOutcome::Queued => {}
            QueueOutcome::QuotaExceeded => {
                trc::event!(
                    Sieve(SieveEvent::QuotaExceeded),
                    SpanId = session_id,
                    Script = CompactString::from(script_id),
                );
            }
            QueueOutcome::Failed => {
                trc::event!(
                    Sieve(SieveEvent::UnexpectedError),
                    Details = "Failed to queue Sieve generated message.",
                    To = recipients
                        .into_iter()
                        .map(trc::Value::from)
                        .collect::<Vec<_>>(),
                    SpanId = session_id,
                    Script = CompactString::from(script_id),
                );
            }
        }
    }
}
