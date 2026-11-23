/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Context, Sieve,
    bytecode::{
        ops,
        rec::{Range, tag},
    },
    compiler::grammar::actions::action_redirect::{ByMode, ByTime, Notify, NotifyItem, Ret},
    runtime::{
        RuntimeError,
        handler::{Action, MessageSource, Recipient},
    },
};
use mail_parser::{DateTime, HeaderName};

const NOTIFY_NEVER: u8 = 0;
const NOTIFY_ITEMS: u8 = 1;
const BY_TIME_RELATIVE: u8 = 0;
const BY_TIME_ABSOLUTE: u8 = 1;

impl<'x> Context<'x> {
    pub(crate) fn exec_redirect(
        &mut self,
        script: &'x Sieve<'x>,
        redirect: &ops::Redirect,
    ) -> Result<(), RuntimeError> {
        let address = self.eval_value(script, redirect.address)?;
        let Some(address) = sanitize_address(address.to_string().as_ref()) else {
            return Ok(());
        };
        if self.num_redirects >= self.runtime.max_redirects
            || self.num_out_messages >= self.runtime.max_out_messages
            || (!redirect.list && address.eq_ignore_ascii_case(self.user_address.as_ref()))
        {
            return Ok(());
        }

        if self
            .root_headers()
            .filter(|h| h.is_named(&HeaderName::Received))
            .count()
            >= self.runtime.max_received_headers
        {
            self.hop_limited = true;
            return Ok(());
        }

        if !redirect.copy && matches!(&self.final_action, Some(Action::Keep { .. })) {
            self.final_action = None;
        }

        let notify = self.notify_spec(script, &redirect.notify)?;
        let by_time = self.by_time(script, &redirect.by_time)?;
        if let Some(created) = self.build_message_id() {
            self.actions.push(created);
        }
        self.num_redirects += 1;
        self.num_out_messages += 1;
        let address = self.alloc_string(address);
        self.actions.push(Action::SendMessage {
            source: MessageSource::Redirect,
            recipient: if !redirect.list {
                Recipient::Address(address)
            } else {
                Recipient::List(address)
            },
            notify,
            return_of_content: ret_from_code(redirect.ret),
            by_time,
            message_id: self.main_message_id,
        });
        Ok(())
    }

    fn notify_spec(
        &self,
        script: &'x Sieve<'x>,
        spec: &ops::NotifySpec,
    ) -> Result<Notify, RuntimeError> {
        Ok(match spec.kind {
            NOTIFY_NEVER => Notify::Never,
            NOTIFY_ITEMS => Notify::Items(notify_items(script, spec.items)?),
            _ => Notify::Default,
        })
    }

    fn by_time(
        &self,
        script: &'x Sieve<'x>,
        by_time: &ops::ByTime,
    ) -> Result<ByTime<i64>, RuntimeError> {
        Ok(match by_time.kind {
            BY_TIME_RELATIVE => ByTime::Relative {
                rlimit: by_time.rlimit,
                mode: by_mode_from_code(by_time.mode),
                trace: by_time.trace,
            },
            BY_TIME_ABSOLUTE => ByTime::Absolute {
                alimit: DateTime::parse_rfc3339(
                    self.eval_value(script, by_time.alimit)?
                        .to_string()
                        .as_ref(),
                )
                .and_then(|d| {
                    if d.is_valid() {
                        d.to_timestamp().into()
                    } else {
                        None
                    }
                })
                .unwrap_or(0),
                mode: by_mode_from_code(by_time.mode),
                trace: by_time.trace,
            },
            _ => ByTime::None,
        })
    }
}

fn notify_items(script: &Sieve<'_>, items: Range) -> Result<Box<[NotifyItem]>, RuntimeError> {
    script
        .recs(items)?
        .map(|rec| {
            if rec.tag != tag::NOTIFY_ITEM {
                return Err(RuntimeError::InvalidBytecode);
            }
            Ok(match rec.b {
                0 => NotifyItem::Success,
                1 => NotifyItem::Failure,
                _ => NotifyItem::Delay,
            })
        })
        .collect()
}

fn ret_from_code(code: u8) -> Ret {
    match code {
        0 => Ret::Full,
        1 => Ret::Hdrs,
        _ => Ret::Default,
    }
}

fn by_mode_from_code(code: u8) -> ByMode {
    match code {
        0 => ByMode::Notify,
        1 => ByMode::Return,
        _ => ByMode::Default,
    }
}

pub(crate) fn sanitize_address(addr: &str) -> Option<String> {
    let mut result = String::with_capacity(addr.len());
    let mut in_quote = false;
    let mut last_ch = '\n';
    let mut has_at = false;
    let mut has_dot = false;

    for ch in addr.chars() {
        match ch {
            '\"' => {
                if !in_quote {
                    in_quote = true;
                } else if last_ch != '\\' {
                    in_quote = false;
                }
            }
            '@' if !in_quote => {
                if !has_at && !result.is_empty() {
                    has_at = true;
                    result.push(ch);
                } else {
                    return None;
                }
            }
            '.' if !in_quote && has_at && !has_dot => {
                has_dot = true;
                result.push(ch);
            }
            '<' => {
                result.clear();
                has_at = false;
                has_dot = false;
            }
            '>' => (),
            _ => {
                if !ch.is_ascii_whitespace() || in_quote {
                    result.push(ch);
                }
            }
        }
        last_ch = ch;
    }

    if !result.is_empty() && has_at && has_dot {
        Some(result)
    } else {
        None
    }
}
