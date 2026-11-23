/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Context, Envelope, ExternalId, Importance, MatchAs, Sieve,
    compiler::grammar::actions::action_redirect::{ByTime, Notify, Ret},
    runtime::{RuntimeError, Variable},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply<T> {
    Ready(T),
    Pending,
    Error(RuntimeError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Finished,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Script<'a> {
    Personal(&'a str),
    Global(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mailbox<'a> {
    Name(&'a str),
    Id(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient<'a> {
    Address(&'a str),
    List(&'a str),
    Group(Vec<&'a str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageSource {
    Redirect,
    Vacation,
    Notification,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action<'a> {
    Keep {
        flags: &'a [&'a str],
        message_id: usize,
    },
    Discard,
    Reject {
        extended: bool,
        reason: &'a str,
    },
    FileInto {
        folder: &'a str,
        flags: &'a [&'a str],
        mailbox_id: Option<&'a str>,
        special_use: Option<&'a str>,
        create: bool,
        message_id: usize,
    },
    SendMessage {
        source: MessageSource,
        recipient: Recipient<'a>,
        notify: Notify,
        return_of_content: Ret,
        by_time: ByTime<i64>,
        message_id: usize,
    },
    Notify {
        from: Option<&'a str>,
        importance: Importance,
        options: &'a [&'a str],
        message: &'a str,
        method: &'a str,
    },
    SetEnvelope {
        envelope: Envelope,
        value: &'a str,
    },
    CreatedMessage {
        message_id: usize,
        message: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub enum Input<'x> {
    Bool(bool),
    Value(Variable<'x>),
    Script(Option<&'x Sieve<'x>>),
    Continue,
}

impl From<bool> for Input<'_> {
    fn from(value: bool) -> Self {
        Input::Bool(value)
    }
}

impl<'x> From<Variable<'x>> for Input<'x> {
    fn from(value: Variable<'x>) -> Self {
        Input::Value(value)
    }
}

impl<'x> From<Option<&'x Sieve<'x>>> for Input<'x> {
    fn from(value: Option<&'x Sieve<'x>>) -> Self {
        Input::Script(value)
    }
}

impl<'x> From<&'x Sieve<'x>> for Input<'x> {
    fn from(value: &'x Sieve<'x>) -> Self {
        Input::Script(Some(value))
    }
}

impl<T> From<T> for Reply<T> {
    fn from(value: T) -> Self {
        Reply::Ready(value)
    }
}

impl<'a> Script<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            Script::Personal(name) | Script::Global(name) => name,
        }
    }

    pub fn is_global(&self) -> bool {
        matches!(self, Script::Global(_))
    }
}

impl std::fmt::Display for Script<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[allow(unused_variables)]
pub trait Handler<'x> {
    fn include_script(
        &mut self,
        ctx: &Context<'x>,
        name: Script<'_>,
        optional: bool,
    ) -> Reply<Option<&'x Sieve<'x>>> {
        Reply::Ready(None)
    }

    fn mailbox_exists(
        &mut self,
        ctx: &Context<'x>,
        mailboxes: &[Mailbox<'_>],
        special_use: &[&str],
    ) -> Reply<bool> {
        Reply::Ready(false)
    }

    fn list_contains(
        &mut self,
        ctx: &Context<'x>,
        lists: &[&str],
        values: &[&str],
        match_as: MatchAs,
    ) -> Reply<bool> {
        Reply::Ready(false)
    }

    fn valid_ext_lists(&mut self, ctx: &Context<'x>, lists: &[&str]) -> Reply<bool> {
        Reply::Ready(
            lists
                .iter()
                .all(|list| ctx.runtime.valid_ext_lists.contains(*list)),
        )
    }

    fn duplicate_id(
        &mut self,
        ctx: &Context<'x>,
        id: &str,
        expiry: u64,
        last: bool,
    ) -> Reply<bool> {
        Reply::Ready(false)
    }

    fn function(
        &mut self,
        ctx: &Context<'x>,
        id: ExternalId,
        arguments: &[Variable<'x>],
    ) -> Reply<Variable<'x>> {
        Reply::Ready(Variable::default())
    }

    fn action(&mut self, ctx: &Context<'x>, action: Action<'x>) -> Reply<()> {
        Reply::Ready(())
    }
}
