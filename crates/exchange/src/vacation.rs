/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use email::sieve::{
    ingest::SieveScriptIngest,
    rules::managed::{ManagedActivity, ManagedSieveScript, SaveError},
};
use mail_parser::{html_to_text, text_to_html};
use std::borrow::Cow;
use trc::AddContext;

const MAX_WRITE_ATTEMPTS: usize = 3;
pub(crate) const MAX_REPLY_LEN: usize = 2048;
const BYTE_ORDER_MARK: char = '\u{feff}';

pub(crate) enum VacationState {
    Disabled,
    Global,
    Active,
    TimeBased { from: u64, to: u64 },
}

pub(crate) struct VacationReply<'a> {
    pub(crate) body: &'a str,
    pub(crate) format: ReplyFormat,
    pub(crate) origin: ReplyOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyOrigin {
    Declared,
    Sniffed,
}

impl<'a> VacationReply<'a> {
    pub(crate) fn new(body: &'a str, format: ReplyFormat, origin: ReplyOrigin) -> Self {
        VacationReply {
            body: body.strip_prefix(BYTE_ORDER_MARK).unwrap_or(body),
            format,
            origin,
        }
    }
}

pub(crate) struct VacationEdit<'a> {
    pub(crate) state: Option<VacationState>,
    pub(crate) reply: Option<VacationReply<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VacationWrite {
    Written,
    Busy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyFormat {
    Text,
    Html,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReplyRead {
    Convert(ReplyFormat),
    Stored,
}

pub(crate) struct VacationView {
    pub(crate) active: bool,
    pub(crate) from: Option<u64>,
    pub(crate) to: Option<u64>,
    pub(crate) format: ReplyFormat,
    pub(crate) reply: String,
}

pub(crate) async fn write_vacation(
    server: &Server,
    account_id: u32,
    access_token: &AccessToken,
    edit: &VacationEdit<'_>,
) -> trc::Result<VacationWrite> {
    for _ in 0..MAX_WRITE_ATTEMPTS {
        match write_once(server, account_id, access_token, edit).await? {
            Ok(()) => return Ok(VacationWrite::Written),
            Err(SaveError::Conflict) => {}
            Err(SaveError::Invalid(err)) => {
                return Err(trc::StoreEvent::UnexpectedError
                    .into_err()
                    .account_id(account_id)
                    .reason(err)
                    .caused_by(trc::location!()));
            }
        }
    }
    Ok(VacationWrite::Busy)
}

pub(crate) async fn read_vacation(
    server: &Server,
    account_id: u32,
    read: ReplyRead,
) -> trc::Result<Option<VacationView>> {
    let Some(vacation) = server
        .managed_vacation_read(account_id)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let (format, reply) = match read {
        ReplyRead::Convert(preferred) => {
            let (format, reply) = reported_reply(
                vacation.html_body.as_deref(),
                vacation.text_body.as_deref(),
                preferred,
            );
            (format, reply.into_owned())
        }
        ReplyRead::Stored => stored_reply(vacation.html_body, vacation.text_body),
    };
    Ok(Some(VacationView {
        active: vacation.is_enabled,
        from: vacation.from_date,
        to: vacation.to_date,
        format,
        reply,
    }))
}

pub(crate) async fn vacation_in_effect(
    server: &Server,
    account_id: u32,
    now: u64,
) -> trc::Result<bool> {
    if server
        .sieve_script_get_active_id_cached(account_id)
        .await
        .caused_by(trc::location!())?
        .is_none()
    {
        return Ok(false);
    }
    let Some(vacation) = server
        .managed_script_read(account_id)
        .await
        .caused_by(trc::location!())?
        .vacation
    else {
        return Ok(false);
    };
    if !vacation.is_enabled
        || vacation.from_date.is_some_and(|from| from > now)
        || vacation.to_date.is_some_and(|to| now > to)
    {
        return Ok(false);
    }
    server
        .managed_script_activity(account_id)
        .await
        .map(activity_in_effect)
        .caused_by(trc::location!())
}

fn activity_in_effect(activity: ManagedActivity) -> bool {
    !activity.is_inactive()
}

async fn write_once(
    server: &Server,
    account_id: u32,
    access_token: &AccessToken,
    edit: &VacationEdit<'_>,
) -> trc::Result<Result<(), SaveError>> {
    let mut state = server
        .managed_script_load(account_id)
        .await
        .caused_by(trc::location!())?;
    let mut vacation = state.script.vacation.take().unwrap_or_default();
    let before = (vacation.is_enabled, vacation.from_date, vacation.to_date);
    match edit.state {
        Some(VacationState::Disabled) => vacation.is_enabled = false,
        Some(VacationState::Global | VacationState::Active | VacationState::TimeBased { .. }) => {
            vacation.is_enabled = true
        }
        None => {}
    }
    match &edit.state {
        Some(VacationState::Global) => {
            vacation.from_date = None;
            vacation.to_date = None;
        }
        Some(VacationState::TimeBased { from, to }) => {
            vacation.from_date = Some(*from);
            vacation.to_date = Some(*to);
        }
        _ => {}
    }
    let reply_changed = match &edit.reply {
        Some(reply)
            if !reply_unchanged(
                vacation.html_body.as_deref(),
                vacation.text_body.as_deref(),
                reply,
            ) =>
        {
            let (body, other) = if reply.format == ReplyFormat::Html {
                (&mut vacation.html_body, &mut vacation.text_body)
            } else {
                (&mut vacation.text_body, &mut vacation.html_body)
            };
            *body = Some(reply.body.to_string());
            *other = None;
            true
        }
        _ => false,
    };
    if !reply_changed && before == (vacation.is_enabled, vacation.from_date, vacation.to_date) {
        return Ok(Ok(()));
    }
    state.script.set_vacation(vacation);
    if let Err(err) = server
        .managed_script_save(access_token, account_id, state)
        .await
        .caused_by(trc::location!())?
    {
        return Ok(Err(err));
    }
    Ok(Ok(()))
}

fn reply_unchanged(
    html_body: Option<&str>,
    text_body: Option<&str>,
    reply: &VacationReply<'_>,
) -> bool {
    (reply.origin == ReplyOrigin::Sniffed
        && html_body.or(text_body).unwrap_or_default() == reply.body)
        || reported_reply(html_body, text_body, reply.format).1 == reply.body
}

fn stored_reply(html_body: Option<String>, text_body: Option<String>) -> (ReplyFormat, String) {
    match (html_body, text_body) {
        (Some(html), _) => (ReplyFormat::Html, html),
        (None, text) => (ReplyFormat::Text, text.unwrap_or_default()),
    }
}

fn reported_reply<'v>(
    html_body: Option<&'v str>,
    text_body: Option<&'v str>,
    preferred: ReplyFormat,
) -> (ReplyFormat, Cow<'v, str>) {
    match (preferred, html_body, text_body) {
        (ReplyFormat::Html, Some(html), _) => (ReplyFormat::Html, Cow::Borrowed(html)),
        (ReplyFormat::Html, None, Some(text)) => {
            (ReplyFormat::Html, Cow::Owned(text_to_html(text)))
        }
        (ReplyFormat::Text, _, Some(text)) => (ReplyFormat::Text, Cow::Borrowed(text)),
        (ReplyFormat::Text, Some(html), None) => {
            (ReplyFormat::Text, Cow::Owned(html_to_text(html)))
        }
        (preferred, None, None) => (preferred, Cow::Borrowed("")),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/vacation/tests.rs"]
mod tests;
