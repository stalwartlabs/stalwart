/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::context::EasContext;
use crate::vacation::{
    MAX_REPLY_LEN, ReplyFormat, ReplyOrigin, ReplyRead, VacationEdit, VacationReply, VacationState,
    VacationWrite, read_vacation, write_vacation,
};
use common::Server;
use exchange_proto::{
    common::time::UtcSeconds,
    eas::{
        commands::{
            appdata::Empty,
            settings::{OofMessage, OofSettings},
        },
        status::SettingsStatus,
        types::EasDateTime,
    },
};
use std::borrow::Cow;

const OOF_DISABLED: u8 = 0;
const OOF_GLOBAL: u8 = 1;
const OOF_TIME_BASED: u8 = 2;
const BODY_TYPE_TEXT: &str = "TEXT";
const BODY_TYPE_HTML: &str = "HTML";
const OOF_MESSAGE_DISABLED: &str = "0";

fn parse_oof<'a>(oof: &'a OofSettings<'_>) -> Result<VacationEdit<'a>, SettingsStatus> {
    if oof.start_time.is_some() != oof.end_time.is_some() {
        return Err(SettingsStatus::PROTOCOL_ERROR);
    }
    let state = match oof.state {
        None => None,
        Some(OOF_DISABLED) => Some(VacationState::Disabled),
        Some(OOF_GLOBAL) => Some(VacationState::Global),
        Some(OOF_TIME_BASED) => match (oof.start_time, oof.end_time) {
            (Some(start), Some(end)) => {
                let (Ok(from), Ok(to)) = (u64::try_from(start.0.0), u64::try_from(end.0.0)) else {
                    return Err(SettingsStatus::INVALID_ARGUMENTS);
                };
                if from >= to {
                    return Err(SettingsStatus::CONFLICTING_ARGUMENTS);
                }
                Some(VacationState::TimeBased { from, to })
            }
            _ => Some(VacationState::Active),
        },
        Some(_) => return Err(SettingsStatus::INVALID_ARGUMENTS),
    };
    if oof.messages.iter().any(|message| {
        message
            .body_type
            .as_deref()
            .is_some_and(|body_type| reply_format(body_type).is_none())
    }) {
        return Err(SettingsStatus::INVALID_ARGUMENTS);
    }
    let reply = oof
        .messages
        .iter()
        .filter_map(|message| message.reply_message.as_deref().map(|body| (message, body)))
        .min_by_key(|(message, _)| {
            (
                message.enabled.as_deref() == Some(OOF_MESSAGE_DISABLED),
                message.applies_to_internal.is_none(),
            )
        })
        .map(|(message, body)| {
            VacationReply::new(
                body,
                message
                    .body_type
                    .as_deref()
                    .and_then(reply_format)
                    .unwrap_or(ReplyFormat::Text),
                ReplyOrigin::Declared,
            )
        });
    if reply
        .as_ref()
        .is_some_and(|reply| reply.body.len() >= MAX_REPLY_LEN)
    {
        return Err(SettingsStatus::INVALID_ARGUMENTS);
    }
    Ok(VacationEdit { state, reply })
}

pub(super) async fn oof_set(
    server: &Server,
    ctx: &EasContext<'_>,
    oof: &OofSettings<'_>,
) -> trc::Result<SettingsStatus> {
    let edit = match parse_oof(oof) {
        Ok(edit) => edit,
        Err(status) => return Ok(status),
    };
    Ok(
        match write_vacation(server, ctx.account_id, &ctx.access_token, &edit).await? {
            VacationWrite::Written => SettingsStatus::SUCCESS,
            VacationWrite::Busy => SettingsStatus::SERVER_UNAVAILABLE,
        },
    )
}

pub(super) async fn oof_get(
    server: &Server,
    account_id: u32,
    body_type: &str,
) -> trc::Result<OofSettings<'static>> {
    let mut oof = OofSettings {
        state: Some(OOF_DISABLED),
        ..Default::default()
    };
    let Some(vacation) = read_vacation(
        server,
        account_id,
        ReplyRead::Convert(reply_format(body_type).unwrap_or(ReplyFormat::Text)),
    )
    .await?
    else {
        return Ok(oof);
    };
    oof.state = Some(
        match (
            vacation.active,
            vacation.from.is_some() || vacation.to.is_some(),
        ) {
            (false, _) => OOF_DISABLED,
            (true, false) => OOF_GLOBAL,
            (true, true) => OOF_TIME_BASED,
        },
    );
    oof.start_time = vacation.from.map(timestamp);
    oof.end_time = vacation.to.map(timestamp);

    let enabled: Cow<'static, str> = Cow::Borrowed(if vacation.active { "1" } else { "0" });
    let body_type = match vacation.format {
        ReplyFormat::Html => BODY_TYPE_HTML,
        ReplyFormat::Text => BODY_TYPE_TEXT,
    };
    let reply: Cow<'static, str> = Cow::Owned(vacation.reply);
    oof.messages.push(OofMessage {
        applies_to_internal: Some(Empty),
        enabled: Some(enabled.clone()),
        reply_message: Some(reply.clone()),
        body_type: Some(Cow::Borrowed(body_type)),
        ..Default::default()
    });
    oof.messages.push(OofMessage {
        applies_to_external_known: Some(Empty),
        enabled: Some(enabled.clone()),
        reply_message: Some(reply.clone()),
        body_type: Some(Cow::Borrowed(body_type)),
        ..Default::default()
    });
    oof.messages.push(OofMessage {
        applies_to_external_unknown: Some(Empty),
        enabled: Some(enabled),
        reply_message: Some(reply),
        body_type: Some(Cow::Borrowed(body_type)),
        ..Default::default()
    });
    Ok(oof)
}

fn timestamp(seconds: u64) -> EasDateTime {
    EasDateTime(UtcSeconds(i64::try_from(seconds).unwrap_or(i64::MAX)), 0)
}

fn reply_format(body_type: &str) -> Option<ReplyFormat> {
    hashify::map_ignore_case!(body_type.as_bytes(), ReplyFormat,
        "TEXT" => ReplyFormat::Text,
        "HTML" => ReplyFormat::Html,
    )
    .copied()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/eas/oof/tests.rs"]
mod tests;
