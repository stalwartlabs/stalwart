/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EwsCaller, EwsContext},
    owns_address,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::vacation::{
    MAX_REPLY_LEN, ReplyFormat, ReplyOrigin, ReplyRead, VacationEdit, VacationReply, VacationState,
    VacationView, VacationWrite, read_vacation, write_vacation,
};
use common::Server;
use exchange_proto::{
    common::UtcSeconds,
    ews::{
        Status,
        fault::{Fault, write_fault},
        requests::oof::{GetUserOofSettings, SetUserOofSettings},
        responses::oof::{GetUserOofSettingsResponse, OofSettings, SetUserOofSettingsResponse},
        schema::{ExternalAudience, OofState, ResponseCode},
        types::{
            availability::TimeWindow,
            oof::{ReplyBody, UserOofSettings},
            value::DateTime,
        },
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::borrow::Cow;
use store::write::now;
use types::type_state::DataType;

const NOT_OWNER: &str =
    "Microsoft.Exchange.Data.Storage.AccessDeniedException: User is not mailbox owner.";
const INVALID_DURATION: &str =
    "The scheduled duration end time must be after its start time and in the future.";
const MISSING_REPLY: &str = "The internal and external replies must be set unless OOF is disabled.";
const BUSY: &str = "The OOF settings changed while they were being saved; retry the request.";
const SCOPE_DENIED: &str = "The access token does not grant access to the OOF settings.";
const REPLY_TOO_LONG: &str = "The OOF reply exceeds the maximum length.";
const DEFAULT_WINDOW_SECONDS: u64 = 86_400;
const HOUR_SECONDS: u64 = 3_600;
const OPEN_END_SECONDS: u64 = 4_102_444_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OofError {
    InvalidDuration,
    MissingReply,
    ReplyTooLong,
}

impl OofError {
    fn status(self) -> Status<'static> {
        match self {
            OofError::InvalidDuration => Status::error(
                ResponseCode::ErrorInvalidScheduledOofDuration,
                INVALID_DURATION,
            ),
            OofError::MissingReply => {
                Status::error(ResponseCode::ErrorInvalidUserOofSettings, MISSING_REPLY)
            }
            OofError::ReplyTooLong => {
                Status::error(ResponseCode::ErrorInvalidUserOofSettings, REPLY_TOO_LONG)
            }
        }
    }
}

pub(crate) async fn get_user_oof_settings(
    server: &Server,
    ctx: &EwsContext,
    request: &GetUserOofSettings<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    if !owns_address(server, &request.mailbox.address, account_id).await? {
        return Ok(not_owner(ctx));
    }
    let (status, settings) = if ctx.account.data_types.contains(DataType::VacationResponse) {
        let settings = oof_settings(
            read_vacation(server, account_id, ReplyRead::Stored).await?,
            now(),
        );
        (Status::SUCCESS, Some(settings))
    } else {
        (scope_denied(), None)
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&GetUserOofSettingsResponse {
        status,
        settings,
        allow_external_oof: ExternalAudience::All,
    });
    Ok(ews_response(out))
}

pub(crate) async fn set_user_oof_settings(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &SetUserOofSettings<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    if !owns_address(server, &request.mailbox.address, account_id).await? {
        return Ok(not_owner(ctx));
    }
    let status = if !ctx.account.data_types.contains(DataType::VacationResponse) {
        scope_denied()
    } else {
        match vacation_edit(&request.user_oof_settings, now()) {
            Ok(edit) => {
                match write_vacation(server, account_id, caller.access_token, &edit).await? {
                    VacationWrite::Written => Status::SUCCESS,
                    VacationWrite::Busy => Status::error(ResponseCode::ErrorServerBusy, BUSY),
                }
            }
            Err(err) => err.status(),
        }
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out)
        .body(&SetUserOofSettingsResponse { status });
    Ok(ews_response(out))
}

fn oof_settings(vacation: Option<VacationView>, now: u64) -> OofSettings<'static> {
    let Some(vacation) = vacation else {
        return OofSettings {
            oof_state: OofState::Disabled,
            external_audience: ExternalAudience::All,
            duration: default_window(now),
            internal_reply: ReplyBody::default(),
            external_reply: ReplyBody::default(),
        };
    };
    let oof_state = match (vacation.active, vacation.from, vacation.to) {
        (false, ..) => OofState::Disabled,
        (true, None, None) => OofState::Enabled,
        (true, ..) => OofState::Scheduled,
    };
    let duration = match (vacation.from, vacation.to) {
        (Some(from), Some(to)) => window(from, to),
        (Some(from), None) => window(
            from,
            OPEN_END_SECONDS.max(from.saturating_add(DEFAULT_WINDOW_SECONDS)),
        ),
        (None, Some(to)) => window(
            hour_floor(now).min(to.saturating_sub(DEFAULT_WINDOW_SECONDS)),
            to,
        ),
        (None, None) => default_window(now),
    };
    let message = Cow::<str>::Owned(vacation.reply);
    OofSettings {
        oof_state,
        external_audience: ExternalAudience::All,
        duration,
        internal_reply: ReplyBody {
            message: Some(message.clone()),
            lang: None,
        },
        external_reply: ReplyBody {
            message: Some(message),
            lang: None,
        },
    }
}

fn vacation_edit<'x>(
    settings: &'x UserOofSettings<'_>,
    now: u64,
) -> Result<VacationEdit<'x>, OofError> {
    let state = match settings.oof_state {
        OofState::Disabled => VacationState::Disabled,
        OofState::Enabled => VacationState::Global,
        OofState::Scheduled => {
            let (from, to) = settings
                .duration
                .as_ref()
                .and_then(|duration| {
                    Some((seconds(&duration.start_time)?, seconds(&duration.end_time)?))
                })
                .ok_or(OofError::InvalidDuration)?;
            if from >= to || to <= now {
                return Err(OofError::InvalidDuration);
            }
            VacationState::TimeBased { from, to }
        }
    };
    let internal = reply_text(settings.internal_reply.as_ref());
    let external = reply_text(settings.external_reply.as_ref());
    if settings.oof_state != OofState::Disabled && (internal.is_none() || external.is_none()) {
        return Err(OofError::MissingReply);
    }
    let reply = internal.or(external).map(|body| {
        let mut reply = VacationReply::new(body, ReplyFormat::Text, ReplyOrigin::Sniffed);
        if reply.body.trim_start().starts_with('<') {
            reply.format = ReplyFormat::Html;
        }
        reply
    });
    if reply
        .as_ref()
        .is_some_and(|reply| reply.body.len() >= MAX_REPLY_LEN)
    {
        return Err(OofError::ReplyTooLong);
    }
    Ok(VacationEdit {
        state: Some(state),
        reply,
    })
}

fn reply_text<'x>(reply: Option<&'x ReplyBody<'_>>) -> Option<&'x str> {
    reply.map(|reply| reply.message.as_deref().unwrap_or_default())
}

fn seconds(time: &DateTime) -> Option<u64> {
    u64::try_from(time.to_utc()?.0).ok()
}

fn window(from: u64, to: u64) -> TimeWindow {
    TimeWindow {
        start_time: utc(from),
        end_time: utc(to),
    }
}

fn default_window(now: u64) -> TimeWindow {
    let start = hour_floor(now);
    window(start, start.saturating_add(DEFAULT_WINDOW_SECONDS))
}

fn hour_floor(seconds: u64) -> u64 {
    seconds - seconds % HOUR_SECONDS
}

fn scope_denied() -> Status<'static> {
    Status::error(ResponseCode::ErrorAccessDenied, SCOPE_DENIED)
}

fn utc(seconds: u64) -> DateTime {
    DateTime::utc(UtcSeconds(i64::try_from(seconds).unwrap_or(i64::MAX)))
}

fn not_owner(ctx: &EwsContext) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    write_fault(
        &mut out,
        &ctx.version,
        &Fault {
            code: ResponseCode::ErrorAccessDenied,
            text: Cow::Borrowed(NOT_OWNER),
            line: None,
            message_xml: None,
        },
    );
    ews_response(out).with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/ews/oof/tests.rs"]
mod tests;
