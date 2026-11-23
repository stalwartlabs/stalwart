/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{EventEdit, ical_size};
use calcard::icalendar::ICalendarParticipationStatus;
use common::GroupwareResources;
use exchange_proto::convert::ical::{
    ParticipationError, RecurrenceId, force_reply, set_participation,
};
use groupware::calendar::write::{EventWriteError, EventWriter, ItipMode};
use store::write::now;
use trc::{EventType, StoreEvent};

const MAX_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingReply {
    Accept,
    Tentative,
    Decline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnchangedReply {
    Apply,
    Ignore,
}

#[derive(Debug, Clone, Copy)]
pub struct MeetingResponse {
    pub calendar_id: u32,
    pub document_id: u32,
    pub instance: Option<RecurrenceId>,
    pub reply: MeetingReply,
    pub itip: ItipMode,
    pub unchanged: UnchangedReply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingOutcome {
    Updated,
    Deleted,
}

#[derive(Debug)]
pub enum MeetingError {
    Participation(ParticipationError),
    TooLarge,
    Write(EventWriteError),
}

impl MeetingReply {
    pub(crate) fn status(self) -> ICalendarParticipationStatus {
        match self {
            MeetingReply::Accept => ICalendarParticipationStatus::Accepted,
            MeetingReply::Tentative => ICalendarParticipationStatus::Tentative,
            MeetingReply::Decline => ICalendarParticipationStatus::Declined,
        }
    }
}

pub fn uid_events<'x>(
    resources: &'x GroupwareResources,
    uid: &str,
) -> impl Iterator<Item = (u32, u32)> + 'x {
    resources
        .uid_matches(uid)
        .into_iter()
        .filter_map(|document_id| {
            let calendar_id = resources
                .item_by_id(document_id)?
                .child_names()
                .first()?
                .parent_id;
            Some((calendar_id, document_id))
        })
}

pub async fn respond_to_meeting(
    writer: &EventWriter<'_>,
    response: MeetingResponse,
) -> trc::Result<Result<MeetingOutcome, MeetingError>> {
    let Some(path) = writer
        .resources
        .format_resource_path_by_parent(response.document_id, response.calendar_id)
    else {
        return Ok(Err(MeetingError::Write(EventWriteError::NotFound)));
    };
    let mut attempt = 1;
    loop {
        match respond_once(writer, response, &path).await? {
            Err(MeetingError::Write(EventWriteError::Store(err)))
                if attempt < MAX_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        EventType::Store(StoreEvent::AssertValueFailed)
                    ) =>
            {
                attempt += 1;
            }
            Err(MeetingError::Write(EventWriteError::Store(err))) => return Err(err),
            outcome => return Ok(outcome),
        }
    }
}

async fn respond_once(
    writer: &EventWriter<'_>,
    response: MeetingResponse,
    path: &str,
) -> trc::Result<Result<MeetingOutcome, MeetingError>> {
    let MeetingResponse {
        calendar_id,
        document_id,
        instance,
        reply,
        itip,
        unchanged,
    } = response;
    let edit = match EventEdit::open(writer, calendar_id, document_id).await {
        Ok(edit) => edit,
        Err(err) => return Ok(Err(MeetingError::Write(err))),
    };
    let mut ical = edit.to_ical()?;
    let addresses = writer.account_info.addresses();
    let changed = match set_participation(&mut ical, addresses, instance, reply.status()) {
        Ok(changed) => changed,
        Err(err) => return Ok(Err(MeetingError::Participation(err))),
    };
    let changed = match unchanged {
        _ if changed => true,
        UnchangedReply::Ignore => return Ok(Ok(MeetingOutcome::Updated)),
        UnchangedReply::Apply => {
            writer.sends_itip(itip)
                && edit.event()?.inner.event_range_end() > now() as i64
                && force_reply(&mut ical, addresses, instance)
        }
    };
    let removes_series = reply == MeetingReply::Decline && instance.is_none();
    if changed && (!removes_series || itip.sends()) {
        if ical_size(writer.server, &ical).is_none() {
            return Ok(Err(MeetingError::TooLarge));
        }
        if let Err(err) = edit.commit(ical, itip).await {
            return Ok(Err(MeetingError::Write(err)));
        }
    }
    if !removes_series {
        return Ok(Ok(MeetingOutcome::Updated));
    }
    let deleted = match writer.prepare_delete(calendar_id, document_id).await {
        Ok(deletion) => {
            writer
                .delete(deletion, None, ItipMode::Suppress, Some(path.to_string()))
                .await
        }
        Err(err) => Err(err),
    };
    match deleted {
        Ok(()) => Ok(Ok(MeetingOutcome::Deleted)),
        Err(err) => Ok(Err(MeetingError::Write(err))),
    }
}
