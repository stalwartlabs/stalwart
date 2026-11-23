/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use calcard::icalendar::{
    ICalendar, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
    ICalendarParticipationStatus, ICalendarProperty, ICalendarStatus, ICalendarValue,
};
use jiff::{Timestamp, civil::Date, tz::TimeZone};
use smallvec::smallvec;

use super::{
    attendees::{set_attendees, set_reply},
    patch::{self, ReminderMode, TimeTarget, clear_draft, target, timestamp},
    props::{
        CLEAN_GLOBAL_OBJECT_ID, EXCEPTION_REPLACE, GLOBAL_OBJECT_ID, INTENDED_BUSY_STATUS,
        INTENDED_STATUS_NAME, RESPONSE_STATUS, START_WHOLE, track_status,
    },
    series::Series,
};
use crate::{
    convert::{
        ConvertError,
        blob::GlobalObjectId,
        context::AddressResolver,
        model::{MessageContent, PropBag},
    },
    mapi::prop::OwnedPropValue,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingMessage {
    Request,
    Cancel,
    Accepted,
    Tentative,
    Declined,
}

impl MeetingMessage {
    pub fn of_class(class: &str) -> Option<Self> {
        hashify::map_ignore_case!(class.trim().as_bytes(), MeetingMessage,
            "IPM.Schedule.Meeting.Request" => MeetingMessage::Request,
            "IPM.Schedule.Meeting.Canceled" => MeetingMessage::Cancel,
            "IPM.Schedule.Meeting.Resp.Pos" => MeetingMessage::Accepted,
            "IPM.Schedule.Meeting.Resp.Tent" => MeetingMessage::Tentative,
            "IPM.Schedule.Meeting.Resp.Neg" => MeetingMessage::Declined,
        )
        .copied()
    }

    pub fn method(self) -> ICalendarMethod {
        match self {
            MeetingMessage::Request => ICalendarMethod::Request,
            MeetingMessage::Cancel => ICalendarMethod::Cancel,
            MeetingMessage::Accepted | MeetingMessage::Tentative | MeetingMessage::Declined => {
                ICalendarMethod::Reply
            }
        }
    }

    fn partstat(self) -> Option<ICalendarParticipationStatus> {
        match self {
            MeetingMessage::Accepted => Some(ICalendarParticipationStatus::Accepted),
            MeetingMessage::Tentative => Some(ICalendarParticipationStatus::Tentative),
            MeetingMessage::Declined => Some(ICalendarParticipationStatus::Declined),
            MeetingMessage::Request | MeetingMessage::Cancel => None,
        }
    }
}

pub(super) fn message_uid(props: &PropBag) -> Option<Cow<'_, str>> {
    [GLOBAL_OBJECT_ID, CLEAN_GLOBAL_OBJECT_ID]
        .into_iter()
        .find_map(|lid| match props.get_any(lid.prop()) {
            Some(OwnedPropValue::Binary(goid)) => GlobalObjectId::uid_of(goid),
            _ => None,
        })
}

pub(super) fn response_status(props: &PropBag) -> Option<ICalendarParticipationStatus> {
    match props.get_any(RESPONSE_STATUS.prop())? {
        OwnedPropValue::I32(track_status::TENTATIVE) => {
            Some(ICalendarParticipationStatus::Tentative)
        }
        OwnedPropValue::I32(track_status::ACCEPTED) => Some(ICalendarParticipationStatus::Accepted),
        OwnedPropValue::I32(track_status::DECLINED) => Some(ICalendarParticipationStatus::Declined),
        OwnedPropValue::I32(track_status::NOT_RESPONDED) => {
            Some(ICalendarParticipationStatus::NeedsAction)
        }
        _ => None,
    }
}

pub(super) fn instance_start(props: &PropBag) -> Result<Option<Timestamp>, ConvertError> {
    let Some(OwnedPropValue::Binary(goid)) = props.get_any(GLOBAL_OBJECT_ID.prop()) else {
        return Ok(None);
    };
    let Some((year, month, day)) = GlobalObjectId::decode(goid).and_then(|goid| goid.instance_date)
    else {
        return Ok(None);
    };
    if let Some(OwnedPropValue::Time(replace)) = props.get_any(EXCEPTION_REPLACE.prop()) {
        return Ok(Some(timestamp(*replace)));
    }
    let Some(OwnedPropValue::Time(start)) = props.get_any(START_WHOLE.prop()) else {
        return Err(ConvertError::Unsupported);
    };
    let time = timestamp(*start).to_zoned(TimeZone::UTC).time();
    i16::try_from(year)
        .ok()
        .zip(i8::try_from(month).ok())
        .zip(i8::try_from(day).ok())
        .and_then(|((year, month), day)| Date::new(year, month, day).ok())
        .and_then(|date| date.to_datetime(time).to_zoned(TimeZone::UTC).ok())
        .map(|zoned| Some(zoned.timestamp()))
        .ok_or(ConvertError::Unsupported)
}

fn set_recurrence_id(ical: &mut ICalendar, start: Timestamp) -> Result<(), ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let index = series.main;
    let entry = series
        .component(index)
        .and_then(|component| {
            let all_day = series.span(component)?.all_day;
            let dtstart = component.property(&ICalendarProperty::Dtstart)?;
            Some(TimeTarget::of_start(&series, dtstart).entry(
                ICalendarProperty::RecurrenceId,
                start,
                all_day,
            ))
        })
        .ok_or(ConvertError::Unsupported)?;
    drop(series);
    let component = ical
        .components
        .get_mut(index)
        .ok_or(ConvertError::Unsupported)?;
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::RecurrenceId
                | ICalendarProperty::Rrule
                | ICalendarProperty::Rdate
                | ICalendarProperty::Exdate
                | ICalendarProperty::Exrule
        )
    });
    component.entries.push(entry);
    Ok(())
}

pub(super) fn to_itip(
    ical: &mut ICalendar,
    message: MeetingMessage,
    content: &MessageContent,
    sender: &str,
    resolver: &dyn AddressResolver,
) -> Result<(), ConvertError> {
    let instance = instance_start(&content.props)?;
    if let Some(start) = instance {
        set_recurrence_id(ical, start)?;
    }
    patch::event(ical, None, &content.props, ReminderMode::Untracked)?;
    if let Some(start) = instance {
        set_recurrence_id(ical, start)?;
    }
    if message == MeetingMessage::Request
        && let Some(OwnedPropValue::I32(status)) =
            content.props.get_any(INTENDED_BUSY_STATUS.prop())
    {
        let index = target(ical, None)?;
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        patch::set_status_name(component, INTENDED_STATUS_NAME, *status);
    }
    match message.partstat() {
        Some(partstat) => set_reply(ical, &content.recipients, sender, partstat, resolver)?,
        None => set_attendees(ical, content, sender, resolver)?,
    }
    clear_draft(ical);
    if message == MeetingMessage::Cancel {
        let index = target(ical, None)?;
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::Status);
        component.entries.push(ICalendarEntry {
            name: ICalendarProperty::Status,
            params: Vec::new(),
            values: smallvec![ICalendarValue::Status(ICalendarStatus::Cancelled)],
        });
    }
    let calendar = ical
        .components
        .iter_mut()
        .find(|component| component.component_type == ICalendarComponentType::VCalendar)
        .ok_or(ConvertError::Unsupported)?;
    calendar
        .entries
        .retain(|entry| entry.name != ICalendarProperty::Method);
    calendar.entries.push(ICalendarEntry {
        name: ICalendarProperty::Method,
        params: Vec::new(),
        values: smallvec![ICalendarValue::Method(message.method())],
    });
    Ok(())
}
