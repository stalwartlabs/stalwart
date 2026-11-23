/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use calcard::icalendar::{ICalendar, ICalendarComponent, ICalendarProperty};

use super::{Render, render_event, utc};
use crate::{
    common::{
        base64::{Base64Text, base64_encode_into},
        time::EasDateForm,
    },
    convert::{
        blob::GlobalObjectId,
        ical::{
            meeting::requests_response,
            series::{Series, sequence},
        },
    },
    eas::{
        commands::appdata::{List, MeetingRecurrence, MeetingRequest, Recurrence, base::Location},
        tokens::ProtocolVersion,
        types::EasDateTime,
    },
};

const SECONDS_PER_MINUTE: u32 = 60;
const ORGANIZER_PUNCTUATION_LEN: usize = 5;
mod instance_type {
    pub const SINGLE: u8 = 0;
    pub const MASTER: u8 = 1;
    pub const EXCEPTION: u8 = 3;
}

mod message_type {
    pub const UNSPECIFIED: u8 = 0;
    pub const INITIAL: u8 = 1;
    pub const FULL_UPDATE: u8 = 2;
    pub const INFORMATIONAL_UPDATE: u8 = 3;
    pub const OUTDATED: u8 = 4;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingKind {
    Request,
    Cancellation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeetingHistory {
    #[default]
    Current,
    Initial,
    Updated,
    Informational,
    Outdated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MeetingRevision {
    pub sequence: i32,
    pub stamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeetingVersion<'x> {
    pub uid: &'x str,
    pub revision: MeetingRevision,
}

pub fn meeting_version(ical: &ICalendar) -> Option<MeetingVersion<'_>> {
    let series = Series::new(ical)?;
    let main = series.component(series.main)?;
    if series.recurrence_id(main).is_some() {
        return None;
    }
    Some(MeetingVersion {
        uid: series.uid()?,
        revision: MeetingRevision {
            sequence: i32::try_from(sequence(main).max(0)).unwrap_or(i32::MAX),
            stamp: main
                .property(&ICalendarProperty::Dtstamp)
                .and_then(|entry| series.resolve_first(entry))
                .map_or(0, |stamp| stamp.to_timestamp().as_second()),
        },
    })
}

pub fn meeting_request_to_eas(
    ical: &ICalendar,
    kind: MeetingKind,
    history: MeetingHistory,
    version: ProtocolVersion,
) -> Option<MeetingRequest<'static>> {
    let series = Series::new(ical)?;
    let main = series.component(series.main)?;
    let calendar = render_event(ical, &[], version, Render::Meeting)?.calendar;
    let recurrence_id = series.recurrence_id(main).map(|id| utc(id.0));
    let instance_type = match (&calendar.recurrence, recurrence_id) {
        (Some(_), _) => instance_type::MASTER,
        (None, Some(_)) => instance_type::EXCEPTION,
        (None, None) => instance_type::SINGLE,
    };
    let organizer = calendar.organizer_email.as_deref().map(|email| {
        let name = calendar.organizer_name.as_deref();
        let mut out = String::with_capacity(
            email
                .len()
                .saturating_add(name.map_or(0, str::len))
                .saturating_add(ORGANIZER_PUNCTUATION_LEN),
        );
        match name {
            Some(name) => {
                out.push('"');
                out.extend(name.chars().filter(|ch| !matches!(ch, '"' | '\\')));
                out.push_str("\" <");
                out.push_str(email);
                out.push('>');
            }
            None => out.push_str(email),
        }
        Cow::Owned(out)
    });
    let response_requested = requests_response(main);
    let sequence = sequence(main);
    let legacy = version < ProtocolVersion::V160;
    let uid = calendar.uid.as_deref();
    let location = calendar
        .location
        .map(|location| Cow::Owned(location.into_owned()));
    let (location, location_details) = if legacy {
        (location, None)
    } else {
        (
            None,
            Some(Location {
                display_name: location,
                ..Default::default()
            }),
        )
    };
    let instance_date = if instance_type == instance_type::EXCEPTION {
        instance_date(&series, main)
    } else {
        None
    };
    Some(MeetingRequest {
        all_day_event: calendar.all_day_event,
        start_time: calendar.start_time.map(|time| time.0),
        dt_stamp: calendar.dt_stamp.map(|time| time.0),
        end_time: calendar.end_time.map(|time| time.0),
        instance_type: Some(instance_type),
        location,
        location_details,
        organizer,
        recurrence_id,
        reminder: calendar
            .reminder
            .and_then(|reminder| reminder.0)
            .map(|minutes| minutes.saturating_mul(SECONDS_PER_MINUTE)),
        response_requested: Some(u8::from(response_requested)),
        recurrences: calendar
            .recurrence
            .as_ref()
            .map(|recurrence| List(vec![meeting_recurrence(recurrence)])),
        sensitivity: calendar.sensitivity,
        busy_status: calendar.busy_status,
        disallow_new_time_proposal: calendar.disallow_new_time_proposal.map(u8::from),
        time_zone: calendar
            .timezone
            .map(|zone| Base64Text(Cow::Owned(zone.0.into_owned()))),
        global_obj_id: uid
            .filter(|_| legacy)
            .map(|uid| global_obj_id(uid, instance_date)),
        meeting_message_type: (version >= ProtocolVersion::V141).then_some(match kind {
            MeetingKind::Cancellation => message_type::UNSPECIFIED,
            MeetingKind::Request => match history {
                MeetingHistory::Outdated => message_type::OUTDATED,
                MeetingHistory::Updated => message_type::FULL_UPDATE,
                MeetingHistory::Informational => message_type::INFORMATIONAL_UPDATE,
                MeetingHistory::Current if sequence > 0 => message_type::FULL_UPDATE,
                MeetingHistory::Current | MeetingHistory::Initial => message_type::INITIAL,
            },
        }),
        uid: uid
            .filter(|_| !legacy)
            .map(|uid| Cow::Owned(uid.to_string())),
        ..Default::default()
    })
}

fn instance_date(series: &Series<'_>, component: &ICalendarComponent) -> Option<(u16, u8, u8)> {
    let local = series
        .resolve_first(component.property(&ICalendarProperty::RecurrenceId)?)?
        .naive_local();
    Some((
        u16::try_from(local.year()).ok()?,
        u8::try_from(local.month()).ok()?,
        u8::try_from(local.day()).ok()?,
    ))
}

fn meeting_recurrence(recurrence: &Recurrence) -> MeetingRecurrence<'static> {
    MeetingRecurrence {
        recurrence_type: recurrence.recurrence_type,
        interval: recurrence.interval.map(u32::from),
        until: recurrence.until.map(|until| compact_text(until.0)),
        occurrences: recurrence.occurrences.map(u32::from),
        week_of_month: recurrence.week_of_month.map(u32::from),
        day_of_month: recurrence.day_of_month.map(u32::from),
        day_of_week: recurrence.day_of_week.map(u32::from),
        month_of_year: recurrence.month_of_year.map(u32::from),
        calendar_type: recurrence.calendar_type,
        is_leap_month: recurrence.is_leap_month,
        first_day_of_week: recurrence.first_day_of_week,
    }
}

fn compact_text(time: EasDateTime) -> Cow<'static, str> {
    let mut out = Vec::new();
    time.write(&mut out, EasDateForm::Compact);
    String::from_utf8(out).map(Cow::Owned).unwrap_or_default()
}

fn global_obj_id(uid: &str, instance_date: Option<(u16, u8, u8)>) -> Cow<'static, str> {
    let mut goid = GlobalObjectId::from_uid(uid);
    if goid.instance_date.is_none() {
        goid.instance_date = instance_date;
    }
    let mut raw = Vec::with_capacity(goid.encoded_len());
    goid.encode(&mut raw);
    let mut out = Vec::new();
    base64_encode_into(&raw, &mut out);
    String::from_utf8(out).map(Cow::Owned).unwrap_or_default()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/eas/meeting/tests.rs"]
mod tests;
