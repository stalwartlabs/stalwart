/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::timezone::ZonedDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty, ICalendarStatus,
        ICalendarValue,
    },
};
use jiff::{Timestamp, tz::TimeZone};

use super::{
    CLASS_TASK, DEFERRED, PERCENT_COMPLETE, PERCENT_DONE, STATUS_EXTENSION, TASK_BLOB_CAPACITY,
    TASK_COMPLETE, TASK_DATE_COMPLETED, TASK_DEAD_OCCURRENCE, TASK_DUE_DATE, TASK_F_RECURRING,
    TASK_RECURRENCE, TASK_START_DATE, TASK_STATUS, WAITING, due_of, mapped_recurrence, status,
    task_anchor,
};
use crate::{
    convert::{
        ConvertError,
        ical::{
            props::{
                COMMON_END, COMMON_START, Lid, MAX_SUBJECT_CHARS, REMINDER_SET,
                REMINDER_SIGNAL_TIME, REMINDER_TIME,
            },
            series::{Series, Span},
            to_message::{
                alarm_fire, file_time, first_text, importance, keywords, other_text, sensitivity,
                truncate_chars,
            },
        },
        model::{MessageContent, PropBag},
        tags::{self, KEYWORDS_NAME},
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey, sets::PS_PUBLIC_STRINGS},
};

pub(crate) fn task(ical: &ICalendar) -> Result<MessageContent, ConvertError> {
    let series =
        Series::of(ical, ICalendarComponentType::VTodo).ok_or(ConvertError::Unsupported)?;
    let main = series
        .component(series.main)
        .ok_or(ConvertError::Unsupported)?;
    let mut content = MessageContent::default();
    let bag = &mut content.props;
    text(bag, tags::MESSAGE_CLASS, CLASS_TASK);
    if let Some(subject) = first_text(main, &ICalendarProperty::Summary) {
        let subject = truncate_chars(subject, MAX_SUBJECT_CHARS);
        text(bag, tags::SUBJECT, subject);
        text(bag, tags::NORMALIZED_SUBJECT, subject);
    }
    if let Some(body) = first_text(main, &ICalendarProperty::Description) {
        text(bag, tags::BODY, body);
    }
    if let Some(level) = main
        .property(&ICalendarProperty::Class)
        .and_then(|entry| entry.values.first())
        .map(sensitivity)
    {
        bag.set(PropKey::tag(tags::SENSITIVITY), OwnedPropValue::I32(level));
    }
    if let Some(level) = importance(main) {
        bag.set(PropKey::tag(tags::IMPORTANCE), OwnedPropValue::I32(level));
    }
    let keywords = keywords(main);
    if !keywords.is_empty() {
        bag.set(
            PropKey::name(PS_PUBLIC_STRINGS, KEYWORDS_NAME),
            OwnedPropValue::MvUnicode(keywords.into_boxed_slice()),
        );
    }
    let resolve = |property: &ICalendarProperty| {
        main.property(property)
            .and_then(|entry| series.resolve_first(entry))
    };
    let start = resolve(&ICalendarProperty::Dtstart);
    let due = due_of(&series, main);
    if let Some(start) = start {
        date_pair(bag, TASK_START_DATE, COMMON_START, start);
    }
    if let Some(due) = due {
        date_pair(bag, TASK_DUE_DATE, COMMON_END, due);
    }
    let fire = start
        .or(due)
        .or_else(|| resolve(&ICalendarProperty::Dtstamp))
        .and_then(|anchor| {
            alarm_fire(
                &series,
                series.main,
                &Span {
                    start: start.unwrap_or(anchor),
                    end: due.unwrap_or(anchor),
                    all_day: false,
                },
            )
        });
    bag.set(REMINDER_SET.key(), OwnedPropValue::Bool(fire.is_some()));
    if let Some(fire) = fire {
        for lid in [REMINDER_TIME, REMINDER_SIGNAL_TIME] {
            bag.set(lid.key(), OwnedPropValue::Time(file_time(fire)));
        }
    }
    let completed = resolve(&ICalendarProperty::Completed);
    let percent = main
        .property(&ICalendarProperty::PercentComplete)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_integer);
    let status = task_status(main, completed.is_some(), percent);
    let percent = match status {
        status::COMPLETE => PERCENT_DONE,
        status::NOT_STARTED => 0,
        _ => percent.unwrap_or_default().clamp(0, PERCENT_DONE),
    };
    bag.set(TASK_STATUS.key(), OwnedPropValue::I32(status));
    bag.set(
        PERCENT_COMPLETE.key(),
        OwnedPropValue::F64(percent as f64 / PERCENT_DONE as f64),
    );
    bag.set(
        TASK_COMPLETE.key(),
        OwnedPropValue::Bool(status == status::COMPLETE),
    );
    let date_completed = (status == status::COMPLETE)
        .then(|| {
            completed.or_else(|| {
                [ICalendarProperty::LastModified, ICalendarProperty::Dtstamp]
                    .iter()
                    .find_map(&resolve)
            })
        })
        .flatten();
    if let Some(completed) = date_completed {
        bag.set(
            TASK_DATE_COMPLETED.key(),
            OwnedPropValue::Time(file_time(completed.to_timestamp())),
        );
    }
    let recurrence = mapped_recurrence(&series, main);
    bag.set(
        TASK_F_RECURRING.key(),
        OwnedPropValue::Bool(recurrence.is_some()),
    );
    if let Some(recurrence) = recurrence {
        let mut blob = Vec::with_capacity(TASK_BLOB_CAPACITY);
        recurrence.encode(&mut blob);
        bag.set(TASK_RECURRENCE.key(), OwnedPropValue::Binary(blob.into()));
        let dead = status == status::COMPLETE
            || task_anchor(&series, main).is_none_or(|anchor| anchor.is_last(&series, main));
        bag.set(TASK_DEAD_OCCURRENCE.key(), OwnedPropValue::Bool(dead));
    }
    Ok(content)
}

pub(super) fn task_status(main: &ICalendarComponent, completed: bool, percent: Option<i64>) -> i32 {
    let extension = other_text(main, STATUS_EXTENSION);
    let marked = |name: &str| extension.is_some_and(|text| text.eq_ignore_ascii_case(name));
    match main.status() {
        Some(ICalendarStatus::Completed) => status::COMPLETE,
        _ if completed || percent == Some(PERCENT_DONE) => status::COMPLETE,
        Some(ICalendarStatus::Cancelled) => status::DEFERRED,
        Some(ICalendarStatus::InProcess) if marked(WAITING) => status::WAITING_ON_OTHERS,
        Some(ICalendarStatus::NeedsAction) if marked(DEFERRED) => status::DEFERRED,
        Some(ICalendarStatus::InProcess) => status::IN_PROGRESS,
        _ if percent.is_some_and(|percent| percent > 0) => status::IN_PROGRESS,
        _ => status::NOT_STARTED,
    }
}

fn date_pair(bag: &mut PropBag, local: Lid, utc: Lid, value: ZonedDateTime) {
    if let Some(midnight) = local_midnight(value) {
        bag.set(local.key(), OwnedPropValue::Time(file_time(midnight)));
    }
    bag.set(
        utc.key(),
        OwnedPropValue::Time(file_time(value.to_timestamp())),
    );
}

fn local_midnight(value: ZonedDateTime) -> Option<Timestamp> {
    value
        .naive_local()
        .date()
        .to_zoned_datetime(TimeZone::UTC)
        .ok()
        .map(|zoned| zoned.timestamp())
}

fn text(bag: &mut PropBag, id: PropId, value: &str) {
    bag.set(PropKey::tag(id), OwnedPropValue::Unicode(value.into()));
}
