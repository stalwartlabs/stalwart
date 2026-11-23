/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use calcard::{
    common::timezone::ZonedDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarRecurrenceRule, ICalendarStatus,
        ICalendarUserTypes, ICalendarValue,
    },
};
use jiff::{Timestamp, tz::TimeZone};

use super::{
    RecurrenceId,
    alarm::{AlarmState, current_state},
    series::{Series, Span},
    task::task_anchor,
    to_message::{
        address, alarm_fire, disallows_counter, first_text, importance, keywords,
        ranged_busy_status, reminder, sensitivity, tz_definition,
    },
};
use crate::{
    common::{base64::Base64Text, time::UtcSeconds},
    convert::blob::{
        PatternType, RecurEnd, RecurFrequency, RecurrencePattern, RuleCount, TaskRecur,
        local_from_minutes, local_minutes,
    },
    eas::{
        commands::appdata::{
            Attendee, Calendar, CalendarException, Compact, List, MAX_LIST_ITEMS, OrEmpty,
            Recurrence, Task, TaskRecurrence, base::Location,
        },
        tokens::ProtocolVersion,
        types::{EasDateTime, TimeZoneInformation},
    },
};

mod event;
mod meeting;
mod recur;
mod todo;

pub use event::{
    EventChange, EventUpdate, event_change_from_eas, event_from_eas, occurrence_change_from_eas,
    occurrence_delete_from_eas,
};
pub use meeting::{
    MeetingHistory, MeetingKind, MeetingRevision, MeetingVersion, meeting_request_to_eas,
    meeting_version,
};
pub use todo::{TaskUpdate, TaskWrite, todo_from_eas};
pub(super) use todo::{is_display_alarm, set_reminder};

const MINUTES_PER_DAY: u32 = 1440;
const MONTHS_PER_YEAR: u32 = 12;

mod meeting_status {
    pub const APPOINTMENT: u8 = 0;
    pub const ORGANIZER: u8 = 1;
    pub const RECEIVED: u8 = 3;
    pub const ORGANIZER_CANCELED: u8 = 5;
    pub const RECEIVED_CANCELED: u8 = 7;
    pub const CANCELED_FLAG: u8 = 4;
}

mod response {
    pub const NONE: u32 = 0;
    pub const ORGANIZER: u32 = 1;
    pub const TENTATIVE: u32 = 2;
    pub const ACCEPTED: u32 = 3;
    pub const DECLINED: u32 = 4;
    pub const NOT_RESPONDED: u32 = 5;
}

const NORMAL_SENSITIVITY: u8 = 0;

mod attendee_status {
    pub const UNKNOWN: u8 = 0;
    pub const TENTATIVE: u8 = 2;
    pub const ACCEPTED: u8 = 3;
    pub const DECLINED: u8 = 4;
    pub const NOT_RESPONDED: u8 = 5;
}

mod attendee_type {
    pub const REQUIRED: u8 = 1;
    pub const OPTIONAL: u8 = 2;
    pub const RESOURCE: u8 = 3;
}

mod recurrence_type {
    pub const DAILY: u8 = 0;
    pub const WEEKLY: u8 = 1;
    pub const MONTHLY: u8 = 2;
    pub const MONTHLY_NTH: u8 = 3;
    pub const YEARLY: u8 = 5;
    pub const YEARLY_NTH: u8 = 6;
}

mod calendar_type {
    pub const DEFAULT: u8 = 0;
    pub const GREGORIAN: u8 = 1;
}

const LAST_DAY_OF_MONTH: u8 = 31;
const NOT_LEAP_MONTH: u8 = 0;

pub struct EasEvent<'c> {
    pub calendar: Calendar<'c>,
    pub description: Option<&'c str>,
    pub exception_bodies: Vec<(usize, &'c str)>,
}

pub struct EasTask<'c> {
    pub task: Task<'c>,
    pub description: Option<&'c str>,
}

pub fn is_event_convertible(ical: &ICalendar) -> bool {
    event_parts(ical).is_some()
}

pub fn is_todo_convertible(ical: &ICalendar) -> bool {
    todo_parts(ical).is_some()
}

pub fn is_todo_complete(ical: &ICalendar) -> bool {
    todo_parts(ical).is_some_and(|(series, main)| {
        is_marked_complete(main)
            || main
                .property(&ICalendarProperty::Completed)
                .and_then(|entry| series.resolve_first(entry))
                .is_some()
    })
}

fn is_marked_complete(main: &ICalendarComponent) -> bool {
    matches!(main.status(), Some(ICalendarStatus::Completed))
        || main
            .property(&ICalendarProperty::PercentComplete)
            .and_then(|entry| entry.values.first())
            .and_then(ICalendarValue::as_integer)
            == Some(100)
}

fn event_parts(ical: &ICalendar) -> Option<(Series<'_>, &ICalendarComponent, Span)> {
    let series = Series::new(ical)?;
    let main = series.component(series.main)?;
    let span = series.span(main)?;
    Some((series, main, span))
}

fn todo_parts(ical: &ICalendar) -> Option<(Series<'_>, &ICalendarComponent)> {
    let series = Series::of(ical, ICalendarComponentType::VTodo)?;
    let main = series.component(series.main)?;
    Some((series, main))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Render {
    Full,
    Fields,
    Meeting,
}

pub fn event_to_eas<'c>(
    ical: &'c ICalendar,
    own_addresses: &[String],
    version: ProtocolVersion,
) -> Option<EasEvent<'c>> {
    render_event(ical, own_addresses, version, Render::Full)
}

fn render_event<'c>(
    ical: &'c ICalendar,
    own_addresses: &[String],
    version: ProtocolVersion,
    render: Render,
) -> Option<EasEvent<'c>> {
    let (series, main, span) = event_parts(ical)?;
    let is_own = |address: &str| {
        own_addresses
            .iter()
            .any(|own| own.eq_ignore_ascii_case(address))
    };

    let mut calendar = component_calendar(&series, series.main, main, &span, version);
    if render == Render::Full {
        calendar.sensitivity.get_or_insert(NORMAL_SENSITIVITY);
    }
    if render == Render::Meeting
        || (render == Render::Full && !(span.all_day && version >= ProtocolVersion::V160))
    {
        calendar.timezone = Some(time_zone(&series, &span));
    }
    calendar.dt_stamp = main
        .property(&ICalendarProperty::Dtstamp)
        .and_then(|entry| series.resolve_first(entry))
        .map(|zoned| compact(zoned.to_timestamp()))
        .or_else(|| Some(compact(span.start.to_timestamp())));
    calendar.uid = series.uid().map(Cow::Borrowed);

    let organizer = main
        .property(&ICalendarProperty::Organizer)
        .and_then(|entry| Some((entry, address(entry)?)));
    let is_organizer = organizer.is_none_or(|(_, smtp)| is_own(smtp));
    if let Some((entry, smtp)) = organizer {
        calendar.organizer_email = Some(Cow::Borrowed(smtp));
        calendar.organizer_name = common_name(entry).map(Cow::Borrowed);
    }
    let mut attendees = Vec::new();
    let mut has_attendees = false;
    let mut own_status = None;
    let mut rsvp = false;
    for entry in main.properties(&ICalendarProperty::Attendee) {
        let Some(smtp) = address(entry) else {
            continue;
        };
        has_attendees = true;
        if render != Render::Full {
            break;
        }
        let attendee = attendee(entry, smtp);
        let requested = entry.params.iter().any(|param| {
            param.name == ICalendarParameterName::Rsvp
                && matches!(param.value, ICalendarParameterValue::Bool(true))
        });
        let own = is_own(smtp);
        if own {
            own_status = attendee.attendee_status;
        }
        if own != is_organizer {
            rsvp |= requested;
        }
        if attendees.len() < MAX_LIST_ITEMS {
            attendees.push(attendee);
        }
    }
    let canceled = matches!(main.status(), Some(ICalendarStatus::Cancelled));
    calendar.meeting_status = Some(match (has_attendees, is_organizer, canceled) {
        (false, _, _) => meeting_status::APPOINTMENT,
        (true, true, false) => meeting_status::ORGANIZER,
        (true, true, true) => meeting_status::ORGANIZER_CANCELED,
        (true, false, false) => meeting_status::RECEIVED,
        (true, false, true) => meeting_status::RECEIVED_CANCELED,
    });
    if !attendees.is_empty() {
        calendar.response_type = Some(if is_organizer {
            response::ORGANIZER
        } else {
            match own_status {
                Some(attendee_status::TENTATIVE) => response::TENTATIVE,
                Some(attendee_status::ACCEPTED) => response::ACCEPTED,
                Some(attendee_status::DECLINED) => response::DECLINED,
                Some(attendee_status::NOT_RESPONDED) => response::NOT_RESPONDED,
                _ => response::NONE,
            }
        });
        calendar.response_requested = Some(rsvp);
        calendar.attendees = Some(List(attendees));
    }

    let mut exception_bodies = Vec::new();
    if let Some(master) = series.master.and_then(|index| series.component(index))
        && let Some((rendered, first)) = recurrence(&series, master, &span)
    {
        calendar.recurrence = Some(rendered);
        if render == Render::Full {
            let (exceptions, bodies) = exceptions(&series, main, version, first);
            if !exceptions.is_empty() {
                calendar.exceptions = Some(List(exceptions));
                exception_bodies = bodies;
            }
        }
    }

    Some(EasEvent {
        calendar,
        description: first_text(main, &ICalendarProperty::Description),
        exception_bodies,
    })
}

fn component_calendar<'c>(
    series: &Series<'c>,
    index: usize,
    component: &'c ICalendarComponent,
    span: &Span,
    version: ProtocolVersion,
) -> Calendar<'c> {
    let (start, end) = if span.all_day && version >= ProtocolVersion::V160 {
        (local_as_utc(span.start), local_as_utc(span.end))
    } else {
        (utc(span.start.to_timestamp()), utc(span.end.to_timestamp()))
    };
    let location = first_text(component, &ICalendarProperty::Location);
    Calendar {
        all_day_event: Some(u8::from(span.all_day)),
        busy_status: Some(narrow(ranged_busy_status(component))),
        disallow_new_time_proposal: disallows_counter(component).then_some(true),
        start_time: Some(Compact(start)),
        end_time: Some(Compact(end)),
        subject: first_text(component, &ICalendarProperty::Summary).map(Cow::Borrowed),
        location: location.map(Cow::Borrowed),
        location_details: Some(location.map(location_details).unwrap_or_default()),
        sensitivity: component
            .property(&ICalendarProperty::Class)
            .and_then(|entry| entry.values.first())
            .map(|value| narrow(sensitivity(value))),
        reminder: reminder(series, index, span)
            .filter(|_| current_state(series, index, span) != Some(AlarmState::Dismissed))
            .map(|minutes| OrEmpty(Some(minutes))),
        categories: categories(component),
        ..Default::default()
    }
}

pub fn todo_to_eas(ical: &ICalendar) -> Option<EasTask<'_>> {
    let (series, main) = todo_parts(ical)?;
    let start = main
        .property(&ICalendarProperty::Dtstart)
        .and_then(|entry| series.resolve_first(entry));
    let due = main
        .property(&ICalendarProperty::Due)
        .and_then(|entry| series.resolve_first(entry))
        .or_else(|| {
            series
                .span(main)
                .filter(|_| start.is_some())
                .map(|span| span.end)
        });
    let completed = main
        .property(&ICalendarProperty::Completed)
        .and_then(|entry| series.resolve_first(entry));
    let complete = completed.is_some() || is_marked_complete(main);

    let mut task = Task {
        subject: first_text(main, &ICalendarProperty::Summary).map(Cow::Borrowed),
        complete: Some(complete),
        date_completed: complete
            .then(|| {
                completed.or_else(|| {
                    [ICalendarProperty::LastModified, ICalendarProperty::Dtstamp]
                        .iter()
                        .find_map(|property| series.resolve_first(main.property(property)?))
                })
            })
            .flatten()
            .map(|zoned| utc(zoned.to_timestamp())),
        start_date: start.map(local_as_utc),
        utc_start_date: start.map(|zoned| utc(zoned.to_timestamp())),
        due_date: due.map(local_as_utc),
        utc_due_date: due.map(|zoned| utc(zoned.to_timestamp())),
        importance: Some(importance(main).map_or(1, narrow)),
        sensitivity: Some(
            main.property(&ICalendarProperty::Class)
                .and_then(|entry| entry.values.first())
                .map_or(0, |value| narrow(sensitivity(value))),
        ),
        categories: categories(main),
        reminder_set: Some(false),
        ..Default::default()
    };
    task.recurrence = series
        .master
        .and_then(|index| series.component(index))
        .and_then(|master| {
            let start = series.span(master).map(|span| span.start).or(due)?;
            let rule = first_rule(master)?;
            let anchor = task_anchor(&series, master)?;
            let recur = TaskRecur::from_rrule(rule, anchor).ok()?;
            let pattern = pattern_recurrence(&series, master, rule, recur.pattern())?;
            Some(TaskRecurrence {
                recurrence_type: pattern.recurrence_type,
                start: Some(utc(start.to_timestamp())),
                until: pattern.until.map(|until| until.0),
                occurrences: pattern.occurrences,
                interval: pattern.interval,
                day_of_month: pattern.day_of_month,
                day_of_week: pattern.day_of_week,
                week_of_month: pattern.week_of_month,
                month_of_year: pattern.month_of_year,
                regenerate: Some(false),
                dead_occur: Some(complete || anchor.is_last(&series, master)),
                calendar_type: pattern.calendar_type,
                is_leap_month: pattern.is_leap_month,
                first_day_of_week: pattern.first_day_of_week,
            })
        });
    if let Some((start, end)) = start.or(due).zip(due.or(start))
        && let Some(fire) = alarm_fire(
            &series,
            series.main,
            &Span {
                start,
                end,
                all_day: false,
            },
        )
    {
        task.reminder_set = Some(true);
        task.reminder_time = Some(utc(fire));
    }
    Some(EasTask {
        task,
        description: first_text(main, &ICalendarProperty::Description),
    })
}

fn time_zone(series: &Series<'_>, span: &Span) -> Base64Text<'static> {
    let year = span.start.naive_local().year();
    let definition = tz_definition(series.tz, year..=year);
    let mut info = TimeZoneInformation::default();
    if let Some(rule) = definition.effective() {
        info.bias = rule.bias;
        info.standard_bias = rule.standard_bias;
        info.daylight_bias = rule.daylight_bias;
        info.standard_date = rule.standard_date;
        info.daylight_date = rule.daylight_date;
    }
    info.set_names(&definition.key_name, &definition.key_name);
    let mut encoded = Vec::with_capacity(TimeZoneInformation::WIRE_LEN.div_ceil(3) * 4);
    info.encode_base64(&mut encoded);
    Base64Text(Cow::Owned(encoded))
}

fn attendee<'c>(entry: &'c ICalendarEntry, smtp: &'c str) -> Attendee<'c> {
    let mut kind = attendee_type::REQUIRED;
    let mut status = attendee_status::NOT_RESPONDED;
    for param in &entry.params {
        match &param.value {
            ICalendarParameterValue::Role(
                ICalendarParticipationRole::OptParticipant
                | ICalendarParticipationRole::NonParticipant,
            ) if kind != attendee_type::RESOURCE => kind = attendee_type::OPTIONAL,
            ICalendarParameterValue::Cutype(
                ICalendarUserTypes::Resource | ICalendarUserTypes::Room,
            ) => kind = attendee_type::RESOURCE,
            ICalendarParameterValue::Partstat(partstat) => {
                status = match partstat {
                    ICalendarParticipationStatus::Tentative => attendee_status::TENTATIVE,
                    ICalendarParticipationStatus::Accepted => attendee_status::ACCEPTED,
                    ICalendarParticipationStatus::Declined => attendee_status::DECLINED,
                    ICalendarParticipationStatus::NeedsAction => attendee_status::NOT_RESPONDED,
                    _ => attendee_status::UNKNOWN,
                }
            }
            _ => {}
        }
    }
    Attendee {
        email: Some(Cow::Borrowed(smtp)),
        name: Some(Cow::Borrowed(common_name(entry).unwrap_or(smtp))),
        attendee_status: Some(status),
        attendee_type: Some(kind),
        ..Default::default()
    }
}

fn common_name(entry: &ICalendarEntry) -> Option<&str> {
    entry
        .parameter(&ICalendarParameterName::Cn)
        .and_then(ICalendarParameterValue::as_text)
        .filter(|name| !name.is_empty())
}

fn recurrence(
    series: &Series<'_>,
    master: &ICalendarComponent,
    span: &Span,
) -> Option<(Recurrence, u32)> {
    let rule = first_rule(master)?;
    let pattern = RecurrencePattern::from_rrule(
        rule,
        span.start.naive_local(),
        series.tz,
        RuleCount::Dtstart,
    )
    .ok()?;
    pattern_recurrence(series, master, rule, &pattern)
        .map(|recurrence| (recurrence, pattern.start_date))
}

fn first_rule(master: &ICalendarComponent) -> Option<&ICalendarRecurrenceRule> {
    master
        .property(&ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => Some(rule.as_ref()),
            _ => None,
        })
}

fn takes_calendar_type(recurrence_type: Option<u8>) -> bool {
    matches!(
        recurrence_type,
        Some(
            recurrence_type::MONTHLY
                | recurrence_type::MONTHLY_NTH
                | recurrence_type::YEARLY
                | recurrence_type::YEARLY_NTH
        )
    )
}

fn pattern_recurrence(
    series: &Series<'_>,
    master: &ICalendarComponent,
    rule: &ICalendarRecurrenceRule,
    pattern: &RecurrencePattern,
) -> Option<Recurrence> {
    let mut recurrence = Recurrence {
        first_day_of_week: u8::try_from(pattern.first_dow).ok(),
        ..Default::default()
    };
    let period = |unit: u32| u16::try_from((pattern.period / unit).max(1)).ok();
    let month =
        local_from_minutes(pattern.start_date).and_then(|start| u8::try_from(start.month()).ok());
    match (pattern.frequency, pattern.pattern) {
        (RecurFrequency::Daily, PatternType::Day) => {
            recurrence.recurrence_type = Some(recurrence_type::DAILY);
            recurrence.interval = period(MINUTES_PER_DAY);
        }
        (RecurFrequency::Daily | RecurFrequency::Weekly, PatternType::Week { days }) => {
            recurrence.recurrence_type = Some(recurrence_type::WEEKLY);
            recurrence.interval = if pattern.frequency == RecurFrequency::Daily {
                Some(1)
            } else {
                period(1)
            };
            recurrence.day_of_week = u16::try_from(days).ok();
        }
        (RecurFrequency::Monthly, PatternType::Month { day }) => {
            recurrence.recurrence_type = Some(recurrence_type::MONTHLY);
            recurrence.interval = period(1);
            recurrence.day_of_month = u8::try_from(day).ok();
        }
        (RecurFrequency::Monthly, PatternType::MonthEnd { .. }) => {
            recurrence.recurrence_type = Some(recurrence_type::MONTHLY);
            recurrence.interval = period(1);
            recurrence.day_of_month = Some(LAST_DAY_OF_MONTH);
        }
        (RecurFrequency::Monthly, PatternType::MonthNth { days, n }) => {
            recurrence.recurrence_type = Some(recurrence_type::MONTHLY_NTH);
            recurrence.interval = period(1);
            recurrence.day_of_week = u16::try_from(days).ok();
            recurrence.week_of_month = u8::try_from(n).ok();
        }
        (RecurFrequency::Yearly, PatternType::Month { day }) => {
            recurrence.recurrence_type = Some(recurrence_type::YEARLY);
            recurrence.interval = period(MONTHS_PER_YEAR);
            recurrence.day_of_month = u8::try_from(day).ok();
            recurrence.month_of_year = month;
        }
        (RecurFrequency::Yearly, PatternType::MonthEnd { .. }) => {
            recurrence.recurrence_type = Some(recurrence_type::YEARLY);
            recurrence.interval = period(MONTHS_PER_YEAR);
            recurrence.day_of_month = Some(LAST_DAY_OF_MONTH);
            recurrence.month_of_year = month;
        }
        (RecurFrequency::Yearly, PatternType::MonthNth { days, n }) => {
            recurrence.recurrence_type = Some(recurrence_type::YEARLY_NTH);
            recurrence.interval = period(MONTHS_PER_YEAR);
            recurrence.day_of_week = u16::try_from(days).ok();
            recurrence.week_of_month = u8::try_from(n).ok();
            recurrence.month_of_year = month;
        }
        _ => return None,
    }
    recurrence.calendar_type =
        takes_calendar_type(recurrence.recurrence_type).then_some(calendar_type::DEFAULT);
    recurrence.is_leap_month = matches!(
        recurrence.recurrence_type,
        Some(recurrence_type::YEARLY | recurrence_type::YEARLY_NTH)
    )
    .then_some(NOT_LEAP_MONTH);
    match pattern.end {
        RecurEnd::AfterCount => {
            recurrence.occurrences = u16::try_from(pattern.occurrence_count).ok();
        }
        RecurEnd::ByDate => {
            recurrence.until = rule
                .until
                .as_ref()
                .and_then(|until| {
                    let entry = master.property(&ICalendarProperty::Dtstart)?;
                    series.resolve(entry, until)
                })
                .map(|zoned| compact(zoned.to_timestamp()));
        }
        RecurEnd::Never | RecurEnd::NeverLegacy => {}
    }
    Some(recurrence)
}

fn exceptions<'c>(
    series: &Series<'c>,
    main: &'c ICalendarComponent,
    version: ProtocolVersion,
    first: u32,
) -> (Vec<CalendarException<'c>>, Vec<(usize, &'c str)>) {
    let in_pattern = |instant: Timestamp| {
        local_minutes(series.local(instant)).is_some_and(|minutes| minutes >= first)
    };
    let mut exceptions: Vec<(CalendarException<'c>, Option<&'c str>)> = series
        .exdates()
        .map(|zoned| zoned.to_timestamp())
        .filter(|instant| in_pattern(*instant))
        .take(MAX_LIST_ITEMS)
        .map(|instant| (deleted(instant), None))
        .collect();
    let main_has_reminder = series
        .span(main)
        .is_some_and(|span| reminder(series, series.main, &span).is_some());
    let mut instances: Vec<RecurrenceId> = series
        .overrides()
        .map(|(_, _, id)| id)
        .take(MAX_LIST_ITEMS)
        .collect();
    series.retain_instances(&mut instances);
    for (index, component, id) in series.overrides() {
        if exceptions.len() >= MAX_LIST_ITEMS {
            break;
        }
        if instances.binary_search(&id).is_err() || !in_pattern(id.0) {
            continue;
        }
        if matches!(component.status(), Some(ICalendarStatus::Cancelled)) {
            exceptions.push((deleted(id.0), None));
            continue;
        }
        let Some(span) = series.span(component) else {
            continue;
        };
        let differs = |property: &ICalendarProperty| {
            let text = first_text(component, property);
            (text != first_text(main, property)).then_some(text.unwrap_or_default())
        };
        let location = differs(&ICalendarProperty::Location);
        let floating_all_day = span.all_day && version >= ProtocolVersion::V160;
        let (start, end) = if floating_all_day {
            (local_as_utc(span.start), local_as_utc(span.end))
        } else {
            (utc(span.start.to_timestamp()), utc(span.end.to_timestamp()))
        };
        let mut exception = CalendarException {
            deleted: Some(0),
            exception_start_time: Some(compact(id.0)),
            instance_id: Some(utc(id.0)),
            start_time: Some(Compact(start)),
            end_time: Some(Compact(end)),
            all_day_event: Some(u8::from(span.all_day)),
            subject: differs(&ICalendarProperty::Summary).map(Cow::Borrowed),
            location: location.map(Cow::Borrowed),
            location_details: location.map(location_details),
            busy_status: Some(narrow(ranged_busy_status(component))),
            reminder: reminder(series, index, &span)
                .map(|minutes| OrEmpty(Some(minutes)))
                .or(main_has_reminder.then_some(OrEmpty(None))),
            ..Default::default()
        };
        if !same_properties(component, main, &ICalendarProperty::Class) {
            exception.sensitivity = component
                .property(&ICalendarProperty::Class)
                .and_then(|entry| entry.values.first())
                .map(|value| narrow(sensitivity(value)));
        }
        if !same_properties(component, main, &ICalendarProperty::Categories) {
            exception.categories = Some(categories(component).unwrap_or_default());
        }
        if !same_properties(component, main, &ICalendarProperty::Attendee) {
            let attendees: Vec<Attendee<'c>> = component
                .properties(&ICalendarProperty::Attendee)
                .filter_map(|entry| Some(attendee(entry, address(entry)?)))
                .take(MAX_LIST_ITEMS)
                .collect();
            if !attendees.is_empty() || !component.has_property(&ICalendarProperty::Attendee) {
                exception.attendees = Some(List(attendees));
            }
        }
        exceptions.push((exception, differs(&ICalendarProperty::Description)));
    }
    exceptions.sort_unstable_by_key(|(exception, _)| exception.exception_start_time);
    exceptions.dedup_by_key(|(exception, _)| exception.exception_start_time);
    let bodies = exceptions
        .iter()
        .enumerate()
        .filter_map(|(position, (_, body))| Some((position, (*body)?)))
        .collect();
    (
        exceptions
            .into_iter()
            .map(|(exception, _)| exception)
            .collect(),
        bodies,
    )
}

fn same_properties(
    component: &ICalendarComponent,
    main: &ICalendarComponent,
    property: &ICalendarProperty,
) -> bool {
    component.properties(property).eq(main.properties(property))
}

fn location_details(display_name: &str) -> Location<'_> {
    Location {
        display_name: Some(Cow::Borrowed(display_name)),
        ..Default::default()
    }
}

fn deleted<'c>(instant: Timestamp) -> CalendarException<'c> {
    CalendarException {
        deleted: Some(1),
        exception_start_time: Some(compact(instant)),
        instance_id: Some(utc(instant)),
        ..Default::default()
    }
}

fn categories<'c, const ITEM: u16>(
    component: &ICalendarComponent,
) -> Option<List<Cow<'c, str>, ITEM>> {
    let keywords = keywords(component);
    (!keywords.is_empty()).then(|| {
        List(
            keywords
                .into_iter()
                .take(MAX_LIST_ITEMS)
                .map(|keyword| Cow::Owned(keyword.into_string()))
                .collect(),
        )
    })
}

fn utc(instant: Timestamp) -> EasDateTime {
    EasDateTime(
        UtcSeconds(instant.as_second()),
        u16::try_from(instant.subsec_millisecond()).unwrap_or_default(),
    )
}

fn compact(instant: Timestamp) -> Compact {
    Compact(utc(instant))
}

fn local_as_utc(zoned: ZonedDateTime) -> EasDateTime {
    let local = zoned.naive_local();
    let seconds = local
        .to_zoned(TimeZone::UTC)
        .map_or(0, |zoned| zoned.timestamp().as_second());
    EasDateTime(UtcSeconds(seconds), 0)
}

fn narrow<T: TryInto<u8>>(value: T) -> u8 {
    value.try_into().unwrap_or_default()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/eas/tests.rs"]
mod tests;
