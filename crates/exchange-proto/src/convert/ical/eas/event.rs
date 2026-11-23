/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, cmp::Reverse, str::FromStr};

use calcard::{
    common::timezone::Tz,
    datecalc::RRule,
    icalendar::{
        ICalendar, ICalendarAction, ICalendarComponent, ICalendarComponentType, ICalendarDuration,
        ICalendarEntry, ICalendarParameter, ICalendarParticipationRole,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarRecurrenceRule,
        ICalendarUserTypes, ICalendarValue,
    },
};
use jiff::{SignedDuration, Timestamp, civil::Time, tz::Offset};
use smallvec::{SmallVec, smallvec};

use super::{
    attendee_status, attendee_type,
    recur::PatternEnd,
    todo::{Edit, class, is_display_alarm, non_empty, rule_edit, seconds, until_value},
    utc,
};
use crate::{
    common::{LocalDateTime, base64::Base64Text},
    convert::{
        ConvertError,
        blob::{RecurrencePattern, RuleCount, TERRITORY_ZONES, TzRule, local_from_minutes},
        ical::{
            patch::{
                TimeTarget, create_override, set_busy_status, set_disallow_counter, set_text,
                set_value,
            },
            props::REMINDER_DESCRIPTION,
            series::{TimeForm, time_form},
            to_message::tz_definition,
        },
    },
    eas::{
        commands::appdata::{
            Attendee, Calendar, CalendarException, OrEmpty, Recurrence, TaskRecurrence,
            base::Location,
            calendar::{Attendees, Categories},
        },
        tokens::ProtocolVersion,
        types::{EasDateTime, TimeZoneInformation},
    },
};

mod change;

pub use change::{
    EventChange, event_change_from_eas, occurrence_change_from_eas, occurrence_delete_from_eas,
};

const SECONDS_PER_MINUTE: i64 = 60;
const ONE_DAY: SignedDuration = SignedDuration::from_hours(24);
const DEFAULT_SLOT: SignedDuration = SignedDuration::from_mins(30);
const UNSTATED_DAY_SHIFT_SECONDS: i64 = 14 * 60 * 60 - 1;
const UTC_TARGET: TimeTarget = TimeTarget {
    tz: Tz::UTC,
    tzid: None,
};
const DELETED: u8 = 1;
const MAX_OCCURRENCES: u16 = 999;
const MAX_EXCEPTION_ATTENDEES: usize = 256;
const ALL_DAY: u8 = 1;

pub struct EventUpdate<'x> {
    pub calendar: &'x Calendar<'x>,
    pub description: Option<&'x str>,
    pub organizer: &'x str,
    pub version: ProtocolVersion,
    pub now: Timestamp,
}

pub fn event_from_eas(ical: &mut ICalendar, update: &EventUpdate<'_>) -> Result<(), ConvertError> {
    let calendar = update.calendar;
    let main = ical
        .components
        .iter()
        .position(|component| component.component_type == ICalendarComponentType::VEvent)
        .ok_or(ConvertError::Unsupported)?;
    let all_day = calendar.all_day_event == Some(ALL_DAY);
    let (start, end) = event_times(calendar, all_day, update.now)?;
    let zone = if all_day && update.version >= ProtocolVersion::V160 {
        Zone::Named(TimeTarget {
            tz: Tz::UTC,
            tzid: None,
        })
    } else if calendar.recurrence.is_some() {
        Zone::decode(calendar.timezone.as_ref()).resolved(start)
    } else {
        Zone::decode(calendar.timezone.as_ref())
    };
    let (start, end) = if all_day {
        let start = match calendar.start_time {
            Some(_) => zone.day(start)?,
            None => start
                .as_second()
                .div_euclid(ONE_DAY.as_secs())
                .checked_mul(ONE_DAY.as_secs())
                .ok_or(ConvertError::Unsupported)
                .and_then(instant_from_seconds)?,
        };
        let next_day = start
            .checked_add(ONE_DAY)
            .map_err(|_| ConvertError::Unsupported)?;
        (start, zone.day(end)?.max(next_day))
    } else {
        (start, end)
    };
    let mut dtstart = zone.time_entry(ICalendarProperty::Dtstart, start, all_day)?;
    let form = time_form(&dtstart);
    let (start, end, rule) = match &calendar.recurrence {
        Some(recurrence) => {
            check_occurrences(recurrence)?;
            let rule = recurrence_rule(recurrence, utc(start), &zone, form)?;
            match zone.first_occurrence(&rule, start, all_day, form) {
                Some(first) if first != start => {
                    dtstart = zone.time_entry(ICalendarProperty::Dtstart, first, all_day)?;
                    let end = first
                        .checked_add(end.duration_since(start))
                        .map_err(|_| ConvertError::Unsupported)?;
                    let rule = recurrence_rule(recurrence, utc(first), &zone, form)?;
                    (first, end, Some(rule))
                }
                _ => (start, end, Some(rule)),
            }
        }
        None => (start, end, None),
    };

    let component = ical
        .components
        .get_mut(main)
        .ok_or(ConvertError::Unsupported)?;
    component.entries.push(dtstart);
    component
        .entries
        .push(zone.time_entry(ICalendarProperty::Dtend, end, all_day)?);
    fill_texts(
        component,
        calendar.subject.as_deref(),
        location(
            calendar.location.as_deref(),
            calendar.location_details.as_ref(),
        ),
        update.description,
    );
    if let Some(Edit::Set(value)) = calendar.sensitivity.and_then(class) {
        set_value(component, ICalendarProperty::Class, value);
    }
    if let Some(status) = calendar.busy_status {
        set_busy_status(component, i32::from(status));
    }
    if calendar.disallow_new_time_proposal == Some(true) {
        set_disallow_counter(component, true);
    }
    component
        .entries
        .extend(calendar.categories.as_ref().and_then(category_entry));
    let attendees = calendar
        .attendees
        .as_ref()
        .map_or(&[][..], |list| list.0.as_slice());
    if attendees.iter().any(|attendee| address(attendee).is_some()) {
        let legacy = update.version < ProtocolVersion::V160;
        component
            .entries
            .push(organizer_entry(calendar, update.organizer, legacy)?);
        component.entries.extend(
            attendees.iter().filter_map(|attendee| {
                attendee_entry(attendee, calendar.response_requested, legacy)
            }),
        );
    }
    if let Some(rule) = rule {
        component.entries.push(rrule_entry(Box::new(rule)));
    }
    if let Some(OrEmpty(Some(minutes))) = calendar.reminder {
        add_alarm(ical, main, minutes)?;
    }
    if calendar.recurrence.is_some() {
        let exceptions = calendar
            .exceptions
            .as_ref()
            .map_or(&[][..], |list| list.0.as_slice());
        for exception in latest_exceptions(exceptions)? {
            let index = add_exception(
                ical,
                main,
                &zone,
                all_day,
                start,
                end.duration_since(start),
                exception,
            )?;
            if let Some((index, list)) = index.zip(exception_attendees(exception)) {
                set_exception_attendees(ical, index, list, update)?;
            }
        }
    }
    Ok(())
}

fn latest_exceptions<'a, 'c>(
    exceptions: &'a [CalendarException<'c>],
) -> Result<impl Iterator<Item = &'a CalendarException<'c>>, ConvertError> {
    let mut latest = exceptions
        .iter()
        .enumerate()
        .map(|(index, exception)| {
            exception
                .exception_start_time
                .map(|time| (seconds(time.0), Reverse(index)))
                .ok_or(ConvertError::Unsupported)
        })
        .collect::<Result<Vec<_>, _>>()?;
    latest.sort_unstable();
    latest.dedup_by_key(|(original, _)| *original);
    latest.sort_unstable_by_key(|(_, Reverse(index))| *index);
    Ok(latest
        .into_iter()
        .filter_map(|(_, Reverse(index))| exceptions.get(index)))
}

fn add_exception(
    ical: &mut ICalendar,
    main: usize,
    zone: &Zone,
    all_day: bool,
    series_start: Timestamp,
    duration: SignedDuration,
    exception: &CalendarException<'_>,
) -> Result<Option<usize>, ConvertError> {
    let original = exception_start(exception)?;
    let recurrence_id = if all_day {
        zone.day(original)?
    } else {
        zone.series_instant(original, series_start)?
    };
    if exception.deleted == Some(DELETED) {
        let entry = zone.slot(original, all_day)?.0.entry(
            ICalendarProperty::Exdate,
            recurrence_id,
            all_day,
        );
        ical.components
            .get_mut(main)
            .ok_or(ConvertError::Unsupported)?
            .entries
            .push(entry);
        return Ok(None);
    }
    override_exception(
        ical,
        main,
        ExceptionSlot {
            zone,
            all_day,
            recurrence_id,
            original,
            duration,
        },
        exception,
    )
    .map(Some)
}

fn exception_attendees<'a, 'c>(exception: &'a CalendarException<'c>) -> Option<&'a Attendees<'c>> {
    exception.attendees.as_ref().filter(|list| {
        list.0.len() <= MAX_EXCEPTION_ATTENDEES
            && (list.0.is_empty() || list.0.iter().any(|attendee| address(attendee).is_some()))
    })
}

fn set_exception_attendees(
    ical: &mut ICalendar,
    index: usize,
    list: &Attendees<'_>,
    update: &EventUpdate<'_>,
) -> Result<(), ConvertError> {
    let legacy = update.version < ProtocolVersion::V160;
    let component = ical
        .components
        .get_mut(index)
        .ok_or(ConvertError::Unsupported)?;
    component
        .entries
        .retain(|entry| entry.name != ICalendarProperty::Attendee);
    if !list.0.is_empty() && !component.has_property(&ICalendarProperty::Organizer) {
        component
            .entries
            .push(organizer_entry(update.calendar, update.organizer, legacy)?);
    }
    component
        .entries
        .extend(list.0.iter().filter_map(|attendee| {
            attendee_entry(attendee, update.calendar.response_requested, legacy)
        }));
    Ok(())
}

struct ExceptionSlot<'z> {
    zone: &'z Zone,
    all_day: bool,
    recurrence_id: Timestamp,
    original: Timestamp,
    duration: SignedDuration,
}

fn exception_start(exception: &CalendarException<'_>) -> Result<Timestamp, ConvertError> {
    instant(
        exception
            .exception_start_time
            .ok_or(ConvertError::Unsupported)?
            .0,
    )
}

fn override_exception(
    ical: &mut ICalendar,
    master: usize,
    slot: ExceptionSlot<'_>,
    exception: &CalendarException<'_>,
) -> Result<usize, ConvertError> {
    let ExceptionSlot {
        zone,
        all_day,
        recurrence_id,
        original,
        duration,
    } = slot;
    let mut index = create_override(
        ical,
        master,
        recurrence_id,
        &zone.slot(original, all_day)?.0,
        all_day,
        Some(duration),
    );
    let start = exception
        .start_time
        .map_or(Ok(original), |time| instant(time.0))?;
    let end = exception
        .end_time
        .map_or_else(
            || {
                start
                    .checked_add(duration)
                    .map_err(|_| ConvertError::Unsupported)
            },
            |time| instant(time.0),
        )?
        .max(start);
    let all_day = exception
        .all_day_event
        .map_or(all_day, |flag| flag == ALL_DAY);
    let component = ical
        .components
        .get_mut(index)
        .ok_or(ConvertError::Unsupported)?;
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Dtstart | ICalendarProperty::Dtend
        )
    });
    component
        .entries
        .push(zone.time_entry(ICalendarProperty::Dtstart, start, all_day)?);
    component
        .entries
        .push(zone.time_entry(ICalendarProperty::Dtend, end, all_day)?);
    if let Some(subject) = &exception.subject {
        set_text(component, ICalendarProperty::Summary, subject);
    }
    if let Some(location) = location(
        exception.location.as_deref(),
        exception.location_details.as_ref(),
    ) {
        set_text(component, ICalendarProperty::Location, location);
    }
    if let Some(description) = exception.body.as_ref().and_then(|body| body.description()) {
        set_text(component, ICalendarProperty::Description, &description);
    }
    if let Some(Edit::Set(value)) = exception.sensitivity.and_then(class) {
        set_value(component, ICalendarProperty::Class, value);
    }
    if let Some(status) = exception.busy_status {
        set_busy_status(component, i32::from(status));
    }
    if let Some(categories) = &exception.categories {
        component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::Categories);
        component.entries.extend(category_entry(categories));
    }
    if let Some(OrEmpty(minutes)) = exception.reminder {
        index = remove_display_alarms(ical, index)?;
        if let Some(minutes) = minutes {
            add_alarm(ical, index, minutes)?;
        }
    }
    Ok(index)
}

fn category_entry(categories: &Categories<'_>) -> Option<ICalendarEntry> {
    let values: SmallVec<[ICalendarValue; 1]> = categories
        .0
        .iter()
        .filter(|category| !category.is_empty())
        .map(|category| ICalendarValue::Text(category.to_string()))
        .collect();
    (!values.is_empty()).then_some(ICalendarEntry {
        name: ICalendarProperty::Categories,
        params: Vec::new(),
        values,
    })
}

fn organizer_entry(
    calendar: &Calendar<'_>,
    owner: &str,
    legacy: bool,
) -> Result<ICalendarEntry, ConvertError> {
    let client_organizer = calendar
        .organizer_email
        .as_deref()
        .map(str::trim)
        .filter(|email| legacy && email.contains('@'));
    let organizer = client_organizer
        .or_else(|| Some(owner.trim()).filter(|email| email.contains('@')))
        .ok_or(ConvertError::Unsupported)?;
    let params = client_organizer
        .and_then(|_| non_empty(calendar.organizer_name.as_deref()))
        .map(|name| vec![ICalendarParameter::cn(name.to_string())])
        .unwrap_or_default();
    Ok(ICalendarEntry {
        name: ICalendarProperty::Organizer,
        params,
        values: smallvec![mailto(organizer)],
    })
}

fn check_occurrences(recurrence: &Recurrence) -> Result<(), ConvertError> {
    if recurrence
        .occurrences
        .is_some_and(|count| count > MAX_OCCURRENCES)
    {
        Err(ConvertError::Unsupported)
    } else {
        Ok(())
    }
}

fn recurrence_rule(
    recurrence: &Recurrence,
    start: EasDateTime,
    zone: &Zone,
    form: Option<TimeForm>,
) -> Result<ICalendarRecurrenceRule, ConvertError> {
    let edit = rule_edit(&task_recurrence(recurrence, Some(start)))?;
    let mut rule = edit.pattern.to_rule(edit.first_day_of_week);
    if let PatternEnd::Until(until) = edit.pattern.end {
        let until = instant_from_seconds(until)?;
        rule.until = Some(match form {
            Some(TimeForm::Date) => UTC_TARGET.date(zone.day(until)?),
            _ => {
                let start = instant(start)?;
                until_value(
                    zone.series_instant(zone.until_instant(until, start)?, start)?
                        .as_second(),
                    form,
                )
            }
        });
    }
    Ok(rule)
}

fn rrule_entry(rule: Box<ICalendarRecurrenceRule>) -> ICalendarEntry {
    ICalendarEntry {
        name: ICalendarProperty::Rrule,
        params: Vec::new(),
        values: smallvec![ICalendarValue::RecurrenceRule(rule)],
    }
}

fn fill_texts(
    component: &mut ICalendarComponent,
    subject: Option<&str>,
    location: Option<&str>,
    description: Option<&str>,
) {
    for (name, text) in [
        (ICalendarProperty::Summary, subject),
        (ICalendarProperty::Location, location),
        (ICalendarProperty::Description, description),
    ] {
        if let Some(text) = non_empty(text) {
            set_text(component, name, text);
        }
    }
}

fn remove_display_alarms(ical: &mut ICalendar, index: usize) -> Result<usize, ConvertError> {
    let alarms: SmallVec<[u32; 2]> = ical
        .components
        .get(index)
        .ok_or(ConvertError::Unsupported)?
        .component_ids
        .iter()
        .copied()
        .filter(|id| {
            usize::try_from(*id)
                .ok()
                .and_then(|id| ical.components.get(id))
                .is_some_and(is_display_alarm)
        })
        .collect();
    if alarms.is_empty() {
        return Ok(index);
    }
    if !ical.remove_component_ids(&alarms) {
        return Err(ConvertError::Unsupported);
    }
    let removed_below = alarms
        .iter()
        .filter(|id| usize::try_from(**id).is_ok_and(|id| id < index))
        .count();
    Ok(index.saturating_sub(removed_below))
}

fn add_alarm(ical: &mut ICalendar, main: usize, minutes: u32) -> Result<(), ConvertError> {
    let id = u32::try_from(ical.components.len()).map_err(|_| ConvertError::Unsupported)?;
    ical.components.push(ICalendarComponent {
        component_type: ICalendarComponentType::VAlarm,
        entries: vec![
            ICalendarEntry {
                name: ICalendarProperty::Action,
                params: Vec::new(),
                values: smallvec![ICalendarValue::Action(ICalendarAction::Display)],
            },
            ICalendarEntry {
                name: ICalendarProperty::Description,
                params: Vec::new(),
                values: smallvec![ICalendarValue::Text(REMINDER_DESCRIPTION.into())],
            },
            ICalendarEntry {
                name: ICalendarProperty::Trigger,
                params: Vec::new(),
                values: smallvec![ICalendarValue::Duration(ICalendarDuration::from_seconds(
                    -i64::from(minutes) * SECONDS_PER_MINUTE
                ))],
            },
        ],
        component_ids: Vec::new(),
    });
    ical.components
        .get_mut(main)
        .ok_or(ConvertError::Unsupported)?
        .component_ids
        .push(id);
    Ok(())
}

fn attendee_entry(
    attendee: &Attendee<'_>,
    response_requested: Option<bool>,
    legacy: bool,
) -> Option<ICalendarEntry> {
    let email = address(attendee)?;
    let mut params = Vec::with_capacity(4);
    if let Some(name) = non_empty(attendee.name.as_deref()) {
        params.push(ICalendarParameter::cn(name.to_string()));
    }
    params.push(attendee_type_parameter(attendee.attendee_type));
    let status = match attendee.attendee_status.filter(|_| legacy) {
        Some(attendee_status::TENTATIVE) => ICalendarParticipationStatus::Tentative,
        Some(attendee_status::ACCEPTED) => ICalendarParticipationStatus::Accepted,
        Some(attendee_status::DECLINED) => ICalendarParticipationStatus::Declined,
        _ => ICalendarParticipationStatus::NeedsAction,
    };
    let rsvp = response_requested.unwrap_or(status == ICalendarParticipationStatus::NeedsAction);
    params.push(ICalendarParameter::partstat(status));
    if rsvp {
        params.push(ICalendarParameter::rsvp(true));
    }
    Some(ICalendarEntry {
        name: ICalendarProperty::Attendee,
        params,
        values: smallvec![mailto(email)],
    })
}

fn attendee_type_parameter(kind: Option<u8>) -> ICalendarParameter {
    match kind {
        Some(attendee_type::OPTIONAL) => {
            ICalendarParameter::role(ICalendarParticipationRole::OptParticipant)
        }
        Some(attendee_type::RESOURCE) => ICalendarParameter::cutype(ICalendarUserTypes::Resource),
        _ => ICalendarParameter::role(ICalendarParticipationRole::ReqParticipant),
    }
}

fn address<'c>(attendee: &'c Attendee<'_>) -> Option<&'c str> {
    attendee
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| email.contains('@'))
}

fn mailto(address: &str) -> ICalendarValue {
    ICalendarValue::Text(format!("mailto:{address}"))
}

fn location<'c>(text: Option<&'c str>, details: Option<&'c Location<'c>>) -> Option<&'c str> {
    details
        .and_then(|details| non_empty(details.display_name.as_deref()))
        .or_else(|| non_empty(text))
}

fn task_recurrence(recurrence: &Recurrence, start: Option<EasDateTime>) -> TaskRecurrence {
    TaskRecurrence {
        recurrence_type: recurrence.recurrence_type,
        start,
        until: recurrence.until.map(|until| until.0),
        occurrences: recurrence.occurrences,
        interval: recurrence.interval,
        day_of_month: recurrence.day_of_month,
        day_of_week: recurrence.day_of_week,
        week_of_month: recurrence.week_of_month,
        month_of_year: recurrence.month_of_year,
        calendar_type: recurrence.calendar_type,
        is_leap_month: recurrence.is_leap_month,
        first_day_of_week: recurrence.first_day_of_week,
        ..Default::default()
    }
}

enum Zone {
    Named(TimeTarget),
    Rules(TzRule),
    Unstated,
}

impl Zone {
    fn decode(blob: Option<&Base64Text<'_>>) -> Self {
        let Some(info) = blob
            .and_then(|blob| TimeZoneInformation::decode_base64(&blob.0).ok())
            .filter(|info| *info != TimeZoneInformation::default())
        else {
            return Zone::Unstated;
        };
        let mut name = [0u8; TimeZoneInformation::NAME_UTF8_LEN];
        match Tz::from_str(info.standard_name(&mut name).trim()) {
            Ok(tz) => Zone::named(tz),
            Err(_) => Zone::Rules(TzRule {
                bias: info.bias,
                standard_bias: info.standard_bias,
                daylight_bias: info.daylight_bias,
                standard_date: info.standard_date,
                daylight_date: info.daylight_date,
                ..Default::default()
            }),
        }
    }

    fn named(tz: Tz) -> Self {
        Zone::Named(TimeTarget {
            tz,
            tzid: tz.name().map(|name| name.into_owned()),
        })
    }

    fn resolved(self, start: Timestamp) -> Self {
        let Zone::Rules(rule) = &self else {
            return self;
        };
        territory_zone(rule, start).map_or(self, Zone::named)
    }

    fn at(&self, instant: Timestamp) -> Cow<'_, TimeTarget> {
        match self {
            Zone::Named(target) => Cow::Borrowed(target),
            Zone::Unstated => Cow::Borrowed(&UTC_TARGET),
            Zone::Rules(rule) => {
                let tz = rule_offset(rule, instant).map_or(Tz::UTC, Tz::Fixed);
                Cow::Owned(TimeTarget { tz, tzid: None })
            }
        }
    }

    fn day(&self, instant: Timestamp) -> Result<Timestamp, ConvertError> {
        let seconds = instant.as_second();
        if seconds.rem_euclid(ONE_DAY.as_secs()) == 0 {
            return Ok(instant);
        }
        if let Zone::Unstated = self {
            return seconds
                .checked_add(UNSTATED_DAY_SHIFT_SECONDS)
                .and_then(|seconds| seconds.checked_div_euclid(ONE_DAY.as_secs()))
                .and_then(|days| days.checked_mul(ONE_DAY.as_secs()))
                .ok_or(ConvertError::Unsupported)
                .and_then(instant_from_seconds);
        }
        let date = self.at(instant).tz.from_timestamp(instant).date();
        Tz::UTC
            .from_local(date.to_datetime(Time::midnight()))
            .map(|midnight| midnight.to_timestamp())
            .ok_or(ConvertError::Unsupported)
    }

    fn until_instant(&self, until: Timestamp, start: Timestamp) -> Result<Timestamp, ConvertError> {
        if until.as_second().rem_euclid(ONE_DAY.as_secs()) != 0 {
            return Ok(until);
        }
        let tz = self.at(until).tz;
        let start_time = self.at(start).tz.from_timestamp(start).naive_local().time();
        if tz.from_timestamp(until).naive_local().time() == start_time {
            return Ok(until);
        }
        tz.from_local(Tz::UTC.from_timestamp(until).date().to_datetime(start_time))
            .map(|last| last.to_timestamp())
            .ok_or(ConvertError::Unsupported)
    }

    fn slot(
        &self,
        instant: Timestamp,
        all_day: bool,
    ) -> Result<(Cow<'_, TimeTarget>, Timestamp), ConvertError> {
        if all_day {
            Ok((Cow::Borrowed(&UTC_TARGET), self.day(instant)?))
        } else {
            Ok((self.at(instant), instant))
        }
    }

    fn time_entry(
        &self,
        name: ICalendarProperty,
        instant: Timestamp,
        all_day: bool,
    ) -> Result<ICalendarEntry, ConvertError> {
        let (target, instant) = self.slot(instant, all_day)?;
        Ok(target.entry(name, instant, all_day))
    }

    fn first_occurrence(
        &self,
        rule: &ICalendarRecurrenceRule,
        start: Timestamp,
        all_day: bool,
        form: Option<TimeForm>,
    ) -> Option<Timestamp> {
        let tz = match form {
            Some(TimeForm::Date) => Tz::UTC,
            Some(TimeForm::Zoned | TimeForm::Floating | TimeForm::Utc) | None => self.at(start).tz,
        };
        let zoned = tz.from_timestamp(start);
        let local = zoned.naive_local();
        let maps = |local| RecurrencePattern::from_rrule(rule, local, tz, RuleCount::Pattern);
        if let Ok(pattern) = maps(local) {
            let first = local_from_minutes(pattern.start_date)?.date();
            return if first == local.date() {
                Some(start)
            } else {
                tz.from_local(first.to_datetime(local.time()))
                    .map(|zoned| zoned.to_timestamp())
            };
        }
        let mut uncounted = rule.clone();
        uncounted.count = None;
        RRule::from_ical(&uncounted, zoned, all_day)
            .ok()?
            .iter()
            .find(|instance| instance.to_timestamp() > start)
            .filter(|instance| maps(instance.naive_local()).is_ok())
            .map(|instance| instance.to_timestamp())
    }

    fn series_instant(
        &self,
        instant: Timestamp,
        series_start: Timestamp,
    ) -> Result<Timestamp, ConvertError> {
        let Zone::Rules(rule) = self else {
            return Ok(instant);
        };
        let offset = |at| rule_offset(rule, at).map_or(0, |offset| offset.seconds());
        instant
            .checked_add(SignedDuration::from_secs(i64::from(
                offset(instant).saturating_sub(offset(series_start)),
            )))
            .map_err(|_| ConvertError::Unsupported)
    }
}

fn territory_zone(rule: &TzRule, start: Timestamp) -> Option<Tz> {
    let offset = rule_offset(rule, start)?;
    let year = Tz::Fixed(offset).from_timestamp(start).date().year();
    TERRITORY_ZONES
        .iter()
        .copied()
        .filter_map(Tz::iana)
        .find(|tz| {
            tz.from_timestamp(start).offset() == offset
                && tz_definition(*tz, year..=year)
                    .effective()
                    .is_some_and(|expected| expected.same_zone(rule))
        })
}

fn rule_offset(rule: &TzRule, instant: Timestamp) -> Option<Offset> {
    let minutes = |minutes: i32| Offset::from_seconds(minutes.checked_mul(60)?).ok();
    let standard = rule
        .bias
        .saturating_add(rule.standard_bias)
        .saturating_neg();
    let daylight = rule
        .bias
        .saturating_add(rule.daylight_bias)
        .saturating_neg();
    let in_daylight = |offset: i32| -> Option<bool> {
        let local = local_time(instant, minutes(offset)?)?;
        Some(rule.utc_offset_minutes(local) == daylight)
    };
    let offset = if standard != daylight && in_daylight(standard)? && in_daylight(daylight)? {
        daylight
    } else {
        standard
    };
    minutes(offset)
}

fn local_time(instant: Timestamp, offset: Offset) -> Option<LocalDateTime> {
    let local = Tz::Fixed(offset).from_timestamp(instant).naive_local();
    LocalDateTime::new(
        u16::try_from(local.year()).ok()?,
        u8::try_from(local.month()).ok()?,
        u8::try_from(local.day()).ok()?,
        u8::try_from(local.hour()).ok()?,
        u8::try_from(local.minute()).ok()?,
        u8::try_from(local.second()).ok()?,
        0,
    )
}

fn event_times(
    calendar: &Calendar<'_>,
    all_day: bool,
    now: Timestamp,
) -> Result<(Timestamp, Timestamp), ConvertError> {
    let start = calendar
        .start_time
        .map(|time| instant(time.0))
        .transpose()?;
    let end = calendar.end_time.map(|time| instant(time.0)).transpose()?;
    match (start, end) {
        (Some(start), Some(end)) => Ok((start, end.max(start))),
        (Some(start), None) if all_day => Ok((start, start)),
        (Some(start), None) if start <= now => Ok((start, after_slot(next_slot(now)?)?)),
        (None, None) => {
            let start = next_slot(now)?;
            Ok((start, after_slot(start)?))
        }
        (None, Some(end)) => {
            let start = next_slot(now)?;
            if start <= end {
                Ok((start, end))
            } else {
                Err(ConvertError::Unsupported)
            }
        }
        (Some(_), None) => Err(ConvertError::Unsupported),
    }
}

fn next_slot(now: Timestamp) -> Result<Timestamp, ConvertError> {
    let slot = DEFAULT_SLOT.as_secs();
    now.as_second()
        .div_euclid(slot)
        .checked_add(1)
        .and_then(|slots| slots.checked_mul(slot))
        .ok_or(ConvertError::Unsupported)
        .and_then(instant_from_seconds)
}

fn after_slot(start: Timestamp) -> Result<Timestamp, ConvertError> {
    start
        .checked_add(DEFAULT_SLOT)
        .map_err(|_| ConvertError::Unsupported)
}

fn instant(time: EasDateTime) -> Result<Timestamp, ConvertError> {
    instant_from_seconds(seconds(time))
}

fn instant_from_seconds(seconds: i64) -> Result<Timestamp, ConvertError> {
    Timestamp::from_second(seconds).map_err(|_| ConvertError::Unsupported)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/eas/event/tests.rs"]
mod tests;
