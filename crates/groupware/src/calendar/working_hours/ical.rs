/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_WORKING_HOURS_SLOTS, MINUTES_PER_DAY, is_active, resolve_tz, weekday_index};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry,
        ICalendarFreeBusyType, ICalendarFrequency, ICalendarProperty, ICalendarRecurrenceRule,
        ICalendarValue, ICalendarWeekday,
    },
};
use common::PROD_ID;
use jiff::{
    Timestamp,
    civil::{Date, Weekday as CivilWeekday},
    tz::TimeZone as CivilTimeZone,
};
use registry::{
    schema::{
        enums::{TimeZone, Weekday},
        prelude::LocalTime,
        structs::{WorkingHours, WorkingHoursSlot},
    },
    types::{EnumImpl, list::List, map::Map},
};
use std::{
    fmt::{Display, Write},
    str::FromStr,
};

const REFERENCE_MONDAY: (i16, i8, i8) = (2024, 1, 1);
const REFERENCE_STAMP: &str = "20240101T000000Z";
const TZ_RANGE_SECONDS: i64 = 2 * 366 * 86_400;
const UTC_NAMES: [&str; 2] = ["UTC", "Etc/UTC"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VAvailabilityError {
    NotOneAvailability,
    UnsupportedComponent,
    UnsupportedBusyType,
    BoundedAvailability,
    TooManySlots,
    MissingStart,
    NoAvailableTime,
    FutureStart,
    UnsupportedRecurrence,
    UnsupportedInterval,
    MixedTimeZones,
    UnknownTimeZone,
}

pub fn generate_vavailability(
    hours: &WorkingHours,
    account_tz: Option<TimeZone>,
    account_id: u32,
    now: i64,
) -> Option<String> {
    if !is_active(hours) {
        return None;
    }
    let time_zone = hours.time_zone.or(account_tz);
    let tz_name = time_zone
        .filter(|tz| !resolve_tz(Some(*tz)).is_utc())
        .map(|tz| tz.as_str());
    let (tz_param, utc_suffix) = match tz_name {
        Some(name) => (format!(";TZID={name}"), ""),
        None => (String::new(), "Z"),
    };
    let mut ical = String::with_capacity(256 + hours.slots.len() * 192);
    let _ = write!(
        ical,
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:{PROD_ID}\r\nBEGIN:VAVAILABILITY\r\n\
         UID:working-hours-{account_id}\r\nDTSTAMP:{REFERENCE_STAMP}\r\nBUSYTYPE:BUSY-UNAVAILABLE\r\n"
    );
    for (slot_id, slot) in hours.slots.values().enumerate() {
        let Some(first_day) = slot.days.iter().map(|day| weekday_index(*day)).min() else {
            continue;
        };
        let Some(start_date) = reference_date(first_day) else {
            continue;
        };
        let start = slot.start.minutes();
        let end = slot.end.minutes();
        let (end_date, end) = if end >= MINUTES_PER_DAY {
            (start_date.tomorrow().unwrap_or(start_date), 0)
        } else {
            (start_date, end)
        };
        let _ = write!(
            ical,
            "BEGIN:AVAILABLE\r\nUID:working-hours-{account_id}-{slot_id}\r\nDTSTAMP:{REFERENCE_STAMP}\r\n\
             DTSTART{tz_param}:{}T{:02}{:02}00{utc_suffix}\r\n\
             DTEND{tz_param}:{}T{:02}{:02}00{utc_suffix}\r\nRRULE:FREQ=WEEKLY;BYDAY=",
            start_date.strftime("%Y%m%d"),
            start / 60,
            start % 60,
            end_date.strftime("%Y%m%d"),
            end / 60,
            end % 60,
        );
        for (pos, day) in slot.days.iter().enumerate() {
            if pos > 0 {
                ical.push(',');
            }
            ical.push_str(weekday_code(*day));
        }
        ical.push_str("\r\nEND:AVAILABLE\r\n");
    }
    ical.push_str("END:VAVAILABILITY\r\nEND:VCALENDAR\r\n");

    match tz_name {
        Some(name) => match ICalendar::parse(&ical) {
            Ok(mut parsed) => {
                let from = reference_date(0)
                    .and_then(|date| date.to_zoned_datetime(CivilTimeZone::UTC).ok())
                    .map_or(now, |zoned| zoned.timestamp().as_second());
                parsed.add_timezone(name, from, now.saturating_add(TZ_RANGE_SECONDS));
                Some(parsed.to_string())
            }
            Err(_) => Some(ical),
        },
        None => Some(ical),
    }
}

pub fn always_available_vavailability(account_id: u32) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:{PROD_ID}\r\nBEGIN:VAVAILABILITY\r\n\
         UID:working-hours-{account_id}\r\nDTSTAMP:{REFERENCE_STAMP}\r\nBUSYTYPE:BUSY-UNAVAILABLE\r\n\
         BEGIN:AVAILABLE\r\nUID:working-hours-{account_id}-0\r\nDTSTAMP:{REFERENCE_STAMP}\r\n\
         DTSTART:20240101T000000\r\nDTEND:20240101T235900\r\n\
         RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR,SA,SU\r\nEND:AVAILABLE\r\n\
         END:VAVAILABILITY\r\nEND:VCALENDAR\r\n"
    )
}

pub fn parse_vavailability(ical: &ICalendar, now: i64) -> Result<WorkingHours, VAvailabilityError> {
    let latest_start = Timestamp::from_second(now)
        .ok()
        .and_then(|now| {
            now.to_zoned_datetime(CivilTimeZone::UTC)
                .date()
                .tomorrow()
                .ok()
        })
        .unwrap_or(Date::MAX);
    let mut availability = None;
    for component in &ical.components {
        match component.component_type {
            ICalendarComponentType::VAvailability => {
                if availability.replace(component).is_some() {
                    return Err(VAvailabilityError::NotOneAvailability);
                }
            }
            ICalendarComponentType::VCalendar
            | ICalendarComponentType::VTimezone
            | ICalendarComponentType::Standard
            | ICalendarComponentType::Daylight
            | ICalendarComponentType::Available => {}
            _ => return Err(VAvailabilityError::UnsupportedComponent),
        }
    }
    let availability = availability.ok_or(VAvailabilityError::NotOneAvailability)?;

    for entry in &availability.entries {
        match entry.name {
            ICalendarProperty::Dtend | ICalendarProperty::Duration => {
                return Err(VAvailabilityError::BoundedAvailability);
            }
            ICalendarProperty::Busytype
                if entry.values.iter().any(|value| {
                    !matches!(
                        value,
                        ICalendarValue::BusyType(ICalendarFreeBusyType::BusyUnavailable)
                    )
                }) =>
            {
                return Err(VAvailabilityError::UnsupportedBusyType);
            }
            ICalendarProperty::Dtstart
                if entry_date(entry).is_some_and(|date| date > latest_start) =>
            {
                return Err(VAvailabilityError::FutureStart);
            }
            _ => {}
        }
    }

    if availability.component_ids.len() > MAX_WORKING_HOURS_SLOTS {
        return Err(VAvailabilityError::TooManySlots);
    }
    let mut zone: Option<Option<&str>> = None;
    let mut slots = List::with_capacity(availability.component_ids.len());
    for component in availability
        .component_ids
        .iter()
        .filter_map(|id| ical.component_by_id(*id))
    {
        if component.component_type != ICalendarComponentType::Available {
            return Err(VAvailabilityError::UnsupportedComponent);
        }
        let (slot, slot_zone) = parse_available(component, latest_start)?;
        match zone {
            None => zone = Some(slot_zone),
            Some(zone) if zone != slot_zone => return Err(VAvailabilityError::MixedTimeZones),
            Some(_) => {}
        }
        slots.push(slot);
    }
    if slots.is_empty() {
        return Err(VAvailabilityError::NoAvailableTime);
    }

    let time_zone = match zone.flatten() {
        Some(name) if UTC_NAMES.contains(&name) => Some(TimeZone::EtcUTC),
        Some(name) => Some(
            TimeZone::parse(name)
                .or_else(|| {
                    Tz::from_str(name)
                        .ok()
                        .and_then(|tz| tz.name())
                        .and_then(|name| TimeZone::parse(&name))
                })
                .ok_or(VAvailabilityError::UnknownTimeZone)?,
        ),
        None => None,
    };

    Ok(WorkingHours {
        enable: true,
        time_zone,
        slots,
    })
}

fn parse_available(
    component: &ICalendarComponent,
    latest_start: Date,
) -> Result<(WorkingHoursSlot, Option<&str>), VAvailabilityError> {
    let mut start = None;
    let mut end = None;
    let mut duration = None;
    let mut rule = None;
    for entry in &component.entries {
        match entry.name {
            ICalendarProperty::Dtstart => start = Some(local_time(entry)?),
            ICalendarProperty::Dtend => end = Some(local_time(entry)?),
            ICalendarProperty::Duration => {
                duration = entry.values.first().and_then(|value| match value {
                    ICalendarValue::Duration(duration) => Some(duration),
                    _ => None,
                })
            }
            ICalendarProperty::Rrule => {
                if rule.is_some() {
                    return Err(VAvailabilityError::UnsupportedRecurrence);
                }
                rule = entry.values.first().and_then(|value| match value {
                    ICalendarValue::RecurrenceRule(rule) => Some(rule.as_ref()),
                    _ => None,
                });
            }
            ICalendarProperty::Rdate
            | ICalendarProperty::Exdate
            | ICalendarProperty::Exrule
            | ICalendarProperty::RecurrenceId => {
                return Err(VAvailabilityError::UnsupportedRecurrence);
            }
            _ => {}
        }
    }

    let start = start.ok_or(VAvailabilityError::MissingStart)?;
    if start.date > latest_start {
        return Err(VAvailabilityError::FutureStart);
    }
    let end_minutes = match (end, duration) {
        (Some(end), None) if end.zone == start.zone => {
            if end.date == start.date {
                end.minutes
            } else if end.minutes == 0 && start.date.tomorrow().ok() == Some(end.date) {
                MINUTES_PER_DAY
            } else {
                return Err(VAvailabilityError::UnsupportedInterval);
            }
        }
        (None, Some(duration)) => start
            .minutes
            .checked_add(duration_minutes(duration)?)
            .ok_or(VAvailabilityError::UnsupportedInterval)?,
        _ => return Err(VAvailabilityError::UnsupportedInterval),
    };
    if end_minutes <= start.minutes || end_minutes > MINUTES_PER_DAY {
        return Err(VAvailabilityError::UnsupportedInterval);
    }

    let rule = rule.ok_or(VAvailabilityError::UnsupportedRecurrence)?;
    if !is_plain_weekly(rule) {
        return Err(VAvailabilityError::UnsupportedRecurrence);
    }
    let mut days = Map::with_capacity(rule.byday.len().max(1));
    if rule.byday.is_empty() {
        days.push(weekday_from_jiff(start.date.weekday()));
    } else {
        for day in &rule.byday {
            if day.ordwk.is_some() {
                return Err(VAvailabilityError::UnsupportedRecurrence);
            }
            days.push(weekday_from_ical(day.weekday));
        }
    }

    Ok((
        WorkingHoursSlot {
            days,
            start: LocalTime::from_minutes(start.minutes),
            end: LocalTime::from_minutes(end_minutes),
        },
        start.zone,
    ))
}

fn entry_date(entry: &ICalendarEntry) -> Option<Date> {
    let Some(ICalendarValue::PartialDateTime(value)) = entry.values.first() else {
        return None;
    };
    Date::new(
        i16::try_from(value.year?).ok()?,
        i8::try_from(value.month?).ok()?,
        i8::try_from(value.day?).ok()?,
    )
    .ok()
}

struct ParsedTime<'x> {
    date: Date,
    minutes: u16,
    zone: Option<&'x str>,
}

fn local_time(entry: &ICalendarEntry) -> Result<ParsedTime<'_>, VAvailabilityError> {
    let Some(ICalendarValue::PartialDateTime(value)) = entry.values.first() else {
        return Err(VAvailabilityError::MissingStart);
    };
    let PartialDateTime {
        year: Some(year),
        month: Some(month),
        day: Some(day),
        hour: Some(hour),
        minute: Some(minute),
        second,
        ..
    } = value
    else {
        return Err(VAvailabilityError::UnsupportedInterval);
    };
    if second.is_some_and(|second| second != 0) || *hour > 23 || *minute > 59 {
        return Err(VAvailabilityError::UnsupportedInterval);
    }
    let date = match (
        i16::try_from(*year),
        i8::try_from(*month),
        i8::try_from(*day),
    ) {
        (Ok(year), Ok(month), Ok(day)) => {
            Date::new(year, month, day).map_err(|_| VAvailabilityError::UnsupportedInterval)?
        }
        _ => return Err(VAvailabilityError::UnsupportedInterval),
    };
    let zone = if value.has_zone() {
        if value.tz_hour != Some(0) || value.tz_minute.is_some_and(|minute| minute != 0) {
            return Err(VAvailabilityError::UnknownTimeZone);
        }
        Some("UTC")
    } else {
        entry.tz_id()
    };
    Ok(ParsedTime {
        date,
        minutes: u16::from(*hour) * 60 + u16::from(*minute),
        zone,
    })
}

fn duration_minutes(duration: &ICalendarDuration) -> Result<u16, VAvailabilityError> {
    if duration.neg || duration.seconds != 0 {
        return Err(VAvailabilityError::UnsupportedInterval);
    }
    let minutes = u64::from(duration.weeks) * 7 * 1440
        + u64::from(duration.days) * 1440
        + u64::from(duration.hours) * 60
        + u64::from(duration.minutes);
    u16::try_from(minutes).map_err(|_| VAvailabilityError::UnsupportedInterval)
}

fn is_plain_weekly(rule: &ICalendarRecurrenceRule) -> bool {
    rule.freq == ICalendarFrequency::Weekly
        && rule.until.is_none()
        && rule.count.is_none()
        && rule.interval.is_none_or(|interval| interval == 1)
        && rule.bysecond.is_empty()
        && rule.byminute.is_empty()
        && rule.byhour.is_empty()
        && rule.bymonthday.is_empty()
        && rule.byyearday.is_empty()
        && rule.byweekno.is_empty()
        && rule.bymonth.is_empty()
        && rule.bysetpos.is_empty()
        && rule.rscale.is_none()
}

fn reference_date(day_index: u8) -> Option<Date> {
    let (year, month, day) = REFERENCE_MONDAY;
    let offset = i8::try_from(day_index).ok()?;
    Date::new(year, month, day.checked_add(offset)?).ok()
}

fn weekday_code(day: Weekday) -> &'static str {
    match day {
        Weekday::Monday => "MO",
        Weekday::Tuesday => "TU",
        Weekday::Wednesday => "WE",
        Weekday::Thursday => "TH",
        Weekday::Friday => "FR",
        Weekday::Saturday => "SA",
        Weekday::Sunday => "SU",
    }
}

fn weekday_from_ical(day: ICalendarWeekday) -> Weekday {
    match day {
        ICalendarWeekday::Monday => Weekday::Monday,
        ICalendarWeekday::Tuesday => Weekday::Tuesday,
        ICalendarWeekday::Wednesday => Weekday::Wednesday,
        ICalendarWeekday::Thursday => Weekday::Thursday,
        ICalendarWeekday::Friday => Weekday::Friday,
        ICalendarWeekday::Saturday => Weekday::Saturday,
        ICalendarWeekday::Sunday => Weekday::Sunday,
    }
}

fn weekday_from_jiff(day: CivilWeekday) -> Weekday {
    match day {
        CivilWeekday::Monday => Weekday::Monday,
        CivilWeekday::Tuesday => Weekday::Tuesday,
        CivilWeekday::Wednesday => Weekday::Wednesday,
        CivilWeekday::Thursday => Weekday::Thursday,
        CivilWeekday::Friday => Weekday::Friday,
        CivilWeekday::Saturday => Weekday::Saturday,
        CivilWeekday::Sunday => Weekday::Sunday,
    }
}

impl Display for VAvailabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VAvailabilityError::NotOneAvailability => {
                "Exactly one VAVAILABILITY component is required."
            }
            VAvailabilityError::UnsupportedComponent => {
                "Only VAVAILABILITY, AVAILABLE and VTIMEZONE components are supported."
            }
            VAvailabilityError::UnsupportedBusyType => {
                "Only BUSYTYPE BUSY-UNAVAILABLE is supported."
            }
            VAvailabilityError::BoundedAvailability => {
                "VAVAILABILITY with an end or duration is not supported."
            }
            VAvailabilityError::TooManySlots => "At most 14 AVAILABLE components are supported.",
            VAvailabilityError::MissingStart => "AVAILABLE requires a DTSTART date-time.",
            VAvailabilityError::NoAvailableTime => {
                "VAVAILABILITY without AVAILABLE components is not supported."
            }
            VAvailabilityError::FutureStart => {
                "VAVAILABILITY and AVAILABLE must not start in the future."
            }
            VAvailabilityError::UnsupportedRecurrence => {
                "AVAILABLE must repeat weekly on whole days, without exceptions or an end."
            }
            VAvailabilityError::UnsupportedInterval => {
                "AVAILABLE must start and end on the same day, on whole minutes."
            }
            VAvailabilityError::MixedTimeZones => {
                "All AVAILABLE components must use the same time zone."
            }
            VAvailabilityError::UnknownTimeZone => "The time zone is not a known IANA time zone.",
        })
    }
}
