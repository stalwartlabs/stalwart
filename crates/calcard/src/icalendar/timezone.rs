/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarDay, ICalendarEntry,
    ICalendarFrequency, ICalendarMonth, ICalendarPeriod, ICalendarProperty,
    ICalendarRecurrenceRule, ICalendarValue, ICalendarWeekday,
};
use crate::{
    common::{
        PartialDateTime,
        timezone::{Tz, ZonedDateTime},
    },
    icalendar::ICalendarParameterName,
};
use ahash::AHashSet;
use jiff::{
    Timestamp,
    civil::{self, Date, Weekday},
    tz::{Offset, TimeZone},
};
use std::{collections::HashMap, ops::Range, str::FromStr};

pub struct TzResolver<T> {
    tzs: HashMap<T, Tz>,
    default: Tz,
}

impl<T> TzResolver<T>
where
    T: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    pub fn resolve(&self, tz_name: &str) -> Option<Tz> {
        self.tzs
            .get(tz_name)
            .copied()
            .or_else(|| Tz::from_str(tz_name).ok())
    }

    pub fn resolve_or_default(&self, tz_name: Option<&str>) -> Tz {
        tz_name
            .and_then(|tz_name| {
                self.tzs
                    .get(tz_name)
                    .copied()
                    .or_else(|| Tz::from_str(tz_name).ok())
            })
            .unwrap_or(self.default)
    }

    pub fn with_default(mut self, default: impl Into<Tz>) -> Self {
        self.default = default.into();
        self
    }
}

impl ICalendar {
    pub fn timezones(&self) -> impl Iterator<Item = &ICalendarComponent> {
        self.components
            .iter()
            .filter(|comp| matches!(comp.component_type, ICalendarComponentType::VTimezone))
    }

    pub fn is_timezone(&self) -> bool {
        self.timezones().count() == 1
    }

    pub fn build_tz_resolver(&self) -> TzResolver<&'_ str> {
        TzResolver {
            tzs: self.timezones().filter_map(|tz| tz.timezone()).collect(),
            default: Tz::Floating,
        }
    }

    pub fn build_owned_tz_resolver(&self) -> TzResolver<String> {
        TzResolver {
            tzs: self
                .timezones()
                .filter_map(|tz| tz.timezone())
                .map(|(name, tz)| (name.to_string(), tz))
                .collect(),
            default: Tz::Floating,
        }
    }
}

impl ICalendarComponent {
    pub fn timezone(&self) -> Option<(&str, Tz)> {
        let mut tz_name = None;
        let mut tz_id = None;
        let mut tz_lic = None;
        let mut tz_cdo_id = None;

        for entry in &self.entries {
            match (&entry.name, entry.values.first()) {
                (ICalendarProperty::Tzid, Some(ICalendarValue::Text(id))) => {
                    tz_id = Tz::from_str(id).ok();
                    tz_name = Some(id.as_str());
                }
                (ICalendarProperty::Other(value), Some(ICalendarValue::Text(id))) => {
                    hashify::fnc_map!(value.as_bytes(),
                        "X-LIC-LOCATION" => {
                            tz_lic = Tz::from_str(id.strip_prefix("SystemV/").unwrap_or(id.as_str())).ok();
                        },
                        "X-MICROSOFT-CDO-TZID" => {
                            tz_cdo_id = Tz::from_ms_cdo_zone_id(id);
                        },
                        _ => {}
                    );
                }
                _ => (),
            }
        }

        tz_name.zip(tz_id.or(tz_lic).or(tz_cdo_id))
    }
}

impl ICalendarPeriod {
    pub fn time_range(&self, tz: Tz) -> Option<(ZonedDateTime, ZonedDateTime)> {
        match self {
            ICalendarPeriod::Range { start, end } => start
                .to_date_time_with_tz(tz)
                .zip(end.to_date_time_with_tz(tz)),
            ICalendarPeriod::Duration { start, duration } => start
                .to_date_time_with_tz(tz)
                .zip(duration.to_nominal())
                .and_then(|(start, duration)| {
                    start.checked_add_nominal(duration).map(|end| (start, end))
                }),
        }
    }
}

impl ICalendarEntry {
    pub fn tz_id(&self) -> Option<&str> {
        self.parameters(&ICalendarParameterName::Tzid)
            .find_map(|v| v.as_text())
    }
}

const TZ_MIN_YEAR: i32 = 1900;
const TZ_MAX_FUTURE_YEARS: i32 = 100;
const TZ_RANGE_MARGIN: i64 = 86400;
const TZ_RULE_ACTIVE_SECONDS: i64 = 366 * 86400;
const MAX_OBSERVANCES: usize = 4096;
const MAX_ADDED_TIMEZONES: usize = 32;

impl ICalendar {
    pub fn add_timezone(&mut self, tz_id: &str, from: i64, to: i64) -> Option<u32> {
        self.calendar_root()?;

        let tz = Tz::from_str(tz_id).ok()?;
        let observances = match tz {
            Tz::Iana(_) => build_observances(tz.time_zone()?, from, to),
            Tz::Fixed(offset) => {
                let offset = round_to_minute(offset.seconds());
                vec![TzObservance {
                    at: from,
                    from_offset: offset,
                    to_offset: offset,
                    is_dst: false,
                    name: None,
                    rrule: None,
                }]
            }
            Tz::Floating => return None,
        };
        if observances.is_empty() {
            return None;
        }

        let tz_component_id = u32::try_from(self.components.len()).ok()?;
        let first_component_id = tz_component_id.checked_add(1)?;
        let last_component_id =
            first_component_id.checked_add(u32::try_from(observances.len()).ok()?)?;
        let insert_at = self
            .calendar_root()?
            .component_ids
            .iter()
            .position(|component_id| {
                self.component_by_id(*component_id)
                    .is_none_or(|comp| comp.component_type != ICalendarComponentType::VTimezone)
            });

        self.components.reserve(observances.len() + 1);
        self.components.push(ICalendarComponent {
            component_type: ICalendarComponentType::VTimezone,
            entries: vec![
                ICalendarEntry::new(ICalendarProperty::Tzid).with_value(tz_id.to_string()),
            ],
            component_ids: (first_component_id..last_component_id).collect(),
        });
        self.components
            .extend(observances.into_iter().map(TzObservance::into_component));

        let root_ids = &mut self.components.first_mut()?.component_ids;
        root_ids.insert(insert_at.unwrap_or(root_ids.len()), tz_component_id);

        Some(tz_component_id)
    }

    pub fn add_missing_timezones(&mut self) -> usize {
        let defined: AHashSet<&str> = self
            .timezones()
            .flat_map(|component| &component.entries)
            .filter(|entry| entry.name == ICalendarProperty::Tzid)
            .filter_map(|entry| match entry.values.first() {
                Some(ICalendarValue::Text(tz_id)) => Some(tz_id.as_str()),
                _ => None,
            })
            .collect();

        let mut referenced: Vec<String> = Vec::new();
        let mut range: Option<(i64, i64)> = None;
        let mut recurrence_span = 0;
        let mut is_unbounded = false;

        for component in &self.components {
            if matches!(
                component.component_type,
                ICalendarComponentType::VTimezone
                    | ICalendarComponentType::Standard
                    | ICalendarComponentType::Daylight
            ) {
                continue;
            }

            for entry in &component.entries {
                for param in &entry.params {
                    if param.name == ICalendarParameterName::Tzid
                        && referenced.len() < MAX_ADDED_TIMEZONES
                        && let Some(tz_id) = param.value.as_text()
                        && !defined.contains(tz_id)
                        && !referenced.iter().any(|id| id == tz_id)
                    {
                        referenced.push(tz_id.to_string());
                    }
                }

                match &entry.name {
                    ICalendarProperty::Rrule => {
                        for value in &entry.values {
                            if let ICalendarValue::RecurrenceRule(rule) = value {
                                match (&rule.until, &rule.count) {
                                    (Some(until), _) => expand_range(&mut range, until),
                                    (None, Some(count)) => {
                                        recurrence_span = recurrence_span.max(recurrence_span_of(
                                            &rule.freq,
                                            *count,
                                            rule.interval,
                                        ));
                                    }
                                    (None, None) => is_unbounded = true,
                                }
                            }
                        }
                    }
                    ICalendarProperty::Dtstart
                    | ICalendarProperty::Dtend
                    | ICalendarProperty::Due
                    | ICalendarProperty::RecurrenceId
                    | ICalendarProperty::Exdate
                    | ICalendarProperty::Rdate => {
                        for value in &entry.values {
                            match value {
                                ICalendarValue::PartialDateTime(dt) => {
                                    expand_range(&mut range, dt);
                                }
                                ICalendarValue::Period(period) => match period.as_ref() {
                                    ICalendarPeriod::Range { start, end } => {
                                        expand_range(&mut range, start);
                                        expand_range(&mut range, end);
                                    }
                                    ICalendarPeriod::Duration { start, .. } => {
                                        expand_range(&mut range, start);
                                    }
                                },
                                _ => (),
                            }
                        }
                    }
                    _ => (),
                }
            }
        }

        if referenced.is_empty() {
            return 0;
        }

        let now = Timestamp::now().as_second();
        let (min, max) = range.unwrap_or((now, now));
        let max = max.saturating_add(recurrence_span);
        let current_year = year_of(now);
        let max_year = current_year.saturating_add(TZ_MAX_FUTURE_YEARS);
        let from_year = year_of(min).clamp(TZ_MIN_YEAR, max_year);
        let to_year = if is_unbounded {
            year_of(max).max(current_year)
        } else {
            year_of(max)
        }
        .saturating_add(2)
        .clamp(from_year.saturating_add(1), max_year.saturating_add(2));
        let from = start_of_year(from_year).saturating_sub(TZ_RANGE_MARGIN);
        let to = start_of_year(to_year);

        let mut added = 0;
        for tz_id in referenced {
            if self.add_timezone(&tz_id, from, to).is_some() {
                added += 1;
            }
        }
        added
    }
}

#[derive(PartialEq, Eq)]
struct TzRuleKey {
    month: u8,
    ordwk: i16,
    weekday: ICalendarWeekday,
    hour: u8,
    minute: u8,
    second: u8,
    from_offset: i32,
    to_offset: i32,
}

struct TzObservance {
    at: i64,
    from_offset: i32,
    to_offset: i32,
    is_dst: bool,
    name: Option<String>,
    rrule: Option<ICalendarRecurrenceRule>,
}

impl TzObservance {
    fn onset(&self) -> civil::DateTime {
        naive_utc(self.at.saturating_add(self.from_offset as i64))
    }

    fn rule_key(&self) -> Option<(i32, TzRuleKey)> {
        let onset = self.onset();
        let day = u32::from(onset.day().unsigned_abs());
        let ordwk = if day.saturating_add(7)
            > days_in_month(
                i32::from(onset.year()),
                u32::from(onset.month().unsigned_abs()),
            ) {
            -1
        } else {
            ((day - 1) / 7 + 1) as i16
        };

        Some((
            i32::from(onset.year()),
            TzRuleKey {
                month: u8::try_from(onset.month()).ok()?,
                ordwk,
                weekday: weekday_of(onset.weekday()),
                hour: u8::try_from(onset.hour()).ok()?,
                minute: u8::try_from(onset.minute()).ok()?,
                second: u8::try_from(onset.second()).ok()?,
                from_offset: self.from_offset,
                to_offset: self.to_offset,
            },
        ))
    }

    fn into_component(self) -> ICalendarComponent {
        let mut component = ICalendarComponent::new(if self.is_dst {
            ICalendarComponentType::Daylight
        } else {
            ICalendarComponentType::Standard
        });

        component
            .entries
            .push(ICalendarEntry::new(ICalendarProperty::Dtstart).with_value(
                PartialDateTime::from_naive_timestamp(naive_seconds(self.onset())),
            ));
        component.entries.push(
            ICalendarEntry::new(ICalendarProperty::Tzoffsetfrom)
                .with_value(offset_to_partial(self.from_offset)),
        );
        component.entries.push(
            ICalendarEntry::new(ICalendarProperty::Tzoffsetto)
                .with_value(offset_to_partial(self.to_offset)),
        );
        if let Some(name) = self.name {
            component
                .entries
                .push(ICalendarEntry::new(ICalendarProperty::Tzname).with_value(name));
        }
        if let Some(rrule) = self.rrule {
            component
                .entries
                .push(ICalendarEntry::new(ICalendarProperty::Rrule).with_value(rrule));
        }

        component
    }
}

/// Collects the observances a zone goes through between two instants.
fn build_observances(tz: &TimeZone, from: i64, to: i64) -> Vec<TzObservance> {
    let Ok(start) = Timestamp::from_second(from) else {
        return Vec::new();
    };
    let initial = tz.to_offset_info(start);
    let mut observances = Vec::with_capacity(estimated_observances(from, to));
    observances.push(TzObservance {
        at: from,
        from_offset: round_to_minute(initial.offset().seconds()),
        to_offset: round_to_minute(initial.offset().seconds()),
        is_dst: initial.dst().is_dst(),
        name: abbreviation(initial.abbreviation()),
        rrule: None,
    });

    let mut previous = initial.offset();
    for transition in tz.following(start) {
        let at = transition.timestamp().as_second();
        if at >= to || observances.len() >= MAX_OBSERVANCES {
            break;
        }
        observances.push(TzObservance {
            at,
            from_offset: round_to_minute(previous.seconds()),
            to_offset: round_to_minute(transition.offset().seconds()),
            is_dst: transition.dst().is_dst(),
            name: abbreviation(transition.abbreviation()),
            rrule: None,
        });
        previous = transition.offset();
    }

    label_observances(&mut observances);

    collapse_observances(observances, to)
}

fn abbreviation(name: &str) -> Option<String> {
    (!name.is_empty()
        && !name.starts_with(['+', '-'])
        && name.bytes().all(|b| b.is_ascii_alphabetic()))
    .then(|| name.to_string())
}

fn label_observances(observances: &mut [TzObservance]) {
    let mut daylight_offset = None;
    let mut standard_offset = None;

    for observance in observances.iter() {
        let slot = if observance.is_dst {
            &mut daylight_offset
        } else {
            &mut standard_offset
        };
        *slot = Some(slot.map_or(observance.to_offset, |offset: i32| {
            offset.max(observance.to_offset)
        }));
    }

    if let (Some(daylight_offset), Some(standard_offset)) = (daylight_offset, standard_offset)
        && daylight_offset < standard_offset
    {
        for observance in observances.iter_mut() {
            observance.is_dst = !observance.is_dst;
        }
    }
}

fn collapse_observances(mut observances: Vec<TzObservance>, to: i64) -> Vec<TzObservance> {
    let mut discard = vec![false; observances.len()];
    let mut unbounded: [Option<(usize, i64)>; 2] = [None, None];
    let mut trailing: [Option<(usize, u8, i16, ICalendarWeekday)>; 2] = [None, None];

    let mut onsets: Vec<(usize, i32, TzRuleKey)> = Vec::new();
    let mut runs: Vec<Range<usize>> = Vec::new();

    for is_dst in [false, true] {
        onsets.clear();
        runs.clear();

        for (index, observance) in observances.iter().enumerate() {
            if index == 0 || observance.is_dst != is_dst {
                continue;
            }
            let Some((year, key)) = observance.rule_key() else {
                continue;
            };
            let extends = onsets
                .last()
                .is_some_and(|(last_index, last_year, last_key)| {
                    last_year.saturating_add(1) == year
                        && last_key == &key
                        && observances[*last_index].name == observance.name
                });

            onsets.push((index, year, key));
            match runs.last_mut() {
                Some(run) if extends => run.end = onsets.len(),
                _ => runs.push(onsets.len() - 1..onsets.len()),
            }
        }

        for (position, run) in runs.iter().enumerate() {
            let (Some((first, _, key)), Some((last, _, _))) =
                (onsets.get(run.start), onsets.get(run.end - 1))
            else {
                continue;
            };
            if run.len() < 2 {
                continue;
            }

            let last_at = observances[*last].at;
            let is_expired = last_at.saturating_add(TZ_RULE_ACTIVE_SECONDS) < to;
            let is_final = position + 1 == runs.len() && !is_expired;
            observances[*first].rrule = Some(ICalendarRecurrenceRule {
                freq: ICalendarFrequency::Yearly,
                until: (!is_final).then(|| PartialDateTime::from_utc_timestamp(last_at)),
                bymonth: vec![ICalendarMonth::new(key.month, false)],
                byday: vec![ICalendarDay {
                    ordwk: Some(key.ordwk),
                    weekday: key.weekday,
                }],
                ..Default::default()
            });
            if is_final {
                unbounded[usize::from(is_dst)] = Some((*first, last_at));
            }

            for (index, _, _) in &onsets[run.start + 1..run.end] {
                discard[*index] = true;
            }
        }

        if let Some(run) = runs.last()
            && run.len() == 1
            && let Some((index, _, key)) = onsets.get(run.start)
        {
            trailing[usize::from(is_dst)] = Some((*index, key.month, key.ordwk, key.weekday));
        }
    }

    for is_dst in [false, true] {
        let class = usize::from(is_dst);
        let (None, Some((other_index, other_at))) =
            (unbounded[class], unbounded[usize::from(!is_dst)])
        else {
            continue;
        };

        match trailing[class] {
            Some((index, month, ordwk, weekday))
                if observances[index].at.saturating_add(TZ_RULE_ACTIVE_SECONDS) >= to =>
            {
                observances[index].rrule = Some(ICalendarRecurrenceRule {
                    freq: ICalendarFrequency::Yearly,
                    bymonth: vec![ICalendarMonth::new(month, false)],
                    byday: vec![ICalendarDay {
                        ordwk: Some(ordwk),
                        weekday,
                    }],
                    ..Default::default()
                });
                unbounded[class] = Some((index, observances[index].at));
            }
            _ => {
                if let Some(rrule) = observances[other_index].rrule.as_mut() {
                    rrule.until = Some(PartialDateTime::from_utc_timestamp(other_at));
                    unbounded[usize::from(!is_dst)] = None;
                }
            }
        }
    }

    let mut index = 0;
    observances.retain(|_| {
        let keep = !discard[index];
        index += 1;
        keep
    });

    observances
}

fn estimated_observances(from: i64, to: i64) -> usize {
    let years = to.saturating_sub(from) / TZ_RULE_ACTIVE_SECONDS;

    (years.clamp(0, 1024) as usize) * 2 + 2
}

/// Returns a civil datetime as seconds since the Unix epoch, read as UTC.
fn naive_seconds(date_time: civil::DateTime) -> i64 {
    Offset::UTC
        .to_timestamp(date_time)
        .map_or(0, |timestamp| timestamp.as_second())
}

fn round_to_minute(offset: i32) -> i32 {
    let minutes = (offset.unsigned_abs() + 30) / 60 * 60;

    if offset < 0 {
        -(minutes as i32)
    } else {
        minutes as i32
    }
}

fn offset_to_partial(offset: i32) -> PartialDateTime {
    let seconds = offset.unsigned_abs();

    PartialDateTime {
        tz_hour: u8::try_from(seconds / 3600).ok(),
        tz_minute: u8::try_from((seconds % 3600) / 60).ok(),
        tz_minus: offset < 0,
        ..Default::default()
    }
}

fn recurrence_span_of(freq: &ICalendarFrequency, count: u32, interval: Option<u16>) -> i64 {
    let unit = match freq {
        ICalendarFrequency::Yearly => 366 * 86400,
        ICalendarFrequency::Monthly => 31 * 86400,
        ICalendarFrequency::Weekly => 7 * 86400,
        ICalendarFrequency::Daily => 86400,
        ICalendarFrequency::Hourly => 3600,
        ICalendarFrequency::Minutely => 60,
        ICalendarFrequency::Secondly => 1,
    };

    i64::from(count)
        .saturating_mul(i64::from(interval.unwrap_or(1)))
        .saturating_mul(unit)
}

fn expand_range(range: &mut Option<(i64, i64)>, value: &PartialDateTime) {
    let Some(timestamp) = value.to_date_time().map(|result| {
        naive_seconds(result.date_time)
            - result
                .offset
                .map_or(0, |offset| i64::from(offset.seconds()))
    }) else {
        return;
    };

    match range {
        Some((min, max)) => {
            *min = (*min).min(timestamp);
            *max = (*max).max(timestamp);
        }
        None => {
            *range = Some((timestamp, timestamp));
        }
    }
}

fn naive_utc(timestamp: i64) -> civil::DateTime {
    Timestamp::from_second(timestamp).map_or(civil::DateTime::default(), |timestamp| {
        Offset::UTC.to_datetime(timestamp)
    })
}

fn year_of(timestamp: i64) -> i32 {
    i32::from(naive_utc(timestamp).year())
}

fn start_of_year(year: i32) -> i64 {
    i16::try_from(year)
        .ok()
        .and_then(|year| civil::DateTime::new(year, 1, 1, 0, 0, 0, 0).ok())
        .map_or(0, naive_seconds)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    i16::try_from(year)
        .ok()
        .zip(i8::try_from(month).ok())
        .and_then(|(year, month)| Date::new(year, month, 1).ok())
        .map_or(31, |date| u32::from(date.days_in_month().unsigned_abs()))
}

fn weekday_of(weekday: Weekday) -> ICalendarWeekday {
    match weekday {
        Weekday::Monday => ICalendarWeekday::Monday,
        Weekday::Tuesday => ICalendarWeekday::Tuesday,
        Weekday::Wednesday => ICalendarWeekday::Wednesday,
        Weekday::Thursday => ICalendarWeekday::Thursday,
        Weekday::Friday => ICalendarWeekday::Friday,
        Weekday::Saturday => ICalendarWeekday::Saturday,
        Weekday::Sunday => ICalendarWeekday::Sunday,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/icalendar/timezone/tests.rs"]
mod tests;
