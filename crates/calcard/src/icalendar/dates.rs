/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarPeriod, ICalendarProperty,
    ICalendarRecurrenceRule, ICalendarValue, timezone::TzResolver,
};
use crate::{
    common::{
        DateTimeResult,
        timezone::{NominalDuration, Tz, ZonedDateTime},
    },
    datecalc::{MAX_UNPRODUCTIVE_WORK, error::RRuleError, rrule::RRule},
    icalendar::ICalendarParameterName,
};
use ahash::{AHashMap, AHashSet};
use jiff::{SignedDuration, civil};
use std::{
    collections::hash_map::Entry,
    fmt::{Display, Formatter},
    hash::Hash,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize)
)]
pub struct CalendarExpand {
    pub events: Vec<CalendarEvent>,
    pub errors: Vec<CalendarError>,
}

/// One instance of a calendar component, with its end already resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize)
)]
pub struct CalendarEvent {
    pub comp_id: u32,
    pub start: ZonedDateTime,
    pub end: ZonedDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize)
)]
pub struct CalendarError {
    pub comp_id: u32,
    pub error: CalendarErrorType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize)
)]
pub enum CalendarErrorType {
    MissingDtStart,
    InvalidDtStart,
    InvalidDtEnd,
    InvalidDuration,
    RRule(RRuleError),
    ExpansionLimitReached,
}

impl ICalendar {
    pub fn expand_dates(&self, default_tz: impl Into<Tz>, mut limit: usize) -> CalendarExpand {
        let tz_resolver = self.build_tz_resolver().with_default(default_tz);
        let mut expand = CalendarExpand::default();
        let mut recurrences = Vec::new();
        let mut overridden = OverriddenInstances::default();

        for (comp_id, comp) in self.components.iter().enumerate() {
            if comp.component_type.has_time_ranges() {
                match comp.build_calendar_date(comp_id as u32, &tz_resolver) {
                    Ok(Some(mut event)) => {
                        if event.rid.is_some() {
                            expand
                                .events
                                .extend(event.rdates.drain(..).map(|rdate| rdate.event));
                            overridden.insert(comp_id as u32, event);
                        } else if event.rrule.is_some()
                            || !event.rdates.is_empty()
                            || !event.exdates.is_empty()
                        {
                            recurrences.push((comp_id as u32, event));
                        } else if let Some(cal_event) = event.event {
                            expand.events.push(cal_event);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        expand.errors.push(CalendarError {
                            comp_id: comp_id as u32,
                            error,
                        });
                    }
                }
            }
        }

        // Expand recurrences
        let mut unproductive_budget = MAX_UNPRODUCTIVE_WORK;
        for (series_id, event) in &mut recurrences {
            let mut comp_id = *series_id;
            let length = event.length();
            let exdates = event
                .exdates
                .iter()
                .filter_map(|(tz_id, dt)| {
                    dt.to_date_time_with_tz(tz_id.map_or(event.start_tz, |tz_id| {
                        tz_resolver.resolve_or_default(Some(tz_id))
                    }))
                })
                .collect::<AHashSet<_>>();
            let start_instance = event
                .rrule
                .is_none()
                .then(|| event.event.take())
                .flatten()
                .map(|start| RecurrenceInstance {
                    event: start,
                    length,
                });
            for instance in std::mem::take(&mut event.rdates)
                .into_iter()
                .chain(start_instance)
            {
                match overridden.take(event, &instance.event.start) {
                    Some((_, overridden_event)) => expand.events.extend(
                        overridden_event
                            .replacing(instance.event.start, instance.length)
                            .map(|(replacement, _)| replacement),
                    ),
                    None if !exdates.contains(&instance.event.start) => {
                        expand.events.push(instance.event)
                    }
                    None => {}
                }
            }
            let Some(rrule) = event.rrule.take() else {
                continue;
            };
            let rrule = match RRule::from_ical(rrule, event.dt_start_zoned, event.is_date) {
                Ok(rrule) => rrule,
                Err(err) => {
                    expand.errors.push(CalendarError {
                        comp_id,
                        error: CalendarErrorType::RRule(err),
                    });
                    continue;
                }
            };
            let mut override_offset = None;
            let mut override_duration = None;
            let mut instances = rrule.iter().with_unproductive_budget(unproductive_budget);

            while limit != 0 {
                let Some(date) = instances.next() else {
                    break;
                };
                limit -= 1;
                if event.rdate_starts.contains(&date) {
                    continue;
                }
                match overridden.take(event, &date) {
                    Some((new_comp_id, overridden_event)) => {
                        if let Some((new_event, new_duration)) =
                            overridden_event.replacing(date, length)
                        {
                            if overridden_event.rid_this_and_future {
                                comp_id = new_comp_id;
                                override_offset =
                                    Some(DefaultDuration::shift(date, new_event.start));
                                override_duration = Some(new_duration);
                            }
                            expand.events.push(new_event);
                        }
                    }
                    None if !exdates.contains(&date) => {
                        let start = match override_offset {
                            Some(offset) => match offset.after(date) {
                                Some(start) => start,
                                None => continue,
                            },
                            None => date,
                        };
                        let duration = override_duration.unwrap_or(event.default_duration);
                        if let Some(end) = duration.after(start) {
                            expand.events.push(CalendarEvent {
                                start,
                                end,
                                comp_id,
                            });
                        }
                    }
                    None => {}
                }
            }

            unproductive_budget = instances.unproductive_budget();
            if instances.is_exhausted() {
                expand.errors.push(CalendarError {
                    comp_id,
                    error: CalendarErrorType::ExpansionLimitReached,
                });
            }
        }

        // Add missing overridden events (this should not occur unless the iCalendar is malformed)
        expand.events.extend(overridden.into_events(&recurrences));

        expand
    }
}

/// How long an instance of a component lasts.
#[derive(Debug, Clone, Copy)]
enum DefaultDuration {
    Exact(SignedDuration),
    Nominal(NominalDuration),
}

impl DefaultDuration {
    /// Returns the duration between the start and end of a series, as
    /// RFC 5545 section 3.8.5.3 says every instance of it should last.
    fn between(start: ZonedDateTime, end: ZonedDateTime, has_time: bool) -> Self {
        if has_time {
            Self::Exact(SignedDuration::from_secs(
                end.timestamp() - start.timestamp(),
            ))
        } else {
            Self::Nominal(NominalDuration::new(end.days_since(start), 0))
        }
    }

    /// Returns the end of an instance that starts at `start`.
    fn shift(from: ZonedDateTime, to: ZonedDateTime) -> Self {
        if from.timezone() == to.timezone() {
            Self::Nominal(NominalDuration::between(from, to))
        } else {
            Self::Exact(to.signed_duration_since(from))
        }
    }

    fn after(&self, start: ZonedDateTime) -> Option<ZonedDateTime> {
        match self {
            Self::Exact(duration) => start.checked_add(*duration),
            Self::Nominal(duration) => start.checked_add_nominal(*duration),
        }
    }
}

struct CalendarEventBuilder<'x> {
    event: Option<CalendarEvent>,
    component_type: &'x ICalendarComponentType,
    start_tz: Tz,
    default_duration: DefaultDuration,
    inherits_start: bool,
    instance_end: InstanceEnd,
    dt_start_zoned: ZonedDateTime,
    is_date: bool,
    rrule: Option<&'x ICalendarRecurrenceRule>,
    uid: Option<&'x str>,
    sequence: i64,
    rdates: Vec<RecurrenceInstance>,
    rdate_starts: AHashSet<ZonedDateTime>,
    exdates: Vec<(Option<&'x str>, DateTimeResult)>,
    rid: Option<ZonedDateTime>,
    rid_this_and_future: bool,
}

#[derive(Debug, Clone, Copy)]
struct RecurrenceInstance {
    event: CalendarEvent,
    length: InstanceLength,
}

#[derive(Debug, Clone, Copy)]
struct InstanceLength {
    duration: DefaultDuration,
    is_date: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstanceEnd {
    Inherited,
    Relative,
    Fixed,
}

impl InstanceEnd {
    fn of(tz_id: Option<&str>, end: &DateTimeResult) -> Self {
        if tz_id.is_some() || end.tz().is_some() {
            InstanceEnd::Fixed
        } else {
            InstanceEnd::Relative
        }
    }
}

impl CalendarEventBuilder<'_> {
    fn length(&self) -> InstanceLength {
        InstanceLength {
            duration: self.default_duration,
            is_date: self.is_date,
        }
    }

    fn anchor(&self, recurrence_id: ZonedDateTime) -> Option<ZonedDateTime> {
        if recurrence_id.timezone().is_floating() {
            self.start_tz.from_local(recurrence_id.naive_local())
        } else {
            Some(recurrence_id.with_timezone(self.start_tz))
        }
    }

    fn replacing(
        &self,
        start: ZonedDateTime,
        replaced: InstanceLength,
    ) -> Option<(CalendarEvent, DefaultDuration)> {
        let event = self.event?;
        if !self.inherits_start || self.is_date != replaced.is_date {
            return Some((event, self.default_duration));
        }
        let (end, duration) = match self.instance_end {
            InstanceEnd::Fixed => (
                event.end,
                DefaultDuration::Exact(event.end.signed_duration_since(start)),
            ),
            InstanceEnd::Relative => (
                self.default_duration.after(start).unwrap_or(event.end),
                self.default_duration,
            ),
            InstanceEnd::Inherited => (
                replaced.duration.after(start).unwrap_or(event.end),
                replaced.duration,
            ),
        };
        Some((
            CalendarEvent {
                start,
                end,
                ..event
            },
            duration,
        ))
    }
}

type OverriddenInstance<'x> = (u32, CalendarEventBuilder<'x>);

type OverrideKey<'x, T> = (Option<&'x str>, &'x ICalendarComponentType, T);

#[derive(Default)]
struct OverriddenInstances<'x> {
    zoned: AHashMap<OverrideKey<'x, ZonedDateTime>, OverriddenInstance<'x>>,
    floating: AHashMap<OverrideKey<'x, civil::DateTime>, OverriddenInstance<'x>>,
}

impl<'x> OverriddenInstances<'x> {
    fn insert(&mut self, comp_id: u32, instance: CalendarEventBuilder<'x>) {
        match instance.rid {
            Some(rid) if rid.timezone().is_floating() => {
                Self::insert_latest(
                    &mut self.floating,
                    (instance.uid, instance.component_type, rid.naive_local()),
                    (comp_id, instance),
                );
            }
            Some(rid) => {
                Self::insert_latest(
                    &mut self.zoned,
                    (instance.uid, instance.component_type, rid),
                    (comp_id, instance),
                );
            }
            None => {}
        }
    }

    fn insert_latest<K: Eq + Hash>(
        instances: &mut AHashMap<K, OverriddenInstance<'x>>,
        key: K,
        instance: OverriddenInstance<'x>,
    ) {
        match instances.entry(key) {
            Entry::Occupied(current) if current.get().1.sequence > instance.1.sequence => {}
            Entry::Occupied(mut current) => {
                current.insert(instance);
            }
            Entry::Vacant(slot) => {
                slot.insert(instance);
            }
        }
    }

    fn take(
        &mut self,
        series: &CalendarEventBuilder<'x>,
        start: &ZonedDateTime,
    ) -> Option<OverriddenInstance<'x>> {
        (!self.zoned.is_empty())
            .then(|| {
                self.zoned
                    .remove(&(series.uid, series.component_type, *start))
            })
            .flatten()
            .or_else(|| {
                (!self.floating.is_empty())
                    .then(|| {
                        self.floating.remove(&(
                            series.uid,
                            series.component_type,
                            start.naive_local(),
                        ))
                    })
                    .flatten()
            })
    }

    fn into_events<'y>(
        self,
        recurrences: &'y [(u32, CalendarEventBuilder<'x>)],
    ) -> impl Iterator<Item = CalendarEvent> + use<'x, 'y> {
        let series = if self.zoned.is_empty() && self.floating.is_empty() {
            AHashMap::new()
        } else {
            recurrences
                .iter()
                .rev()
                .map(|(_, series)| ((series.uid, series.component_type), series))
                .collect::<AHashMap<_, _>>()
        };
        self.zoned
            .into_values()
            .chain(self.floating.into_values())
            .filter_map(move |(_, instance)| {
                series
                    .get(&(instance.uid, instance.component_type))
                    .and_then(|series| {
                        instance.replacing(series.anchor(instance.rid?)?, series.length())
                    })
                    .map(|(replacement, _)| replacement)
                    .or(instance.event)
            })
    }
}

/// How an `RDATE` of PERIOD value type names the end of its instance.
enum PeriodEnd {
    Time(DateTimeResult),
    Duration(NominalDuration),
}

impl ICalendarComponent {
    fn build_calendar_date(
        &self,
        comp_id: u32,
        tz_resolver: &TzResolver<&'_ str>,
    ) -> Result<Option<CalendarEventBuilder<'_>>, CalendarErrorType> {
        let mut dt_start = None;
        let mut dt_start_tzid = None;
        let mut dt_start_has_time = false;
        let mut dt_end: Option<DateTimeResult> = None;
        let mut dt_end_tzid = None;
        let mut todo_dates = vec![];
        let mut rid: Option<DateTimeResult> = None;
        let mut rid_tzid = None;
        let mut rid_has_time = false;
        let mut rid_this_and_future = false;
        let mut duration = None;
        let mut rrule = None;
        let mut uid = None;
        let mut sequence = 0;
        let mut rdates = vec![];
        let mut rdates_periods = vec![];
        let mut exdates = vec![];

        for entry in &self.entries {
            match (&entry.name, entry.values.first()) {
                (ICalendarProperty::Dtstart, Some(ICalendarValue::PartialDateTime(dt))) => {
                    dt_start = dt.to_date_time();
                    dt_start_tzid = entry.tz_id();
                    dt_start_has_time = dt.has_time();
                }
                (ICalendarProperty::Dtend, Some(ICalendarValue::PartialDateTime(dt))) => {
                    if let Some(dt) = dt.to_date_time() {
                        dt_end = Some(dt);
                        dt_end_tzid = entry.tz_id();
                    }
                }
                (
                    ICalendarProperty::Due
                    | ICalendarProperty::Completed
                    | ICalendarProperty::Created,
                    Some(ICalendarValue::PartialDateTime(dt)),
                ) if self.component_type == ICalendarComponentType::VTodo => {
                    todo_dates.push((&entry.name, dt.to_date_time(), entry.tz_id()));
                }
                (ICalendarProperty::RecurrenceId, Some(ICalendarValue::PartialDateTime(value))) => {
                    if let Some(dt) = value.to_date_time() {
                        for param in &entry.params {
                            match &param.name {
                                ICalendarParameterName::Tzid => {
                                    rid_tzid = param.value.as_text();
                                }
                                ICalendarParameterName::Range => {
                                    rid_this_and_future = true;
                                }
                                _ => (),
                            }
                        }

                        rid_has_time = value.has_time();
                        rid = Some(dt);
                    }
                }
                (ICalendarProperty::Duration, Some(ICalendarValue::Duration(dur))) => {
                    duration = Some(dur);
                }
                (ICalendarProperty::Rrule, Some(ICalendarValue::RecurrenceRule(rule)))
                    if rrule.is_none() =>
                {
                    rrule = Some(rule);
                }
                (ICalendarProperty::Uid, Some(ICalendarValue::Text(value))) => {
                    uid = Some(value.as_str());
                }
                (ICalendarProperty::Sequence, Some(ICalendarValue::Integer(value))) => {
                    sequence = *value;
                }
                (ICalendarProperty::Rdate, _) => {
                    let tz_id = entry.tz_id();
                    for value in &entry.values {
                        match value {
                            ICalendarValue::PartialDateTime(dt) => {
                                if let Some(dt) = dt.to_date_time() {
                                    rdates.push((tz_id, dt));
                                }
                            }
                            ICalendarValue::Period(period) => match period.as_ref() {
                                ICalendarPeriod::Range { start, end } => {
                                    if let (Some(start), Some(end)) =
                                        (start.to_date_time(), end.to_date_time())
                                    {
                                        rdates_periods.push((tz_id, start, PeriodEnd::Time(end)));
                                    }
                                }
                                ICalendarPeriod::Duration { start, duration } => {
                                    if let (Some(start), Some(duration)) =
                                        (start.to_date_time(), duration.to_nominal())
                                    {
                                        rdates_periods.push((
                                            tz_id,
                                            start,
                                            PeriodEnd::Duration(duration),
                                        ));
                                    }
                                }
                            },
                            _ => (),
                        }
                    }
                }
                (ICalendarProperty::Exdate, _) => {
                    let tz_id = entry.tz_id();
                    for value in &entry.values {
                        if let ICalendarValue::PartialDateTime(dt) = value
                            && let Some(dt) = dt.to_date_time()
                        {
                            exdates.push((tz_id, dt));
                        }
                    }
                }
                _ => (),
            }
        }

        let has_start = dt_start.is_some();
        let dt_start = match dt_start {
            Some(dt_start) => dt_start,
            None => match &rid {
                Some(rid) => {
                    dt_start_tzid = rid_tzid;
                    dt_start_has_time = rid_has_time;
                    rid.clone()
                }
                None => match self.component_type {
                    ICalendarComponentType::VEvent => {
                        return Err(CalendarErrorType::MissingDtStart);
                    }
                    ICalendarComponentType::VTodo => {
                        let mut due_idx = None;
                        let mut completed_idx = None;
                        let mut created_idx = None;

                        for (idx, (prop, dt, _)) in todo_dates.iter().enumerate() {
                            if dt.is_some() {
                                match prop {
                                    ICalendarProperty::Due => due_idx = Some(idx),
                                    ICalendarProperty::Completed => completed_idx = Some(idx),
                                    ICalendarProperty::Created => created_idx = Some(idx),
                                    _ => (),
                                }
                            }
                        }

                        match (due_idx, completed_idx, created_idx) {
                            (Some(due_idx), _, _) => {
                                let due = &mut todo_dates[due_idx];
                                dt_start_tzid = due.2;
                                dt_start_has_time = true;
                                due.1.take().unwrap()
                            }
                            (_, Some(completed_idx), Some(created_idx)) => {
                                let completed = &mut todo_dates[completed_idx];
                                dt_end = completed.1.take();
                                dt_end_tzid = completed.2;

                                let created = &mut todo_dates[created_idx];
                                dt_start_tzid = created.2;
                                created.1.take().unwrap()
                            }
                            (_, Some(date_idx), _) | (_, _, Some(date_idx)) => {
                                let date = &mut todo_dates[date_idx];
                                dt_start_tzid = date.2;
                                dt_start_has_time = true;
                                date.1.take().unwrap()
                            }
                            _ => {
                                return Ok(None);
                            }
                        }
                    }
                    _ => {
                        return Ok(None);
                    }
                },
            },
        };
        let mut event = None;
        let is_instance = rid.is_some();
        let start_tz = dt_start
            .tz()
            .unwrap_or_else(|| tz_resolver.resolve_or_default(dt_start_tzid));
        let value_tz = |tz_id: Option<&str>| {
            tz_id.map_or(start_tz, |tz_id| {
                tz_resolver.resolve_or_default(Some(tz_id))
            })
        };
        let dt_start_tz = dt_start
            .to_date_time_with_tz(start_tz)
            .ok_or(CalendarErrorType::InvalidDtStart)?;
        let mut instance_end = InstanceEnd::Relative;
        let default_duration = if let Some(dt_end) = dt_end {
            let end = dt_end
                .to_date_time_with_tz(tz_resolver.resolve_or_default(dt_end_tzid.or(dt_start_tzid)))
                .ok_or(CalendarErrorType::InvalidDtEnd)?;

            if rrule.is_none() || is_instance {
                event = Some(CalendarEvent {
                    start: dt_start_tz,
                    end,
                    comp_id,
                });
            }
            instance_end = InstanceEnd::of(dt_end_tzid, &dt_end);
            DefaultDuration::between(dt_start_tz, end, dt_start_has_time)
        } else if let Some(duration) = duration {
            let duration = duration
                .to_nominal()
                .ok_or(CalendarErrorType::InvalidDuration)?;
            let duration = DefaultDuration::Nominal(duration);
            if rrule.is_none() || is_instance {
                event = Some(CalendarEvent {
                    start: dt_start_tz,
                    end: duration
                        .after(dt_start_tz)
                        .ok_or(CalendarErrorType::InvalidDuration)?,
                    comp_id,
                });
            }
            duration
        } else if let Some((due, due_tzid)) = todo_dates
            .into_iter()
            .filter_map(|(prop, dt, tz_id)| {
                if prop == &ICalendarProperty::Due {
                    dt.map(|dt| (dt, tz_id))
                } else {
                    None
                }
            })
            .next()
        {
            let end = due
                .to_date_time_with_tz(tz_resolver.resolve_or_default(due_tzid.or(dt_start_tzid)))
                .ok_or(CalendarErrorType::InvalidDtEnd)?;

            if rrule.is_none() || is_instance {
                event = Some(CalendarEvent {
                    start: dt_start_tz,
                    end,
                    comp_id,
                });
            }
            instance_end = InstanceEnd::of(due_tzid, &due);
            DefaultDuration::between(dt_start_tz, end, dt_start_has_time)
        } else {
            /*
               For cases where a "VEVENT" calendar component
               specifies a "DTSTART" property with a DATE value type but no
               "DTEND" nor "DURATION" property, the event's duration is taken to
               be one day.  For cases where a "VEVENT" calendar component
               specifies a "DTSTART" property with a DATE-TIME value type but no
               "DTEND" property, the event ends on the same calendar date and
               time of day specified by the "DTSTART" property.
            */

            instance_end = InstanceEnd::Inherited;
            let duration =
                if dt_start_has_time || self.component_type == ICalendarComponentType::VTodo {
                    DefaultDuration::Exact(SignedDuration::ZERO)
                } else {
                    DefaultDuration::Nominal(NominalDuration::DAY)
                };
            if rrule.is_none() || is_instance {
                event = Some(CalendarEvent {
                    start: dt_start_tz,
                    end: duration
                        .after(dt_start_tz)
                        .ok_or(CalendarErrorType::InvalidDuration)?,
                    comp_id,
                });
            }
            duration
        };
        let rid = rid.and_then(|rid| {
            rid.to_date_time_with_tz(rid_tzid.map_or(Tz::Floating, |tz_id| {
                tz_resolver.resolve_or_default(Some(tz_id))
            }))
        });

        // Add rdates
        let is_date = !dt_start_has_time;
        let series_length = InstanceLength {
            duration: default_duration,
            is_date,
        };
        let mut rdate_events = rdates
            .into_iter()
            .filter_map(|(tz_id, rdate)| {
                let start = rdate.to_date_time_with_tz(value_tz(tz_id))?;
                Some(RecurrenceInstance {
                    event: CalendarEvent {
                        start,
                        end: default_duration.after(start)?,
                        comp_id,
                    },
                    length: series_length,
                })
            })
            .chain(
                rdates_periods
                    .into_iter()
                    .filter_map(|(tz_id, start, end)| {
                        let tz = value_tz(tz_id);
                        let start = start.to_date_time_with_tz(tz)?;
                        let (end, duration) = match end {
                            PeriodEnd::Time(end) => {
                                let end = end.to_date_time_with_tz(tz)?;
                                (
                                    end,
                                    DefaultDuration::Exact(end.signed_duration_since(start)),
                                )
                            }
                            PeriodEnd::Duration(duration) => {
                                let duration = DefaultDuration::Nominal(duration);
                                (duration.after(start)?, duration)
                            }
                        };
                        Some(RecurrenceInstance {
                            event: CalendarEvent {
                                start,
                                end,
                                comp_id,
                            },
                            length: InstanceLength {
                                duration,
                                is_date: false,
                            },
                        })
                    }),
            )
            .collect::<Vec<_>>();
        let mut rdate_starts = AHashSet::new();
        if !rdate_events.is_empty() {
            rdate_events.retain(|rdate| rdate_starts.insert(rdate.event.start));
            if event
                .as_ref()
                .is_some_and(|event| rdate_starts.contains(&event.start))
            {
                event = None;
            }
        }

        Ok(Some(CalendarEventBuilder {
            event,
            component_type: &self.component_type,
            default_duration,
            inherits_start: is_instance && !has_start,
            instance_end,
            dt_start_zoned: dt_start_tz,
            is_date,
            uid,
            sequence,
            rrule: rrule.map(|rule| &**rule),
            rdates: rdate_events,
            rdate_starts,
            exdates,
            start_tz,
            rid,
            rid_this_and_future,
        }))
    }
}

impl CalendarEvent {
    /// Returns the instant the instance starts and the instant it ends.
    pub fn timestamps(&self) -> (i64, i64) {
        (self.start.timestamp(), self.end.timestamp())
    }

    /// Returns the wall clock readings of the start and end, as seconds since
    /// the Unix epoch, for callers that index instances by displayed time.
    pub fn naive_timestamps(&self) -> (i64, i64) {
        (self.start.naive_timestamp(), self.end.naive_timestamp())
    }
}

impl Display for CalendarErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CalendarErrorType::MissingDtStart => write!(f, "Missing DTSTART property"),
            CalendarErrorType::InvalidDtStart => write!(f, "Invalid DTSTART property"),
            CalendarErrorType::InvalidDtEnd => write!(f, "Invalid DTEND property"),
            CalendarErrorType::InvalidDuration => write!(f, "Invalid DURATION property"),
            CalendarErrorType::RRule(err) => write!(f, "RRule error: {err}"),
            CalendarErrorType::ExpansionLimitReached => {
                write!(f, "Recurrence expansion gave up before the rule finished")
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/icalendar/dates/tests.rs"]
mod tests;
