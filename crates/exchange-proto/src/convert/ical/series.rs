/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::{
        PartialDateTime,
        timezone::{Tz, ZonedDateTime},
    },
    datecalc::RRule,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarProperty,
        ICalendarRecurrenceRule, ICalendarValue, timezone::TzResolver,
    },
};
use jiff::{SignedDuration, Timestamp, civil::DateTime};

use super::RecurrenceId;

pub(super) const MAX_INSTANCE_SCAN: usize = 1 << 16;
pub(super) const MAX_RECURRENCE_RULES: usize = 4;
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeForm {
    Date,
    Utc,
    Floating,
    Zoned,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Span {
    pub start: ZonedDateTime,
    pub end: ZonedDateTime,
    pub all_day: bool,
}

impl Span {
    pub fn duration(&self) -> SignedDuration {
        self.end.signed_duration_since(self.start)
    }
}

pub(super) struct Series<'c> {
    pub ical: &'c ICalendar,
    resolver: TzResolver<&'c str>,
    pub master: Option<usize>,
    pub main: usize,
    pub tz: Tz,
}

impl<'c> Series<'c> {
    pub fn new(ical: &'c ICalendar) -> Option<Self> {
        Self::of(ical, ICalendarComponentType::VEvent)
    }

    pub fn of(ical: &'c ICalendar, kind: ICalendarComponentType) -> Option<Self> {
        let mut events = ical
            .components
            .iter()
            .enumerate()
            .filter(|(_, component)| component.component_type == kind);
        let (first, _) = events.clone().next()?;
        let master = events
            .find(|(_, component)| !component.is_recurrence_override())
            .map(|(index, _)| index);
        let main = master.unwrap_or(first);
        let mut series = Series {
            ical,
            resolver: ical.build_tz_resolver(),
            master,
            main,
            tz: Tz::Floating,
        };
        series.tz = series
            .component(main)
            .and_then(|component| component.property(&ICalendarProperty::Dtstart))
            .map_or(Tz::Floating, |entry| series.entry_zone(entry));
        Some(series)
    }

    pub fn component(&self, index: usize) -> Option<&'c ICalendarComponent> {
        self.ical.components.get(index)
    }

    pub fn uid(&self) -> Option<&'c str> {
        self.component(self.main)?.uid()
    }

    pub fn entry_zone(&self, entry: &ICalendarEntry) -> Tz {
        match time_form(entry) {
            Some(TimeForm::Utc) => Tz::UTC,
            Some(TimeForm::Zoned) => entry
                .tz_id()
                .and_then(|id| self.resolver.resolve(id))
                .unwrap_or(Tz::Floating),
            _ => Tz::Floating,
        }
    }

    pub fn resolve(
        &self,
        entry: &ICalendarEntry,
        value: &PartialDateTime,
    ) -> Option<ZonedDateTime> {
        let result = value.to_date_time()?;
        if !value.has_time() {
            return self.tz.from_local(result.date_time);
        }
        let zone = if value.has_zone() {
            Tz::UTC
        } else {
            self.entry_zone(entry)
        };
        result.to_date_time_with_tz(zone)
    }

    pub fn resolve_first(&self, entry: &ICalendarEntry) -> Option<ZonedDateTime> {
        self.resolve(entry, first_date_time(entry)?)
    }

    pub fn recurrence_id(&self, component: &ICalendarComponent) -> Option<RecurrenceId> {
        let entry = component.property(&ICalendarProperty::RecurrenceId)?;
        self.resolve_first(entry)
            .map(|zoned| RecurrenceId(zoned.to_timestamp()))
    }

    pub fn overrides(&self) -> impl Iterator<Item = (usize, &'c ICalendarComponent, RecurrenceId)> {
        let uid = self.uid();
        let kind = self.component(self.main).map(|main| &main.component_type);
        let components = &self.ical.components;
        components
            .first()
            .into_iter()
            .flat_map(|root| root.component_ids.iter())
            .filter_map(move |id| {
                let index = *id as usize;
                components.get(index).map(|component| (index, component))
            })
            .filter(move |(_, component)| {
                kind == Some(&component.component_type) && component.uid() == uid
            })
            .filter_map(|(index, component)| {
                self.recurrence_id(component)
                    .map(|id| (index, component, id))
            })
    }

    pub fn find_override(&self, id: RecurrenceId) -> Option<usize> {
        self.overrides()
            .find(|(_, _, rid)| *rid == id)
            .map(|(index, _, _)| index)
    }

    pub fn span(&self, component: &ICalendarComponent) -> Option<Span> {
        let start_entry = component.property(&ICalendarProperty::Dtstart)?;
        let start_value = first_date_time(start_entry)?;
        let start = self.resolve(start_entry, start_value)?;
        let all_day = !start_value.has_time();
        let end = component
            .property(&ICalendarProperty::Dtend)
            .and_then(|entry| self.resolve_first(entry))
            .or_else(|| {
                component
                    .property(&ICalendarProperty::Duration)
                    .and_then(|entry| entry.values.first())
                    .and_then(|value| match value {
                        ICalendarValue::Duration(duration) => duration.to_nominal(),
                        _ => None,
                    })
                    .and_then(|duration| start.checked_add_nominal(duration))
            })
            .or_else(|| {
                if all_day {
                    start.checked_add(SignedDuration::from_secs(SECONDS_PER_DAY))
                } else {
                    Some(start)
                }
            })?;
        Some(Span {
            start,
            end: end.max(start),
            all_day,
        })
    }

    pub fn dates(
        &self,
        component: &'c ICalendarComponent,
        property: &'static ICalendarProperty,
    ) -> impl Iterator<Item = ZonedDateTime> + '_ {
        component.properties(property).flat_map(move |entry| {
            entry.values.iter().filter_map(move |value| {
                value
                    .as_partial_date_time()
                    .and_then(|value| self.resolve(entry, value))
            })
        })
    }

    pub fn exdates(&self) -> impl Iterator<Item = ZonedDateTime> + '_ {
        self.master
            .and_then(|index| self.component(index))
            .into_iter()
            .flat_map(|master| self.dates(master, &ICalendarProperty::Exdate))
    }

    pub fn excluded(&self, id: RecurrenceId) -> bool {
        self.exdates().any(|zoned| zoned.to_timestamp() == id.0)
    }

    pub fn is_instance(&self, id: RecurrenceId) -> bool {
        let mut ids = vec![id];
        self.retain_instances(&mut ids);
        !ids.is_empty()
    }

    pub fn is_recurring(&self) -> bool {
        self.master
            .and_then(|index| self.component(index))
            .is_some_and(|master| {
                master.property(&ICalendarProperty::Rrule).is_some()
                    || master.property(&ICalendarProperty::Rdate).is_some()
            })
    }

    pub fn rules_capped(&self) -> bool {
        self.master
            .and_then(|index| self.component(index))
            .is_some_and(|master| recurrence_rules(master).nth(MAX_RECURRENCE_RULES).is_some())
    }

    pub fn nth_instance(&self, index: usize) -> Option<RecurrenceId> {
        let position = index.checked_sub(1)?;
        let master = self.master.and_then(|index| self.component(index))?;
        let span = self.span(master)?;
        let mut members: Vec<Timestamp> = self
            .dates(master, &ICalendarProperty::Rdate)
            .take(MAX_INSTANCE_SCAN)
            .map(|zoned| zoned.to_timestamp())
            .collect();
        let mut recurring = !members.is_empty();
        members.push(span.start.to_timestamp());
        for rule in recurrence_rules(master).take(MAX_RECURRENCE_RULES) {
            let Ok(rule) = RRule::from_ical(rule, span.start, span.all_day) else {
                continue;
            };
            recurring = true;
            members.extend(
                rule.iter()
                    .take(index.min(MAX_INSTANCE_SCAN))
                    .map(|instance| instance.to_timestamp()),
            );
        }
        if !recurring {
            return None;
        }
        members.sort_unstable();
        members.dedup();
        members.get(position).copied().map(RecurrenceId)
    }

    pub fn retain_instances(&self, ids: &mut Vec<RecurrenceId>) {
        ids.sort_unstable();
        ids.dedup();
        let Some((master, span)) = self
            .master
            .and_then(|index| self.component(index))
            .and_then(|master| Some((master, self.span(master)?)))
        else {
            ids.clear();
            return;
        };
        let Some(&RecurrenceId(last)) = ids.last() else {
            return;
        };
        let mut excluded: Vec<Timestamp> =
            self.exdates().map(|zoned| zoned.to_timestamp()).collect();
        excluded.sort_unstable();
        let mut members: Vec<Timestamp> = self
            .dates(master, &ICalendarProperty::Rdate)
            .map(|zoned| zoned.to_timestamp())
            .collect();
        members.push(span.start.to_timestamp());
        for rule in recurrence_rules(master).take(MAX_RECURRENCE_RULES) {
            let Ok(rule) = RRule::from_ical(rule, span.start, span.all_day) else {
                continue;
            };
            let mut pending = ids.iter().map(|id| id.0).peekable();
            for instant in rule
                .iter()
                .take(MAX_INSTANCE_SCAN)
                .map(|instance| instance.to_timestamp())
                .take_while(|instant| *instant <= last)
            {
                while pending.next_if(|id| *id < instant).is_some() {}
                if pending.next_if_eq(&instant).is_some() {
                    members.push(instant);
                }
                if pending.peek().is_none() {
                    break;
                }
            }
        }
        members.sort_unstable();
        ids.retain(|id| {
            members.binary_search(&id.0).is_ok() && excluded.binary_search(&id.0).is_err()
        });
    }

    pub fn at(&self, instant: Timestamp) -> ZonedDateTime {
        self.tz.from_timestamp(instant)
    }

    pub fn local(&self, instant: Timestamp) -> DateTime {
        self.at(instant).naive_local()
    }
}

pub(super) fn first_date_time(entry: &ICalendarEntry) -> Option<&PartialDateTime> {
    entry
        .values
        .first()
        .and_then(ICalendarValue::as_partial_date_time)
}

pub(super) fn recurrence_rules(
    component: &ICalendarComponent,
) -> impl Iterator<Item = &ICalendarRecurrenceRule> {
    component
        .properties(&ICalendarProperty::Rrule)
        .filter_map(|entry| match entry.values.first() {
            Some(ICalendarValue::RecurrenceRule(rule)) => Some(&**rule),
            _ => None,
        })
}

pub(super) fn sequence(component: &ICalendarComponent) -> i64 {
    component
        .property(&ICalendarProperty::Sequence)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_integer)
        .unwrap_or_default()
}

pub(super) fn time_form(entry: &ICalendarEntry) -> Option<TimeForm> {
    let value = first_date_time(entry)?;
    Some(if !value.has_time() {
        TimeForm::Date
    } else if value.has_zone() {
        TimeForm::Utc
    } else if entry.tz_id().is_some() {
        TimeForm::Zoned
    } else {
        TimeForm::Floating
    })
}
