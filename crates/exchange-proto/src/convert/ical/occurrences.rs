/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{datecalc::RRule, icalendar::ICalendarProperty};
use jiff::Timestamp;
use std::iter::once;

use super::{
    RecurrenceId,
    series::{MAX_INSTANCE_SCAN, MAX_RECURRENCE_RULES, Series, recurrence_rules},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventOccurrence {
    pub instance: RecurrenceId,
    pub start: Timestamp,
    pub end: Timestamp,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventOccurrences {
    pub first: Option<EventOccurrence>,
    pub last: Option<EventOccurrence>,
    pub modified: Vec<EventOccurrence>,
    pub deleted: Vec<RecurrenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OccurrenceBounds {
    First,
    FirstAndLast,
}

impl Series<'_> {
    pub fn occurrences(&self, bounds: OccurrenceBounds) -> Option<EventOccurrences> {
        let master = self
            .master
            .and_then(|index| self.component(index))
            .filter(|component| component.is_recurrent())?;
        let span = self.span(master)?;
        let mut deleted: Vec<Timestamp> =
            self.exdates().map(|zoned| zoned.to_timestamp()).collect();
        deleted.sort_unstable();
        deleted.dedup();
        let mut modified: Vec<EventOccurrence> = self
            .overrides()
            .filter(|(_, _, instance)| deleted.binary_search(&instance.0).is_err())
            .filter_map(|(_, component, instance)| {
                let span = self.span(component)?;
                Some(EventOccurrence {
                    instance,
                    start: span.start.to_timestamp(),
                    end: span.end.to_timestamp(),
                })
            })
            .collect();
        modified.sort_by_key(|occurrence| occurrence.instance);
        modified.dedup_by_key(|occurrence| occurrence.instance);

        let mut range = None;
        let mut members = once(span.start.to_timestamp()).chain(
            self.dates(master, &ICalendarProperty::Rdate)
                .map(|zoned| zoned.to_timestamp()),
        );
        for instant in members.by_ref().take(MAX_INSTANCE_SCAN) {
            if deleted.binary_search(&instant).is_err() {
                widen(&mut range, instant);
            }
        }
        let mut open = members.next().is_some();
        let mut rules = recurrence_rules(master);
        for value in rules.by_ref().take(MAX_RECURRENCE_RULES) {
            let Ok(rule) = RRule::from_ical(value, span.start, span.all_day) else {
                open = true;
                continue;
            };
            let walk_all = bounds == OccurrenceBounds::FirstAndLast
                && (value.count.is_some() || value.until.is_some());
            let mut instants = rule.iter().map(|instance| instance.to_timestamp());
            for instant in instants.by_ref().take(MAX_INSTANCE_SCAN) {
                if deleted.binary_search(&instant).is_err() {
                    widen(&mut range, instant);
                    if !walk_all {
                        break;
                    }
                }
            }
            open |= !walk_all || instants.next().is_some();
        }
        open |= rules.next().is_some();

        let occurrence = |instant: Timestamp| {
            let instance = RecurrenceId(instant);
            if let Ok(index) =
                modified.binary_search_by_key(&instance, |occurrence| occurrence.instance)
            {
                return modified.get(index).copied();
            }
            let end = self.at(instant).checked_add(span.duration())?;
            Some(EventOccurrence {
                instance,
                start: instant,
                end: end.to_timestamp(),
            })
        };
        let first = range.and_then(|(first, _)| occurrence(first));
        let last = range
            .filter(|_| bounds == OccurrenceBounds::FirstAndLast && !open)
            .and_then(|(_, last)| occurrence(last));
        Some(EventOccurrences {
            first,
            last,
            modified,
            deleted: deleted.into_iter().map(RecurrenceId).collect(),
        })
    }
}

fn widen(range: &mut Option<(Timestamp, Timestamp)>, instant: Timestamp) {
    *range = Some(match *range {
        Some((first, last)) => (first.min(instant), last.max(instant)),
        None => (instant, instant),
    });
}
