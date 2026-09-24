/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Series;
use crate::scheduling::itip::itip_date_params;
use ahash::RandomState;
use calcard::{
    common::{
        PartialDateTime,
        timezone::{NominalDuration, Tz, ZonedDateTime},
    },
    icalendar::{
        ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameterName,
        ICalendarPeriod, ICalendarProperty, ICalendarValue,
    },
};
use indexmap::IndexSet;
use jiff::Timestamp;

#[derive(Debug, Clone, Copy)]
enum DateForm {
    Date,
    Floating,
    Utc,
    Zoned(Tz),
}

impl Series<'_> {
    pub(crate) fn occurrence(
        &self,
        mut component: ICalendarComponent,
        recurrence_id: &ICalendarEntry,
        original_start: i64,
    ) -> Option<Vec<ICalendarComponent>> {
        let series_start = self
            .master
            .as_ref()?
            .component
            .property(&ICalendarProperty::Dtstart)?;
        let series_form = self.date_form(series_start)?;
        let series_tz = self.tz.resolve_or_default(series_start.tz_id());
        let original = match self.entry_zoned(recurrence_id) {
            Some(original) if original.timestamp() == original_start => original,
            _ => series_tz.from_timestamp(Timestamp::from_second(original_start).ok()?),
        }
        .with_timezone(series_tz);
        let source_original = component
            .property(&ICalendarProperty::RecurrenceId)
            .and_then(|entry| self.entry_zoned(entry))
            .map(|source_original| source_original.with_timezone(series_tz));
        let has_start = component.has_property(&ICalendarProperty::Dtstart);
        let has_end = [
            ICalendarProperty::Dtend,
            ICalendarProperty::Duration,
            ICalendarProperty::Due,
        ]
        .iter()
        .any(|name| component.has_property(name));
        let source_start = component
            .property(&ICalendarProperty::Dtstart)
            .and_then(|entry| self.entry_zoned(entry))
            .or(source_original)?;
        let start = match source_original {
            Some(source_original) => shift(original, source_original, source_start)?,
            None => original,
        };

        for entry in &mut component.entries {
            let instant = match entry.name {
                ICalendarProperty::Dtstart => start,
                ICalendarProperty::Dtend | ICalendarProperty::Due => {
                    self.end(entry, source_start, start)?
                }
                _ => continue,
            };
            let form = self.date_form(entry)?;
            entry.values = vec![ICalendarValue::PartialDateTime(Box::new(
                form.value(instant),
            ))];
        }

        let period_end = self.period_end(&component.component_type, original_start);
        component.entries.retain(|entry| match entry.name {
            ICalendarProperty::Rrule
            | ICalendarProperty::Rdate
            | ICalendarProperty::Exdate
            | ICalendarProperty::Exrule
            | ICalendarProperty::RecurrenceId => false,
            ICalendarProperty::Dtend | ICalendarProperty::Due | ICalendarProperty::Duration => {
                period_end.is_none()
            }
            _ => true,
        });
        if !has_start {
            component.entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtstart,
                params: itip_date_params(series_start),
                values: vec![ICalendarValue::PartialDateTime(Box::new(
                    series_form.value(start),
                ))],
            });
        }
        let end = match period_end {
            Some(period_end) => Some(period_end),
            None if !has_start && !has_end => self.series_end(start),
            None => None,
        };
        component.entries.extend(end);
        component.entries.push(ICalendarEntry {
            name: ICalendarProperty::RecurrenceId,
            params: itip_date_params(series_start)
                .into_iter()
                .chain(
                    recurrence_id
                        .params
                        .iter()
                        .filter(|param| param.name == ICalendarParameterName::Range)
                        .cloned(),
                )
                .collect(),
            values: vec![ICalendarValue::PartialDateTime(Box::new(
                series_form.value(original),
            ))],
        });

        Some(self.with_subcomponents(component))
    }

    fn end(
        &self,
        entry: &ICalendarEntry,
        source_start: ZonedDateTime,
        start: ZonedDateTime,
    ) -> Option<ZonedDateTime> {
        let source_end = self.entry_zoned(entry)?;
        match self.date_form(entry)? {
            DateForm::Date => start
                .checked_add_nominal(NominalDuration::new(source_end.days_since(source_start), 0)),
            DateForm::Floating | DateForm::Utc | DateForm::Zoned(_) => {
                start.checked_add(source_end.signed_duration_since(source_start))
            }
        }
    }

    fn series_end(&self, start: ZonedDateTime) -> Option<ICalendarEntry> {
        let master = self.master.as_ref()?.component;
        if let Some(duration) = master.property(&ICalendarProperty::Duration) {
            return Some(duration.clone());
        }
        let series_start = self.entry_zoned(master.property(&ICalendarProperty::Dtstart)?)?;
        [ICalendarProperty::Dtend, ICalendarProperty::Due]
            .iter()
            .find_map(|name| {
                let entry = master.property(name)?;
                Some(ICalendarEntry {
                    name: name.clone(),
                    params: itip_date_params(entry),
                    values: vec![ICalendarValue::PartialDateTime(Box::new(
                        self.date_form(entry)?
                            .value(self.end(entry, series_start, start)?),
                    ))],
                })
            })
    }

    fn period_end(
        &self,
        component_type: &ICalendarComponentType,
        original_start: i64,
    ) -> Option<ICalendarEntry> {
        self.master
            .as_ref()?
            .component
            .properties(&ICalendarProperty::Rdate)
            .find_map(|entry| {
                let tz_id = entry.tz_id();
                entry.values.iter().find_map(|value| match value {
                    ICalendarValue::Period(ICalendarPeriod::Range { start, end })
                        if self.timestamp(start, tz_id) == Some(original_start) =>
                    {
                        Some(ICalendarEntry {
                            name: if component_type == &ICalendarComponentType::VTodo {
                                ICalendarProperty::Due
                            } else {
                                ICalendarProperty::Dtend
                            },
                            params: entry
                                .params
                                .iter()
                                .filter(|param| param.name == ICalendarParameterName::Tzid)
                                .cloned()
                                .collect(),
                            values: vec![ICalendarValue::PartialDateTime(Box::new(end.clone()))],
                        })
                    }
                    ICalendarValue::Period(ICalendarPeriod::Duration { start, duration })
                        if self.timestamp(start, tz_id) == Some(original_start) =>
                    {
                        Some(ICalendarEntry {
                            name: ICalendarProperty::Duration,
                            params: vec![],
                            values: vec![ICalendarValue::Duration(duration.clone())],
                        })
                    }
                    _ => None,
                })
            })
    }

    fn entry_zoned(&self, entry: &ICalendarEntry) -> Option<ZonedDateTime> {
        self.zoned(entry.values.first()?.as_partial_date_time()?, entry.tz_id())
    }

    fn date_form(&self, entry: &ICalendarEntry) -> Option<DateForm> {
        let date = entry.values.first()?.as_partial_date_time()?;
        Some(if !date.has_time() {
            DateForm::Date
        } else if date.has_zone() {
            DateForm::Utc
        } else if let Some(tz_id) = entry.tz_id() {
            DateForm::Zoned(self.tz.resolve_or_default(Some(tz_id)))
        } else {
            DateForm::Floating
        })
    }

    fn with_subcomponents(&self, mut component: ICalendarComponent) -> Vec<ICalendarComponent> {
        let mut subtree: IndexSet<u32, RandomState> = IndexSet::default();
        let mut pending = component
            .component_ids
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if let Some(subcomponent) = self.ical.components.get(id as usize)
                && subtree.insert(id)
            {
                pending.extend(subcomponent.component_ids.iter().rev());
            }
        }

        let relink = |component_ids: &[u32]| {
            component_ids
                .iter()
                .filter_map(|id| subtree.get_index_of(id))
                .map(|index| index as u32 + 1)
                .collect::<Vec<_>>()
        };
        component.component_ids = relink(&component.component_ids);
        let mut components = Vec::with_capacity(subtree.len() + 1);
        components.push(component);
        components.extend(
            subtree
                .iter()
                .filter_map(|id| self.ical.components.get(*id as usize))
                .map(|subcomponent| ICalendarComponent {
                    component_type: subcomponent.component_type.clone(),
                    entries: subcomponent.entries.clone(),
                    component_ids: relink(&subcomponent.component_ids),
                }),
        );
        components
    }
}

impl DateForm {
    fn value(self, instant: ZonedDateTime) -> PartialDateTime {
        match self {
            DateForm::Date => PartialDateTime::from_date_timestamp(instant.naive_timestamp()),
            DateForm::Floating => PartialDateTime::from_naive_timestamp(instant.naive_timestamp()),
            DateForm::Utc => PartialDateTime::from_utc_timestamp(instant.timestamp()),
            DateForm::Zoned(tz) => {
                PartialDateTime::from_naive_timestamp(instant.with_timezone(tz).naive_timestamp())
            }
        }
    }
}

fn shift(instant: ZonedDateTime, from: ZonedDateTime, to: ZonedDateTime) -> Option<ZonedDateTime> {
    if from.timezone() == to.timezone() {
        instant.checked_add_nominal(NominalDuration::between(from, to))
    } else {
        instant.checked_add(to.signed_duration_since(from))
    }
}
