/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{ItipTime, itip::itip_date_entry};
use calcard::{
    common::{
        PartialDateTime,
        timezone::{Tz, ZonedDateTime},
    },
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameterName, ICalendarPeriod, ICalendarProperty, ICalendarRecurrenceRule,
        ICalendarValue, timezone::TzResolver,
    },
};
use std::{borrow::Cow, cell::OnceCell};

mod occurrence;

const SECONDS_PER_DAY: i64 = 86400;
const EXPANSION_COMPONENT_ID: u32 = 1;

pub(crate) struct Series<'x> {
    ical: &'x ICalendar,
    tz: TzResolver<&'x str>,
    master: Option<Master<'x>>,
    max_instances: usize,
    occurrences: OnceCell<RuleOccurrences>,
}

struct Master<'x> {
    component: &'x ICalendarComponent,
    start: Option<i64>,
    start_form: StartForm,
    tz_id: Option<&'x str>,
    has_rule: bool,
    rdates: Vec<i64>,
}

#[derive(Debug, Clone, Copy)]
enum StartForm {
    Date,
    Floating,
    Utc,
}

pub(super) struct Recurrence<'x> {
    entry: &'x ICalendarEntry,
    start: Option<i64>,
    this_and_future: bool,
}

struct RuleOccurrences {
    starts: Vec<i64>,
    is_complete: bool,
}

pub(super) struct SeriesPlan<'x> {
    cut: Option<i64>,
    has_instances: bool,
    exdates: Vec<&'x ICalendarEntry>,
    removed_rdates: Vec<i64>,
}

trait InstanceStart {
    fn instance_start(&self) -> Option<&PartialDateTime>;
}

impl<'x> Series<'x> {
    pub(crate) fn new(
        ical: &'x ICalendar,
        master: Option<&'x ICalendarComponent>,
        max_instances: usize,
    ) -> Self {
        let tz = ical.build_tz_resolver();
        let master = master.map(|component| Master::new(component, &tz));
        Series {
            ical,
            tz,
            master,
            max_instances,
            occurrences: OnceCell::new(),
        }
    }

    pub(super) fn master_component(&self) -> Option<&'x ICalendarComponent> {
        self.master.as_ref().map(|master| master.component)
    }

    pub(super) fn entry_time(&self, entry: &ICalendarEntry) -> Option<ItipTime> {
        let tz = self.tz.resolve_or_default(entry.tz_id());
        entry
            .values
            .first()
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date| date.to_date_time_with_tz(tz))
            .map(|date| ItipTime {
                start: date.timestamp(),
                tz_id: tz.as_id(),
            })
    }

    pub(super) fn recurrence(&self, entry: &'x ICalendarEntry) -> Recurrence<'x> {
        Recurrence {
            entry,
            start: entry
                .values
                .first()
                .and_then(|value| value.as_partial_date_time())
                .and_then(|date| self.timestamp(date, entry.tz_id())),
            this_and_future: entry
                .params
                .iter()
                .any(|param| param.name == ICalendarParameterName::Range),
        }
    }

    pub(super) fn plan(&self, excluded: &[&Recurrence<'x>]) -> SeriesPlan<'x> {
        let cut = excluded
            .iter()
            .filter(|recurrence| recurrence.this_and_future)
            .filter_map(|recurrence| recurrence.start)
            .min();
        let mut plan = SeriesPlan {
            cut,
            has_instances: cut.is_none_or(|cut| {
                self.master
                    .as_ref()
                    .and_then(|master| master.start)
                    .is_none_or(|start| start < cut)
            }),
            exdates: Vec::new(),
            removed_rdates: Vec::new(),
        };

        if plan.has_instances {
            for recurrence in excluded
                .iter()
                .filter(|recurrence| !recurrence.this_and_future)
            {
                match recurrence.start {
                    Some(start) if cut.is_some_and(|cut| start >= cut) => {}
                    Some(start) => {
                        let is_rdate = self.is_rdate(start);
                        if is_rdate {
                            plan.removed_rdates.push(start);
                        }
                        if self.is_rule_instance(start, is_rdate) {
                            plan.exdates.push(recurrence.entry);
                        }
                    }
                    None => plan.exdates.push(recurrence.entry),
                }
            }
        }

        plan
    }

    fn timestamp(&self, date: &PartialDateTime, tz_id: Option<&str>) -> Option<i64> {
        self.zoned(date, tz_id).map(|date| date.timestamp())
    }

    fn zoned(&self, date: &PartialDateTime, tz_id: Option<&str>) -> Option<ZonedDateTime> {
        date.to_date_time_with_tz(self.tz.resolve_or_default(
            tz_id.or_else(|| self.master.as_ref().and_then(|master| master.tz_id)),
        ))
    }

    pub(crate) fn has_occurrence(&self, start: i64) -> bool {
        let Some(master) = &self.master else {
            return false;
        };
        let is_rule_instance = || {
            let occurrences = self.occurrences();
            occurrences.contains(start)
                || (master
                    .start
                    .is_some_and(|master_start| start > master_start)
                    && occurrences.is_unknown_at(start))
        };
        let is_instance = self.is_rdate(start)
            || (master.has_rule && is_rule_instance())
            || (!master.has_rule && !master.rdates.is_empty() && master.start == Some(start));
        is_instance && !self.is_exdate(start)
    }

    fn is_rdate(&self, start: i64) -> bool {
        self.master
            .as_ref()
            .is_some_and(|master| master.rdates.binary_search(&start).is_ok())
    }

    fn is_exdate(&self, start: i64) -> bool {
        self.master.as_ref().is_some_and(|master| {
            master
                .component
                .properties(&ICalendarProperty::Exdate)
                .any(|entry| {
                    entry
                        .values
                        .iter()
                        .filter_map(|value| value.as_partial_date_time())
                        .any(|date| self.timestamp(date, entry.tz_id()) == Some(start))
                })
        })
    }

    fn is_rule_instance(&self, start: i64, is_rdate: bool) -> bool {
        let Some(master) = &self.master else {
            return false;
        };
        match master.start {
            Some(master_start) if start == master_start => true,
            Some(master_start) if start < master_start => false,
            _ if !master.has_rule => false,
            _ => {
                let occurrences = self.occurrences();
                occurrences.contains(start) || (!is_rdate && occurrences.is_unknown_at(start))
            }
        }
    }

    fn occurrences(&self) -> &RuleOccurrences {
        self.occurrences.get_or_init(|| match &self.master {
            Some(master) if master.has_rule => {
                RuleOccurrences::expand(self.ical, master, self.max_instances)
            }
            _ => RuleOccurrences {
                starts: Vec::new(),
                is_complete: true,
            },
        })
    }

    fn truncate(&self, rule: &ICalendarRecurrenceRule, cut: i64) -> ICalendarRecurrenceRule {
        let Some(master) = &self.master else {
            return rule.clone();
        };
        if rule.count.is_some() && self.occurrences().ends_before(cut) {
            return rule.clone();
        }

        let (until, until_timestamp) = master.start_form.until_before(cut);
        let until = match &rule.until {
            Some(current)
                if current
                    .to_date_time_with_tz(Tz::Floating)
                    .is_some_and(|current| current.timestamp() <= until_timestamp) =>
            {
                current.clone()
            }
            _ => until,
        };

        ICalendarRecurrenceRule {
            count: None,
            until: Some(until),
            ..rule.clone()
        }
    }
}

impl<'x> Master<'x> {
    fn new(component: &'x ICalendarComponent, tz: &TzResolver<&'x str>) -> Self {
        let start_entry = component.property(&ICalendarProperty::Dtstart);
        let tz_id = start_entry.and_then(|entry| entry.tz_id());
        let start_date = start_entry
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_partial_date_time());
        let resolve = |date: &PartialDateTime, tz_id: Option<&str>| {
            date.to_date_time_with_tz(tz.resolve_or_default(tz_id))
                .map(|date| date.timestamp())
        };
        let mut rdates = component
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Rdate)
            .flat_map(|entry| {
                let entry_tz_id = entry.tz_id().or(tz_id);
                entry
                    .values
                    .iter()
                    .filter_map(|value| value.instance_start())
                    .filter_map(move |date| resolve(date, entry_tz_id))
            })
            .collect::<Vec<_>>();
        rdates.sort_unstable();

        Master {
            component,
            start: start_date.and_then(|date| resolve(date, tz_id)),
            start_form: match start_date {
                Some(date) if !date.has_time() => StartForm::Date,
                Some(date) if !date.has_zone() && tz_id.is_none() => StartForm::Floating,
                _ => StartForm::Utc,
            },
            tz_id,
            has_rule: component.has_property(&ICalendarProperty::Rrule),
            rdates,
        }
    }
}

impl StartForm {
    fn until_before(self, cut: i64) -> (PartialDateTime, i64) {
        let last = cut - 1;
        match self {
            StartForm::Date => (
                PartialDateTime::from_date_timestamp(last),
                last.div_euclid(SECONDS_PER_DAY) * SECONDS_PER_DAY,
            ),
            StartForm::Floating => (PartialDateTime::from_naive_timestamp(last), last),
            StartForm::Utc => (PartialDateTime::from_utc_timestamp(last), last),
        }
    }
}

impl RuleOccurrences {
    fn expand(ical: &ICalendar, master: &Master<'_>, limit: usize) -> Self {
        let root = ICalendarComponent {
            component_type: ICalendarComponentType::VCalendar,
            entries: Vec::new(),
            component_ids: vec![EXPANSION_COMPONENT_ID],
        };
        let rule = ICalendarComponent {
            component_type: master.component.component_type.clone(),
            entries: master
                .component
                .entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.name,
                        ICalendarProperty::Dtstart
                            | ICalendarProperty::Dtend
                            | ICalendarProperty::Duration
                            | ICalendarProperty::Due
                            | ICalendarProperty::Rrule
                    )
                })
                .cloned()
                .collect(),
            component_ids: Vec::new(),
        };
        let timezones = ical
            .components
            .iter()
            .filter(|component| {
                component.component_type == ICalendarComponentType::VTimezone
                    && master.tz_id.is_some()
                    && component
                        .property(&ICalendarProperty::Tzid)
                        .and_then(|entry| entry.values.first())
                        .and_then(|value| value.as_text())
                        == master.tz_id
            })
            .map(|component| ICalendarComponent {
                component_type: ICalendarComponentType::VTimezone,
                entries: component.entries.clone(),
                component_ids: Vec::new(),
            });
        let expanded = ICalendar {
            components: [root, rule].into_iter().chain(timezones).collect(),
        }
        .expand_dates(Tz::Floating, limit.saturating_add(1));

        let mut starts = expanded
            .events
            .iter()
            .map(|event| event.start.timestamp())
            .collect::<Vec<_>>();
        starts.sort_unstable();

        RuleOccurrences {
            is_complete: expanded.errors.is_empty() && starts.len() <= limit,
            starts,
        }
    }

    fn contains(&self, start: i64) -> bool {
        self.starts.binary_search(&start).is_ok()
    }

    fn is_unknown_at(&self, start: i64) -> bool {
        !self.is_complete && self.starts.last().is_none_or(|last| *last < start)
    }

    fn ends_before(&self, start: i64) -> bool {
        self.is_complete && self.starts.last().is_none_or(|last| *last < start)
    }
}

impl<'x> Recurrence<'x> {
    pub(super) fn entry(&self) -> &'x ICalendarEntry {
        self.entry
    }

    pub(super) fn is_this_and_future(&self) -> bool {
        self.this_and_future
    }
}

impl<'x> SeriesPlan<'x> {
    pub(super) fn has_instances(&self) -> bool {
        self.has_instances
    }

    pub(super) fn exdate_count(&self) -> usize {
        self.exdates.len()
    }

    pub(super) fn entry<'y>(
        &self,
        series: &Series<'_>,
        entry: &'y ICalendarEntry,
    ) -> Option<Cow<'y, ICalendarEntry>> {
        match (&entry.name, self.cut) {
            (ICalendarProperty::Rdate, cut) if cut.is_some() || !self.removed_rdates.is_empty() => {
                let tz_id = entry.tz_id();
                let values = entry
                    .values
                    .iter()
                    .filter(|value| {
                        value
                            .instance_start()
                            .and_then(|date| series.timestamp(date, tz_id))
                            .is_none_or(|start| {
                                cut.is_none_or(|cut| start < cut)
                                    && !self.removed_rdates.contains(&start)
                            })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (!values.is_empty()).then(|| {
                    Cow::Owned(ICalendarEntry {
                        name: ICalendarProperty::Rdate,
                        params: entry.params.clone(),
                        values,
                    })
                })
            }
            (ICalendarProperty::Rrule, Some(cut)) => Some(Cow::Owned(ICalendarEntry {
                name: ICalendarProperty::Rrule,
                params: entry.params.clone(),
                values: entry
                    .values
                    .iter()
                    .map(|value| match value {
                        ICalendarValue::RecurrenceRule(rule) => {
                            ICalendarValue::RecurrenceRule(Box::new(series.truncate(rule, cut)))
                        }
                        value => value.clone(),
                    })
                    .collect(),
            })),
            _ => Some(Cow::Borrowed(entry)),
        }
    }

    pub(super) fn exdates(&self) -> impl Iterator<Item = ICalendarEntry> + '_ {
        self.exdates
            .iter()
            .map(|entry| itip_date_entry(ICalendarProperty::Exdate, entry))
    }
}

impl InstanceStart for ICalendarValue {
    fn instance_start(&self) -> Option<&PartialDateTime> {
        match self {
            ICalendarValue::PartialDateTime(date) => Some(date),
            ICalendarValue::Period(
                ICalendarPeriod::Range { start, .. } | ICalendarPeriod::Duration { start, .. },
            ) => Some(start),
            _ => None,
        }
    }
}
