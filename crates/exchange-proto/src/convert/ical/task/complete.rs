/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::timezone::ZonedDateTime,
    datecalc::RRule,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty, ICalendarStatus,
        ICalendarValue,
    },
};
use jiff::{Timestamp, civil::Date};

use super::{
    STATUS_EXTENSION, due_of, mapped_recurrence,
    patch::{mark_done, remove_all, shift_dates},
    rrule_of, status,
    to_message::task_status,
};
use crate::convert::ical::{
    patch::{remove_components, remove_other, set_value},
    series::{MAX_INSTANCE_SCAN, Series, first_date_time},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskInstance {
    pub start: Option<Date>,
    pub due: Option<Date>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    Next(TaskInstance),
    Last,
}

pub(super) struct NextOccurrence {
    date: Date,
    passed: u32,
}

impl TaskInstance {
    fn anchor(self) -> Option<Date> {
        self.start.or(self.due)
    }

    fn moved_to(self, date: Date) -> Option<Self> {
        let Some(start) = self.start else {
            return Some(TaskInstance {
                start: None,
                due: Some(date),
            });
        };
        let due = match self.due {
            Some(due) => Some(date.checked_add(start.until(due).ok()?).ok()?),
            None => None,
        };
        Some(TaskInstance {
            start: Some(date),
            due,
        })
    }
}

pub fn next_task_instance(ical: &ICalendar, after: TaskInstance) -> Option<TaskInstance> {
    let series = Series::of(ical, ICalendarComponentType::VTodo)?;
    let main = series.component(series.main)?;
    let next = next_occurrence(&series, main, after.anchor()?)?;
    after.moved_to(next.date)
}

pub fn advance_recurring_todo(ical: &mut ICalendar, completed_at: Timestamp) -> Advance {
    let Some((index, current, next, final_instance)) =
        Series::of(ical, ICalendarComponentType::VTodo).and_then(|series| {
            let main = series.component(series.main)?;
            let date = |value: Option<ZonedDateTime>| value.map(|value| value.naive_local().date());
            let current = TaskInstance {
                start: date(
                    main.property(&ICalendarProperty::Dtstart)
                        .and_then(|entry| series.resolve_first(entry)),
                ),
                due: date(due_of(&series, main)),
            };
            let next = current
                .anchor()
                .and_then(|anchor| next_occurrence(&series, main, anchor));
            let final_instance = next
                .as_ref()
                .is_some_and(|next| next_occurrence(&series, main, next.date).is_none());
            Some((series.main, current, next, final_instance))
        })
    else {
        return Advance::Last;
    };
    let Some(component) = ical.components.get_mut(index) else {
        return Advance::Last;
    };
    let advanced = next.and_then(|next| {
        let shift = current.anchor()?.until(next.date).ok()?;
        Some((next.passed, shift, current.moved_to(next.date)?))
    });
    match advanced {
        Some((passed, shift, instance)) => {
            shift_dates(
                component,
                &[ICalendarProperty::Dtstart, ICalendarProperty::Due],
                shift,
            );
            if final_instance {
                component.entries.retain(|entry| {
                    !matches!(
                        entry.name,
                        ICalendarProperty::Rrule
                            | ICalendarProperty::Rdate
                            | ICalendarProperty::Exdate
                    )
                });
            } else {
                decrement_count(component, passed);
            }
            reopen(component);
            Advance::Next(instance)
        }
        None => {
            mark_done(component, Some(completed_at), completed_at);
            Advance::Last
        }
    }
}

pub fn is_open_recurring_todo(ical: &ICalendar) -> bool {
    Series::of(ical, ICalendarComponentType::VTodo).is_some_and(|series| {
        series
            .component(series.main)
            .is_some_and(|main| !is_complete(main) && mapped_recurrence(&series, main).is_some())
    })
}

pub fn todo_completed_at(ical: &ICalendar) -> Option<Timestamp> {
    let series = Series::of(ical, ICalendarComponentType::VTodo)?;
    let main = series.component(series.main)?;
    if !is_complete(main) {
        return None;
    }
    main.property(&ICalendarProperty::Completed)
        .and_then(|entry| series.resolve_first(entry))
        .map(|completed| completed.to_timestamp())
}

fn is_complete(main: &ICalendarComponent) -> bool {
    let percent = main
        .property(&ICalendarProperty::PercentComplete)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_integer);
    task_status(
        main,
        main.property(&ICalendarProperty::Completed).is_some(),
        percent,
    ) == status::COMPLETE
}

pub fn completed_copy(ical: &ICalendar, completed_at: Timestamp, uid: &str) -> ICalendar {
    let mut copy = ical.clone();
    let overrides: Vec<usize> = Series::of(&copy, ICalendarComponentType::VTodo)
        .map(|series| series.overrides().map(|(index, _, _)| index).collect())
        .unwrap_or_default();
    remove_components(&mut copy, &overrides);
    let main = Series::of(&copy, ICalendarComponentType::VTodo).map(|series| series.main);
    if let Some(component) = main.and_then(|index| copy.components.get_mut(index)) {
        component.entries.retain(|entry| {
            !matches!(
                entry.name,
                ICalendarProperty::Rrule | ICalendarProperty::Rdate | ICalendarProperty::Exdate
            )
        });
        set_value(
            component,
            ICalendarProperty::Uid,
            ICalendarValue::Text(uid.into()),
        );
        mark_done(component, Some(completed_at), completed_at);
    }
    copy
}

pub(super) fn next_occurrence(
    series: &Series<'_>,
    main: &ICalendarComponent,
    after: Date,
) -> Option<NextOccurrence> {
    let rule = rrule_of(main)?;
    let entry = main
        .property(&ICalendarProperty::Dtstart)
        .or_else(|| main.property(&ICalendarProperty::Due))?;
    let value = first_date_time(entry)?;
    let origin = series.resolve(entry, value)?;
    let rule = RRule::from_ical(rule, origin, !value.has_time()).ok()?;
    let mut excluded: Vec<Date> = series
        .exdates()
        .map(|zoned| zoned.naive_local().date())
        .collect();
    excluded.sort_unstable();
    let mut passed = 0u32;
    for instance in rule.iter().take(MAX_INSTANCE_SCAN) {
        let date = instance.naive_local().date();
        if date > after && excluded.binary_search(&date).is_err() {
            return Some(NextOccurrence { date, passed });
        }
        passed = passed.checked_add(1)?;
    }
    None
}

fn decrement_count(component: &mut ICalendarComponent, passed: u32) {
    if let Some(ICalendarValue::RecurrenceRule(rule)) = component
        .entries
        .iter_mut()
        .find(|entry| entry.name == ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first_mut())
        && let Some(count) = rule.count
    {
        rule.count = Some(count.saturating_sub(passed).max(1));
    }
}

fn reopen(component: &mut ICalendarComponent) {
    remove_all(component, &ICalendarProperty::Completed);
    remove_all(component, &ICalendarProperty::PercentComplete);
    remove_other(component, STATUS_EXTENSION);
    set_value(
        component,
        ICalendarProperty::Status,
        ICalendarValue::Status(ICalendarStatus::NeedsAction),
    );
}
