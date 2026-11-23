/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod complete;
mod patch;
mod to_message;

pub use complete::{
    Advance, TaskInstance, advance_recurring_todo, completed_copy, is_open_recurring_todo,
    next_task_instance, todo_completed_at,
};
pub(super) use patch::task as patch_task;
pub(super) use to_message::task as task_message;

use super::{
    props::Lid,
    series::{Series, first_date_time},
};
use crate::{
    convert::blob::{TaskAnchor, TaskRecur},
    mapi::prop::sets::PSETID_TASK,
};
use calcard::{
    common::timezone::ZonedDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty,
        ICalendarRecurrenceRule, ICalendarValue,
    },
};
use jiff::civil::Date;

pub(crate) const CLASS_TASK: &str = "IPM.Task";
const STATUS_EXTENSION: &str = "X-MS-TASK-STATUS";
const WAITING: &str = "WAITING";
const DEFERRED: &str = "DEFERRED";
const PERCENT_DONE: i64 = 100;
pub(crate) const TASK_BLOB_CAPACITY: usize = 64;

const fn task_lid(lid: u32) -> Lid {
    Lid {
        set: PSETID_TASK,
        lid,
    }
}

const TASK_STATUS: Lid = task_lid(0x8101);
const PERCENT_COMPLETE: Lid = task_lid(0x8102);
const TASK_START_DATE: Lid = task_lid(0x8104);
const TASK_DUE_DATE: Lid = task_lid(0x8105);
const TASK_DEAD_OCCURRENCE: Lid = task_lid(0x8109);
const TASK_DATE_COMPLETED: Lid = task_lid(0x810F);
const TASK_RECURRENCE: Lid = task_lid(0x8116);
const TASK_COMPLETE: Lid = task_lid(0x811C);
const TASK_F_RECURRING: Lid = task_lid(0x8126);

pub(crate) mod keys {
    use super::{
        PERCENT_COMPLETE, TASK_DATE_COMPLETED, TASK_DUE_DATE, TASK_F_RECURRING, TASK_RECURRENCE,
        TASK_START_DATE, TASK_STATUS,
    };
    use crate::mapi::prop::PropKeyRef;

    pub(crate) const STATUS: PropKeyRef<'static> = TASK_STATUS.prop();
    pub(crate) const PERCENT: PropKeyRef<'static> = PERCENT_COMPLETE.prop();
    pub(crate) const START_DATE: PropKeyRef<'static> = TASK_START_DATE.prop();
    pub(crate) const DUE_DATE: PropKeyRef<'static> = TASK_DUE_DATE.prop();
    pub(crate) const DATE_COMPLETED: PropKeyRef<'static> = TASK_DATE_COMPLETED.prop();
    pub(crate) const RECURRING: PropKeyRef<'static> = TASK_F_RECURRING.prop();
    pub(crate) const RECURRENCE: PropKeyRef<'static> = TASK_RECURRENCE.prop();
}

pub(crate) mod status {
    pub(crate) const NOT_STARTED: i32 = 0;
    pub(crate) const IN_PROGRESS: i32 = 1;
    pub(crate) const COMPLETE: i32 = 2;
    pub(crate) const WAITING_ON_OTHERS: i32 = 3;
    pub(crate) const DEFERRED: i32 = 4;
}

impl TaskAnchor {
    pub fn of(ical: &ICalendar) -> Option<Self> {
        let series = Series::of(ical, ICalendarComponentType::VTodo)?;
        task_anchor(&series, series.component(series.main)?)
    }

    fn date(self) -> Date {
        match self {
            TaskAnchor::Date(date) => date,
            TaskAnchor::Local { start, .. } => start.date(),
        }
    }

    pub(super) fn is_last(self, series: &Series<'_>, main: &ICalendarComponent) -> bool {
        complete::next_occurrence(series, main, self.date()).is_none()
    }
}

pub(super) fn task_anchor(series: &Series<'_>, main: &ICalendarComponent) -> Option<TaskAnchor> {
    let entry = main
        .property(&ICalendarProperty::Dtstart)
        .or_else(|| main.property(&ICalendarProperty::Due))?;
    let value = first_date_time(entry)?;
    let local = series.resolve(entry, value)?.naive_local();
    Some(if value.has_time() {
        TaskAnchor::Local {
            start: local,
            tz: series.entry_zone(entry),
        }
    } else {
        TaskAnchor::Date(local.date())
    })
}

fn rrule_of(main: &ICalendarComponent) -> Option<&ICalendarRecurrenceRule> {
    let mut rules = main.properties(&ICalendarProperty::Rrule);
    let rule = match rules.next()?.values.first()? {
        ICalendarValue::RecurrenceRule(rule) => rule,
        _ => return None,
    };
    rules.next().is_none().then_some(rule)
}

fn has_recurrence(series: &Series<'_>, main: &ICalendarComponent) -> bool {
    series.overrides().next().is_some()
        || [
            ICalendarProperty::Rrule,
            ICalendarProperty::Rdate,
            ICalendarProperty::Exdate,
        ]
        .iter()
        .any(|name| main.property(name).is_some())
}

fn mapped_recurrence(series: &Series<'_>, main: &ICalendarComponent) -> Option<TaskRecur> {
    if series.master != Some(series.main)
        || series.overrides().next().is_some()
        || main.property(&ICalendarProperty::Rdate).is_some()
        || main.property(&ICalendarProperty::Exdate).is_some()
    {
        return None;
    }
    TaskRecur::from_rrule(rrule_of(main)?, task_anchor(series, main)?).ok()
}

pub(crate) fn has_unmapped_recurrence(ical: &ICalendar) -> bool {
    Series::of(ical, ICalendarComponentType::VTodo).is_some_and(|series| {
        series.component(series.main).is_some_and(|main| {
            has_recurrence(&series, main) && mapped_recurrence(&series, main).is_none()
        })
    })
}

fn due_of(series: &Series<'_>, main: &ICalendarComponent) -> Option<ZonedDateTime> {
    main.property(&ICalendarProperty::Due)
        .and_then(|entry| series.resolve_first(entry))
        .or_else(|| series.span(main).map(|span| span.end))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/task/tests.rs"]
mod tests;
