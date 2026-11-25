/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarAction, ICalendarClassification, ICalendarComponent,
        ICalendarComponentType, ICalendarDuration, ICalendarEntry, ICalendarParameter,
        ICalendarParameterName, ICalendarParameterValue, ICalendarProperty, ICalendarRelated,
        ICalendarStatus, ICalendarValue, ICalendarValueType,
    },
};
use jiff::{Timestamp, tz::TimeZone};
use smallvec::smallvec;

use super::{
    EasTask, calendar_type,
    recur::{Pattern, PatternEnd},
    takes_calendar_type, todo_parts, todo_to_eas,
};
use crate::{
    convert::{
        ConvertError,
        ical::{
            patch::{TimeTarget, remove_other, set_text, set_value},
            props::{
                CDO_IMPORTANCE_NAME, PERSONAL_CLASS, REMINDER_DESCRIPTION, importance, sensitivity,
            },
            series::{Series, TimeForm, time_form},
            task::task_anchor,
        },
    },
    eas::{
        commands::appdata::{Task, TaskRecurrence},
        types::EasDateTime,
    },
};

const PERCENT_DONE: i64 = 100;
const LAST_WEEKDAY: u8 = 6;
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskWrite {
    Add,
    Change,
}

pub struct TaskUpdate<'x> {
    pub task: &'x Task<'x>,
    pub description: Option<&'x str>,
    pub write: TaskWrite,
    pub now: Timestamp,
}

pub fn todo_from_eas(ical: &mut ICalendar, update: &TaskUpdate<'_>) -> Result<bool, ConvertError> {
    let plan = Plan::new(ical, update)?;
    let before = matches!(plan.start, Some(Edit::Remove))
        .then(|| rendered_fire(ical))
        .transpose()?
        .flatten();
    let mut changed = !plan.is_empty();
    if changed {
        plan.apply(ical, update.now)?;
    }
    changed |= reminder(ical, update.task, before)?;
    if changed {
        let index = main_index(ical)?;
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        let stamp = ICalendarValue::PartialDateTime(PartialDateTime::from_utc_timestamp(
            update.now.as_second(),
        ));
        set_value(component, ICalendarProperty::LastModified, stamp.clone());
        set_value(component, ICalendarProperty::Dtstamp, stamp);
    }
    Ok(changed)
}

pub(super) enum Edit<T> {
    Set(T),
    Remove,
}

enum Completion {
    Done(Option<i64>),
    Open,
}

pub(super) struct RuleEdit {
    pub pattern: Pattern,
    pub first_day_of_week: Option<u8>,
    pub start: i64,
}

#[derive(Default)]
struct Plan {
    summary: Option<String>,
    description: Option<String>,
    priority: Option<i64>,
    class: Option<Edit<ICalendarValue>>,
    categories: Option<Vec<String>>,
    completion: Option<Completion>,
    start: Option<Edit<ICalendarEntry>>,
    due: Option<Edit<ICalendarEntry>>,
    drop_duration: bool,
    rule: Option<Edit<RuleEdit>>,
}

#[derive(Clone, Copy)]
struct Moment {
    utc: Option<i64>,
    local: Option<i64>,
}

impl Plan {
    fn new(ical: &ICalendar, update: &TaskUpdate<'_>) -> Result<Self, ConvertError> {
        let (series, main) = todo_parts(ical).ok_or(ConvertError::Unsupported)?;
        let EasTask {
            task: current,
            description,
        } = todo_to_eas(ical).ok_or(ConvertError::Unsupported)?;
        let given = update.task;
        let mut plan = Plan::default();

        let subject = non_empty(given.subject.as_deref());
        if subject != current.subject.as_deref() {
            plan.summary = Some(subject.unwrap_or_default().to_string());
        }
        if let Some(text) = update.description
            && non_empty(Some(text)) != description
        {
            plan.description = Some(text.to_string());
        }
        plan.priority = given
            .importance
            .filter(|level| Some(*level) != current.importance)
            .and_then(priority);
        let level = given.sensitivity.unwrap_or_default();
        if level != current.sensitivity.unwrap_or_default() {
            plan.class = class(level);
        }
        let categories = given
            .categories
            .as_ref()
            .map_or(&[][..], |list| list.0.as_slice());
        if categories
            != current
                .categories
                .as_ref()
                .map_or(&[][..], |list| list.0.as_slice())
        {
            plan.categories = Some(
                categories
                    .iter()
                    .filter(|category| !category.is_empty())
                    .map(|category| category.to_string())
                    .collect(),
            );
        }

        let completed_at = given.date_completed.map(seconds);
        plan.completion = match (
            given.complete.unwrap_or_default(),
            current.complete == Some(true),
        ) {
            (true, false) => Some(Completion::Done(completed_at)),
            (true, true)
                if completed_at.is_some()
                    && completed_at != current.date_completed.map(seconds) =>
            {
                Some(Completion::Done(completed_at))
            }
            (false, true) => Some(Completion::Open),
            _ => None,
        };

        let start = Moment::of(given.utc_start_date, given.start_date);
        let due = Moment::of(given.utc_due_date, given.due_date);
        let keeps_anchor = start.is_none() && given.recurrence.is_some();
        let untimed = [start, due]
            .into_iter()
            .flatten()
            .all(Moment::is_local_date);
        if !keeps_anchor && !Moment::matches(start, current.utc_start_date, current.start_date) {
            plan.start = time_edit(&series, main, ICalendarProperty::Dtstart, start, untimed)?;
        }
        if !Moment::matches(due, current.utc_due_date, current.due_date) {
            plan.due = time_edit(&series, main, ICalendarProperty::Due, due, untimed)?;
        }
        if (plan.start.is_some() || plan.due.is_some())
            && main.property(&ICalendarProperty::Duration).is_some()
        {
            plan.drop_duration = true;
            if plan.due.is_none() {
                let kept = Moment::of(current.utc_due_date, None);
                plan.due = time_edit(&series, main, ICalendarProperty::Due, kept, untimed)?;
            }
        }

        match &given.recurrence {
            Some(recurrence)
                if update.write == TaskWrite::Add
                    && recurrence.calendar_type.is_some()
                    && !takes_calendar_type(recurrence.recurrence_type) =>
            {
                return Err(ConvertError::Unsupported);
            }
            Some(recurrence) => {
                let edit = rule_edit(recurrence)?;
                if current
                    .recurrence
                    .as_ref()
                    .and_then(|current| Pattern::from_task(current).ok())
                    != Some(edit.pattern)
                {
                    plan.rule = Some(Edit::Set(edit));
                }
            }
            None if current.recurrence.is_some() => plan.rule = Some(Edit::Remove),
            None => {}
        }
        Ok(plan)
    }

    fn is_empty(&self) -> bool {
        self.summary.is_none()
            && self.description.is_none()
            && self.priority.is_none()
            && self.class.is_none()
            && self.categories.is_none()
            && self.completion.is_none()
            && self.start.is_none()
            && self.due.is_none()
            && !self.drop_duration
            && self.rule.is_none()
    }

    fn apply(self, ical: &mut ICalendar, now: Timestamp) -> Result<(), ConvertError> {
        let index = main_index(ical)?;
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        if let Some(summary) = &self.summary {
            set_text(component, ICalendarProperty::Summary, summary);
        }
        if let Some(description) = &self.description {
            set_text(component, ICalendarProperty::Description, description);
        }
        if let Some(priority) = self.priority {
            set_value(
                component,
                ICalendarProperty::Priority,
                ICalendarValue::Integer(priority),
            );
            remove_other(component, CDO_IMPORTANCE_NAME);
        }
        match self.class {
            Some(Edit::Set(value)) => set_value(component, ICalendarProperty::Class, value),
            Some(Edit::Remove) => remove_all(component, &ICalendarProperty::Class),
            None => {}
        }
        if let Some(categories) = self.categories {
            remove_all(component, &ICalendarProperty::Categories);
            if !categories.is_empty() {
                component.entries.push(ICalendarEntry {
                    name: ICalendarProperty::Categories,
                    params: Vec::new(),
                    values: categories.into_iter().map(ICalendarValue::Text).collect(),
                });
            }
        }
        match self.completion {
            Some(Completion::Done(at)) => {
                set_value(
                    component,
                    ICalendarProperty::Status,
                    ICalendarValue::Status(ICalendarStatus::Completed),
                );
                set_value(
                    component,
                    ICalendarProperty::PercentComplete,
                    ICalendarValue::Integer(PERCENT_DONE),
                );
                set_value(
                    component,
                    ICalendarProperty::Completed,
                    ICalendarValue::PartialDateTime(PartialDateTime::from_utc_timestamp(
                        at.unwrap_or_else(|| now.as_second()),
                    )),
                );
            }
            Some(Completion::Open) => {
                remove_all(component, &ICalendarProperty::Completed);
                remove_all(component, &ICalendarProperty::PercentComplete);
                if matches!(component.status(), Some(ICalendarStatus::Completed)) {
                    set_value(
                        component,
                        ICalendarProperty::Status,
                        ICalendarValue::Status(ICalendarStatus::NeedsAction),
                    );
                }
            }
            None => {}
        }
        replace(component, &ICalendarProperty::Dtstart, self.start);
        replace(component, &ICalendarProperty::Due, self.due);
        if self.drop_duration {
            remove_all(component, &ICalendarProperty::Duration);
        }
        match self.rule {
            Some(Edit::Set(edit)) => {
                if component.property(&ICalendarProperty::Dtstart).is_none() {
                    let anchor = match component.property(&ICalendarProperty::Due) {
                        Some(due) => ICalendarEntry {
                            name: ICalendarProperty::Dtstart,
                            params: due.params.clone(),
                            values: due.values.clone(),
                        },
                        None => utc_entry(ICalendarProperty::Dtstart, edit.start),
                    };
                    component.entries.push(anchor);
                }
                let form = component
                    .property(&ICalendarProperty::Dtstart)
                    .and_then(time_form);
                let mut rule = edit.pattern.to_rule(edit.first_day_of_week);
                if let PatternEnd::Until(until) = edit.pattern.end {
                    rule.until = Some(until_value(until, form));
                }
                remove_all(component, &ICalendarProperty::Rrule);
                if let Some(anchor) =
                    todo_parts(ical).and_then(|(series, main)| task_anchor(&series, main))
                {
                    anchor.count_start(&mut rule);
                }
                let component = ical
                    .components
                    .get_mut(index)
                    .ok_or(ConvertError::Unsupported)?;
                component.entries.push(ICalendarEntry {
                    name: ICalendarProperty::Rrule,
                    params: Vec::new(),
                    values: smallvec![ICalendarValue::RecurrenceRule(Box::new(rule))],
                });
            }
            Some(Edit::Remove) => remove_all(component, &ICalendarProperty::Rrule),
            None => {}
        }
        Ok(())
    }
}

impl Moment {
    fn of(utc: Option<EasDateTime>, local: Option<EasDateTime>) -> Option<Self> {
        (utc.is_some() || local.is_some()).then(|| Moment {
            utc: utc.map(seconds),
            local: local.map(seconds),
        })
    }

    fn matches(
        given: Option<Self>,
        current_utc: Option<EasDateTime>,
        current_local: Option<EasDateTime>,
    ) -> bool {
        match given {
            None => current_utc.is_none(),
            Some(Moment { utc: Some(utc), .. }) => current_utc.map(seconds) == Some(utc),
            Some(Moment { local, .. }) => current_local.map(seconds) == local,
        }
    }

    fn is_local_date(self) -> bool {
        match (self.utc, self.local) {
            (Some(utc), Some(local)) => utc != local && local.rem_euclid(SECONDS_PER_DAY) == 0,
            _ => false,
        }
    }

    fn instant(self, target: &TimeTarget, all_day: bool) -> Option<Timestamp> {
        match (self.utc, self.local, all_day) {
            (Some(utc), _, false) | (Some(utc), None, true) => Timestamp::from_second(utc).ok(),
            (_, Some(local), _) => {
                let wall = Timestamp::from_second(local)
                    .ok()?
                    .to_zoned_datetime(TimeZone::UTC)
                    .datetime();
                target.tz.from_local(wall).map(|zoned| zoned.to_timestamp())
            }
            (None, None, _) => None,
        }
    }
}

fn time_edit(
    series: &Series<'_>,
    main: &ICalendarComponent,
    name: ICalendarProperty,
    moment: Option<Moment>,
    untimed: bool,
) -> Result<Option<Edit<ICalendarEntry>>, ConvertError> {
    let Some(moment) = moment else {
        return Ok(main.property(&name).map(|_| Edit::Remove));
    };
    let template = [&name, &ICalendarProperty::Dtstart, &ICalendarProperty::Due]
        .into_iter()
        .find_map(|property| main.property(property));
    let (target, all_day) = match template {
        Some(entry) => {
            let form = time_form(entry);
            (
                TimeTarget {
                    tz: series.entry_zone(entry),
                    tzid: (form == Some(TimeForm::Zoned))
                        .then(|| entry.tz_id().map(str::to_string))
                        .flatten(),
                },
                form == Some(TimeForm::Date),
            )
        }
        None => (
            TimeTarget {
                tz: Tz::UTC,
                tzid: None,
            },
            untimed,
        ),
    };
    let instant = moment
        .instant(&target, all_day)
        .ok_or(ConvertError::Unsupported)?;
    let entry = target.entry(name, instant, all_day);
    Ok((main.property(&entry.name) != Some(&entry)).then_some(Edit::Set(entry)))
}

pub(super) fn rule_edit(recurrence: &TaskRecurrence) -> Result<RuleEdit, ConvertError> {
    let start = recurrence.start.ok_or(ConvertError::Unsupported)?;
    if recurrence
        .first_day_of_week
        .is_some_and(|day| day > LAST_WEEKDAY)
        || recurrence.regenerate == Some(true)
        || recurrence
            .calendar_type
            .is_some_and(|kind| kind != calendar_type::DEFAULT && kind != calendar_type::GREGORIAN)
    {
        return Err(ConvertError::Unsupported);
    }
    Ok(RuleEdit {
        pattern: Pattern::from_task(recurrence)?,
        first_day_of_week: recurrence.first_day_of_week,
        start: seconds(start),
    })
}

fn rendered_fire(ical: &ICalendar) -> Result<Option<i64>, ConvertError> {
    let current = todo_to_eas(ical).ok_or(ConvertError::Unsupported)?.task;
    Ok(current
        .reminder_time
        .filter(|_| current.reminder_set == Some(true))
        .map(seconds))
}

fn reminder(
    ical: &mut ICalendar,
    task: &Task<'_>,
    before: Option<i64>,
) -> Result<bool, ConvertError> {
    set_reminder(
        ical,
        task.reminder_set,
        task.reminder_time.map(seconds),
        before,
    )
}

pub(in crate::convert::ical) fn set_reminder(
    ical: &mut ICalendar,
    set: Option<bool>,
    time: Option<i64>,
    before: Option<i64>,
) -> Result<bool, ConvertError> {
    if set.is_none() && before.is_none() {
        return Ok(false);
    }
    let current_fire = rendered_fire(ical)?;
    let fire = match (set, time) {
        (Some(false), _) => None,
        (Some(true), Some(time)) => Some(time),
        (Some(true), None) => before.or(current_fire),
        (None, _) if before.is_some() => before,
        (None, _) => return Ok(false),
    };
    if fire == current_fire && before.is_none() {
        return Ok(false);
    }
    let (series, main) = todo_parts(ical).ok_or(ConvertError::Unsupported)?;
    let alarms: Vec<u32> = main
        .component_ids
        .iter()
        .copied()
        .filter(|id| {
            series
                .component(usize::try_from(*id).unwrap_or(usize::MAX))
                .is_some_and(is_display_alarm)
        })
        .collect();
    let trigger = fire
        .map(|fire| {
            let fire = Timestamp::from_second(fire).map_err(|_| ConvertError::Unsupported)?;
            let resolve = |property: &ICalendarProperty| {
                main.property(property)
                    .and_then(|entry| series.resolve_first(entry))
                    .map(|zoned| zoned.to_timestamp())
            };
            Ok::<_, ConvertError>(
                match (
                    resolve(&ICalendarProperty::Dtstart),
                    resolve(&ICalendarProperty::Due),
                ) {
                    (Some(start), _) => relative_trigger(fire, start, None),
                    (None, Some(due)) => relative_trigger(fire, due, Some(ICalendarRelated::End)),
                    (None, None) => utc_entry(ICalendarProperty::Trigger, fire.as_second()),
                },
            )
        })
        .transpose()?;
    if !alarms.is_empty() && !ical.remove_component_ids(&alarms) {
        return Err(ConvertError::Unsupported);
    }
    if let Some(trigger) = trigger {
        let index = main_index(ical)?;
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
                trigger,
            ],
            component_ids: Vec::new(),
        });
        ical.components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?
            .component_ids
            .push(id);
    }
    Ok(true)
}

pub(in crate::convert::ical) fn is_display_alarm(component: &ICalendarComponent) -> bool {
    component.component_type == ICalendarComponentType::VAlarm
        && component
            .property(&ICalendarProperty::Action)
            .and_then(|entry| entry.values.first())
            .is_none_or(|value| matches!(value, ICalendarValue::Action(ICalendarAction::Display)))
}

fn relative_trigger(
    fire: Timestamp,
    anchor: Timestamp,
    related: Option<ICalendarRelated>,
) -> ICalendarEntry {
    ICalendarEntry {
        name: ICalendarProperty::Trigger,
        params: related
            .map(|related| ICalendarParameter {
                name: ICalendarParameterName::Related,
                value: ICalendarParameterValue::Related(related),
            })
            .into_iter()
            .collect(),
        values: smallvec![ICalendarValue::Duration(ICalendarDuration::from_seconds(
            fire.as_second().saturating_sub(anchor.as_second())
        ))],
    }
}

fn utc_entry(name: ICalendarProperty, seconds: i64) -> ICalendarEntry {
    let params = if name == ICalendarProperty::Trigger {
        vec![ICalendarParameter {
            name: ICalendarParameterName::Value,
            value: ICalendarParameterValue::Value(ICalendarValueType::DateTime),
        }]
    } else {
        Vec::new()
    };
    ICalendarEntry {
        name,
        params,
        values: smallvec![ICalendarValue::PartialDateTime(
            PartialDateTime::from_utc_timestamp(seconds)
        )],
    }
}

pub(super) fn until_value(seconds: i64, form: Option<TimeForm>) -> PartialDateTime {
    let mut value = PartialDateTime::from_utc_timestamp(seconds);
    if matches!(form, Some(TimeForm::Date | TimeForm::Floating)) {
        value.tz_hour = None;
        value.tz_minute = None;
    }
    if form == Some(TimeForm::Date) {
        value.hour = None;
        value.minute = None;
        value.second = None;
    }
    value
}

fn replace(
    component: &mut ICalendarComponent,
    name: &ICalendarProperty,
    edit: Option<Edit<ICalendarEntry>>,
) {
    let Some(edit) = edit else {
        return;
    };
    remove_all(component, name);
    if let Edit::Set(entry) = edit {
        component.entries.push(entry);
    }
}

fn remove_all(component: &mut ICalendarComponent, name: &ICalendarProperty) {
    component.entries.retain(|entry| &entry.name != name);
}

fn main_index(ical: &ICalendar) -> Result<usize, ConvertError> {
    todo_parts(ical)
        .map(|(series, _)| series.main)
        .ok_or(ConvertError::Unsupported)
}

fn priority(level: u8) -> Option<i64> {
    match i32::from(level) {
        importance::HIGH => Some(1),
        importance::NORMAL => Some(5),
        importance::LOW => Some(9),
        _ => None,
    }
}

pub(super) fn class(level: u8) -> Option<Edit<ICalendarValue>> {
    match i32::from(level) {
        sensitivity::NORMAL => Some(Edit::Remove),
        sensitivity::PERSONAL => Some(Edit::Set(ICalendarValue::Text(PERSONAL_CLASS.into()))),
        sensitivity::PRIVATE => Some(Edit::Set(ICalendarValue::Classification(
            ICalendarClassification::Private,
        ))),
        sensitivity::CONFIDENTIAL => Some(Edit::Set(ICalendarValue::Classification(
            ICalendarClassification::Confidential,
        ))),
        _ => None,
    }
}

pub(super) fn non_empty(text: Option<&str>) -> Option<&str> {
    text.filter(|text| !text.is_empty())
}

pub(super) fn seconds(time: EasDateTime) -> i64 {
    time.0.0
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/eas/todo/tests.rs"]
mod tests;
