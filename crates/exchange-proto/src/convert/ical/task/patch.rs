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
    icalendar::{
        ICalendar, ICalendarClassification, ICalendarComponent, ICalendarComponentType,
        ICalendarEntry, ICalendarProperty, ICalendarStatus, ICalendarValue,
    },
};
use jiff::{Span, Timestamp, civil::Date, tz::TimeZone};
use smallvec::smallvec;

use super::{
    DEFERRED, PERCENT_COMPLETE, PERCENT_DONE, STATUS_EXTENSION, TASK_COMPLETE, TASK_DATE_COMPLETED,
    TASK_DEAD_OCCURRENCE, TASK_DUE_DATE, TASK_F_RECURRING, TASK_RECURRENCE, TASK_START_DATE,
    TASK_STATUS, WAITING, due_of, status, task_anchor,
};
use crate::{
    common::time::{FILETIME_NO_DATE, FileTime},
    convert::{
        BlobLimits, ConvertError,
        blob::TaskRecur,
        ical::{
            eas::{is_display_alarm, set_reminder},
            patch::{TimeTarget, remove_other, set_text, set_value},
            props::{
                CDO_IMPORTANCE_NAME, COMMON_END, COMMON_START, Lid, PERSONAL_CLASS, REMINDER_DELTA,
                REMINDER_SET, REMINDER_SIGNAL_TIME, REMINDER_TIME, importance, sensitivity,
            },
            series::Series,
        },
        model::{PatchReport, PropBag},
        tags::{self, KEYWORDS_NAME},
    },
    mapi::prop::{OwnedPropValue, PropKeyRef, sets::PS_PUBLIC_STRINGS},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Subject,
    Body,
    Sensitivity,
    Importance,
    Keywords,
    Status,
    PercentComplete,
    StartDate,
    DueDate,
    DateCompleted,
    ReminderSet,
    ReminderTime,
    Recurring,
    Recurrence,
    DeadOccurrence,
    Derived,
}

const LID_FIELDS: [(Lid, Field); 15] = [
    (TASK_STATUS, Field::Status),
    (PERCENT_COMPLETE, Field::PercentComplete),
    (TASK_START_DATE, Field::StartDate),
    (TASK_DUE_DATE, Field::DueDate),
    (TASK_DATE_COMPLETED, Field::DateCompleted),
    (TASK_COMPLETE, Field::Derived),
    (TASK_F_RECURRING, Field::Recurring),
    (TASK_RECURRENCE, Field::Recurrence),
    (TASK_DEAD_OCCURRENCE, Field::DeadOccurrence),
    (COMMON_START, Field::Derived),
    (COMMON_END, Field::Derived),
    (REMINDER_SET, Field::ReminderSet),
    (REMINDER_TIME, Field::ReminderTime),
    (REMINDER_SIGNAL_TIME, Field::Derived),
    (REMINDER_DELTA, Field::Derived),
];

fn field(key: PropKeyRef<'_>) -> Option<Field> {
    match key {
        PropKeyRef::Tag(id) => Some(match id {
            tags::SUBJECT => Field::Subject,
            tags::BODY => Field::Body,
            tags::SENSITIVITY => Field::Sensitivity,
            tags::IMPORTANCE => Field::Importance,
            tags::SUBJECT_PREFIX | tags::NORMALIZED_SUBJECT | tags::MESSAGE_CLASS => Field::Derived,
            _ => return None,
        }),
        PropKeyRef::Lid { set, lid } => LID_FIELDS
            .iter()
            .find(|(known, _)| known.set == set && known.lid == lid)
            .map(|(_, field)| *field),
        PropKeyRef::Name { set, name } => {
            (set == PS_PUBLIC_STRINGS && name == KEYWORDS_NAME).then_some(Field::Keywords)
        }
    }
}

#[derive(Default)]
struct Current {
    start: Option<Date>,
    due: Option<Date>,
    implied_due: Option<ICalendarEntry>,
    recurring: bool,
    reminder: bool,
}

enum RecurrenceChange<'x> {
    Set(&'x [u8]),
    Clear,
}

#[derive(Clone, Copy)]
enum RecurrenceEdit<'x> {
    Set(&'x [u8]),
    End,
    Clear,
}

#[derive(Default)]
struct Recurrence<'x> {
    change: Option<RecurrenceChange<'x>>,
    cleared: bool,
    dead: bool,
}

#[derive(Clone, Copy)]
enum ImpliedDue {
    Moved(Date),
    Unchanged(Date),
    Kept(Date),
    Cleared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completion {
    Open,
    Done(Option<Timestamp>),
}

pub(crate) fn task(
    ical: &mut ICalendar,
    changes: &PropBag,
    now: Timestamp,
) -> Result<PatchReport, ConvertError> {
    let series =
        Series::of(ical, ICalendarComponentType::VTodo).ok_or(ConvertError::Unsupported)?;
    let target = series.main;
    let current = series
        .component(target)
        .map(|main| {
            let date = |value: Option<ZonedDateTime>| value.map(|value| value.naive_local().date());
            Current {
                start: date(
                    main.property(&ICalendarProperty::Dtstart)
                        .and_then(|entry| series.resolve_first(entry)),
                ),
                due: date(due_of(&series, main)),
                implied_due: implied_due(&series, main),
                recurring: main.property(&ICalendarProperty::Rrule).is_some(),
                reminder: u32::try_from(target)
                    .is_ok_and(|id| series.ical.alarms_for_id(id).any(is_display_alarm)),
            }
        })
        .unwrap_or_default();
    let component = ical
        .components
        .get_mut(target)
        .ok_or(ConvertError::Unsupported)?;
    let mut report = PatchReport::default();
    let mut completion = None;
    let mut reminder_set = None;
    let mut reminder_time = None;
    let mut recurrence = Recurrence::default();
    let mut pending_due = None;
    for (key, value) in changes.iter() {
        let applied = match (field(key.as_ref()), value) {
            (Some(Field::Recurring), OwnedPropValue::Bool(recurring)) => {
                recurrence.cleared |= !*recurring;
                true
            }
            (Some(Field::DeadOccurrence), OwnedPropValue::Bool(dead)) => {
                recurrence.dead = *dead;
                true
            }
            (Some(Field::Recurrence), OwnedPropValue::Binary(blob)) if !blob.is_empty() => {
                recurrence.change = Some(RecurrenceChange::Set(blob));
                true
            }
            (Some(Field::Recurrence), OwnedPropValue::Binary(_) | OwnedPropValue::Null) => {
                recurrence.change = Some(RecurrenceChange::Clear);
                true
            }
            (Some(Field::ReminderSet), OwnedPropValue::Bool(set)) => {
                reminder_set = Some(*set);
                true
            }
            (Some(Field::ReminderTime), OwnedPropValue::Time(time)) => {
                reminder_time = timestamp(*time).map(Timestamp::as_second);
                reminder_time.is_some()
            }
            (Some(field), value) => apply(
                component,
                field,
                value,
                &current,
                &mut completion,
                &mut pending_due,
            ),
            (None, _) => false,
        };
        if !applied {
            report.unmapped.set(key.clone(), value.clone());
        }
    }
    if changes.text(tags::SUBJECT).is_none()
        && let Some(subject) = changes.composed_subject()
    {
        set_text(component, ICalendarProperty::Summary, &subject);
    }
    if let Some(due) = pending_due {
        materialize_due(component, due);
    }
    match completion {
        Some(Completion::Done(at)) => mark_done(component, at, now),
        Some(Completion::Open) => mark_open(component),
        None => {}
    }
    if let Some(edit) = recurrence.resolve(current.recurring, || {
        [TASK_START_DATE, TASK_DUE_DATE]
            .iter()
            .any(|lid| report.unmapped.get_any(lid.prop()).is_some())
    }) {
        set_recurrence(ical, target, edit)?;
    }
    let reminder_set = match (reminder_set, reminder_time) {
        (None, Some(_)) if current.reminder => Some(true),
        (set, _) => set,
    };
    set_reminder(ical, reminder_set, reminder_time, None)?;
    Ok(report)
}

impl<'x> Recurrence<'x> {
    fn resolve(
        self,
        recurring: bool,
        dates_refused: impl FnOnce() -> bool,
    ) -> Option<RecurrenceEdit<'x>> {
        if self.cleared {
            return Some(RecurrenceEdit::Clear);
        }
        if self.dead {
            return (recurring && !dates_refused()).then_some(RecurrenceEdit::End);
        }
        match self.change? {
            RecurrenceChange::Clear => Some(RecurrenceEdit::Clear),
            RecurrenceChange::Set(_) if dates_refused() => None,
            RecurrenceChange::Set(blob) => Some(RecurrenceEdit::Set(blob)),
        }
    }
}

fn set_recurrence(
    ical: &mut ICalendar,
    target: usize,
    edit: RecurrenceEdit<'_>,
) -> Result<(), ConvertError> {
    let rule = match edit {
        RecurrenceEdit::Set(blob) => {
            let recur = TaskRecur::decode(blob, &BlobLimits::DEFAULT)
                .map_err(|_| ConvertError::Unsupported)?;
            let series =
                Series::of(ical, ICalendarComponentType::VTodo).ok_or(ConvertError::Unsupported)?;
            let anchor = series
                .component(target)
                .and_then(|main| task_anchor(&series, main))
                .ok_or(ConvertError::Unsupported)?;
            let rule = recur
                .to_rrule(anchor)
                .map_err(|_| ConvertError::Unsupported)?;
            TaskRecur::from_rrule(&rule, anchor).map_err(|_| ConvertError::Unsupported)?;
            Some(rule)
        }
        RecurrenceEdit::End | RecurrenceEdit::Clear => None,
    };
    let component = ical
        .components
        .get_mut(target)
        .ok_or(ConvertError::Unsupported)?;
    if matches!(edit, RecurrenceEdit::End) {
        for value in component
            .entries
            .iter_mut()
            .filter(|entry| entry.name == ICalendarProperty::Rrule)
            .flat_map(|entry| entry.values.iter_mut())
        {
            if let ICalendarValue::RecurrenceRule(rule) = value {
                rule.count = Some(1);
                rule.until = None;
            }
        }
        return Ok(());
    }
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Rrule | ICalendarProperty::Exdate
        )
    });
    if let Some(rule) = rule {
        component.entries.push(ICalendarEntry {
            name: ICalendarProperty::Rrule,
            params: Vec::new(),
            values: smallvec![ICalendarValue::RecurrenceRule(Box::new(rule))],
        });
    }
    Ok(())
}

fn implied_due(series: &Series<'_>, main: &ICalendarComponent) -> Option<ICalendarEntry> {
    if main.property(&ICalendarProperty::Due).is_some()
        || main.property(&ICalendarProperty::Duration).is_none()
    {
        return None;
    }
    let start = main.property(&ICalendarProperty::Dtstart)?;
    let span = series.span(main)?;
    let target = TimeTarget {
        tz: series.entry_zone(start),
        tzid: start.tz_id().map(str::to_string),
    };
    Some(target.entry(
        ICalendarProperty::Due,
        span.end.to_timestamp(),
        span.all_day,
    ))
}

fn complete(completion: &mut Option<Completion>, at: Option<Timestamp>) {
    let kept = match completion {
        Some(Completion::Done(kept)) => *kept,
        _ => None,
    };
    *completion = Some(Completion::Done(at.or(kept)));
}

pub(super) fn mark_done(component: &mut ICalendarComponent, at: Option<Timestamp>, now: Timestamp) {
    set_value(
        component,
        ICalendarProperty::Status,
        ICalendarValue::Status(ICalendarStatus::Completed),
    );
    remove_other(component, STATUS_EXTENSION);
    set_value(
        component,
        ICalendarProperty::PercentComplete,
        ICalendarValue::Integer(PERCENT_DONE),
    );
    let at = match at {
        Some(at) => at,
        None if component.property(&ICalendarProperty::Completed).is_some() => return,
        None => now,
    };
    remove_all(component, &ICalendarProperty::Completed);
    component
        .entries
        .push(utc_target().entry(ICalendarProperty::Completed, at, false));
}

fn mark_open(component: &mut ICalendarComponent) {
    remove_all(component, &ICalendarProperty::Completed);
    let percent = component
        .property(&ICalendarProperty::PercentComplete)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_integer);
    if percent == Some(PERCENT_DONE) {
        remove_all(component, &ICalendarProperty::PercentComplete);
    }
    if matches!(component.status(), Some(ICalendarStatus::Completed)) {
        let status = if percent.is_some_and(|percent| percent > 0 && percent < PERCENT_DONE) {
            ICalendarStatus::InProcess
        } else {
            ICalendarStatus::NeedsAction
        };
        set_value(
            component,
            ICalendarProperty::Status,
            ICalendarValue::Status(status),
        );
    }
}

fn apply(
    component: &mut ICalendarComponent,
    field: Field,
    value: &OwnedPropValue,
    current: &Current,
    completion: &mut Option<Completion>,
    pending_due: &mut Option<ImpliedDue>,
) -> bool {
    match (field, value) {
        (Field::Derived, _) => {}
        (Field::Subject, OwnedPropValue::Unicode(text)) => {
            set_text(component, ICalendarProperty::Summary, text)
        }
        (Field::Body, OwnedPropValue::Unicode(text)) => {
            set_text(component, ICalendarProperty::Description, text)
        }
        (Field::Sensitivity, OwnedPropValue::I32(level)) => {
            let value = match *level {
                sensitivity::PERSONAL => ICalendarValue::Text(PERSONAL_CLASS.into()),
                sensitivity::PRIVATE => {
                    ICalendarValue::Classification(ICalendarClassification::Private)
                }
                sensitivity::CONFIDENTIAL => {
                    ICalendarValue::Classification(ICalendarClassification::Confidential)
                }
                _ => ICalendarValue::Classification(ICalendarClassification::Public),
            };
            set_value(component, ICalendarProperty::Class, value);
        }
        (Field::Importance, OwnedPropValue::I32(level)) => {
            let priority = match *level {
                importance::HIGH => 1,
                importance::LOW => 9,
                _ => 5,
            };
            set_value(
                component,
                ICalendarProperty::Priority,
                ICalendarValue::Integer(priority),
            );
            remove_other(component, CDO_IMPORTANCE_NAME);
        }
        (Field::Keywords, OwnedPropValue::MvUnicode(keywords)) => {
            remove_all(component, &ICalendarProperty::Categories);
            if !keywords.is_empty() {
                component.entries.push(ICalendarEntry {
                    name: ICalendarProperty::Categories,
                    params: Vec::new(),
                    values: keywords
                        .iter()
                        .map(|keyword| ICalendarValue::Text(keyword.to_string()))
                        .collect(),
                });
            }
        }
        (Field::Status, OwnedPropValue::I32(level)) => {
            let (value, extension) = match *level {
                status::NOT_STARTED => (ICalendarStatus::NeedsAction, None),
                status::IN_PROGRESS => (ICalendarStatus::InProcess, None),
                status::COMPLETE => (ICalendarStatus::Completed, None),
                status::WAITING_ON_OTHERS => (ICalendarStatus::InProcess, Some(WAITING)),
                status::DEFERRED => (ICalendarStatus::NeedsAction, Some(DEFERRED)),
                _ => return false,
            };
            if *level == status::COMPLETE {
                complete(completion, None);
            } else {
                *completion = Some(Completion::Open);
            }
            if *level == status::DEFERRED
                && matches!(component.status(), Some(ICalendarStatus::Cancelled))
            {
                return true;
            }
            if *level == status::NOT_STARTED {
                remove_all(component, &ICalendarProperty::PercentComplete);
            }
            set_value(
                component,
                ICalendarProperty::Status,
                ICalendarValue::Status(value),
            );
            remove_other(component, STATUS_EXTENSION);
            if let Some(extension) = extension {
                component.entries.push(ICalendarEntry {
                    name: ICalendarProperty::Other(STATUS_EXTENSION.into()),
                    params: Vec::new(),
                    values: smallvec![ICalendarValue::Text(extension.into())],
                });
            }
        }
        (Field::PercentComplete, OwnedPropValue::F64(fraction)) => {
            if !fraction.is_finite() {
                return false;
            }
            let percent = ((fraction * PERCENT_DONE as f64).round() as i64).clamp(0, PERCENT_DONE);
            set_value(
                component,
                ICalendarProperty::PercentComplete,
                ICalendarValue::Integer(percent),
            );
            if percent == PERCENT_DONE {
                complete(completion, None);
            } else {
                *completion = Some(Completion::Open);
            }
        }
        (Field::StartDate, value) => {
            return set_date(
                component,
                (ICalendarProperty::Dtstart, current.start),
                (ICalendarProperty::Due, current.due),
                value,
                current,
                pending_due,
            );
        }
        (Field::DueDate, value) => {
            return set_date(
                component,
                (ICalendarProperty::Due, current.due),
                (ICalendarProperty::Dtstart, current.start),
                value,
                current,
                pending_due,
            );
        }
        (Field::DateCompleted, OwnedPropValue::Null) => *completion = Some(Completion::Open),
        (Field::DateCompleted, OwnedPropValue::Time(time)) => {
            let Some(instant) = timestamp(*time) else {
                return false;
            };
            complete(completion, Some(instant));
        }
        _ => return false,
    }
    true
}

fn set_date(
    component: &mut ICalendarComponent,
    (name, current_date): (ICalendarProperty, Option<Date>),
    (partner, partner_date): (ICalendarProperty, Option<Date>),
    value: &OwnedPropValue,
    current: &Current,
    pending_due: &mut Option<ImpliedDue>,
) -> bool {
    let editing_start = name == ICalendarProperty::Dtstart;
    match value {
        OwnedPropValue::Null | OwnedPropValue::Time(FileTime(FILETIME_NO_DATE..)) => {
            if current.recurring && editing_start {
                return false;
            }
            drop_duration(component, current, editing_start);
            remove_all(component, &name);
            if editing_start {
                keep_implied_due(component, partner_date, pending_due);
            } else {
                *pending_due = Some(ImpliedDue::Cleared);
            }
        }
        OwnedPropValue::Time(time) => {
            let Some(instant) = timestamp(*time) else {
                return false;
            };
            let target = utc_target();
            let date = target.tz.from_timestamp(instant).naive_local().date();
            if current.recurring && timed_anchor(component) {
                let Some(shift) = current_date.and_then(|from| from.until(date).ok()) else {
                    return false;
                };
                if !shift.is_zero() {
                    drop_duration(component, current, true);
                }
                if component.property(&name).is_none() {
                    *pending_due = Some(if shift.is_zero() {
                        ImpliedDue::Unchanged(date)
                    } else {
                        ImpliedDue::Moved(date)
                    });
                    return true;
                }
                shift_dates(component, &[name], shift);
                if editing_start {
                    keep_implied_due(component, partner_date, pending_due);
                }
                return true;
            }
            if current_date == Some(date) {
                if !editing_start && implied(component) {
                    *pending_due = Some(ImpliedDue::Unchanged(date));
                }
                return true;
            }
            drop_duration(component, current, editing_start);
            remove_all(component, &name);
            component.entries.push(target.entry(name, instant, true));
            if editing_start {
                keep_implied_due(component, partner_date, pending_due);
            }
            if let Some(midnight) = partner_date
                .filter(|_| has_time(component, &partner))
                .and_then(|date| date.to_zoned(TimeZone::UTC).ok())
            {
                remove_all(component, &partner);
                component
                    .entries
                    .push(target.entry(partner, midnight.timestamp(), true));
            }
        }
        _ => return false,
    }
    true
}

fn implied(component: &ICalendarComponent) -> bool {
    component.property(&ICalendarProperty::Due).is_none()
        && component.property(&ICalendarProperty::Duration).is_none()
}

fn keep_implied_due(
    component: &ICalendarComponent,
    due: Option<Date>,
    pending_due: &mut Option<ImpliedDue>,
) {
    if let Some(due) = due
        && implied(component)
    {
        pending_due.get_or_insert(ImpliedDue::Kept(due));
    }
}

fn drop_duration(component: &mut ICalendarComponent, current: &Current, keep_due: bool) {
    if component.property(&ICalendarProperty::Duration).is_none() {
        return;
    }
    remove_all(component, &ICalendarProperty::Duration);
    if keep_due && let Some(due) = &current.implied_due {
        component.entries.push(due.clone());
    }
}

pub(super) fn shift_dates(
    component: &mut ICalendarComponent,
    names: &[ICalendarProperty],
    shift: Span,
) {
    for entry in component
        .entries
        .iter_mut()
        .filter(|entry| names.contains(&entry.name))
    {
        shift_entry(entry, shift);
    }
}

fn shift_entry(entry: &mut ICalendarEntry, shift: Span) {
    for value in &mut entry.values {
        if let ICalendarValue::PartialDateTime(value) = value
            && let Some(date) = partial_date(value).and_then(|date| date.checked_add(shift).ok())
        {
            value.year = u16::try_from(date.year()).ok();
            value.month = u8::try_from(date.month()).ok();
            value.day = u8::try_from(date.day()).ok();
        }
    }
}

fn partial_date(value: &PartialDateTime) -> Option<Date> {
    let year = i16::try_from(value.year?).ok()?;
    let month = i8::try_from(value.month?).ok()?;
    let day = i8::try_from(value.day?).ok()?;
    Date::new(year, month, day).ok()
}

fn materialize_due(component: &mut ICalendarComponent, pending: ImpliedDue) {
    let (ImpliedDue::Moved(due) | ImpliedDue::Unchanged(due) | ImpliedDue::Kept(due)) = pending
    else {
        return;
    };
    if !implied(component) {
        return;
    }
    let start = component
        .property(&ICalendarProperty::Dtstart)
        .and_then(|entry| match entry.values.first() {
            Some(ICalendarValue::PartialDateTime(value)) => {
                partial_date(value).map(|date| (entry, date, value.hour.is_some()))
            }
            _ => None,
        });
    let follows = match start {
        Some((_, date, true)) => Some(date),
        Some((_, date, false)) => date.tomorrow().ok(),
        None => None,
    };
    let store = match pending {
        ImpliedDue::Moved(_) => follows != Some(due),
        ImpliedDue::Unchanged(_) => {
            follows != Some(due) && start.is_none_or(|(_, start, _)| due >= start)
        }
        ImpliedDue::Kept(_) => follows.is_none_or(|follows| due > follows),
        ImpliedDue::Cleared => false,
    };
    if !store {
        return;
    }
    let entry = match start {
        Some((entry, date, true)) => {
            let Ok(shift) = date.until(due) else {
                return;
            };
            let mut entry = entry.clone();
            entry.name = ICalendarProperty::Due;
            shift_entry(&mut entry, shift);
            entry
        }
        _ => {
            let Ok(midnight) = due.to_zoned(TimeZone::UTC) else {
                return;
            };
            utc_target().entry(ICalendarProperty::Due, midnight.timestamp(), true)
        }
    };
    component.entries.push(entry);
}

fn timed_anchor(component: &ICalendarComponent) -> bool {
    let name = if component.property(&ICalendarProperty::Dtstart).is_some() {
        ICalendarProperty::Dtstart
    } else {
        ICalendarProperty::Due
    };
    has_time(component, &name)
}

fn has_time(component: &ICalendarComponent, name: &ICalendarProperty) -> bool {
    component
        .property(name)
        .and_then(|entry| entry.values.first())
        .is_some_and(
            |value| matches!(value, ICalendarValue::PartialDateTime(date) if date.hour.is_some()),
        )
}

fn utc_target() -> TimeTarget {
    TimeTarget {
        tz: Tz::UTC,
        tzid: None,
    }
}

fn timestamp(time: FileTime) -> Option<Timestamp> {
    let (seconds, nanos) = time.to_utc();
    Timestamp::new(seconds.0, i32::try_from(nanos).ok()?).ok()
}

pub(super) fn remove_all(component: &mut ICalendarComponent, name: &ICalendarProperty) {
    component.entries.retain(|entry| &entry.name != name);
}
