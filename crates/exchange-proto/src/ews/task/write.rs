/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::FileTime,
    convert::{
        blob::{TaskAnchor, TaskRecur, TaskRecurError},
        context::ConvertOptions,
        ical::{
            has_unmapped_task_recurrence, patch_task_from_message,
            props::{REMINDER_SET, REMINDER_TIME},
            task::{TASK_BLOB_CAPACITY, keys, status},
        },
        model::PropBag,
    },
    ews::{
        calendar::rule::{RuleError, SeriesRule, rule_of},
        item_edit::{
            CommonField, cleared_value, common_field, extended_value, with_appended_categories,
        },
        schema::{TaskStatus, UnindexedField},
        types::{
            change::ItemChange,
            item::{Item, TaskItem},
            path::Path,
            recurrence::Recurrence,
            value::DateTime,
            xprop::ExtendedProperty,
        },
    },
    mapi::prop::{OwnedPropValue, PropKey, PropKeyRef, PropType},
};
use calcard::icalendar::{ICalendar, ICalendarComponent, ICalendarComponentType};

const MAX_PERCENT: f64 = 100.0;

const CREATE_FIELDS: [UnindexedField; 13] = [
    UnindexedField::ItemSubject,
    UnindexedField::ItemBody,
    UnindexedField::ItemSensitivity,
    UnindexedField::ItemImportance,
    UnindexedField::ItemCategories,
    UnindexedField::ItemReminderIsSet,
    UnindexedField::ItemReminderNextTime,
    UnindexedField::TaskStartDate,
    UnindexedField::TaskDueDate,
    UnindexedField::TaskCompleteDate,
    UnindexedField::TaskPercentComplete,
    UnindexedField::TaskStatus,
    UnindexedField::TaskRecurrence,
];

const COMPLETION_KEYS: [PropKeyRef<'static>; 3] =
    [keys::STATUS, keys::PERCENT, keys::DATE_COMPLETED];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskEditError {
    NotATask,
    InvalidPropertySet,
    InvalidPropertyAppend,
    InvalidRecurrence,
    NoOccurrence,
    UnsupportedRecurrence,
    Conversion,
}

#[derive(Debug, Default)]
pub struct TaskEdit {
    props: PropBag,
    appended_categories: Vec<Box<str>>,
}

enum Source<'v, 'x> {
    Set(&'v TaskItem<'x>),
    Delete,
}

impl TaskEdit {
    pub fn from_item(item: &TaskItem<'_>) -> Result<Self, TaskEditError> {
        let task = &item.task;
        if task.assigned_time.is_some()
            || task.change_count.is_some()
            || task.delegation_state.is_some()
            || task.delegator.is_some()
            || task.is_assignment_editable.is_some()
            || task.is_complete.is_some()
            || task.is_recurring.is_some()
            || task.is_team_task.is_some()
            || task.status_description.is_some()
        {
            return Err(TaskEditError::InvalidPropertySet);
        }
        let mut edit = TaskEdit::default();
        let source = Source::Set(item);
        for field in CREATE_FIELDS {
            edit.field(field, &source)?;
        }
        for property in item.item.extended_property.iter().flat_map(|list| &list.0) {
            edit.extended_value(property)?;
        }
        Ok(edit)
    }

    pub fn change(&mut self, change: &ItemChange<'_>) -> Result<(), TaskEditError> {
        let based;
        let (path, source) = match change {
            ItemChange::Set {
                path,
                value: Item::Item(fields),
            } => {
                based = TaskItem {
                    item: fields.as_ref().clone(),
                    ..Default::default()
                };
                (path, Source::Set(&based))
            }
            ItemChange::Set { path, value } => (path, Source::Set(task_of(value)?)),
            ItemChange::Append { path, value } => {
                return match path {
                    Path::Field(UnindexedField::ItemCategories) => {
                        let names = task_of(value)?
                            .item
                            .categories
                            .as_ref()
                            .ok_or(TaskEditError::InvalidPropertySet)?;
                        self.appended_categories
                            .extend(names.0.iter().map(|name| Box::from(name.as_ref())));
                        Ok(())
                    }
                    _ => Err(TaskEditError::InvalidPropertyAppend),
                };
            }
            ItemChange::Delete(path) => (path, Source::Delete),
        };
        match path {
            Path::Field(UnindexedField::ItemItemClass) => Ok(()),
            Path::Field(field) if is_unstored(*field) => Ok(()),
            Path::Field(field) => {
                if self.field(*field, &source)? {
                    Ok(())
                } else {
                    Err(TaskEditError::InvalidPropertySet)
                }
            }
            Path::Indexed { .. } => Err(TaskEditError::InvalidPropertySet),
            Path::Extended(uri) => match source {
                Source::Set(item) => {
                    let property = item
                        .item
                        .extended_property
                        .iter()
                        .flat_map(|list| &list.0)
                        .find(|property| property.uri == *uri)
                        .ok_or(TaskEditError::InvalidPropertySet)?;
                    self.extended_value(property)
                }
                Source::Delete => {
                    let (key, ptype) = uri
                        .to_prop()
                        .map_err(|_| TaskEditError::InvalidPropertySet)?;
                    self.set_prop(key, cleared_value(ptype));
                    Ok(())
                }
            },
        }
    }

    pub fn apply(
        &self,
        ical: &mut ICalendar,
        opts: &ConvertOptions<'_>,
    ) -> Result<(), TaskEditError> {
        let mut props =
            with_appended_categories(&self.props, &self.appended_categories, main_todo(ical));
        if props.get_any(keys::RECURRENCE).is_some() && has_unmapped_task_recurrence(ical) {
            let props = props.to_mut();
            while let Some(value) = props.get_any(keys::RECURRENCE) {
                if !clears_recurrence(value) {
                    return Err(TaskEditError::UnsupportedRecurrence);
                }
                let ptype = value.ptype();
                props
                    .remove(keys::RECURRENCE, ptype)
                    .ok_or(TaskEditError::Conversion)?;
            }
        }
        patch_task_from_message(ical, &props, opts).map_err(|_| TaskEditError::Conversion)?;
        Ok(())
    }

    fn field(
        &mut self,
        field: UnindexedField,
        source: &Source<'_, '_>,
    ) -> Result<bool, TaskEditError> {
        let item = match source {
            Source::Set(item) => Some(*item),
            Source::Delete => None,
        };
        match common_field(&mut self.props, field, item.map(|item| &item.item)) {
            CommonField::Applied => return Ok(true),
            CommonField::MissingValue => return Ok(false),
            CommonField::NotCommon => {}
        }
        let (key, value) = match field {
            UnindexedField::ItemReminderIsSet => match item.map(|item| item.item.reminder_is_set) {
                Some(None) => return Ok(false),
                Some(Some(set)) => (REMINDER_SET.prop(), OwnedPropValue::Bool(set)),
                None => (REMINDER_SET.prop(), OwnedPropValue::Bool(false)),
            },
            UnindexedField::ItemReminderNextTime => {
                match item.map(|item| item.item.reminder_next_time.as_ref()) {
                    Some(None) => return Ok(false),
                    Some(Some(date)) => (
                        REMINDER_TIME.prop(),
                        OwnedPropValue::Time(
                            date.to_utc()
                                .map(|seconds| FileTime::from_utc(seconds, 0))
                                .ok_or(TaskEditError::InvalidPropertySet)?,
                        ),
                    ),
                    None => return Err(TaskEditError::InvalidPropertySet),
                }
            }
            UnindexedField::TaskStatus => {
                let level = match item.map(|item| item.task.status) {
                    Some(None) => return Ok(false),
                    Some(Some(TaskStatus::InProgress)) => status::IN_PROGRESS,
                    Some(Some(TaskStatus::Completed)) => status::COMPLETE,
                    Some(Some(TaskStatus::WaitingOnOthers)) => status::WAITING_ON_OTHERS,
                    Some(Some(TaskStatus::Deferred)) => status::DEFERRED,
                    Some(Some(TaskStatus::NotStarted)) | None => status::NOT_STARTED,
                };
                (keys::STATUS, OwnedPropValue::I32(level))
            }
            UnindexedField::TaskPercentComplete => {
                let percent = match item.map(|item| item.task.percent_complete) {
                    Some(None) => return Ok(false),
                    Some(Some(percent)) if (0.0..=MAX_PERCENT).contains(&percent) => percent,
                    Some(Some(_)) => return Err(TaskEditError::InvalidPropertySet),
                    None => 0.0,
                };
                (keys::PERCENT, OwnedPropValue::F64(percent / MAX_PERCENT))
            }
            UnindexedField::TaskStartDate => match item.map(|item| item.task.start_date.as_ref()) {
                Some(None) => return Ok(false),
                Some(Some(date)) => (keys::START_DATE, day_value(date)),
                None => (keys::START_DATE, OwnedPropValue::Null),
            },
            UnindexedField::TaskDueDate => match item.map(|item| item.task.due_date.as_ref()) {
                Some(None) => return Ok(false),
                Some(Some(date)) => (keys::DUE_DATE, day_value(date)),
                None => (keys::DUE_DATE, OwnedPropValue::Null),
            },
            UnindexedField::TaskCompleteDate => {
                match item.map(|item| item.task.complete_date.as_ref()) {
                    Some(None) => return Ok(false),
                    Some(Some(date)) => (
                        keys::DATE_COMPLETED,
                        OwnedPropValue::Time(
                            date.to_utc()
                                .map(|seconds| FileTime::from_utc(seconds, 0))
                                .ok_or(TaskEditError::InvalidPropertySet)?,
                        ),
                    ),
                    None => (keys::DATE_COMPLETED, OwnedPropValue::Null),
                }
            }
            UnindexedField::TaskRecurrence => (
                keys::RECURRENCE,
                match item.map(|item| item.task.recurrence.as_deref()) {
                    Some(None) => return Ok(false),
                    Some(Some(recurrence)) => recurrence_value(recurrence)?,
                    None => OwnedPropValue::Null,
                },
            ),
            _ => return Err(TaskEditError::InvalidPropertySet),
        };
        self.set_prop(key.to_key(), value);
        Ok(true)
    }

    fn extended_value(&mut self, property: &ExtendedProperty<'_>) -> Result<(), TaskEditError> {
        let (key, value) = extended_value(property).ok_or(TaskEditError::InvalidPropertySet)?;
        self.set_prop(key, value);
        Ok(())
    }

    fn set_prop(&mut self, key: PropKey, value: OwnedPropValue) {
        if COMPLETION_KEYS.iter().any(|known| *known == key.as_ref()) {
            let done = completes(&value);
            for other in COMPLETION_KEYS {
                if other == key.as_ref() {
                    continue;
                }
                if let Some(ptype) = self
                    .props
                    .get_any(other)
                    .filter(|known| completes(known) != done)
                    .map(OwnedPropValue::ptype)
                {
                    self.props.remove(other, ptype);
                }
            }
            if key.as_ref() == keys::STATUS
                && value == OwnedPropValue::I32(status::NOT_STARTED)
                && self.props.get(keys::PERCENT, PropType::F64).is_some_and(
                    |percent| !matches!(percent, OwnedPropValue::F64(fraction) if *fraction <= 0.0),
                )
            {
                self.props.remove(keys::PERCENT, PropType::F64);
            }
        }
        self.props.set(key, value);
    }
}

fn is_unstored(field: UnindexedField) -> bool {
    (field.is_unstored_groupware_field() && field != UnindexedField::ItemReminderIsSet)
        || matches!(
            field,
            UnindexedField::TaskActualWork
                | UnindexedField::TaskTotalWork
                | UnindexedField::TaskMileage
                | UnindexedField::TaskBillingInformation
                | UnindexedField::TaskCompanies
                | UnindexedField::TaskContacts
        )
}

fn main_todo(ical: &ICalendar) -> Option<&ICalendarComponent> {
    let mut todos = ical
        .components
        .iter()
        .filter(|component| component.component_type == ICalendarComponentType::VTodo);
    todos
        .clone()
        .find(|component| !component.is_recurrence_override())
        .or_else(|| todos.next())
}

fn completes(value: &OwnedPropValue) -> bool {
    match value {
        OwnedPropValue::I32(level) => *level == status::COMPLETE,
        OwnedPropValue::F64(fraction) => (fraction * MAX_PERCENT).round() >= MAX_PERCENT,
        OwnedPropValue::Time(_) => true,
        _ => false,
    }
}

fn clears_recurrence(value: &OwnedPropValue) -> bool {
    match value {
        OwnedPropValue::Null => true,
        OwnedPropValue::Binary(blob) => blob.is_empty(),
        _ => false,
    }
}

fn recurrence_value(recurrence: &Recurrence) -> Result<OwnedPropValue, TaskEditError> {
    let SeriesRule { rule, first } = rule_of(recurrence).map_err(|err| match err {
        RuleError::Unsupported => TaskEditError::UnsupportedRecurrence,
        RuleError::Invalid => TaskEditError::InvalidRecurrence,
        RuleError::NoOccurrence => TaskEditError::NoOccurrence,
    })?;
    let recur =
        TaskRecur::from_client_rrule(&rule, TaskAnchor::Date(first)).map_err(|err| match err {
            TaskRecurError::Unmappable | TaskRecurError::Sliding => {
                TaskEditError::UnsupportedRecurrence
            }
            TaskRecurError::Invalid => TaskEditError::InvalidRecurrence,
        })?;
    let mut blob = Vec::with_capacity(TASK_BLOB_CAPACITY);
    recur.encode(&mut blob);
    Ok(OwnedPropValue::Binary(blob.into()))
}

fn day_value(date: &DateTime) -> OwnedPropValue {
    OwnedPropValue::Time(FileTime::from_utc(date.local_day_start(), 0))
}

fn task_of<'v, 'x>(value: &'v Item<'x>) -> Result<&'v TaskItem<'x>, TaskEditError> {
    match value {
        Item::Task(task) => Ok(task),
        _ => Err(TaskEditError::NotATask),
    }
}
