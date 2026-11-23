/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod write;

use crate::{
    common::FileTime,
    convert::{
        BlobLimits,
        blob::TaskRecur,
        ical::{
            props::{REMINDER_DELTA, REMINDER_SET, REMINDER_SIGNAL_TIME, REMINDER_TIME},
            task::{CLASS_TASK, keys, status},
        },
        model::PropBag,
        tags::{BODY, IMPORTANCE, MESSAGE_CLASS, NORMALIZED_SUBJECT, SENSITIVITY},
    },
    ews::{
        calendar::recurrence_of,
        item_edit::KEYWORDS,
        schema::{
            BaseShape, BodyType, BodyTypeResponse, Importance, ReminderGroup, Sensitivity,
            TaskStatus, UnindexedField,
        },
        types::{
            common::Body,
            ids::ItemId,
            item::{ItemFields, TaskItem, task::TaskFields},
            path::Path,
            recurrence::Recurrence,
            reminder::Reminder,
            shape::ItemShape,
            value::{DateTime, Strings},
        },
    },
    mapi::prop::{OwnedPropValue, PropKeyRef, PropType},
};
use mail_parser::text_to_html;
use std::borrow::Cow;

pub use write::{TaskEdit, TaskEditError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaskFieldSet(u32);

impl TaskFieldSet {
    pub const ID: u32 = 1;
    pub const PARENT: u32 = 1 << 1;
    pub const CLASS: u32 = 1 << 2;
    pub const SUBJECT: u32 = 1 << 3;
    pub const SENSITIVITY: u32 = 1 << 4;
    pub const BODY: u32 = 1 << 5;
    pub const CATEGORIES: u32 = 1 << 6;
    pub const IMPORTANCE: u32 = 1 << 7;
    pub const HAS_ATTACHMENTS: u32 = 1 << 8;
    pub const COMPLETE_DATE: u32 = 1 << 9;
    pub const DUE_DATE: u32 = 1 << 10;
    pub const IS_COMPLETE: u32 = 1 << 11;
    pub const IS_RECURRING: u32 = 1 << 12;
    pub const PERCENT_COMPLETE: u32 = 1 << 13;
    pub const START_DATE: u32 = 1 << 14;
    pub const STATUS: u32 = 1 << 15;
    pub const RECURRENCE: u32 = 1 << 16;
    pub const BODY_HTML: u32 = 1 << 17;
    pub const REMINDER_IS_SET: u32 = 1 << 18;
    pub const REMINDER_MINUTES: u32 = 1 << 19;
    pub const REMINDER_DUE_BY: u32 = 1 << 20;
    pub const REMINDER_NEXT_TIME: u32 = 1 << 21;

    const LAST: u32 = Self::RECURRENCE;
    const ALL: u32 = ((Self::LAST << 1) - 1)
        | Self::REMINDER_IS_SET
        | Self::REMINDER_MINUTES
        | Self::REMINDER_DUE_BY
        | Self::REMINDER_NEXT_TIME;
    const DEFAULT: u32 = Self::ALL
        & !(Self::BODY
            | Self::REMINDER_IS_SET
            | Self::REMINDER_MINUTES
            | Self::REMINDER_DUE_BY
            | Self::REMINDER_NEXT_TIME);
    const GET_ONLY: u32 = Self::BODY | Self::RECURRENCE;

    pub fn from_shape(shape: &ItemShape<'_>) -> Self {
        let mut fields = match shape.base {
            BaseShape::IdOnly => Self::ID,
            BaseShape::Default => Self::DEFAULT,
            BaseShape::AllProperties | BaseShape::PcxPeopleSearch => Self::ALL,
        };
        for path in &shape.additional {
            if let Path::Field(field) = path {
                fields |= Self::of_field(*field);
            }
        }
        if shape.body_type == Some(BodyTypeResponse::Html) {
            fields |= Self::BODY_HTML;
        }
        TaskFieldSet(fields)
    }

    pub const fn all() -> Self {
        TaskFieldSet(Self::ALL)
    }

    pub const fn id_only() -> Self {
        TaskFieldSet(Self::ID)
    }

    pub const fn for_list(self) -> Self {
        TaskFieldSet(self.0 & !Self::GET_ONLY)
    }

    pub const fn has(self, field: u32) -> bool {
        self.0 & field != 0
    }

    pub const fn needs_content(self) -> bool {
        self.0 & !(Self::ID | Self::PARENT | Self::BODY_HTML) != 0
    }

    fn of_field(field: UnindexedField) -> u32 {
        match field {
            UnindexedField::ItemItemId => Self::ID,
            UnindexedField::ItemParentFolderId => Self::PARENT,
            UnindexedField::ItemItemClass => Self::CLASS,
            UnindexedField::ItemSubject => Self::SUBJECT,
            UnindexedField::ItemSensitivity => Self::SENSITIVITY,
            UnindexedField::ItemBody => Self::BODY,
            UnindexedField::ItemCategories => Self::CATEGORIES,
            UnindexedField::ItemImportance => Self::IMPORTANCE,
            UnindexedField::ItemHasAttachments => Self::HAS_ATTACHMENTS,
            UnindexedField::ItemReminderIsSet => Self::REMINDER_IS_SET,
            UnindexedField::ItemReminderMinutesBeforeStart => Self::REMINDER_MINUTES,
            UnindexedField::ItemReminderDueBy => Self::REMINDER_DUE_BY,
            UnindexedField::ItemReminderNextTime => Self::REMINDER_NEXT_TIME,
            UnindexedField::TaskCompleteDate => Self::COMPLETE_DATE,
            UnindexedField::TaskDueDate => Self::DUE_DATE,
            UnindexedField::TaskIsComplete => Self::IS_COMPLETE,
            UnindexedField::TaskIsRecurring => Self::IS_RECURRING,
            UnindexedField::TaskPercentComplete => Self::PERCENT_COMPLETE,
            UnindexedField::TaskStartDate => Self::START_DATE,
            UnindexedField::TaskStatus => Self::STATUS,
            UnindexedField::TaskRecurrence => Self::RECURRENCE,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskField {
    ItemClass,
    Subject,
    Importance,
    Status,
    IsComplete,
    StartDate,
    DueDate,
    CompleteDate,
}

impl TaskField {
    pub fn of_path(path: &Path<'_>) -> Option<Self> {
        match path {
            Path::Field(field) => match field {
                UnindexedField::ItemItemClass => Some(TaskField::ItemClass),
                UnindexedField::ItemSubject => Some(TaskField::Subject),
                UnindexedField::ItemImportance => Some(TaskField::Importance),
                UnindexedField::TaskStatus => Some(TaskField::Status),
                UnindexedField::TaskIsComplete => Some(TaskField::IsComplete),
                UnindexedField::TaskStartDate => Some(TaskField::StartDate),
                UnindexedField::TaskDueDate => Some(TaskField::DueDate),
                UnindexedField::TaskCompleteDate => Some(TaskField::CompleteDate),
                _ => None,
            },
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskValue<'p> {
    Text(&'p str),
    Importance(Importance),
    Status(TaskStatus),
    Bool(bool),
    Time(FileTime),
}

#[derive(Debug, Clone, Copy)]
pub struct TaskProps<'p>(&'p PropBag);

impl<'p> TaskProps<'p> {
    pub fn new(props: &'p PropBag) -> Self {
        TaskProps(props)
    }

    pub fn render(self, fields: TaskFieldSet) -> TaskItem<'p> {
        let mut item = ItemFields::default();
        let mut task = TaskFields::default();
        if fields.has(TaskFieldSet::CLASS) {
            item.item_class = Some(Cow::Borrowed(
                self.str(PropKeyRef::Tag(MESSAGE_CLASS))
                    .unwrap_or(CLASS_TASK),
            ));
        }
        if fields.has(TaskFieldSet::SUBJECT) {
            item.subject = self
                .str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                .map(Cow::Borrowed);
        }
        if fields.has(TaskFieldSet::SENSITIVITY) {
            item.sensitivity = Some(match self.int(PropKeyRef::Tag(SENSITIVITY)) {
                Some(1) => Sensitivity::Personal,
                Some(2) => Sensitivity::Private,
                Some(3) => Sensitivity::Confidential,
                _ => Sensitivity::Normal,
            });
        }
        if fields.has(TaskFieldSet::IMPORTANCE) {
            item.importance = Some(self.importance());
        }
        if fields.has(TaskFieldSet::BODY) {
            let text = self.str(PropKeyRef::Tag(BODY)).unwrap_or_default();
            item.body = Some(if fields.has(TaskFieldSet::BODY_HTML) {
                Body {
                    body_type: BodyType::Html,
                    is_truncated: None,
                    text: Cow::Owned(text_to_html(text)),
                }
            } else {
                Body {
                    body_type: BodyType::Text,
                    is_truncated: None,
                    text: Cow::Borrowed(text),
                }
            });
        }
        if fields.has(TaskFieldSet::CATEGORIES) {
            item.categories = match self.0.get(KEYWORDS, PropType::MvUnicode) {
                Some(OwnedPropValue::MvUnicode(list)) if !list.is_empty() => Some(Strings(
                    list.iter().map(|text| Cow::Borrowed(&**text)).collect(),
                )),
                _ => None,
            };
        }
        if fields.has(TaskFieldSet::HAS_ATTACHMENTS) {
            item.has_attachments = Some(false);
        }
        let reminder = self.bool(REMINDER_SET.prop());
        if fields.has(TaskFieldSet::REMINDER_IS_SET) {
            item.reminder_is_set = Some(reminder);
        }
        if fields.has(TaskFieldSet::REMINDER_MINUTES) {
            item.reminder_minutes_before_start =
                Some(self.int(REMINDER_DELTA.prop()).unwrap_or_default());
        }
        if fields.has(TaskFieldSet::REMINDER_DUE_BY) && reminder {
            item.reminder_due_by = self.date_time(REMINDER_TIME.prop());
        }
        if fields.has(TaskFieldSet::REMINDER_NEXT_TIME) {
            item.reminder_next_time = self.reminder_signal();
        }
        if fields.has(TaskFieldSet::COMPLETE_DATE) {
            task.complete_date = self.date_time(keys::DATE_COMPLETED);
        }
        if fields.has(TaskFieldSet::DUE_DATE) {
            task.due_date = self.date_time(keys::DUE_DATE);
        }
        if fields.has(TaskFieldSet::IS_COMPLETE) {
            task.is_complete = Some(self.status() == status::COMPLETE);
        }
        if fields.has(TaskFieldSet::IS_RECURRING) {
            task.is_recurring = Some(self.bool(keys::RECURRING));
        }
        if fields.has(TaskFieldSet::PERCENT_COMPLETE) {
            task.percent_complete = Some(match self.0.get(keys::PERCENT, PropType::F64) {
                Some(OwnedPropValue::F64(fraction)) => (fraction * 100.0).clamp(0.0, 100.0),
                _ => 0.0,
            });
        }
        if fields.has(TaskFieldSet::START_DATE) {
            task.start_date = self.date_time(keys::START_DATE);
        }
        if fields.has(TaskFieldSet::STATUS) {
            task.status = Some(self.task_status());
        }
        if fields.has(TaskFieldSet::RECURRENCE) {
            task.recurrence = self.recurrence().map(Box::new);
        }
        TaskItem { item, task }
    }

    pub fn value(self, field: TaskField) -> Option<TaskValue<'p>> {
        match field {
            TaskField::ItemClass => Some(TaskValue::Text(
                self.str(PropKeyRef::Tag(MESSAGE_CLASS))
                    .unwrap_or(CLASS_TASK),
            )),
            TaskField::Subject => self
                .str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                .map(TaskValue::Text),
            TaskField::Importance => Some(TaskValue::Importance(self.importance())),
            TaskField::Status => Some(TaskValue::Status(self.task_status())),
            TaskField::IsComplete => Some(TaskValue::Bool(self.status() == status::COMPLETE)),
            TaskField::StartDate => self.time(keys::START_DATE).map(TaskValue::Time),
            TaskField::DueDate => self.time(keys::DUE_DATE).map(TaskValue::Time),
            TaskField::CompleteDate => self.time(keys::DATE_COMPLETED).map(TaskValue::Time),
        }
    }

    pub fn reminder_signal(self) -> Option<DateTime> {
        if self.bool(REMINDER_SET.prop()) {
            self.date_time(REMINDER_SIGNAL_TIME.prop())
        } else {
            None
        }
    }

    pub fn reminder(self, item_id: ItemId<'static>) -> Option<Reminder<'static>> {
        let reminder_time = self.reminder_signal()?;
        let start_date = self.date_time(keys::START_DATE).unwrap_or(reminder_time);
        Some(Reminder {
            subject: Cow::Owned(
                self.str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                    .unwrap_or_default()
                    .to_owned(),
            ),
            location: None,
            reminder_time,
            start_date,
            end_date: self.date_time(keys::DUE_DATE).unwrap_or(start_date),
            uid: Cow::Owned(item_id.id.as_str().to_owned()),
            item_id,
            recurring_master_item_id: None,
            reminder_group: Some(ReminderGroup::Task),
        })
    }

    fn recurrence(self) -> Option<Recurrence> {
        let OwnedPropValue::Binary(blob) = self.0.get(keys::RECURRENCE, PropType::Binary)? else {
            return None;
        };
        recurrence_of(
            TaskRecur::decode(blob, &BlobLimits::DEFAULT)
                .ok()?
                .pattern(),
        )
    }

    fn status(self) -> i32 {
        self.int(keys::STATUS).unwrap_or(status::NOT_STARTED)
    }

    fn task_status(self) -> TaskStatus {
        match self.status() {
            status::IN_PROGRESS => TaskStatus::InProgress,
            status::COMPLETE => TaskStatus::Completed,
            status::WAITING_ON_OTHERS => TaskStatus::WaitingOnOthers,
            status::DEFERRED => TaskStatus::Deferred,
            _ => TaskStatus::NotStarted,
        }
    }

    fn importance(self) -> Importance {
        match self.int(PropKeyRef::Tag(IMPORTANCE)) {
            Some(0) => Importance::Low,
            Some(2) => Importance::High,
            _ => Importance::Normal,
        }
    }

    fn str(self, key: PropKeyRef<'_>) -> Option<&'p str> {
        match self.0.get(key, PropType::Unicode) {
            Some(OwnedPropValue::Unicode(text)) => Some(text),
            _ => None,
        }
    }

    fn int(self, key: PropKeyRef<'_>) -> Option<i32> {
        match self.0.get(key, PropType::I32) {
            Some(OwnedPropValue::I32(value)) => Some(*value),
            _ => None,
        }
    }

    fn bool(self, key: PropKeyRef<'_>) -> bool {
        matches!(
            self.0.get(key, PropType::Bool),
            Some(OwnedPropValue::Bool(true))
        )
    }

    fn time(self, key: PropKeyRef<'_>) -> Option<FileTime> {
        match self.0.get(key, PropType::Time) {
            Some(OwnedPropValue::Time(time)) => Some(*time),
            _ => None,
        }
    }

    fn date_time(self, key: PropKeyRef<'_>) -> Option<DateTime> {
        self.time(key).map(|time| DateTime::utc(time.to_utc().0))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ews/task/tests.rs"]
mod tests;
