/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::filter::{FilterProp, NameValue, PropValue};
use exchange_proto::ews::{
    task::{TaskField, TaskProps, TaskValue},
    types::path::Path,
};
use jiff::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskProp(TaskField);

impl FilterProp for TaskProp {
    fn of_path(path: &Path<'_>) -> Option<Self> {
        TaskField::of_path(path).map(TaskProp)
    }
}

impl TaskProp {
    pub(super) fn value<'p>(self, props: TaskProps<'p>) -> Option<PropValue<'p>> {
        Some(match props.value(self.0)? {
            TaskValue::Text(text) => PropValue::Text(text),
            TaskValue::Importance(value) => PropValue::Name(NameValue::Importance(value)),
            TaskValue::Status(value) => PropValue::Name(NameValue::TaskStatus(value)),
            TaskValue::Bool(value) => PropValue::Bool(value),
            TaskValue::Time(time) => {
                PropValue::Time(Timestamp::from_second(time.to_utc().0.0).ok()?)
            }
        })
    }
}
