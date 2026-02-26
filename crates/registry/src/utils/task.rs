/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{Task, TaskStatus, TaskStatusPending, UTCDateTime};

impl Task {
    pub fn set_status(&mut self, status: TaskStatus) {
        match self {
            Task::IndexDocument(task) => task.status = status,
            Task::UnindexDocument(task) => task.status = status,
            Task::IndexTrace(task) => task.status = status,
            Task::CalendarAlarmEmail(task) => task.status = status,
            Task::CalendarAlarmNotification(task) => task.status = status,
            Task::CalendarItipMessage(task) => task.status = status,
            Task::MergeThreads(task) => task.status = status,
            Task::DmarcReport(task) => task.status = status,
            Task::TlsReport(task) => task.status = status,
        }
    }

    pub fn status(&self) -> &TaskStatus {
        match self {
            Task::IndexDocument(task) => &task.status,
            Task::UnindexDocument(task) => &task.status,
            Task::IndexTrace(task) => &task.status,
            Task::CalendarAlarmEmail(task) => &task.status,
            Task::CalendarAlarmNotification(task) => &task.status,
            Task::CalendarItipMessage(task) => &task.status,
            Task::MergeThreads(task) => &task.status,
            Task::DmarcReport(task) => &task.status,
            Task::TlsReport(task) => &task.status,
        }
    }

    pub fn attempt_number(&self) -> u64 {
        match self.status() {
            TaskStatus::Pending(_) => 0,
            TaskStatus::Retry(status) => status.attempt_number,
            TaskStatus::Failed(status) => status.failed_attempt_number,
        }
    }

    pub fn due_timestamp(&self) -> u64 {
        match self.status() {
            TaskStatus::Pending(status) => status.due.timestamp() as u64,
            TaskStatus::Retry(status) => status.due.timestamp() as u64,
            TaskStatus::Failed(_) => u64::MAX,
        }
    }
}

impl TaskStatus {
    pub fn now() -> Self {
        let now = UTCDateTime::now();
        TaskStatus::Pending(TaskStatusPending {
            created_at: now,
            due: now,
        })
    }

    pub fn at(timestamp: i64) -> Self {
        TaskStatus::Pending(TaskStatusPending {
            due: UTCDateTime::from_timestamp(timestamp),
            created_at: UTCDateTime::now(),
        })
    }
}
