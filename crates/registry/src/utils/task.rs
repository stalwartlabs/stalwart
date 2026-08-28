/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::{
        enums::{IndexType, Permission},
        prelude::{Action, Task, TaskStatus, TaskStatusPending, UTCDateTime},
    },
    types::{EnumImpl, index::IndexValue},
};
use types::id::Id;

impl Task {
    pub fn set_status(&mut self, status: TaskStatus) {
        match self {
            Task::CalendarAlarmEmail(task) => task.status = status,
            Task::CalendarAlarmNotification(task) => task.status = status,
            Task::CalendarItipMessage(task) => task.status = status,
            Task::MergeThreads(task) => task.status = status,
            Task::DmarcReport(task) => task.status = status,
            Task::TlsReport(task) => task.status = status,
            Task::RestoreArchivedItem(task) => task.status = status,
            Task::DestroyAccount(task) => task.status = status,
            Task::AccountMaintenance(task) => task.status = status,
            Task::StoreMaintenance(task) => task.status = status,
            Task::SpamFilterMaintenance(task) => task.status = status,
            Task::AcmeRenewal(task) => task.status = status,
            Task::DkimManagement(task) => task.status = status,
            Task::DnsManagement(task) => task.status = status,
            Task::TenantMaintenance(task) => task.status = status,
        }
    }

    pub fn status(&self) -> &TaskStatus {
        match self {
            Task::CalendarAlarmEmail(task) => &task.status,
            Task::CalendarAlarmNotification(task) => &task.status,
            Task::CalendarItipMessage(task) => &task.status,
            Task::MergeThreads(task) => &task.status,
            Task::DmarcReport(task) => &task.status,
            Task::TlsReport(task) => &task.status,
            Task::RestoreArchivedItem(task) => &task.status,
            Task::DestroyAccount(task) => &task.status,
            Task::AccountMaintenance(task) => &task.status,
            Task::StoreMaintenance(task) => &task.status,
            Task::SpamFilterMaintenance(task) => &task.status,
            Task::AcmeRenewal(task) => &task.status,
            Task::DkimManagement(task) => &task.status,
            Task::DnsManagement(task) => &task.status,
            Task::TenantMaintenance(task) => &task.status,
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

    pub fn permission(&self) -> Permission {
        match self {
            Task::CalendarAlarmEmail(_) => Permission::TaskCalendarAlarmEmail,
            Task::CalendarAlarmNotification(_) => Permission::TaskCalendarAlarmNotification,
            Task::CalendarItipMessage(_) => Permission::TaskCalendarItipMessage,
            Task::MergeThreads(_) => Permission::TaskMergeThreads,
            Task::DmarcReport(_) => Permission::TaskDmarcReport,
            Task::TlsReport(_) => Permission::TaskTlsReport,
            Task::RestoreArchivedItem(_) => Permission::TaskRestoreArchivedItem,
            Task::DestroyAccount(_) => Permission::TaskDestroyAccount,
            Task::AccountMaintenance(_) => Permission::TaskAccountMaintenance,
            Task::StoreMaintenance(_) => Permission::TaskStoreMaintenance,
            Task::SpamFilterMaintenance(_) => Permission::TaskSpamFilterMaintenance,
            Task::AcmeRenewal(_) => Permission::TaskAcmeRenewal,
            Task::DkimManagement(_) => Permission::TaskDkimManagement,
            Task::DnsManagement(_) => Permission::TaskDnsManagement,
            Task::TenantMaintenance(_) => Permission::TaskTenantMaintenance,
        }
    }

    pub fn set_document_id(&mut self, document_id: Id) {
        match self {
            Task::CalendarAlarmEmail(task) => task.document_id = document_id,
            Task::CalendarAlarmNotification(task) => task.document_id = document_id,
            Task::CalendarItipMessage(task) => task.document_id = document_id,
            _ => unreachable!("task type does not carry a document id"),
        }
    }

    pub fn size_hint(&self) -> usize {
        match self {
            Task::CalendarItipMessage(task) => task
                .messages
                .iter()
                .map(|message| message.i_calendar_data.len() + message.summary.len())
                .sum(),
            _ => 64,
        }
    }
}

impl Action {
    pub fn permission(&self) -> Permission {
        match self {
            Action::ReloadSettings => Permission::ActionReloadSettings,
            Action::ReloadTlsCertificates => Permission::ActionReloadTlsCertificates,
            Action::ReloadLookupStores => Permission::ActionReloadLookupStores,
            Action::ReloadBlockedIps => Permission::ActionReloadBlockedIps,
            Action::TroubleshootDmarc(_) => Permission::ActionTroubleshootDmarc,
            Action::ClassifySpam(_) => Permission::ActionClassifySpam,
            Action::InvalidateCaches => Permission::ActionInvalidateCaches,
            Action::InvalidateNegativeCaches => Permission::ActionInvalidateNegativeCaches,
            Action::PauseMtaQueue => Permission::ActionPauseMtaQueue,
            Action::ResumeMtaQueue => Permission::ActionResumeMtaQueue,
            Action::UpdateApps => Permission::ActionUpdateApps,
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

impl From<&IndexType> for IndexValue<'_> {
    fn from(value: &IndexType) -> Self {
        IndexValue::U16(value.to_id())
    }
}
