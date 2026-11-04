/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::{
        enums::{
            IndexType, Permission, SharedObjectType, TaskSpamFilterMaintenanceType,
            TaskStoreMaintenanceType,
        },
        prelude::{Action, Task, TaskStatus, TaskStatusPending, UTCDateTime},
    },
    types::{EnumImpl, index::IndexValue},
};
use types::{collection::Collection, id::Id};

impl Task {
    pub fn set_status(&mut self, status: TaskStatus) {
        match self {
            Task::CalendarAlarmEmail(task) => task.status = status,
            Task::CalendarAlarmNotification(task) => task.status = status,
            Task::CalendarItipMessage(task) => task.status = status,
            Task::MergeThreads(task) => task.status = status,
            Task::DmarcReport(task) => task.status = status,
            Task::TlsReport(task) => task.status = status,
            Task::DmarcReportWindow(task) | Task::TlsReportWindow(task) => task.status = status,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::RestoreArchivedItem(task) => task.status = status,
            // SPDX-SnippetEnd
            Task::DestroyAccount(task) => task.status = status,
            Task::AccountMaintenance(task) => task.status = status,
            Task::StoreMaintenance(task) => task.status = status,
            Task::SpamFilterMaintenance(task) => task.status = status,
            Task::AcmeRenewal(task) => task.status = status,
            Task::DkimManagement(task) => task.status = status,
            Task::DnsManagement(task) => task.status = status,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::TenantMaintenance(task) => task.status = status,
            // SPDX-SnippetEnd
            Task::ShareRevokeCleanup(task) => task.status = status,
            Task::ExternalPublicKeyMaintenance(task) => task.status = status,
            Task::BlobRecode(task) => task.status = status,
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
            Task::DmarcReportWindow(task) | Task::TlsReportWindow(task) => &task.status,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::RestoreArchivedItem(task) => &task.status,
            // SPDX-SnippetEnd
            Task::DestroyAccount(task) => &task.status,
            Task::AccountMaintenance(task) => &task.status,
            Task::StoreMaintenance(task) => &task.status,
            Task::SpamFilterMaintenance(task) => &task.status,
            Task::AcmeRenewal(task) => &task.status,
            Task::DkimManagement(task) => &task.status,
            Task::DnsManagement(task) => &task.status,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::TenantMaintenance(task) => &task.status,
            // SPDX-SnippetEnd
            Task::ShareRevokeCleanup(task) => &task.status,
            Task::ExternalPublicKeyMaintenance(task) => &task.status,
            Task::BlobRecode(task) => &task.status,
        }
    }

    pub fn attempt_number(&self) -> u64 {
        match self.status() {
            TaskStatus::Pending(_) => 0,
            TaskStatus::Retry(status) | TaskStatus::Stalled(status) => status.attempt_number,
            TaskStatus::Failed(status) => status.failed_attempt_number,
        }
    }

    pub fn due_timestamp(&self) -> u64 {
        match self.status() {
            TaskStatus::Pending(status) => status.due.timestamp() as u64,
            TaskStatus::Retry(status) | TaskStatus::Stalled(status) => {
                status.due.timestamp() as u64
            }
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
            Task::DmarcReportWindow(_) => Permission::TaskDmarcReportWindow,
            Task::TlsReportWindow(_) => Permission::TaskTlsReportWindow,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::RestoreArchivedItem(_) => Permission::TaskRestoreArchivedItem,
            // SPDX-SnippetEnd
            Task::DestroyAccount(_) => Permission::TaskDestroyAccount,
            Task::AccountMaintenance(_) => Permission::TaskAccountMaintenance,
            Task::StoreMaintenance(_) => Permission::TaskStoreMaintenance,
            Task::SpamFilterMaintenance(_) => Permission::TaskSpamFilterMaintenance,
            Task::AcmeRenewal(_) => Permission::TaskAcmeRenewal,
            Task::DkimManagement(_) => Permission::TaskDkimManagement,
            Task::DnsManagement(_) => Permission::TaskDnsManagement,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::TenantMaintenance(_) => Permission::TaskTenantMaintenance,
            // SPDX-SnippetEnd
            Task::ShareRevokeCleanup(_) => Permission::TaskShareRevokeCleanup,
            Task::ExternalPublicKeyMaintenance(_) => Permission::TaskExternalPublicKeyMaintenance,
            Task::BlobRecode(_) => Permission::TaskBlobRecode,
        }
    }

    pub fn singleton_key(&self) -> Option<(u16, u64)> {
        match self {
            Task::ExternalPublicKeyMaintenance(_) => Some((0, u64::MAX)),
            Task::BlobRecode(task) => Some((0, task.shard_index.unwrap_or(u64::MAX))),
            Task::AcmeRenewal(task) | Task::DkimManagement(task) => Some((0, task.domain_id.id())),
            Task::DmarcReportWindow(task) | Task::TlsReportWindow(task) => {
                Some((0, task.window_end.timestamp().cast_unsigned()))
            }
            Task::AccountMaintenance(task) => {
                Some((task.maintenance_type.to_id(), task.account_id.id()))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Task::TenantMaintenance(task) => {
                Some((task.maintenance_type.to_id(), task.tenant_id.id()))
            }
            // SPDX-SnippetEnd
            Task::StoreMaintenance(task) => match (task.maintenance_type, task.shard_index) {
                (TaskStoreMaintenanceType::PurgeBlob, Some(shard_index)) => {
                    Some((task.maintenance_type.to_id(), shard_index))
                }
                (
                    TaskStoreMaintenanceType::PurgeAccounts
                    | TaskStoreMaintenanceType::PurgeData
                    | TaskStoreMaintenanceType::PurgeBlob
                    | TaskStoreMaintenanceType::ReindexAccounts
                    | TaskStoreMaintenanceType::ResetUserQuotas,
                    _,
                ) => Some((task.maintenance_type.to_id(), u64::MAX)),
                _ => None,
            },
            Task::SpamFilterMaintenance(task) => match task.maintenance_type {
                TaskSpamFilterMaintenanceType::Train
                | TaskSpamFilterMaintenanceType::Retrain
                | TaskSpamFilterMaintenanceType::UpdateRules => {
                    Some((task.maintenance_type.to_id(), u64::MAX))
                }
                _ => None,
            },
            _ => None,
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
            Action::ReloadSettings(_) => Permission::ActionReloadSettings,
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
    pub fn created_at(&self) -> UTCDateTime {
        match self {
            TaskStatus::Pending(status) => status.created_at,
            TaskStatus::Retry(status) | TaskStatus::Stalled(status) => status.created_at,
            TaskStatus::Failed(status) => status.created_at,
        }
    }

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

impl SharedObjectType {
    pub fn from_collection(collection: Collection) -> Option<Self> {
        match collection {
            Collection::Mailbox => Some(SharedObjectType::Mailbox),
            Collection::Calendar => Some(SharedObjectType::Calendar),
            Collection::AddressBook => Some(SharedObjectType::AddressBook),
            Collection::FileNode => Some(SharedObjectType::FileNode),
            _ => None,
        }
    }

    pub fn collection(self) -> Collection {
        match self {
            SharedObjectType::Mailbox => Collection::Mailbox,
            SharedObjectType::Calendar => Collection::Calendar,
            SharedObjectType::AddressBook => Collection::AddressBook,
            SharedObjectType::FileNode => Collection::FileNode,
        }
    }
}

impl From<&IndexType> for IndexValue<'_> {
    fn from(value: &IndexType) -> Self {
        IndexValue::U16(value.to_id())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/registry/src/utils/task/tests.rs"]
mod tests;
