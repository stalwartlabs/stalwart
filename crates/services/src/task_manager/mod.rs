/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::enums::TaskType;
use registry::schema::structs::Task;
use registry::types::EnumImpl;
use std::time::{Duration, Instant};
use store::Deserialize;
use store::ahash::AHashMap;
use store::xxhash_rust::xxh3::xxh3_64;
use tokio::sync::mpsc;

use lock::TaskLock;

pub mod lock;
pub mod manager;
pub mod outcome;
pub mod reconcile;
pub mod scheduler;
pub mod tasks;
mod worker;

const QUEUE_REFRESH_INTERVAL: u64 = 60 * 5;
const DEFAULT_LOCK_EXPIRY: u64 = 60 * 60;
const LEASE_DURATION: u64 = 60 * 5;
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(LEASE_DURATION / 3);

pub(crate) struct TaskManagerIpc {
    queues: Box<[TaskTypeQueue]>,
    candidates: Vec<TaskJob>,
    revision: u64,
}

#[derive(Debug)]
pub(crate) struct TaskTypeQueue {
    typ: TaskType,
    tx: mpsc::Sender<Dispatch>,
    locked: AHashMap<u64, Locked>,
    next_due: u64,
    has_more: bool,
    is_stale: bool,
    has_sent: bool,
    scanned_at: Instant,
    wake_at: Instant,
}

#[derive(Debug)]
pub(crate) struct Locked {
    expires: Instant,
    due: u64,
    revision: u64,
    state: LockState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockState {
    InFlight {
        dispatch_revision: u64,
        has_pending_due: bool,
    },
    Parked,
}

pub(crate) struct StoredTask {
    task: Task,
    hash: u64,
}

impl Deserialize for StoredTask {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Task::deserialize(bytes).map(|task| StoredTask {
            task,
            hash: xxh3_64(bytes),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TaskJob {
    id: u64,
    due: u64,
    typ: TaskType,
    dispatch_revision: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Dispatch {
    job: TaskJob,
    lock: TaskLock,
    dispatched_at: Instant,
}

#[derive(Debug)]
pub(crate) struct TaskDone {
    id: u64,
    typ: TaskType,
    dispatch_revision: u64,
    is_committed: bool,
}

pub(crate) trait TaskInfo {
    fn name(&self) -> &'static str;
}

impl TaskInfo for Task {
    fn name(&self) -> &'static str {
        self.object_type().as_str()
    }
}

impl TaskJob {
    fn done(&self, is_committed: bool) -> TaskDone {
        TaskDone {
            id: self.id,
            typ: self.typ,
            dispatch_revision: self.dispatch_revision,
            is_committed,
        }
    }
}

pub(crate) trait TaskTypeLimits {
    fn channel_capacity(self) -> usize;

    fn concurrency(self) -> usize;
}

impl TaskTypeLimits for TaskType {
    fn channel_capacity(self) -> usize {
        match self {
            TaskType::DestroyAccount
            | TaskType::AccountMaintenance
            | TaskType::StoreMaintenance
            | TaskType::BlobRecode => 1,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            TaskType::TenantMaintenance => 1,
            // SPDX-SnippetEnd
            TaskType::SpamFilterMaintenance => 2,
            TaskType::CalendarAlarmEmail
            | TaskType::CalendarAlarmNotification
            | TaskType::CalendarItipMessage
            | TaskType::MergeThreads
            | TaskType::DmarcReport
            | TaskType::TlsReport
            | TaskType::DmarcReportWindow
            | TaskType::TlsReportWindow
            | TaskType::AcmeRenewal
            | TaskType::DkimManagement
            | TaskType::DnsManagement
            | TaskType::ExternalPublicKeyMaintenance
            | TaskType::ShareRevokeCleanup => manager::TASK_QUEUE_BUFFER,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            TaskType::RestoreArchivedItem => manager::TASK_QUEUE_BUFFER,
            // SPDX-SnippetEnd
        }
    }

    fn concurrency(self) -> usize {
        match self {
            TaskType::DestroyAccount
            | TaskType::AccountMaintenance
            | TaskType::StoreMaintenance
            | TaskType::BlobRecode
            | TaskType::ExternalPublicKeyMaintenance
            | TaskType::SpamFilterMaintenance => 1,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            TaskType::TenantMaintenance | TaskType::RestoreArchivedItem => 1,
            // SPDX-SnippetEnd
            TaskType::MergeThreads
            | TaskType::DmarcReport
            | TaskType::TlsReport
            | TaskType::DmarcReportWindow
            | TaskType::TlsReportWindow
            | TaskType::AcmeRenewal
            | TaskType::DkimManagement
            | TaskType::DnsManagement
            | TaskType::ShareRevokeCleanup => 2,
            TaskType::CalendarAlarmEmail
            | TaskType::CalendarAlarmNotification
            | TaskType::CalendarItipMessage => 4,
        }
    }
}
