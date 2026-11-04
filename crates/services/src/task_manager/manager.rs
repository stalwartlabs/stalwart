/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::lock::TaskLockManager;
use crate::task_manager::worker::spawn_worker;
use crate::task_manager::{
    DEFAULT_LOCK_EXPIRY, Dispatch, LockState, Locked, QUEUE_REFRESH_INTERVAL, TaskDone, TaskJob,
    TaskManagerIpc, TaskTypeLimits, TaskTypeQueue,
};
use common::BuildServer;
use common::config::network::ClusterRoles;
use common::config::server::{DEFAULT_TLS_TIMEOUT, ServerProtocol};
use common::network::limiter::ConcurrencyLimiter;
use common::network::{ServerInstance, TcpAcceptor};
use common::{Inner, Server};
use registry::schema::enums::TaskType;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
use store::ahash::AHashMap;
use store::rand::RngExt;
use store::rand::seq::SliceRandom;
use store::{
    IterateParams, ValueKey, rand,
    write::{TaskDue, TaskId, TaskQueueClass, TaskTypes, ValueClass, now},
};
use tokio::sync::{mpsc, watch};
use trc::TaskManagerEvent;
use utils::snowflake::SnowflakeIdGenerator;

pub(crate) const TASK_QUEUE_BUFFER: usize = 10;
const CANDIDATE_OVERSCAN: usize = 4;
const REMOTE_LOCK_EXPIRY: u64 = QUEUE_REFRESH_INTERVAL;
const MIN_SCAN_INTERVAL: Duration = Duration::from_millis(100);
const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(QUEUE_REFRESH_INTERVAL / 2);
const SCAN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub fn spawn_task_manager(inner: Arc<Inner>) {
    let is_clustered = {
        let server = inner.build_server();
        let roles = &server.core.network.roles;

        if !roles.account_maintenance
            && !roles.store_maintenance
            && !roles.spam_training
            && !roles.task_manager
        {
            return;
        }

        server.core.storage.coordinator.is_enabled()
    };

    trc::event!(TaskManager(TaskManagerEvent::ManagerStarted));

    // Create dummy server instance for alarms
    let server_instance = Arc::new(ServerInstance {
        id: "_local".to_string(),
        protocol: ServerProtocol::Smtp,
        acceptor: TcpAcceptor::Plain,
        limiter: ConcurrencyLimiter::new(100),
        tls_timeout: DEFAULT_TLS_TIMEOUT,
        shutdown_rx: watch::channel(false).1,
        proxy_networks: vec![],
        span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
    });

    // Spawn workers for each task type
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<TaskDone>();
    let started = Instant::now();
    let queues = TaskType::ALL
        .iter()
        .map(|&task_type| {
            let (tx, rx) = mpsc::channel::<Dispatch>(task_type.channel_capacity());
            spawn_worker(
                inner.clone(),
                task_type,
                rx,
                done_tx.clone(),
                server_instance.clone(),
            );
            TaskTypeQueue::new(task_type, tx, started)
        })
        .collect::<Box<[_]>>();

    const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
    tokio::spawn(async move {
        let mut ipc = TaskManagerIpc {
            queues,
            candidates: Vec::with_capacity(TASK_QUEUE_BUFFER * CANDIDATE_OVERSCAN),
            revision: 0,
        };
        loop {
            // Release the locks held by tasks that have completed, unless the event
            // was already dispatched again
            while let Ok(done) = done_rx.try_recv() {
                ipc.task_done(done);
            }

            let flagged = inner.ipc.task_tx.take();
            let mut sleep_for = inner.build_server().process_tasks(&mut ipc, flagged).await;
            if is_clustered && sleep_for > REFRESH_INTERVAL {
                sleep_for = REFRESH_INTERVAL;
            }

            let _ = tokio::time::timeout(sleep_for, inner.ipc.task_tx.notified()).await;
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanEnd {
    Future(u64),
    Exhausted,
    Truncated(u64),
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Dispatched {
    sent: usize,
    released: bool,
}

impl TaskManagerIpc {
    fn task_done(&mut self, done: TaskDone) {
        if let Some(queue) = self.queues.iter_mut().find(|queue| queue.typ == done.typ)
            && let Entry::Occupied(entry) = queue.locked.entry(done.id)
            && let LockState::InFlight {
                dispatch_revision,
                has_pending_due,
            } = entry.get().state
            && dispatch_revision == done.dispatch_revision
        {
            entry.remove();

            // The queue entry could not be updated, make sure it is visited again
            if !done.is_committed || has_pending_due {
                queue.is_stale = true;
            }
        }
    }
}

impl TaskTypeQueue {
    fn new(typ: TaskType, tx: mpsc::Sender<Dispatch>, now: Instant) -> Self {
        TaskTypeQueue {
            typ,
            tx,
            locked: AHashMap::new(),
            next_due: u64::MAX,
            has_more: false,
            is_stale: true,
            has_sent: false,
            scanned_at: now.checked_sub(MIN_SCAN_INTERVAL).unwrap_or(now),
            wake_at: now,
        }
    }

    fn has_due_work(&self, now_timestamp: u64) -> bool {
        self.has_more || self.next_due <= now_timestamp
    }

    fn should_scan(&self, now: Instant, now_timestamp: u64) -> bool {
        let free = self.tx.capacity();
        free > 0
            && !self.tx.is_closed()
            && (self.wake_at <= now
                || ((self.is_stale || self.has_more)
                    && (self.scanned_at + MIN_SCAN_INTERVAL <= now
                        || (self.has_sent
                            && free == self.tx.max_capacity()
                            && self.has_due_work(now_timestamp)))))
    }

    fn next_wake(&self, now: Instant, now_timestamp: u64) -> Instant {
        if self.tx.capacity() == 0 || self.tx.is_closed() {
            if self.wake_at > now {
                self.wake_at
            } else {
                now + Duration::from_secs(QUEUE_REFRESH_INTERVAL)
            }
        } else if self.should_scan(now, now_timestamp) {
            now
        } else if self.is_stale || self.has_more {
            self.scanned_at + MIN_SCAN_INTERVAL
        } else {
            self.wake_at
        }
    }

    fn finish_scan(
        &mut self,
        scan: ScanEnd,
        dispatched: Dispatched,
        revision: u64,
        now: Instant,
        now_timestamp: u64,
    ) {
        let released = dispatched.released;
        self.scanned_at = now;
        self.is_stale = false;
        self.has_sent = dispatched.sent > 0;
        let mut wake_at = now + FULL_SCAN_INTERVAL;

        let evict_below = match scan {
            ScanEnd::Future(due) => {
                self.next_due = due;
                self.has_more = released;
                wake_at = wake_at.min(now + Duration::from_secs(due.saturating_sub(now_timestamp)));
                u64::MAX
            }
            ScanEnd::Exhausted => {
                self.next_due = u64::MAX;
                self.has_more = released;
                u64::MAX
            }
            ScanEnd::Truncated(last_due) => {
                self.next_due = u64::MAX;
                self.has_more = true;
                last_due
            }
            ScanEnd::Failed => {
                self.next_due = u64::MAX;
                self.has_more = false;
                wake_at = now + SCAN_RETRY_INTERVAL;
                0
            }
        };

        self.locked.retain(|_, locked| {
            let keep =
                locked.expires > now && (locked.revision == revision || locked.due >= evict_below);
            if keep && locked.expires < wake_at {
                wake_at = locked.expires;
            }
            keep
        });
        self.wake_at = wake_at;
    }
}

pub(crate) trait TaskQueueManager: Sync + Send {
    fn process_tasks(
        &self,
        ipc: &mut TaskManagerIpc,
        flagged: TaskTypes,
    ) -> impl Future<Output = Duration> + Send;

    fn scan_tasks(
        &self,
        queue: &mut TaskTypeQueue,
        candidates: &mut Vec<TaskJob>,
        revision: u64,
        now: Instant,
        now_timestamp: u64,
    ) -> impl Future<Output = ScanEnd> + Send;

    fn dispatch_tasks(
        &self,
        queue: &mut TaskTypeQueue,
        candidates: &mut Vec<TaskJob>,
        revision: u64,
        now: Instant,
    ) -> impl Future<Output = Dispatched> + Send;
}

impl TaskQueueManager for Server {
    async fn process_tasks(&self, ipc: &mut TaskManagerIpc, flagged: TaskTypes) -> Duration {
        let roles = &self.core.network.roles;
        let now_timestamp = now();
        let now_instant = Instant::now();
        let mut wake_at = now_instant + Duration::from_secs(QUEUE_REFRESH_INTERVAL);
        let TaskManagerIpc {
            queues,
            candidates,
            revision,
        } = ipc;

        for queue in queues
            .iter_mut()
            .filter(|queue| is_enabled(queue.typ, roles))
        {
            if flagged.contains(queue.typ) {
                queue.is_stale = true;
            }

            if queue.should_scan(now_instant, now_timestamp) {
                *revision += 1;
                let scan = self
                    .scan_tasks(queue, candidates, *revision, now_instant, now_timestamp)
                    .await;
                let dispatched = self
                    .dispatch_tasks(queue, candidates, *revision, now_instant)
                    .await;
                queue.finish_scan(scan, dispatched, *revision, now_instant, now_timestamp);
            }

            wake_at = wake_at.min(queue.next_wake(now_instant, now_timestamp));
        }

        wake_at.saturating_duration_since(Instant::now())
    }

    async fn scan_tasks(
        &self,
        queue: &mut TaskTypeQueue,
        candidates: &mut Vec<TaskJob>,
        revision: u64,
        now: Instant,
        now_timestamp: u64,
    ) -> ScanEnd {
        let want = queue.tx.capacity() * CANDIDATE_OVERSCAN;
        let limit = queue.locked.len() + want + 1;
        let typ = queue.typ;
        let from_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(0),
            typ,
            due: 0,
        }));
        let to_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(u64::MAX),
            typ,
            due: now_timestamp + QUEUE_REFRESH_INTERVAL,
        }));

        let locked = &mut queue.locked;
        let mut rows = 0;
        let mut last_due = 0;
        let mut end = ScanEnd::Exhausted;
        candidates.clear();
        let result = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key)
                    .ascending()
                    .no_values()
                    .limit(limit),
                |key, _| {
                    let TaskDue { due, id, .. } = TaskDue::deserialize(key)?;
                    rows += 1;

                    if due > now_timestamp {
                        end = ScanEnd::Future(due);
                        return Ok(false);
                    }
                    last_due = due;

                    // Refreshed even when not dispatched, or a stale revision would evict it
                    if let Some(entry) = locked.get_mut(&id) {
                        entry.revision = revision;
                        if entry.expires > now {
                            match &mut entry.state {
                                LockState::InFlight {
                                    has_pending_due, ..
                                } => {
                                    *has_pending_due |= entry.due != due;
                                    return Ok(true);
                                }
                                LockState::Parked if entry.due >= due => {
                                    entry.due = due;
                                    return Ok(true);
                                }
                                LockState::Parked => {
                                    entry.due = due;
                                }
                            }
                        }
                    }

                    candidates.push(TaskJob {
                        id,
                        due,
                        typ,
                        dispatch_revision: revision,
                    });
                    if candidates.len() < want {
                        Ok(true)
                    } else {
                        end = ScanEnd::Truncated(due);
                        Ok(false)
                    }
                },
            )
            .await;

        match result {
            Ok(()) if end == ScanEnd::Exhausted && rows >= limit => ScanEnd::Truncated(last_due),
            Ok(()) => end,
            Err(err) => {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to iterate over task queue.")
                );
                ScanEnd::Failed
            }
        }
    }

    async fn dispatch_tasks(
        &self,
        queue: &mut TaskTypeQueue,
        candidates: &mut Vec<TaskJob>,
        revision: u64,
        now: Instant,
    ) -> Dispatched {
        let mut dispatched = Dispatched::default();
        if candidates.is_empty() {
            return dispatched;
        }

        trc::event!(
            TaskManager(TaskManagerEvent::TaskAcquired),
            Total = candidates.len(),
            Used = queue.locked.len(),
        );

        if candidates.len() > 1 {
            candidates.shuffle(&mut rand::rng());
        }

        let lock_expires = now + Duration::from_secs(DEFAULT_LOCK_EXPIRY + 1);
        for job in candidates.drain(..) {
            if queue.tx.capacity() == 0 {
                dispatched.released = true;
                break;
            }

            let (id, due) = (job.id, job.due);
            if let Some(Locked {
                expires,
                state:
                    LockState::InFlight {
                        has_pending_due, ..
                    },
                ..
            }) = queue.locked.get_mut(&id)
                && *expires > now
            {
                *has_pending_due = true;
            } else if let Some(lock) = self.lock_task(id).await {
                if queue
                    .tx
                    .send(Dispatch {
                        job,
                        lock,
                        dispatched_at: Instant::now(),
                    })
                    .await
                    .is_ok()
                {
                    dispatched.sent += 1;
                    queue.locked.insert(
                        id,
                        Locked {
                            expires: lock_expires,
                            due,
                            revision,
                            state: LockState::InFlight {
                                dispatch_revision: revision,
                                has_pending_due: false,
                            },
                        },
                    );
                } else {
                    trc::event!(
                        Server(trc::ServerEvent::ThreadError),
                        Details = "Error sending task.",
                        CausedBy = trc::location!()
                    );
                    self.unlock_task(lock).await;
                }
            } else {
                // Another node owns the task, retry shortly after its lock expires
                queue.locked.insert(
                    id,
                    Locked {
                        expires: now
                            + Duration::from_secs(
                                REMOTE_LOCK_EXPIRY + rand::rng().random_range(0..=60),
                            ),
                        due,
                        revision,
                        state: LockState::Parked,
                    },
                );
            }
        }

        dispatched
    }
}

#[inline(always)]
fn is_enabled(task_type: TaskType, roles: &ClusterRoles) -> bool {
    match task_type {
        TaskType::AccountMaintenance | TaskType::DestroyAccount | TaskType::ShareRevokeCleanup => {
            roles.account_maintenance
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        TaskType::TenantMaintenance => roles.account_maintenance,
        // SPDX-SnippetEnd
        TaskType::StoreMaintenance | TaskType::BlobRecode => roles.store_maintenance,
        TaskType::SpamFilterMaintenance => roles.spam_training,
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
        | TaskType::ExternalPublicKeyMaintenance => true,
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        TaskType::RestoreArchivedItem => true,
        // SPDX-SnippetEnd
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/task_manager/manager/tests.rs"]
mod tests;
