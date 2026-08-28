/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::lock::TaskLockManager;
use crate::task_manager::tasks::acme::AcmeTask;
use crate::task_manager::tasks::alarm::SendAlarmTask;
use crate::task_manager::tasks::destroy_account::DestroyAccountTask;
use crate::task_manager::tasks::dkim::DkimManagementTask;
use crate::task_manager::tasks::dns::DnsManagementTask;
use crate::task_manager::tasks::imip::SendImipTask;
use crate::task_manager::tasks::maintenance::MaintenanceTask;
use crate::task_manager::tasks::merge_threads::MergeThreadsTask;
use crate::task_manager::tasks::report::{self, SubmitReportTask};
use crate::task_manager::tasks::restore_item::RestoreItemTask;
use crate::task_manager::tasks::spam_classifier::SpamFilterMaintenanceTask;
use crate::task_manager::{
    DEFAULT_LOCK_EXPIRY, Locked, QUEUE_REFRESH_INTERVAL, TaskDetails, TaskDone, TaskFailureType,
    TaskInfo, TaskJob, TaskManagerIpc, TaskResult,
};
use common::BuildServer;
use common::config::network::ClusterRoles;
use common::config::server::ServerProtocol;
use common::network::limiter::ConcurrencyLimiter;
use common::network::{ServerInstance, TcpAcceptor};
use common::{Inner, Server};
use registry::schema::enums::TaskType;
use registry::schema::structs::{
    Task, TaskManager, TaskRetryStrategy, TaskStatus, TaskStatusFailed, TaskStatusRetry,
};
use registry::types::datetime::UTCDateTime;
use registry::types::{EnumImpl, ObjectImpl};
use std::collections::hash_map::Entry;
use std::future::Future;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
use store::ahash::AHashMap;
use store::rand::RngExt;
use store::rand::seq::SliceRandom;
use store::write::key::DeserializeBigEndian;
use store::{
    IterateParams, ValueKey,
    write::{BatchBuilder, TaskId, TaskQueueClass, ValueClass, assert::AssertValue, now},
};
use store::{SerializeInfallible, U64_LEN, rand};
use tokio::sync::{mpsc, watch};
use trc::TaskManagerEvent;
use utils::snowflake::SnowflakeIdGenerator;

const TASK_QUEUE_BUFFER: usize = 10;
const CANDIDATE_OVERSCAN: usize = 4;
const REMOTE_LOCK_EXPIRY: u64 = QUEUE_REFRESH_INTERVAL;
const MIN_SCAN_INTERVAL: Duration = Duration::from_millis(100);
const FULL_SCAN_INTERVAL: Duration = Duration::from_secs(QUEUE_REFRESH_INTERVAL / 2);
const PERPETUAL_RETRY_MIN_DELAY: u64 = 3600;
const PERPETUAL_RETRY_MAX_DELAY: u64 = 21600;

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
        shutdown_rx: watch::channel(false).1,
        proxy_networks: vec![],
        span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
    });

    // Spawn workers for each task type
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<TaskDone>();
    let mut txs = Vec::with_capacity(TaskType::COUNT);
    for idx in 0..TaskType::COUNT {
        let task_type = TaskType::from_id(idx as u16).unwrap();
        let channel_capacity = match task_type {
            TaskType::DestroyAccount
            | TaskType::AccountMaintenance
            | TaskType::TenantMaintenance
            | TaskType::StoreMaintenance => 1,
            TaskType::SpamFilterMaintenance => 2,
            TaskType::CalendarAlarmEmail
            | TaskType::CalendarAlarmNotification
            | TaskType::CalendarItipMessage
            | TaskType::MergeThreads
            | TaskType::DmarcReport
            | TaskType::TlsReport
            | TaskType::RestoreArchivedItem
            | TaskType::AcmeRenewal
            | TaskType::DkimManagement
            | TaskType::DnsManagement => TASK_QUEUE_BUFFER,
        };

        let (tx, mut rx) = mpsc::channel::<TaskJob>(channel_capacity);
        txs.push(tx);
        let inner = inner.clone();
        let done_tx = done_tx.clone();

        let server_instance = server_instance.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let server = inner.build_server();
                let mut refresh_queue = false;
                let (job_id, job_revision) = (job.id, job.dispatch_revision);

                match server
                    .store()
                    .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                        TaskQueueClass::Task {
                            id: TaskId::Assigned(job_id),
                        },
                    )))
                    .await
                {
                    Ok(Some(task)) => {
                        let result = match &task {
                            Task::CalendarAlarmEmail(task) => {
                                server.send_email_alarm(task, server_instance.clone()).await
                            }
                            Task::CalendarAlarmNotification(task) => {
                                server.send_display_alarm(task).await
                            }
                            Task::CalendarItipMessage(task) => {
                                server.send_imip(task, server_instance.clone()).await
                            }
                            Task::MergeThreads(task) => server.merge_threads(task).await,
                            Task::DmarcReport(task) => {
                                server
                                    .submit_report(report::ReportId::Dmarc(task.report_id.id()))
                                    .await
                            }
                            Task::TlsReport(task) => {
                                server
                                    .submit_report(report::ReportId::Tls(task.report_id.id()))
                                    .await
                            }
                            Task::RestoreArchivedItem(task) => server.restore_item(task).await,
                            Task::DestroyAccount(task) => server.destroy_account(task).await,
                            Task::AccountMaintenance(task) => {
                                server.account_maintenance(task).await
                            }
                            Task::TenantMaintenance(task) => server.tenant_maintenance(task).await,
                            Task::StoreMaintenance(task) => server.store_maintenance(task).await,
                            Task::SpamFilterMaintenance(task) => {
                                Box::pin(server.spam_filter_maintenance(task)).await
                            }
                            Task::AcmeRenewal(task) => server.acme_management(task).await,
                            Task::DkimManagement(task_dkim_rotation) => {
                                server.dkim_management(task_dkim_rotation).await
                            }
                            Task::DnsManagement(task_dns_management) => {
                                server.dns_management(task_dns_management).await
                            }
                        };

                        refresh_queue = result.is_retry();

                        let is_committed = update_tasks(
                            &server,
                            &mut [TaskDetails { task, info: job }],
                            vec![result],
                        )
                        .await;

                        // The distributed lock has been released, drop the local one as well
                        let _ = done_tx.send(TaskDone {
                            id: job_id,
                            dispatch_revision: job_revision,
                            is_committed,
                        });
                    }
                    Ok(None) => {
                        trc::event!(
                            TaskManager(TaskManagerEvent::TaskIgnored),
                            Id = job_id,
                            Reason = "Task not found in store, likely already processed.",
                        );
                    }
                    Err(err) => {
                        trc::error!(
                            err.id(job_id)
                                .details("Failed to retrieve task details.")
                                .caused_by(trc::location!())
                        );
                    }
                }

                if refresh_queue || rx.is_empty() {
                    server.notify_task_queue();
                }
            }
        });
    }

    const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
    tokio::spawn(async move {
        let mut ipc = TaskManagerIpc {
            txs: txs.try_into().expect("Incorrect number of task channels"),
            locked: AHashMap::with_capacity(128),
            revision: 0,
            scan_from: 0,
            last_full_scan: Instant::now(),
        };
        let rx = inner.ipc.task_tx.clone();
        loop {
            // Release the locks held by tasks that have completed, unless the event
            // was already dispatched again
            while let Ok(done) = done_rx.try_recv() {
                if let Entry::Occupied(entry) = ipc.locked.entry(done.id)
                    && entry.get().dispatch_revision == done.dispatch_revision
                {
                    let due = entry.remove().due;

                    // The queue entry could not be updated, make sure it is visited again
                    if !done.is_committed && due < ipc.scan_from {
                        ipc.scan_from = due;
                    }
                }
            }

            // Index any queued tasks
            let mut sleep_for = inner.build_server().process_tasks(&mut ipc).await;
            if is_clustered && sleep_for > REFRESH_INTERVAL {
                sleep_for = REFRESH_INTERVAL;
            }
            let scanned_at = Instant::now();

            // Wait for a signal or sleep until the next task is due
            if tokio::time::timeout(sleep_for, rx.notified()).await.is_ok() {
                // Coalesce bursts of notifications into a single scan
                if let Some(wait_for) = MIN_SCAN_INTERVAL.checked_sub(scanned_at.elapsed()) {
                    tokio::time::sleep(wait_for).await;
                }
            }
        }
    });
}

pub(crate) trait TaskQueueManager: Sync + Send {
    fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> impl Future<Output = Duration> + Send;
}

impl TaskQueueManager for Server {
    async fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> Duration {
        let now_timestamp = now();
        let now_instant = Instant::now();

        // Scan the entire queue periodically, a partial scan cannot see events
        // written below its floor
        if ipc.scan_from != 0
            && now_instant.duration_since(ipc.last_full_scan) >= FULL_SCAN_INTERVAL
        {
            ipc.scan_from = 0;
        }
        if ipc.scan_from == 0 {
            ipc.last_full_scan = now_instant;
        }
        let scan_floor = ipc.scan_from;

        let from_key = ValueKey::<ValueClass> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::TaskQueue(TaskQueueClass::Due {
                id: TaskId::Assigned(0),
                due: scan_floor.max(1),
            }),
        };
        let to_key = ValueKey::<ValueClass> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::TaskQueue(TaskQueueClass::Due {
                id: TaskId::Assigned(u64::MAX),
                due: now_timestamp + QUEUE_REFRESH_INTERVAL,
            }),
        };

        // Over-sample the free worker slots so the shuffle still has a pool to pick from,
        // task types this node does not run are given no budget at all
        let roles = &self.core.network.roles;
        let mut budgets = [0usize; TaskType::COUNT];
        let mut total_budget = 0usize;
        for (idx, (budget, tx)) in budgets.iter_mut().zip(ipc.txs.iter()).enumerate() {
            if TaskType::from_id(idx as u16).is_some_and(|task_type| is_enabled(task_type, roles)) {
                *budget = tx.capacity() * CANDIDATE_OVERSCAN;
                total_budget += *budget;
            }
        }

        // Retrieve tasks pending to be processed
        let mut tasks = Vec::with_capacity(total_budget);
        let mut next_event = None;
        let mut next_scan_from = u64::MAX;
        let mut scan_ceiling = u64::MAX;
        let lock_expires = now_instant + Duration::from_secs(DEFAULT_LOCK_EXPIRY + 1);
        ipc.revision += 1;
        let revision = ipc.revision;
        let result = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    if key.len() != U64_LEN * 2 {
                        return Ok(true);
                    }
                    let task_due = key.deserialize_be_u64(0)?;
                    let task_id = key.deserialize_be_u64(U64_LEN)?;

                    if task_due > now_timestamp {
                        next_event = Some(task_due);
                        return Ok(false);
                    }

                    let task_type_idx = value.deserialize_be_u16(0)?;
                    let task_type = TaskType::from_id(task_type_idx).ok_or_else(|| {
                        trc::StoreEvent::DataCorruption
                            .caused_by(trc::location!())
                            .ctx(trc::Key::Value, value)
                    })?;
                    if !is_enabled(task_type, roles) {
                        trc::event!(
                            TaskManager(TaskManagerEvent::TaskIgnored),
                            Id = task_id,
                            Details = task_type.as_str(),
                            Reason = "Task type is disabled by cluster roles.",
                        );
                        return Ok(true);
                    }

                    // Refreshed even when not dispatched, or a stale revision would evict it
                    if let Some(locked) = ipc.locked.get_mut(&task_id) {
                        let is_locked = locked.expires > now_instant && locked.due >= task_due;
                        locked.due = task_due;
                        locked.revision = revision;
                        if is_locked {
                            return Ok(true);
                        }
                    }

                    let budget = &mut budgets[task_type_idx as usize];
                    if *budget > 0 {
                        *budget -= 1;
                        total_budget -= 1;
                        ipc.locked.insert(
                            task_id,
                            Locked {
                                expires: lock_expires,
                                due: task_due,
                                revision,
                                dispatch_revision: revision,
                            },
                        );
                        tasks.push((
                            TaskJob {
                                id: task_id,
                                due: task_due,
                                typ: task_type,
                                dispatch_revision: revision,
                            },
                            task_type_idx,
                        ));
                    } else if task_due < next_scan_from {
                        next_scan_from = task_due;
                    }

                    // Everything from here on is left for the next scan
                    if total_budget == 0 {
                        scan_ceiling = task_due;
                        if task_due < next_scan_from {
                            next_scan_from = task_due;
                        }
                        return Ok(false);
                    }

                    Ok(true)
                },
            )
            .await;

        let mut has_pending_work = true;
        if let Err(err) = result {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to iterate over task queue.")
            );

            // Restart from the top on the next scan, without evicting any lock
            ipc.scan_from = 0;
            scan_ceiling = 0;
        } else if next_scan_from == u64::MAX {
            // Nothing was left behind, there is no prefix worth skipping
            ipc.scan_from = 0;
            has_pending_work = false;
        } else {
            ipc.scan_from = std::cmp::min(next_scan_from, now_timestamp);
        }

        if !tasks.is_empty() {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskAcquired),
                Total = tasks.len(),
                Details = ipc.locked.len(),
            );
        }

        // Shuffle tasks
        if tasks.len() > 1 {
            tasks.shuffle(&mut rand::rng());
        }

        // Dispatch tasks
        for (task_job, task_type_idx) in tasks {
            let tx = &ipc.txs[task_type_idx as usize];

            if tx.capacity() > 0 {
                let task_id = task_job.id;

                if self.try_lock_task(task_id).await {
                    if tx.send(task_job).await.is_err() {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending task.",
                            CausedBy = trc::location!()
                        );
                    }
                } else if let Some(locked) = ipc.locked.get_mut(&task_id) {
                    // Another node owns the task, retry shortly after its lock expires
                    locked.expires = now_instant
                        + Duration::from_secs(
                            REMOTE_LOCK_EXPIRY + rand::rng().random_range(0..=60),
                        );
                }
            } else {
                // If the channel is full, release the lock so it can be picked up in the next scan
                ipc.locked.remove(&task_job.id);
                has_pending_work = true;
                if task_job.due < ipc.scan_from {
                    ipc.scan_from = task_job.due;
                }
            }
        }

        // Delete expired locks, keeping the ones this scan did not visit
        let mut dropped_due = u64::MAX;
        ipc.locked.retain(|_, locked| {
            if locked.expires <= now_instant {
                if locked.due < dropped_due {
                    dropped_due = locked.due;
                }
                false
            } else {
                locked.revision == revision || locked.due < scan_floor || locked.due >= scan_ceiling
            }
        });

        // Do not wait for the next scheduled event while there is work left over
        let mut sleep_for =
            Duration::from_secs(next_event.map_or(QUEUE_REFRESH_INTERVAL, |timestamp| {
                timestamp.saturating_sub(store::write::now())
            }));
        if has_pending_work {
            sleep_for = std::cmp::min(sleep_for, FULL_SCAN_INTERVAL);
        }

        // An expired lock uncovered an event no scan can see from the current floor
        if dropped_due < ipc.scan_from {
            ipc.scan_from = dropped_due;
            sleep_for = std::cmp::min(sleep_for, MIN_SCAN_INTERVAL);
        }

        sleep_for
    }
}

async fn update_tasks(
    server: &Server,
    tasks: &mut [TaskDetails],
    results: impl IntoIterator<Item = TaskResult>,
) -> bool {
    let mut batch = BatchBuilder::new();

    for (task, result) in tasks.iter_mut().zip(results) {
        let task_id = task.info.id;
        let id = TaskId::Assigned(task_id);
        batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            due: task.info.due,
        }));
        match result {
            TaskResult::Success(tasks) => {
                for task in tasks {
                    batch.schedule_task(task);
                }
                batch.clear(ValueClass::TaskQueue(TaskQueueClass::Task { id }));
            }
            TaskResult::Update(ops) => {
                for op in ops {
                    batch.any_op(op);
                }
            }
            TaskResult::Failure {
                typ,
                message,
                max_attempts,
            } => {
                let (attempt_number, retry_since) = match task.task.status() {
                    TaskStatus::Pending(_) => (0, UTCDateTime::now()),
                    TaskStatus::Retry(status) => (status.attempt_number, status.created_at),
                    TaskStatus::Failed(status) => (status.failed_attempt_number, status.failed_at),
                };
                let retry_at = match typ {
                    TaskFailureType::Retry(retry_at) => (attempt_number
                        < max_attempts.unwrap_or(server.core.network.task_manager.max_attempts)
                        && retry_at
                            <= (retry_since.timestamp() as u64).saturating_add(
                                server.core.network.task_manager.total_deadline.as_secs(),
                            ))
                    .then_some(retry_at)
                    .or_else(|| perpetual_retry_time(task.info.typ, attempt_number)),
                    TaskFailureType::Temporary => next_retry_time(
                        &server.core.network.task_manager,
                        max_attempts,
                        retry_since.timestamp() as u64,
                        attempt_number,
                        now(),
                    )
                    .or_else(|| perpetual_retry_time(task.info.typ, attempt_number)),
                    TaskFailureType::Perpetual => {
                        perpetual_retry_time(task.info.typ, attempt_number)
                    }
                    TaskFailureType::Permanent => None,
                };

                let due = if let Some(retry_at) = retry_at {
                    trc::event!(
                        TaskManager(TaskManagerEvent::TaskRetry),
                        Id = task_id,
                        Details = task.task.name(),
                        Reason = message.to_string(),
                        NextRetry = trc::Value::Timestamp(retry_at),
                    );

                    task.task.set_status(TaskStatus::Retry(TaskStatusRetry {
                        due: UTCDateTime::from_timestamp(retry_at as i64),
                        attempt_number: attempt_number + 1,
                        failure_reason: message,
                        created_at: retry_since,
                    }));

                    retry_at
                } else {
                    trc::event!(
                        TaskManager(TaskManagerEvent::TaskFailed),
                        Id = task_id,
                        Details = task.task.name(),
                        Reason = message.to_string(),
                    );

                    task.task.set_status(TaskStatus::Failed(TaskStatusFailed {
                        failed_at: UTCDateTime::now(),
                        failed_attempt_number: attempt_number,
                        failure_reason: message,
                        created_at: retry_since,
                    }));
                    u64::MAX
                };
                batch
                    .assert_value(
                        ValueClass::TaskQueue(TaskQueueClass::Task { id }),
                        AssertValue::Some,
                    )
                    .set(
                        ValueClass::TaskQueue(TaskQueueClass::Due { id, due }),
                        task.info.typ.to_id().serialize(),
                    )
                    .set(
                        ValueClass::TaskQueue(TaskQueueClass::Task { id }),
                        task.task.to_pickled_vec(),
                    );
            }
        }
    }

    let is_committed = match server.store().write_batch(batch.build_all()).await {
        Ok(_) => true,
        Err(err) => {
            if err.matches(trc::EventType::Store(trc::StoreEvent::AssertValueFailed)) {
                trc::event!(
                    TaskManager(TaskManagerEvent::TaskIgnored),
                    Reason = "Task was deleted while being processed; skipping update.",
                );
            } else {
                trc::error!(err.details("Failed to remove task(s) from queue."));
            }
            false
        }
    };

    for task in tasks {
        server.remove_index_lock(task.info.id).await;
    }

    is_committed
}

pub fn perpetual_retry_time(typ: TaskType, attempt: u64) -> Option<u64> {
    matches!(typ, TaskType::AcmeRenewal | TaskType::DkimManagement).then(|| {
        now().saturating_add(
            PERPETUAL_RETRY_MIN_DELAY
                .saturating_mul(1u64 << attempt.min(4))
                .min(PERPETUAL_RETRY_MAX_DELAY),
        )
    })
}

pub fn next_retry_time(
    manager: &TaskManager,
    max_attempts_override: Option<u64>,
    retry_since: u64,
    attempt: u64,
    now: u64,
) -> Option<u64> {
    if attempt >= max_attempts_override.unwrap_or(manager.max_attempts) {
        return None;
    }

    let delay_secs: u64 = match &manager.strategy {
        TaskRetryStrategy::FixedDelay(fixed) => fixed.delay.as_secs(),
        TaskRetryStrategy::ExponentialBackoff(backoff) => {
            let delay = (backoff.initial_delay.as_secs() as f64
                * backoff.factor.into_inner().powi(attempt as i32))
            .min(backoff.max_delay.as_secs() as f64) as u64;

            if backoff.jitter {
                let jitter_factor = rand::random::<f64>() + 0.5;
                ((delay as f64 * jitter_factor) as u64).min(backoff.max_delay.as_secs())
            } else {
                delay
            }
        }
    };

    let next_time = now.saturating_add(delay_secs);
    let deadline = retry_since.saturating_add(manager.total_deadline.as_secs());
    if next_time > deadline {
        return None;
    }

    Some(next_time)
}

impl TaskResult {
    pub fn is_retry(&self) -> bool {
        matches!(
            self,
            TaskResult::Update(_)
                | TaskResult::Failure {
                    typ: TaskFailureType::Temporary
                        | TaskFailureType::Retry(_)
                        | TaskFailureType::Perpetual,
                    ..
                }
        )
    }
}

#[inline(always)]
fn is_enabled(task_type: TaskType, roles: &ClusterRoles) -> bool {
    match task_type {
        TaskType::AccountMaintenance | TaskType::TenantMaintenance | TaskType::DestroyAccount => {
            roles.account_maintenance
        }
        TaskType::StoreMaintenance => roles.store_maintenance,
        TaskType::SpamFilterMaintenance => roles.spam_training,
        TaskType::CalendarAlarmEmail
        | TaskType::CalendarAlarmNotification
        | TaskType::CalendarItipMessage
        | TaskType::MergeThreads
        | TaskType::DmarcReport
        | TaskType::TlsReport
        | TaskType::RestoreArchivedItem
        | TaskType::AcmeRenewal
        | TaskType::DkimManagement
        | TaskType::DnsManagement => true,
    }
}
