/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::imip::SendImipTask;
use crate::task_manager::index::SearchIndexTask;
use crate::task_manager::lock::TaskLockManager;
use crate::task_manager::merge_threads::MergeThreadsTask;
use alarm::SendAlarmTask;
use common::config::server::ServerProtocol;
use common::network::limiter::ConcurrencyLimiter;
use common::network::{ServerInstance, TcpAcceptor};
use common::{BuildServer, IPC_CHANNEL_BUFFER};
use common::{Inner, KV_LOCK_TASK, Server};
use registry::pickle::Pickle;
use registry::schema::enums::TaskType;
use registry::schema::structs::{
    Task, TaskManager, TaskRetryStrategy, TaskStatus, TaskStatusFailed, TaskStatusRetry,
};
use registry::types::EnumImpl;
use registry::types::datetime::UTCDateTime;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
use store::rand::seq::SliceRandom;
use store::write::Operation;
use store::write::key::DeserializeBigEndian;
use store::{
    IterateParams, ValueKey,
    ahash::AHashMap,
    write::{BatchBuilder, TaskQueueClass, ValueClass, now},
};
use store::{SerializeInfallible, U64_LEN, rand};
use tokio::sync::{mpsc, watch};
use trc::TaskQueueEvent;
use utils::snowflake::SnowflakeIdGenerator;

pub mod alarm;
pub mod imip;
pub mod index;
pub mod lock;
pub mod merge_threads;

const QUEUE_REFRESH_INTERVAL: u64 = 60 * 5; // 5 minutes
const DEFAULT_LOCK_EXPIRY: u64 = 60 * 5; // 5 minutes

pub(crate) struct TaskManagerIpc {
    txs: [mpsc::Sender<TaskJob>; TaskType::COUNT],
    locked: AHashMap<u64, Locked>,
    revision: u64,
}

pub(crate) struct TaskDetails {
    task: Task,
    info: TaskJob,
}

pub(crate) struct TaskJob {
    id: u64,
    due: u64,
    typ: TaskType,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TaskResult {
    Success,
    Update([Operation; 2]),
    Failure {
        typ: TaskFailureType,
        message: String,
    },
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TaskFailureType {
    Retry(u64),
    Temporary,
    Permanent,
}

struct Locked {
    expires: Instant,
    revision: u64,
}

pub fn spawn_task_manager(inner: Arc<Inner>) {
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
    let mut txs = Vec::with_capacity(TaskType::COUNT);
    for idx in 0..TaskType::COUNT {
        let (tx, mut rx) = mpsc::channel::<TaskJob>(IPC_CHANNEL_BUFFER);
        txs.push(tx);
        let inner = inner.clone();
        let server_instance = server_instance.clone();

        if matches!(
            TaskType::from_id(idx as u16).unwrap(),
            TaskType::IndexDocument | TaskType::UnindexDocument | TaskType::IndexTrace
        ) {
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    let server = inner.build_server();

                    let batch_size = server.core.email.index_batch_size;
                    let mut batch = Vec::with_capacity(batch_size);
                    match server
                        .store()
                        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                            TaskQueueClass::Task { id: job.id },
                        )))
                        .await
                    {
                        Ok(Some(task)) => {
                            batch.push(TaskDetails { task, info: job });
                        }
                        Ok(None) => {
                            trc::event!(
                                TaskQueue(TaskQueueEvent::TaskIgnored),
                                Id = job.id,
                                Reason = "Task not found in store, likely already processed.",
                            );
                        }
                        Err(err) => {
                            trc::error!(
                                err.id(job.id)
                                    .details("Failed to retrieve task details.")
                                    .caused_by(trc::location!())
                            );
                        }
                    }

                    while batch.len() < batch_size {
                        match rx.try_recv() {
                            Ok(job) => {
                                match server
                                    .store()
                                    .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                                        TaskQueueClass::Task { id: job.id },
                                    )))
                                    .await
                                {
                                    Ok(Some(task)) => {
                                        batch.push(TaskDetails { task, info: job });
                                    }
                                    Ok(None) => {
                                        trc::event!(
                                            TaskQueue(TaskQueueEvent::TaskIgnored),
                                            Id = job.id,
                                            Reason = "Task not found in store, likely already processed.",
                                        );
                                    }
                                    Err(err) => {
                                        trc::error!(
                                            err.id(job.id)
                                                .details("Failed to retrieve task details.")
                                                .caused_by(trc::location!())
                                        );
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    // Dispatch
                    let results = server.index(&batch).await.into_iter().map(|r| r.result);
                    update_tasks(&server, &mut batch, results).await;
                }
            });
        } else {
            let server_instance = server_instance.clone();
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    let server = inner.build_server();

                    match server
                        .store()
                        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                            TaskQueueClass::Task { id: job.id },
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
                                Task::IndexDocument(_)
                                | Task::UnindexDocument(_)
                                | Task::IndexTrace(_) => unreachable!(),
                            };

                            update_tasks(
                                &server,
                                &mut [TaskDetails { task, info: job }],
                                vec![result],
                            )
                            .await;
                        }
                        Ok(None) => {
                            trc::event!(
                                TaskQueue(TaskQueueEvent::TaskIgnored),
                                Id = job.id,
                                Reason = "Task not found in store, likely already processed.",
                            );
                        }
                        Err(err) => {
                            trc::error!(
                                err.id(job.id)
                                    .details("Failed to retrieve task details.")
                                    .caused_by(trc::location!())
                            );
                        }
                    }
                }
            });
        }
    }

    tokio::spawn(async move {
        let mut ipc = TaskManagerIpc {
            txs: txs.try_into().expect("Incorrect number of task channels"),
            locked: Default::default(),
            revision: 0,
        };
        let rx = inner.ipc.task_tx.clone();
        loop {
            // Index any queued tasks
            let sleep_for = inner.build_server().process_tasks(&mut ipc).await;

            // Wait for a signal or sleep until the next task is due
            let _ = tokio::time::timeout(sleep_for, rx.notified()).await;
        }
    });
}

pub(crate) trait TaskQueueManager: Sync + Send {
    fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> impl Future<Output = Duration> + Send;
}

impl TaskQueueManager for Server {
    async fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> Duration {
        let now_timestamp = now();
        let from_key = ValueKey::<ValueClass> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::TaskQueue(TaskQueueClass::Due { id: 0, due: 0 }),
        };
        let to_key = ValueKey::<ValueClass> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::TaskQueue(TaskQueueClass::Due {
                id: u64::MAX,
                due: now_timestamp + QUEUE_REFRESH_INTERVAL,
            }),
        };

        // Retrieve tasks pending to be processed
        let mut tasks = Vec::new();
        let now = Instant::now();
        let mut next_event = None;
        ipc.revision += 1;
        let _ = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    if key.len() == U64_LEN * 2 {
                        let task_due = key.deserialize_be_u64(0)?;
                        let task_id = key.deserialize_be_u64(U64_LEN)?;

                        if task_due <= now_timestamp {
                            let task_type_idx = value.deserialize_be_u16(0)?;
                            let task_type = TaskType::from_id(task_type_idx).ok_or_else(|| {
                                trc::StoreEvent::DataCorruption
                                    .caused_by(trc::location!())
                                    .ctx(trc::Key::Value, value)
                            })?;
                            match ipc.locked.entry(task_id) {
                                Entry::Occupied(mut entry) => {
                                    let locked = entry.get_mut();
                                    if locked.expires <= now {
                                        locked.expires = Instant::now()
                                            + std::time::Duration::from_secs(
                                                DEFAULT_LOCK_EXPIRY + 1,
                                            );
                                        tasks.push((
                                            TaskJob {
                                                id: task_id,
                                                due: task_due,
                                                typ: task_type,
                                            },
                                            task_type_idx,
                                        ));
                                    }
                                    locked.revision = ipc.revision;
                                }
                                Entry::Vacant(entry) => {
                                    entry.insert(Locked {
                                        expires: Instant::now()
                                            + std::time::Duration::from_secs(
                                                DEFAULT_LOCK_EXPIRY + 1,
                                            ),
                                        revision: ipc.revision,
                                    });
                                    tasks.push((
                                        TaskJob {
                                            id: task_id,
                                            due: task_due,
                                            typ: task_type,
                                        },
                                        task_type_idx,
                                    ));
                                }
                            }

                            Ok(true)
                        } else {
                            next_event = Some(task_due);
                            Ok(false)
                        }
                    } else {
                        Ok(true)
                    }
                },
            )
            .await
            .map_err(|err| {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to iterate over task queue.")
                );
            });

        if !tasks.is_empty() || !ipc.locked.is_empty() {
            trc::event!(
                TaskQueue(TaskQueueEvent::TaskAcquired),
                Total = tasks.len(),
                Details = ipc.locked.len(),
            );
        }

        // Shuffle tasks
        if tasks.len() > 1 {
            tasks.shuffle(&mut rand::rng());
        }

        // Dispatch tasks
        let roles = &self.core.network.roles;
        for (task_job, task_type_idx) in tasks {
            let enabled = match task_job.typ {
                TaskType::IndexDocument | TaskType::UnindexDocument | TaskType::IndexTrace => roles
                    .fts_indexing
                    .is_enabled_for_integer(task_job.id as u32),
                TaskType::CalendarAlarmEmail | TaskType::CalendarAlarmNotification => roles
                    .calendar_alerts
                    .is_enabled_for_integer(task_job.id as u32),
                TaskType::CalendarItipMessage => roles
                    .imip_processing
                    .is_enabled_for_integer(task_job.id as u32),
                TaskType::MergeThreads => roles
                    .merge_threads
                    .is_enabled_for_integer(task_job.id as u32),
            };

            if enabled {
                if self.try_lock_task(task_job.id).await
                    && ipc.txs[task_type_idx as usize]
                        .send(task_job)
                        .await
                        .is_err()
                {
                    trc::event!(
                        Server(trc::ServerEvent::ThreadError),
                        Details = "Error sending task.",
                        CausedBy = trc::location!()
                    );
                }
            } else {
                trc::event!(
                    TaskQueue(TaskQueueEvent::TaskIgnored),
                    Id = task_job.id,
                    Details = task_job.typ.as_str(),
                    Reason = "Task type is disabled by cluster roles.",
                );
            }
        }

        // Delete expired locks
        let now = Instant::now();
        ipc.locked
            .retain(|_, locked| locked.expires > now && locked.revision == ipc.revision);
        Duration::from_secs(next_event.map_or(QUEUE_REFRESH_INTERVAL, |timestamp| {
            timestamp.saturating_sub(store::write::now())
        }))
    }
}

async fn update_tasks(
    server: &Server,
    tasks: &mut [TaskDetails],
    results: impl IntoIterator<Item = TaskResult>,
) {
    let mut batch = BatchBuilder::new();

    for (task, result) in tasks.iter_mut().zip(results.into_iter()) {
        let id = task.info.id;
        batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            due: task.info.due,
        }));
        match result {
            TaskResult::Success | TaskResult::Ignored => {
                batch.clear(ValueClass::TaskQueue(TaskQueueClass::Task { id }));
            }
            TaskResult::Update(ops) => {
                for op in ops {
                    batch.any_op(op);
                }
            }
            TaskResult::Failure { typ, message } => {
                let (attempt_number, created_at) = match task.task.status() {
                    TaskStatus::Pending(status) => (0, status.created_at),
                    TaskStatus::Retry(status) => (status.attempt_number, status.created_at),
                    TaskStatus::Failed(status) => (status.failed_attempt_number, status.failed_at),
                };
                let retry_at = match typ {
                    TaskFailureType::Retry(retry_at) => (attempt_number
                        < server.core.network.task_manager.max_attempts
                        && retry_at
                            < retry_at.saturating_add(
                                server.core.network.task_manager.total_deadline.as_secs(),
                            ))
                    .then_some(retry_at),
                    TaskFailureType::Temporary => next_retry_time(
                        &server.core.network.task_manager,
                        created_at.timestamp() as u64,
                        attempt_number,
                        now(),
                    ),
                    TaskFailureType::Permanent => None,
                };

                let due = if let Some(retry_at) = retry_at {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::TaskRetry),
                        Id = id,
                        Details = task.task.name(),
                        Reason = message.to_string(),
                        NextRetry = trc::Value::Timestamp(retry_at),
                    );

                    task.task.set_status(TaskStatus::Retry(TaskStatusRetry {
                        due: UTCDateTime::from_timestamp(retry_at as i64),
                        attempt_number: attempt_number + 1,
                        failure_reason: message,
                        created_at,
                    }));

                    retry_at
                } else {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::TaskFailed),
                        Id = id,
                        Details = task.task.name(),
                        Reason = message.to_string(),
                    );

                    task.task.set_status(TaskStatus::Failed(TaskStatusFailed {
                        failed_at: UTCDateTime::now(),
                        failed_attempt_number: attempt_number,
                        failure_reason: message,
                        created_at,
                    }));
                    u64::MAX
                };
                batch
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

    if let Err(err) = server.store().write(batch.build_all()).await {
        trc::error!(err.details("Failed to remove task(s) from queue."));
    }

    for task in tasks {
        server.remove_index_lock(task.info.id).await;
    }
}

pub fn next_retry_time(
    manager: &TaskManager,
    create_time: u64,
    attempt: u64,
    now: u64,
) -> Option<u64> {
    if attempt >= manager.max_attempts {
        return None;
    }

    let delay_secs: u64 = match &manager.strategy {
        TaskRetryStrategy::FixedDelay(fixed) => fixed.delay.as_secs(),
        TaskRetryStrategy::ExponentialBackoff(backoff) => {
            let delay = (backoff.initial_delay.as_secs() as f64
                * backoff.factor.powi(attempt as i32))
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
    let deadline = create_time.saturating_add(manager.total_deadline.as_secs());
    if next_time > deadline {
        return None;
    }

    Some(next_time)
}

pub(crate) trait TaskInfo {
    fn name(&self) -> &'static str;
}

impl TaskInfo for Task {
    fn name(&self) -> &'static str {
        match self {
            Task::IndexDocument(_) => "IndexDocument",
            Task::UnindexDocument(_) => "UnindexDocument",
            Task::IndexTrace(_) => "IndexTrace",
            Task::CalendarAlarmEmail(_) => "CalendarAlarmEmail",
            Task::CalendarAlarmNotification(_) => "CalendarAlarmNotification",
            Task::CalendarItipMessage(_) => "CalendarItipMessage",
            Task::MergeThreads(_) => "MergeThreads",
        }
    }
}

impl TaskResult {
    pub fn permanent(message: impl Into<String>) -> Self {
        TaskResult::Failure {
            typ: TaskFailureType::Permanent,
            message: message.into(),
        }
    }

    pub fn temporary(message: impl Into<String>) -> Self {
        TaskResult::Failure {
            typ: TaskFailureType::Temporary,
            message: message.into(),
        }
    }
}
