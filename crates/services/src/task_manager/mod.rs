/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::imip::SendImipTask;
use crate::task_manager::index::SearchIndexTask;
use crate::task_manager::lock::{TaskLock, TaskLockManager};
use crate::task_manager::merge_threads::MergeThreadsTask;
use alarm::SendAlarmTask;
use common::IPC_CHANNEL_BUFFER;
use common::config::server::ServerProtocol;
use common::listener::limiter::ConcurrencyLimiter;
use common::listener::{ServerInstance, TcpAcceptor};
use common::{Inner, KV_LOCK_TASK, Server, core::BuildServer};
use email::message::ingest::MergeThreadIds;
use groupware::calendar::alarm::{CalendarAlarm, CalendarAlarmType};
use std::collections::hash_map::Entry;
use std::future::Future;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
use store::ahash::AHashSet;
use store::rand;
use store::rand::seq::SliceRandom;
use store::write::{SearchIndex, TaskEpoch};
use store::{
    IterateParams, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    ahash::AHashMap,
    write::{
        BatchBuilder, TaskQueueClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use tokio::sync::{mpsc, watch};
use trc::TaskQueueEvent;
use utils::snowflake::SnowflakeIdGenerator;

pub mod alarm;
pub mod imip;
pub mod index;
pub mod lock;
pub mod merge_threads;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Task<T> {
    pub account_id: u32,
    pub document_id: u32,
    pub due: TaskEpoch,
    pub action: T,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TaskAction {
    UpdateIndex(IndexAction),
    SendAlarm(CalendarAlarm),
    SendImip,
    MergeThreads(MergeThreadIds<AHashSet<u32>>),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct IndexAction {
    pub index: SearchIndex,
    pub is_insert: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct ImipAction;

const INDEX_EXPIRY: u64 = 60 * 5; // 5 minutes
const ALARM_EXPIRY: u64 = 60 * 2; // 2 minutes
const QUEUE_REFRESH_INTERVAL: u64 = 60 * 5; // 5 minutes

pub(crate) struct TaskManagerIpc {
    tx_fts: mpsc::Sender<Task<IndexAction>>,
    tx_alarm: mpsc::Sender<Task<CalendarAlarm>>,
    tx_imip: mpsc::Sender<Task<ImipAction>>,
    tx_threads: mpsc::Sender<Task<MergeThreadIds<AHashSet<u32>>>>,
    locked: AHashMap<Vec<u8>, Locked>,
    revision: u64,
}

struct Locked {
    expires: Instant,
    revision: u64,
}

pub fn spawn_task_manager(inner: Arc<Inner>) {
    // Create mpsc channels for the different task types
    let (tx_index_1, mut rx_index_1) = mpsc::channel::<Task<IndexAction>>(IPC_CHANNEL_BUFFER);
    let (tx_index_2, mut rx_index_2) = mpsc::channel::<Task<CalendarAlarm>>(IPC_CHANNEL_BUFFER);
    let (tx_index_3, mut rx_index_3) = mpsc::channel::<Task<ImipAction>>(IPC_CHANNEL_BUFFER);
    let (tx_index_4, mut rx_index_4) =
        mpsc::channel::<Task<MergeThreadIds<AHashSet<u32>>>>(IPC_CHANNEL_BUFFER);

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

    // Indexing worker
    {
        let inner = inner.clone();
        tokio::spawn(async move {
            while let Some(task) = rx_index_1.recv().await {
                let server = inner.build_server();
                let batch_size = server.core.jmap.index_batch_size;
                let mut batch = Vec::with_capacity(batch_size);
                batch.push(task);

                while batch.len() < batch_size {
                    match rx_index_1.try_recv() {
                        Ok(task) => batch.push(task),
                        Err(_) => break,
                    }
                }

                if batch.len() > 1 {
                    batch.shuffle(&mut rand::rng());
                }

                // Lock tasks
                let mut locked_batch = Vec::with_capacity(batch.len());
                for task in batch {
                    if server
                        .try_lock_task(
                            task.account_id,
                            task.document_id,
                            task.lock_key(),
                            task.lock_expiry(),
                        )
                        .await
                    {
                        locked_batch.push(task);
                    }
                }

                // Dispatch
                if !locked_batch.is_empty() {
                    let success = server.index(&locked_batch).await;

                    if success.iter().all(|t| t.is_done()) {
                        delete_tasks(&server, &locked_batch).await;
                    } else {
                        trc::event!(
                            TaskQueue(TaskQueueEvent::TaskFailed),
                            Total = locked_batch.len(),
                            Details = "Indexing task failed",
                        );

                        // Remove successful entries from queue
                        let mut to_delete = Vec::with_capacity(locked_batch.len());
                        for (task, result) in locked_batch.into_iter().zip(success.into_iter()) {
                            if result.is_done() {
                                to_delete.push(task);
                            }
                        }
                        if !to_delete.is_empty() {
                            delete_tasks(&server, &to_delete).await;
                        }
                    }
                }
            }
        });
    }

    // Send alarm worker
    {
        let inner = inner.clone();
        let server_instance = server_instance.clone();
        tokio::spawn(async move {
            while let Some(task) = rx_index_2.recv().await {
                let server = inner.build_server();

                // Lock task
                if server.core.groupware.alarms_enabled
                    && server
                        .try_lock_task(
                            task.account_id,
                            task.document_id,
                            task.lock_key(),
                            task.lock_expiry(),
                        )
                        .await
                {
                    let success = server
                        .send_alarm(
                            task.account_id,
                            task.document_id,
                            &task.action,
                            server_instance.clone(),
                        )
                        .await;

                    // Remove entry from queue
                    if success {
                        delete_tasks(&server, &[task]).await;
                    } else {
                        trc::event!(
                            TaskQueue(TaskQueueEvent::TaskFailed),
                            AccountId = task.account_id,
                            DocumentId = task.document_id,
                            Details = "Sending alarm task failed",
                        );
                    }
                }
            }
        });
    }

    // Send iMIP worker
    {
        let inner = inner.clone();
        let server_instance = server_instance.clone();
        tokio::spawn(async move {
            while let Some(task) = rx_index_3.recv().await {
                let server = inner.build_server();

                // Lock task
                if server.core.groupware.itip_enabled
                    && server
                        .try_lock_task(
                            task.account_id,
                            task.document_id,
                            task.lock_key(),
                            task.lock_expiry(),
                        )
                        .await
                {
                    let success = server
                        .send_imip(
                            task.account_id,
                            task.document_id,
                            task.due,
                            server_instance.clone(),
                        )
                        .await;

                    // Remove entry from queue
                    if success {
                        delete_tasks(&server, &[task]).await;
                    } else {
                        trc::event!(
                            TaskQueue(TaskQueueEvent::TaskFailed),
                            AccountId = task.account_id,
                            DocumentId = task.document_id,
                            Details = "Sending iMIP task failed",
                        );
                    }
                }
            }
        });
    }

    // Merge threads worker
    {
        let inner = inner.clone();
        tokio::spawn(async move {
            while let Some(task) = rx_index_4.recv().await {
                let server = inner.build_server();

                // Lock task
                if server
                    .try_lock_task(
                        task.account_id,
                        task.document_id,
                        task.lock_key(),
                        task.lock_expiry(),
                    )
                    .await
                {
                    let success = server.merge_threads(task.account_id, &task.action).await;

                    // Remove entry from queue
                    if success {
                        delete_tasks(&server, &[task]).await;
                    } else {
                        trc::event!(
                            TaskQueue(TaskQueueEvent::TaskFailed),
                            AccountId = task.account_id,
                            DocumentId = task.document_id,
                            Details = "Merging threads task failed",
                        );
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        let mut ipc = TaskManagerIpc {
            tx_fts: tx_index_1,
            tx_alarm: tx_index_2,
            tx_imip: tx_index_3,
            tx_threads: tx_index_4,
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
            class: ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                due: TaskEpoch::from_inner(0),
                index: SearchIndex::Email,
                is_insert: true,
            }),
        };
        let to_key = ValueKey::<ValueClass> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                due: TaskEpoch::new(now_timestamp + QUEUE_REFRESH_INTERVAL)
                    .with_attempt(u16::MAX)
                    .with_sequence_id(u16::MAX),
                index: SearchIndex::Email,
                is_insert: true,
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
                    let task = Task::deserialize(key, value)?;

                    let task_due = task.due.due();
                    if task_due <= now_timestamp {
                        match ipc.locked.entry(key.to_vec()) {
                            Entry::Occupied(mut entry) => {
                                let locked = entry.get_mut();
                                if locked.expires <= now {
                                    locked.expires = Instant::now()
                                        + std::time::Duration::from_secs(task.lock_expiry() + 1);
                                    tasks.push(task);
                                }
                                locked.revision = ipc.revision;
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(Locked {
                                    expires: Instant::now()
                                        + std::time::Duration::from_secs(task.lock_expiry() + 1),
                                    revision: ipc.revision,
                                });
                                tasks.push(task);
                            }
                        }

                        Ok(true)
                    } else {
                        next_event = Some(task_due);
                        Ok(false)
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
        for event in tasks {
            match event.action {
                TaskAction::UpdateIndex(index)
                    if roles.fts_indexing.is_enabled_for_hash(&event) =>
                {
                    if ipc
                        .tx_fts
                        .send(Task {
                            account_id: event.account_id,
                            document_id: event.document_id,
                            due: event.due,
                            action: index,
                        })
                        .await
                        .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending task.",
                            CausedBy = trc::location!()
                        );
                    }
                }
                TaskAction::SendAlarm(alarm)
                    if roles.calendar_alerts.is_enabled_for_hash(&event) =>
                {
                    if ipc
                        .tx_alarm
                        .send(Task {
                            account_id: event.account_id,
                            document_id: event.document_id,
                            due: event.due,
                            action: alarm,
                        })
                        .await
                        .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending task.",
                            CausedBy = trc::location!()
                        );
                    }
                }
                TaskAction::SendImip if roles.imip_processing.is_enabled_for_hash(&event) => {
                    if ipc
                        .tx_imip
                        .send(Task {
                            account_id: event.account_id,
                            document_id: event.document_id,
                            due: event.due,
                            action: ImipAction,
                        })
                        .await
                        .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending task.",
                            CausedBy = trc::location!()
                        );
                    }
                }
                TaskAction::MergeThreads(info)
                    if roles.merge_threads.is_enabled_for_hash(&event) =>
                {
                    if ipc
                        .tx_threads
                        .send(Task {
                            account_id: event.account_id,
                            document_id: event.document_id,
                            due: event.due,
                            action: info,
                        })
                        .await
                        .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending task.",
                            CausedBy = trc::location!()
                        );
                    }
                }
                _ => {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::TaskIgnored),
                        Details = event.action.name(),
                        AccountId = event.account_id,
                        DocumentId = event.document_id,
                    );

                    continue;
                }
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

async fn delete_tasks<T: TaskLock>(server: &Server, tasks: &[T]) {
    let mut batch = BatchBuilder::new();

    for task in tasks {
        batch
            .with_account_id(task.account_id())
            .with_document(task.document_id());

        for value in task.value_classes() {
            batch.clear(value);
        }
    }

    if let Err(err) = server.store().write(batch.build_all()).await {
        trc::error!(err.details("Failed to remove task(s) from queue."));
    }

    for task in tasks {
        server.remove_index_lock(task.lock_key()).await;
    }
}

impl TaskAction {
    pub fn name(&self) -> &'static str {
        match self {
            TaskAction::UpdateIndex(_) => "UpdateIndex",
            TaskAction::SendAlarm(_) => "SendAlarm",
            TaskAction::SendImip => "SendImip",
            TaskAction::MergeThreads(_) => "MergeThreads",
        }
    }
}
