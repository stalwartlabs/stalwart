/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::index_queue::index::{SearchIndexTask, spawn_bulk_indexer};
use crate::index_queue::{
    CANDIDATE_OVERSCAN, FULL_SCAN_INTERVAL, IndexQueueState, MIN_SCAN_INTERVAL, Partition,
    PartitionOutcome, PartitionResult, Sink,
};
use crate::index_queue::{LOCKED_BACKOFF, MAX_RETRY_DELAY, MIN_RETRY_DELAY};
use common::storage::search::SearchIndexStatus;
use common::{BuildServer, Inner, Server};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use store::{
    IterateParams, U32_LEN, U64_LEN,
    write::{BatchBuilder, SearchIndex, SearchIndexClass, key::DeserializeBigEndian, now},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use trc::TaskManagerEvent;

pub fn spawn_index_queue_manager(inner: Arc<Inner>) {
    let (concurrency, batch_size, is_bulk, is_clustered) = {
        let server = inner.build_server();

        if !server.core.network.roles.search_indexing {
            return;
        }

        (
            server.core.email.index_concurrency,
            server.core.email.index_batch_size,
            server.search_store().internal_fts().is_none(),
            server.core.storage.coordinator.is_enabled(),
        )
    };

    trc::event!(TaskManager(TaskManagerEvent::ManagerStarted));

    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<PartitionResult>();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let active = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(if is_bulk {
        Sink::Bulk(spawn_bulk_indexer(
            inner.clone(),
            batch_size,
            active.clone(),
        ))
    } else {
        Sink::Internal
    });

    tokio::spawn(async move {
        let mut state = IndexQueueState::default();
        let rx = inner.ipc.index_tx.clone();

        loop {
            let server = inner.build_server();

            // Update the status of the partitions processed since the last scan
            let mut results = Vec::new();
            while let Ok(result) = done_rx.try_recv() {
                state.claimed.remove(&result.partition);
                results.push(result);
            }
            if !results.is_empty() {
                update_partition_status(&server, &mut state, results).await;
            }

            let sleep_for = server
                .scan_index_queue(
                    &mut state,
                    &inner,
                    &semaphore,
                    &active,
                    &sink,
                    &done_tx,
                    batch_size,
                    concurrency,
                    is_clustered,
                )
                .await;
            let scanned_at = Instant::now();

            // Wait for a signal or sleep until the next retry is due
            if tokio::time::timeout(sleep_for, rx.notified()).await.is_ok()
                && let Some(wait_for) = MIN_SCAN_INTERVAL.checked_sub(scanned_at.elapsed())
            {
                // Coalesce bursts of notifications into a single scan
                tokio::time::sleep(wait_for).await;
            }
        }
    });
}

pub(crate) trait IndexQueueManager: Sync + Send {
    #[allow(clippy::too_many_arguments)]
    fn scan_index_queue(
        &self,
        state: &mut IndexQueueState,
        inner: &Arc<Inner>,
        semaphore: &Arc<Semaphore>,
        active: &Arc<AtomicUsize>,
        sink: &Arc<Sink>,
        done_tx: &mpsc::UnboundedSender<PartitionResult>,
        batch_size: usize,
        concurrency: usize,
        is_clustered: bool,
    ) -> impl Future<Output = Duration> + Send;
}

impl IndexQueueManager for Server {
    async fn scan_index_queue(
        &self,
        state: &mut IndexQueueState,
        inner: &Arc<Inner>,
        semaphore: &Arc<Semaphore>,
        active: &Arc<AtomicUsize>,
        sink: &Arc<Sink>,
        done_tx: &mpsc::UnboundedSender<PartitionResult>,
        batch_size: usize,
        concurrency: usize,
        is_clustered: bool,
    ) -> Duration {
        let now_timestamp = now();
        let now_instant = Instant::now();
        let budget = concurrency * CANDIDATE_OVERSCAN;

        // Drop the partitions that were deferred because another node held their lock
        state
            .deferred
            .retain(|_, deferred_until| *deferred_until > now_instant);
        let from_partition = state.cursor.take().unwrap_or(Partition {
            index: SearchIndex::Email,
            partition: 0,
        });

        let (from_key, to_key) =
            SearchIndexClass::control_range((from_partition.index, from_partition.partition), None);

        // Each partition is stored as a queue index key optionally followed by a status key
        let mut candidates = Vec::with_capacity(budget);
        let mut pending: Option<Partition> = None;
        let mut next_retry = u64::MAX;
        let mut next_deferred: Option<Instant> = None;
        let mut budget_exhausted = false;

        let result = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    if key.len() != U32_LEN + 3 {
                        return Ok(true);
                    }
                    let Some(index) = SearchIndex::try_from_u8(key[1]) else {
                        return Ok(true);
                    };
                    let partition = Partition {
                        index,
                        partition: key.deserialize_be_u32(2)?,
                    };

                    if key[U32_LEN + 2] == SearchIndexClass::CONTROL_INDEX {
                        if let Some(pending) = pending.take() {
                            state.failed.remove(&pending);
                            candidates.push(pending);
                        }

                        if candidates.len() >= budget {
                            budget_exhausted = true;
                            state.cursor = Some(partition);
                            return Ok(false);
                        }

                        pending = Some(partition);
                    } else {
                        let status_retry = value.deserialize_be_u64(0)?;
                        state
                            .failed
                            .insert(partition, value.deserialize_be_u32(U64_LEN)?);
                        let has_queued_documents = pending == Some(partition);
                        pending = None;

                        if status_retry > now_timestamp {
                            next_retry = std::cmp::min(next_retry, status_retry);
                        } else if has_queued_documents {
                            candidates.push(partition);
                        } else if candidates.len() < budget {
                            // A status without a queue index is stale, process the partition to clear it
                            candidates.push(partition);
                        } else {
                            budget_exhausted = true;
                            state.cursor = Some(partition);
                            return Ok(false);
                        }
                    }

                    Ok(true)
                },
            )
            .await;

        if let Err(err) = result {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to iterate over the search index queue.")
            );

            state.cursor = None;
            let backoff = MIN_SCAN_INTERVAL
                .saturating_mul(1u32 << std::cmp::min(state.scan_failures, 12))
                .min(FULL_SCAN_INTERVAL);
            state.scan_failures += 1;
            return backoff;
        }
        state.scan_failures = 0;

        if let Some(pending) = pending {
            state.failed.remove(&pending);
            candidates.push(pending);
        }

        if !candidates.is_empty() {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskAcquired),
                Total = candidates.len(),
                Details = state.claimed.len(),
            );
        }

        // Dispatch partitions, waiting for a free indexing slot when necessary
        for partition in candidates {
            if let Some(deferred_until) = state.deferred.get(&partition) {
                next_deferred =
                    Some(next_deferred.map_or(*deferred_until, |next| next.min(*deferred_until)));
                continue;
            }

            if !state.claimed.insert(partition) {
                continue;
            }

            let Ok(permit) = semaphore.clone().acquire_owned().await else {
                state.claimed.remove(&partition);
                break;
            };

            let inner = inner.clone();
            let sink = sink.clone();
            let active = active.clone();
            let done_tx = done_tx.clone();

            active.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let server = inner.build_server();

                // The slot is released by the guard
                let mut slot = PartitionSlot {
                    partition,
                    outcome: PartitionOutcome::Incomplete,
                    active,
                    done_tx,
                    permit: Some(permit),
                };

                slot.outcome = server
                    .process_partition(partition, sink.as_ref(), batch_size, is_clustered)
                    .await;
                drop(slot);

                server.notify_index_queue();
            });
        }

        // Sleep until the next partition is due, unless there is work left over
        let mut sleep_for = FULL_SCAN_INTERVAL;
        if budget_exhausted {
            sleep_for = MIN_SCAN_INTERVAL;
        }
        if next_retry != u64::MAX {
            sleep_for = sleep_for.min(Duration::from_secs(next_retry.saturating_sub(now())));
        }
        if let Some(next_deferred) = next_deferred {
            sleep_for = sleep_for.min(next_deferred.saturating_duration_since(Instant::now()));
        }

        sleep_for.max(MIN_SCAN_INTERVAL)
    }
}

struct PartitionSlot {
    partition: Partition,
    outcome: PartitionOutcome,
    active: Arc<AtomicUsize>,
    done_tx: mpsc::UnboundedSender<PartitionResult>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for PartitionSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.permit.take();
        let _ = self.done_tx.send(PartitionResult {
            partition: self.partition,
            outcome: std::mem::replace(&mut self.outcome, PartitionOutcome::Incomplete),
        });
    }
}

fn retry_delay(attempts: u32) -> u64 {
    MIN_RETRY_DELAY
        .saturating_mul(1 << std::cmp::min(attempts, 8))
        .min(MAX_RETRY_DELAY)
}

async fn update_partition_status(
    server: &Server,
    state: &mut IndexQueueState,
    results: Vec<PartitionResult>,
) {
    let mut batch = BatchBuilder::new();

    for result in results {
        let partition = result.partition;

        match result.outcome {
            PartitionOutcome::Completed => {
                if state.failed.remove(&partition).is_some() {
                    batch.clear(partition.status_class()).commit_point();
                }
            }
            PartitionOutcome::Failed(failure) => {
                let attempts = state.failed.get(&partition).copied().unwrap_or_default();
                let (reason, deferred_until) = failure.into_parts();
                let next_retry = deferred_until
                    .filter(|retry_at| *retry_at > now())
                    .unwrap_or_else(|| now() + retry_delay(attempts));

                trc::event!(
                    TaskManager(TaskManagerEvent::TaskRetry),
                    Type = partition.index.name(),
                    Id = partition.partition,
                    Reason = reason.clone(),
                    NextRetry = trc::Value::Timestamp(next_retry),
                );

                state.failed.insert(partition, attempts + 1);
                batch
                    .set(
                        partition.status_class(),
                        SearchIndexStatus {
                            next_retry,
                            attempts: attempts + 1,
                            reason,
                        }
                        .serialize(),
                    )
                    .commit_point();
            }
            PartitionOutcome::Locked => {
                // The partition is being processed by another node
                state
                    .deferred
                    .insert(partition, Instant::now() + LOCKED_BACKOFF);
            }
            PartitionOutcome::Incomplete => (),
        }
    }

    if batch.is_empty() {
        return;
    }

    let mut commit_points = batch.commit_points();
    for commit_point in commit_points.iter() {
        if let Err(err) = server.store().write(batch.build_one(commit_point)).await {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to update the search index queue status.")
            );
        }
    }
}
