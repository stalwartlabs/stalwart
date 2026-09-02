/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapCadence, SwapKey, SwapPart, SwapTier};
use crate::{DavResources, Inner, MessageStoreCache};
use ahash::AHashMap;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use types::collection::SyncCollection;

pub const QUEUE_DEPTH: usize = 1024;
const METRICS_INTERVAL: Duration = Duration::from_secs(300);

pub enum SwapSignal {
    Changed(SwapTarget, u32),
    EvictedMessages(u32, Arc<MessageStoreCache>),
    EvictedResources(SwapTarget, Arc<DavResources>),
    Flush(oneshot::Sender<()>),
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwapTarget {
    pub account_id: u32,
    pub collection: SyncCollection,
}

impl SwapTarget {
    pub fn new(account_id: u32, collection: SyncCollection) -> Self {
        SwapTarget {
            account_id,
            collection,
        }
    }

    pub fn messages(account_id: u32) -> Self {
        SwapTarget::new(account_id, SyncCollection::Email)
    }

    fn key(&self) -> SwapKey {
        SwapKey::new(
            self.account_id,
            self.collection,
            if matches!(self.collection, SyncCollection::Email) {
                SwapPart::Messages
            } else {
                SwapPart::Resources
            },
        )
    }
}

enum Snapshot {
    Messages(Arc<MessageStoreCache>),
    Resources(Arc<DavResources>),
}

impl Snapshot {
    fn size(&self) -> u64 {
        match self {
            Snapshot::Messages(cache) => cache.size,
            Snapshot::Resources(cache) => cache.size,
        }
    }

    fn change_id(&self) -> u64 {
        match self {
            Snapshot::Messages(cache) => cache.last_change_id,
            Snapshot::Resources(cache) => cache.highest_change_id,
        }
    }

    fn len(&self) -> usize {
        match self {
            Snapshot::Messages(cache) => cache.emails.len(),
            Snapshot::Resources(cache) => cache.resources.len(),
        }
    }

    fn encode(&self) -> Option<Vec<u8>> {
        match self {
            Snapshot::Messages(cache) => cache.emails.to_snapshot(),
            Snapshot::Resources(cache) => cache.to_snapshot(),
        }
    }
}

#[derive(Default)]
struct PendingAccount {
    changes: u32,
    last_write: Option<Instant>,
}

impl PendingAccount {
    fn is_due(&self, cadence: &SwapCadence) -> bool {
        if self.changes == 0 {
            return false;
        }
        if self.changes >= cadence.flush_changes {
            return true;
        }
        self.last_write
            .is_none_or(|last| last.elapsed() >= cadence.flush_interval)
    }

    fn age(&self) -> Option<Duration> {
        self.last_write.map(|last| last.elapsed())
    }
}

struct SwapWriter {
    inner: Arc<Inner>,
    pending: AHashMap<SwapTarget, PendingAccount>,
    bytes_written: u64,
    snapshots_written: u64,
    window_started: Instant,
}

impl SwapWriter {
    fn tier(&self) -> &SwapTier {
        &self.inner.cache.swap
    }

    fn cadence(&self) -> SwapCadence {
        *self.tier().cadence()
    }

    fn record_changes(&mut self, target: SwapTarget, changes: u32) {
        let entry = self.pending.entry(target).or_default();
        entry.changes = entry.changes.saturating_add(changes);
    }

    fn peek(&self, target: SwapTarget) -> Option<Snapshot> {
        let caches = &self.inner.cache;
        match target.collection {
            SyncCollection::Email => caches
                .messages
                .peek(&target.account_id)
                .map(Snapshot::Messages),
            SyncCollection::Calendar => caches
                .events
                .peek(&target.account_id)
                .map(Snapshot::Resources),
            SyncCollection::AddressBook => caches
                .contacts
                .peek(&target.account_id)
                .map(Snapshot::Resources),
            SyncCollection::FileNode => caches
                .files
                .peek(&target.account_id)
                .map(Snapshot::Resources),
            SyncCollection::CalendarEventNotification => caches
                .scheduling
                .peek(&target.account_id)
                .map(Snapshot::Resources),
            _ => None,
        }
    }

    async fn flush_if_due(&mut self, target: SwapTarget) {
        let cadence = self.cadence();
        if !self
            .pending
            .get(&target)
            .is_some_and(|entry| entry.is_due(&cadence))
        {
            return;
        }

        match self.peek(target) {
            Some(snapshot) => self.write(target, &snapshot).await,
            None => {
                self.pending.remove(&target);
            }
        }
    }

    async fn flush_due(&mut self) {
        let cadence = self.cadence();
        let due = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.is_due(&cadence))
            .map(|(target, _)| *target)
            .collect::<Vec<_>>();

        for target in due {
            self.flush_if_due(target).await;
        }
    }

    async fn flush_all(&mut self) {
        let targets = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.changes > 0)
            .map(|(target, _)| *target)
            .collect::<Vec<_>>();

        for target in targets {
            match self.peek(target) {
                Some(snapshot) => self.write(target, &snapshot).await,
                None => {
                    self.pending.remove(&target);
                }
            }
        }
    }

    async fn write(&mut self, target: SwapTarget, snapshot: &Snapshot) {
        let cadence = self.cadence();
        let size = snapshot.size();
        if size > cadence.max_account_size {
            trc::event!(
                Store(trc::StoreEvent::SwapError),
                AccountId = target.account_id,
                Collection = target.collection.as_str(),
                Size = size,
                Limit = cadence.max_account_size,
                Details = "Cache snapshot exceeds the configured maximum size",
            );
            self.pending.remove(&target);
            return;
        }
        if size < cadence.min_account_size {
            self.pending.remove(&target);
            return;
        }

        let start_time = Instant::now();
        let Some(encoded) = snapshot.encode() else {
            trc::event!(
                Store(trc::StoreEvent::SwapError),
                AccountId = target.account_id,
                Collection = target.collection.as_str(),
                Details = "Failed to encode the cache snapshot",
            );
            self.pending.remove(&target);
            return;
        };

        let bytes = encoded.len() as u64;
        match self.tier().store(target.key(), &encoded).await {
            Ok(()) => {
                let entry = self.pending.entry(target).or_default();
                entry.changes = 0;
                entry.last_write = Some(Instant::now());
                self.bytes_written += bytes;
                self.snapshots_written += 1;

                trc::event!(
                    Store(trc::StoreEvent::SwapWrite),
                    AccountId = target.account_id,
                    Collection = target.collection.as_str(),
                    ChangeId = snapshot.change_id(),
                    Total = snapshot.len(),
                    Size = bytes,
                    Elapsed = start_time.elapsed(),
                );
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to write the cache snapshot")
                        .ctx(trc::Key::AccountId, target.account_id)
                        .ctx(trc::Key::Collection, target.collection.as_str())
                );
            }
        }
    }

    fn prune(&mut self) {
        let flush_interval = self.cadence().flush_interval;
        self.pending.retain(|_, entry| {
            entry.changes > 0
                || entry
                    .last_write
                    .is_some_and(|last| last.elapsed() < flush_interval)
        });
        self.pending.shrink_to_fit();
    }

    fn report_metrics(&mut self) {
        let elapsed = self.window_started.elapsed();
        if elapsed.is_zero() {
            return;
        }

        let mut ages = self
            .pending
            .values()
            .filter(|entry| entry.changes > 0)
            .filter_map(PendingAccount::age)
            .map(|age| age.as_secs())
            .collect::<Vec<_>>();
        ages.sort_unstable();

        let percentile = |ages: &[u64], fraction: f64| -> u64 {
            if ages.is_empty() {
                0
            } else {
                ages[((ages.len() as f64 * fraction) as usize).min(ages.len() - 1)]
            }
        };

        trc::event!(
            Store(trc::StoreEvent::SwapWrite),
            Total = vec![self.snapshots_written as usize, self.pending.len()],
            Size = (self.bytes_written as f64 * 3600.0 / elapsed.as_secs_f64()) as u64,
            Details = vec![
                percentile(&ages, 0.5).to_string(),
                percentile(&ages, 0.95).to_string(),
                ages.last().copied().unwrap_or_default().to_string(),
            ],
            Elapsed = elapsed,
        );

        self.bytes_written = 0;
        self.snapshots_written = 0;
        self.window_started = Instant::now();
    }
}

impl SwapTier {
    pub fn spawn_writer(inner: Arc<Inner>) -> mpsc::Sender<SwapSignal> {
        let (tx, mut rx) = mpsc::channel::<SwapSignal>(QUEUE_DEPTH);

        tokio::spawn(async move {
            let mut writer = SwapWriter {
                inner,
                pending: AHashMap::new(),
                bytes_written: 0,
                snapshots_written: 0,
                window_started: Instant::now(),
            };
            let mut timer = tokio::time::interval(METRICS_INTERVAL);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            timer.tick().await;

            loop {
                tokio::select! {
                    signal = rx.recv() => match signal {
                        Some(SwapSignal::Changed(target, changes)) => {
                            writer.record_changes(target, changes);
                            writer.flush_if_due(target).await;
                        }
                        Some(SwapSignal::EvictedMessages(account_id, cache)) => {
                            let target = SwapTarget::messages(account_id);
                            writer.write(target, &Snapshot::Messages(cache)).await;
                            writer.pending.remove(&target);
                        }
                        Some(SwapSignal::EvictedResources(target, cache)) => {
                            writer.write(target, &Snapshot::Resources(cache)).await;
                            writer.pending.remove(&target);
                        }
                        Some(SwapSignal::Flush(ack)) => {
                            writer.flush_all().await;
                            let _ = ack.send(());
                        }
                        Some(SwapSignal::Stop) | None => {
                            writer.flush_all().await;
                            break;
                        }
                    },
                    _ = timer.tick() => {
                        writer.flush_due().await;
                        writer.report_metrics();
                        writer.prune();
                    }
                }
            }
        });

        tx
    }
}
