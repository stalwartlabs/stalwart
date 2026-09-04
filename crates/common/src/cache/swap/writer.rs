/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BLOCKING_CODEC_THRESHOLD, SwapCadence, SwapKey, SwapPart, SwapReceiver, SwapTier};
use crate::{GroupwareResources, Inner, MessageStoreCache};
use ahash::AHashMap;
use parking_lot::Mutex;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use types::collection::SyncCollection;

pub const QUEUE_DEPTH: usize = 1024;
const METRICS_INTERVAL: Duration = Duration::from_secs(300);

pub enum SwapSignal {
    Changed(SwapTarget, u32),
    Forget(u32),
    Flush(oneshot::Sender<()>),
    Stop(oneshot::Sender<usize>),
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

#[derive(Clone)]
pub enum Snapshot {
    Messages(Arc<MessageStoreCache>),
    Resources(Arc<GroupwareResources>),
}

impl Snapshot {
    pub fn size(&self) -> u64 {
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

    async fn encode_off_runtime(&self) -> Option<Vec<u8>> {
        if self.size() < BLOCKING_CODEC_THRESHOLD as u64 {
            return self.encode();
        }

        let snapshot = self.clone();
        tokio::task::spawn_blocking(move || snapshot.encode())
            .await
            .ok()
            .flatten()
    }
}

struct RefreshSlot {
    snapshot: Snapshot,
    stored_at: Instant,
}

#[derive(Default)]
pub struct RefreshSlots(Mutex<AHashMap<SwapTarget, RefreshSlot>>);

impl RefreshSlots {
    pub fn store(&self, target: SwapTarget, snapshot: Snapshot) {
        let previous = self.0.lock().insert(
            target,
            RefreshSlot {
                snapshot,
                stored_at: Instant::now(),
            },
        );
        drop(previous);
    }

    fn take(&self, target: SwapTarget) -> Option<Snapshot> {
        self.0.lock().remove(&target).map(|slot| slot.snapshot)
    }

    fn forget(&self, account_id: u32) {
        let removed = self
            .0
            .lock()
            .extract_if(|target, _| target.account_id == account_id)
            .collect::<Vec<_>>();
        drop(removed);
    }

    fn drain(&self) -> Vec<(SwapTarget, Snapshot)> {
        let mut slots = self.0.lock();
        let drained = slots
            .drain()
            .map(|(target, slot)| (target, slot.snapshot))
            .collect();
        slots.shrink_to_fit();
        drained
    }

    fn prune(&self, max_age: Duration) {
        let mut slots = self.0.lock();
        let removed = slots
            .extract_if(|_, slot| slot.stored_at.elapsed() >= max_age)
            .collect::<Vec<_>>();
        slots.shrink_to_fit();
        drop(slots);
        drop(removed);
    }

    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }
}

#[derive(Default)]
struct PendingAccount {
    changes: u32,
    last_write: Option<Instant>,
    persisted_change_id: Option<u64>,
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

    fn is_due(&self, target: SwapTarget) -> bool {
        let cadence = self.cadence();
        self.pending
            .get(&target)
            .is_some_and(|entry| entry.is_due(&cadence))
    }

    fn forget(&mut self, account_id: u32) {
        self.pending
            .retain(|target, _| target.account_id != account_id);
        self.tier().refresh.forget(account_id);
    }

    fn unwritten(&self) -> usize {
        self.pending
            .values()
            .filter(|entry| entry.changes > 0)
            .count()
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

    fn take_snapshot(&self, target: SwapTarget) -> Option<Snapshot> {
        let slot = self.tier().refresh.take(target);
        self.peek(target).or(slot)
    }

    fn mark_absent(&mut self, target: SwapTarget) {
        match self.pending.get_mut(&target) {
            Some(entry) if entry.last_write.is_some() => entry.changes = 0,
            _ => {
                self.pending.remove(&target);
            }
        }
    }

    async fn flush_now(&mut self, target: SwapTarget) {
        match self.take_snapshot(target) {
            Some(snapshot) => self.write_if_changed(target, &snapshot).await,
            None => self.mark_absent(target),
        }
    }

    async fn flush_if_due(&mut self, target: SwapTarget) {
        if self.is_due(target) {
            self.flush_now(target).await;
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

    async fn flush_all(&mut self) -> u64 {
        let written_before = self.snapshots_written;
        let mut targets = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.changes > 0)
            .map(|(target, entry)| (*target, entry.changes))
            .collect::<Vec<_>>();
        targets.sort_unstable_by(|(_, left), (_, right)| right.cmp(left));

        for (target, _) in targets {
            self.flush_now(target).await;
        }

        for (target, snapshot) in self.tier().refresh.drain() {
            let snapshot = self.peek(target).unwrap_or(snapshot);
            self.write_if_changed(target, &snapshot).await;
        }

        self.snapshots_written - written_before
    }

    fn report_flush(&self, written: u64) {
        trc::event!(
            Cache(trc::CacheEvent::SwapFlush),
            Total = written as usize,
            Details = self.unwritten(),
        );
    }

    async fn write_if_changed(&mut self, target: SwapTarget, snapshot: &Snapshot) {
        if let Some(entry) = self.pending.get_mut(&target)
            && entry.persisted_change_id == Some(snapshot.change_id())
        {
            entry.changes = 0;
            return;
        }

        self.write(target, snapshot).await;
    }

    async fn write(&mut self, target: SwapTarget, snapshot: &Snapshot) {
        let cadence = self.cadence();
        let size = snapshot.size();
        if size > cadence.max_account_size {
            trc::event!(
                Cache(trc::CacheEvent::SwapError),
                AccountId = target.account_id,
                Collection = target.collection.as_str(),
                Size = size,
                Limit = cadence.max_account_size,
                Details = "Cache snapshot exceeds the configured maximum size",
            );
            let entry = self.pending.entry(target).or_default();
            entry.changes = 0;
            entry.last_write = Some(Instant::now());
            return;
        }
        if size < cadence.min_account_size {
            self.pending.remove(&target);
            return;
        }

        let start_time = Instant::now();
        let Some(encoded) = snapshot.encode_off_runtime().await else {
            trc::event!(
                Cache(trc::CacheEvent::SwapError),
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
                entry.persisted_change_id = Some(snapshot.change_id());
                self.bytes_written += bytes;
                self.snapshots_written += 1;
                self.tier().record_write();

                trc::event!(
                    Cache(trc::CacheEvent::SwapWrite),
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
        self.tier().refresh.prune(flush_interval);
    }

    fn pending_ages(&self) -> Vec<String> {
        let mut ages = self
            .pending
            .values()
            .filter(|entry| entry.changes > 0)
            .filter_map(PendingAccount::age)
            .map(|age| age.as_secs())
            .collect::<Vec<_>>();
        ages.sort_unstable();

        let percentile = |fraction: f64| -> u64 {
            if ages.is_empty() {
                0
            } else {
                ages[((ages.len() as f64 * fraction) as usize).min(ages.len() - 1)]
            }
        };

        vec![
            percentile(0.5).to_string(),
            percentile(0.95).to_string(),
            ages.last().copied().unwrap_or_default().to_string(),
        ]
    }

    fn report_metrics(&mut self) {
        let elapsed = self.window_started.elapsed();
        if elapsed.is_zero() {
            return;
        }

        trc::event!(
            Cache(trc::CacheEvent::SwapMetrics),
            Total = vec![self.snapshots_written as usize, self.pending.len()],
            Size = (self.bytes_written as f64 * 3600.0 / elapsed.as_secs_f64()) as u64,
            Details = self.pending_ages(),
            Elapsed = elapsed,
        );

        self.bytes_written = 0;
        self.snapshots_written = 0;
        self.window_started = Instant::now();
    }
}

impl SwapTier {
    pub fn spawn_writer(inner: Arc<Inner>, mut rx: SwapReceiver) {
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
                        Some(SwapSignal::Forget(account_id)) => {
                            writer.forget(account_id);
                        }
                        Some(SwapSignal::Flush(ack)) => {
                            let written = writer.flush_all().await;
                            writer.report_flush(written);
                            let _ = ack.send(());
                        }
                        Some(SwapSignal::Stop(ack)) => {
                            let written = writer.flush_all().await;
                            writer.report_flush(written);
                            let _ = ack.send(writer.unwritten());
                            break;
                        }
                        None => {
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
    }
}
