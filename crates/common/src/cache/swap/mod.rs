/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{GroupwareResources, Inner, MessageStoreCache};
use blob::BlobSwapStore;
use evict::SwapEviction;
use file::FileSwapStore;
#[cfg(any(feature = "redis", feature = "keep"))]
use redis::InMemorySwapStore;
use registry::schema::{prelude::ObjectType, structs};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
#[cfg(any(feature = "redis", feature = "keep"))]
use store::InMemoryStore;
use store::{BlobStore, registry::bootstrap::Bootstrap};
use tokio::sync::{mpsc, oneshot};
use types::collection::SyncCollection;
use writer::{QUEUE_DEPTH, RefreshSlots, Snapshot, SwapChanges, SwapSignal, SwapTarget};

pub mod blob;
pub mod evict;
pub mod file;
pub mod frame;
pub mod messages;
pub mod pointer;
#[cfg(any(feature = "redis", feature = "keep"))]
pub mod redis;
pub mod resources;
pub mod writer;

pub const BLOCKING_CODEC_THRESHOLD: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapPart {
    Messages,
    Resources,
}

impl SwapPart {
    pub fn code(&self) -> u8 {
        match self {
            SwapPart::Messages => 1,
            SwapPart::Resources => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(SwapPart::Messages),
            3 => Some(SwapPart::Resources),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SwapPart::Messages => "messages",
            SwapPart::Resources => "resources",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapKey {
    pub account_id: u32,
    pub collection: SyncCollection,
    pub part: SwapPart,
}

impl SwapKey {
    pub fn new(account_id: u32, collection: SyncCollection, part: SwapPart) -> Self {
        SwapKey {
            account_id,
            collection,
            part,
        }
    }

    pub fn messages(account_id: u32) -> Self {
        SwapKey::new(account_id, SyncCollection::Email, SwapPart::Messages)
    }

    pub fn file_name(&self) -> String {
        format!(
            "{:08x}-{}-{}.swap",
            self.account_id,
            u8::from(self.collection),
            self.part.code()
        )
    }

    pub fn resource_parts(account_id: u32) -> impl Iterator<Item = SwapKey> {
        [
            SyncCollection::Calendar,
            SyncCollection::AddressBook,
            SyncCollection::FileNode,
            SyncCollection::CalendarEventNotification,
        ]
        .into_iter()
        .map(move |collection| SwapKey::new(account_id, collection, SwapPart::Resources))
    }

    pub fn all_parts(account_id: u32) -> impl Iterator<Item = SwapKey> {
        std::iter::once(SwapKey::messages(account_id)).chain(SwapKey::resource_parts(account_id))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SwapCadence {
    pub flush_changes: u32,
    pub flush_interval: Duration,
    pub min_account_size: u64,
    pub max_account_size: u64,
}

impl Default for SwapCadence {
    fn default() -> Self {
        SwapCadence {
            flush_changes: 2000,
            flush_interval: Duration::from_secs(600),
            min_account_size: 1024 * 1024,
            max_account_size: 1024 * 1024 * 1024,
        }
    }
}

pub enum SwapBackend {
    Disabled,
    File(FileSwapStore),
    Blob(BlobSwapStore),
    #[cfg(any(feature = "redis", feature = "keep"))]
    InMemory(InMemorySwapStore),
}

pub struct SwapTier {
    backend: SwapBackend,
    cadence: SwapCadence,
    handoff: Arc<SwapHandoff>,
    writes: AtomicU64,
    dirty_targets: AtomicU64,
    #[cfg(stalwart_tests)]
    reads: AtomicU64,
}

pub struct SwapHandoff {
    writer: mpsc::Sender<SwapSignal>,
    refresh: RefreshSlots,
}

pub type SwapReceiver = mpsc::Receiver<SwapSignal>;

impl SwapHandoff {
    fn signal(&self, signal: SwapSignal) {
        let _ = self.writer.try_send(signal);
    }

    fn refresh(&self, target: SwapTarget, changes: SwapChanges, snapshot: Snapshot) {
        self.refresh.store(target, snapshot);
        self.signal(SwapSignal::Changed(target, changes));
    }

    fn evicted(&self, target: SwapTarget, snapshot: Snapshot) {
        self.refresh.store(target, snapshot);
        self.signal(SwapSignal::Evicted(target));
    }
}

impl SwapTier {
    pub async fn build(
        bp: &mut Bootstrap,
        config: structs::CacheSwap,
        storage: &crate::config::storage::Storage,
    ) -> (Self, SwapReceiver) {
        #[allow(unreachable_patterns)]
        let (backend, cadence) = match config {
            structs::CacheSwap::Disabled => return SwapTier::disabled(),
            structs::CacheSwap::LocalFile(config) => {
                let cadence = SwapCadence {
                    flush_changes: config.flush_changes as u32,
                    flush_interval: config.flush_interval.into_inner(),
                    min_account_size: config.min_account_size,
                    max_account_size: config.max_account_size,
                };
                match FileSwapStore::open(&config).await {
                    Ok(store) => (SwapBackend::File(store), cadence),
                    Err(err) => {
                        bp.build_error(ObjectType::Cache.singleton(), err);
                        return SwapTier::disabled();
                    }
                }
            }
            structs::CacheSwap::BlobStore(config) => {
                let cadence = SwapCadence {
                    flush_changes: config.flush_changes as u32,
                    flush_interval: config.flush_interval.into_inner(),
                    min_account_size: config.min_account_size,
                    max_account_size: config.max_account_size,
                };
                let retention = config.retention.into_inner().as_secs();
                match BlobStore::build_cache_swap(bp, config.store, &storage.blob).await {
                    Ok(store) => (
                        SwapBackend::Blob(BlobSwapStore::new(
                            store,
                            storage.data.clone(),
                            retention,
                            cadence.max_account_size,
                        )),
                        cadence,
                    ),
                    Err(err) => {
                        bp.build_error(ObjectType::Cache.singleton(), err);
                        return SwapTier::disabled();
                    }
                }
            }
            #[cfg(any(feature = "redis", feature = "keep"))]
            structs::CacheSwap::InMemory(config) => {
                let cadence = SwapCadence {
                    flush_changes: config.flush_changes as u32,
                    flush_interval: config.flush_interval.into_inner(),
                    min_account_size: config.min_account_size,
                    max_account_size: config.max_account_size,
                };
                let chunk_size = config.chunk_size;
                let retention = config.retention.into_inner().as_secs();
                match InMemoryStore::build_cache_swap(bp, config.store, &storage.memory).await {
                    Ok(store) => (
                        SwapBackend::InMemory(InMemorySwapStore::new(
                            store,
                            chunk_size,
                            retention,
                            cadence.max_account_size,
                        )),
                        cadence,
                    ),
                    Err(err) => {
                        bp.build_error(ObjectType::Cache.singleton(), err);
                        return SwapTier::disabled();
                    }
                }
            }
            _ => {
                bp.build_error(
                    ObjectType::Cache.singleton(),
                    "Binary was not compiled with the selected cache swap backend".to_string(),
                );
                return SwapTier::disabled();
            }
        };

        SwapTier::new(backend, cadence)
    }

    pub fn start(inner: &Arc<Inner>, receiver: SwapReceiver) {
        if inner.cache.swap.is_enabled() {
            SwapTier::spawn_writer(inner.clone(), receiver);
        }
    }

    pub fn eviction(&self, collection: SyncCollection) -> SwapEviction {
        SwapEviction::new(self.is_enabled().then(|| self.handoff.clone()), collection)
    }

    pub fn notify_changed(
        &self,
        account_id: u32,
        collection: SyncCollection,
        changes: SwapChanges,
    ) {
        if self.is_enabled() {
            self.handoff.signal(SwapSignal::Changed(
                SwapTarget::new(account_id, collection),
                changes,
            ));
        }
    }

    pub fn notify_refresh_messages(
        &self,
        account_id: u32,
        changes: SwapChanges,
        cache: &Arc<MessageStoreCache>,
    ) {
        if self.is_enabled() {
            self.handoff.refresh(
                SwapTarget::messages(account_id),
                changes,
                Snapshot::Messages(cache.clone()),
            );
        }
    }

    pub fn notify_refresh_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
        changes: SwapChanges,
        cache: &Arc<GroupwareResources>,
    ) {
        if self.is_enabled() {
            self.handoff.refresh(
                SwapTarget::new(account_id, collection),
                changes,
                Snapshot::Resources(cache.clone()),
            );
        }
    }

    pub(crate) fn notify_evicted_messages(&self, account_id: u32, cache: Arc<MessageStoreCache>) {
        if self.is_enabled() {
            self.handoff
                .evicted(SwapTarget::messages(account_id), Snapshot::Messages(cache));
        }
    }

    pub(crate) fn notify_evicted_resources(
        &self,
        target: SwapTarget,
        cache: Arc<GroupwareResources>,
    ) {
        if self.is_enabled() {
            self.handoff.evicted(target, Snapshot::Resources(cache));
        }
    }

    pub fn pending_refresh_snapshots(&self) -> usize {
        self.handoff.refresh.len()
    }

    pub(crate) fn refresh_slots(&self) -> &RefreshSlots {
        &self.handoff.refresh
    }

    pub fn forget(&self, account_id: u32) {
        if self.is_enabled() {
            self.handoff.signal(SwapSignal::Forget(account_id));
        }
    }

    pub(crate) fn record_write(&self) {
        self.writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn pending_targets(&self) -> u64 {
        self.dirty_targets.load(Ordering::Relaxed)
    }

    fn track_dirty(&self, was_dirty: bool, is_dirty: bool) {
        match (was_dirty, is_dirty) {
            (false, true) => {
                self.dirty_targets.fetch_add(1, Ordering::Relaxed);
            }
            (true, false) => self.untrack_dirty(1),
            _ => {}
        }
    }

    fn untrack_dirty(&self, count: u64) {
        if count > 0 {
            self.dirty_targets.fetch_sub(count, Ordering::Relaxed);
        }
    }

    pub fn snapshots_written(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    pub async fn flush(&self) {
        if !self.is_enabled() {
            return;
        }
        let (ack, ack_rx) = oneshot::channel();
        if self
            .handoff
            .writer
            .send(SwapSignal::Flush(ack))
            .await
            .is_ok()
        {
            let _ = ack_rx.await;
        }
    }

    pub async fn stop(&self) {
        if !self.is_enabled() {
            return;
        }
        let (ack, ack_rx) = oneshot::channel();
        if self
            .handoff
            .writer
            .send(SwapSignal::Stop(ack))
            .await
            .is_err()
        {
            return;
        }

        let timeout = self.shutdown_timeout();
        match tokio::time::timeout(timeout, ack_rx).await {
            Ok(Ok(0)) | Ok(Err(_)) => (),
            Ok(Ok(unwritten)) => {
                trc::event!(
                    Cache(trc::CacheEvent::SwapError),
                    Total = unwritten,
                    Details = "Shut down with pending cache snapshots whose write failed",
                );
            }
            Err(_) => {
                trc::event!(
                    Cache(trc::CacheEvent::SwapError),
                    Elapsed = timeout,
                    Details = "Timed out flushing the pending cache snapshots on shutdown",
                );
            }
        }
    }

    fn shutdown_timeout(&self) -> Duration {
        match &self.backend {
            SwapBackend::Blob(_) => Duration::from_secs(60),
            _ => Duration::from_secs(10),
        }
    }

    pub fn new(backend: SwapBackend, cadence: SwapCadence) -> (Self, SwapReceiver) {
        let (writer, receiver) = mpsc::channel(QUEUE_DEPTH);
        (
            SwapTier {
                backend,
                cadence,
                handoff: Arc::new(SwapHandoff {
                    writer,
                    refresh: RefreshSlots::default(),
                }),
                writes: AtomicU64::new(0),
                dirty_targets: AtomicU64::new(0),
                #[cfg(stalwart_tests)]
                reads: AtomicU64::new(0),
            },
            receiver,
        )
    }

    pub fn disabled() -> (Self, SwapReceiver) {
        SwapTier::new(SwapBackend::Disabled, SwapCadence::default())
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self.backend, SwapBackend::Disabled)
    }

    pub fn cadence(&self) -> &SwapCadence {
        &self.cadence
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        let snapshot = match &self.backend {
            SwapBackend::Disabled => Ok(None),
            SwapBackend::File(store) => store.load(key).await,
            SwapBackend::Blob(store) => store.load(key).await,
            #[cfg(any(feature = "redis", feature = "keep"))]
            SwapBackend::InMemory(store) => Box::pin(store.load(key)).await,
        };
        self.record_read(&snapshot);
        snapshot
    }

    #[cfg(not(stalwart_tests))]
    fn record_read(&self, _: &trc::Result<Option<Vec<u8>>>) {}

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        match &self.backend {
            SwapBackend::Disabled => Ok(()),
            SwapBackend::File(store) => store.store(key, data).await,
            SwapBackend::Blob(store) => store.store(key, data).await,
            #[cfg(any(feature = "redis", feature = "keep"))]
            SwapBackend::InMemory(store) => Box::pin(store.store(key, data)).await,
        }
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        match &self.backend {
            SwapBackend::Disabled => Ok(()),
            SwapBackend::File(store) => store.remove(key).await,
            SwapBackend::Blob(store) => store.remove(key).await,
            #[cfg(any(feature = "redis", feature = "keep"))]
            SwapBackend::InMemory(store) => Box::pin(store.remove(key)).await,
        }
    }

    pub async fn remove_account(&self, account_id: u32) {
        self.remove_keys(account_id, SwapKey::all_parts(account_id))
            .await;
    }

    pub async fn remove_resources(&self, account_id: u32) {
        self.remove_keys(account_id, SwapKey::resource_parts(account_id))
            .await;
    }

    async fn remove_keys(&self, account_id: u32, keys: impl Iterator<Item = SwapKey>) {
        if !self.is_enabled() {
            return;
        }

        for key in keys {
            if let Err(err) = self.remove(key).await {
                trc::error!(
                    err.details("Failed to remove cache snapshot")
                        .ctx(trc::Key::AccountId, account_id)
                        .ctx(trc::Key::Type, key.part.as_str())
                );
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/cache/swap/tests.rs"]
mod tests;

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/cache/swap/test_support.rs"]
mod test_support;
