/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavResources, Inner, MessageStoreCache};
use blob::BlobSwapStore;
use file::FileSwapStore;
#[cfg(feature = "redis")]
use redis::RedisSwapStore;
use registry::schema::{prelude::ObjectType, structs};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
#[cfg(feature = "redis")]
use store::InMemoryStore;
use store::{BlobStore, registry::bootstrap::Bootstrap};
use tokio::sync::{mpsc, oneshot};
use types::collection::SyncCollection;
use writer::{QUEUE_DEPTH, Snapshot, SwapSignal, SwapTarget};

pub mod blob;
pub mod file;
pub mod frame;
pub mod messages;
#[cfg(feature = "redis")]
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
    #[cfg(feature = "redis")]
    Redis(RedisSwapStore),
}

pub struct SwapTier {
    backend: SwapBackend,
    cadence: SwapCadence,
    writer: mpsc::Sender<SwapSignal>,
    writes: AtomicU64,
}

pub type SwapReceiver = mpsc::Receiver<SwapSignal>;

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
            #[cfg(feature = "redis")]
            structs::CacheSwap::Redis(config) => {
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
                        SwapBackend::Redis(RedisSwapStore::new(
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

    pub fn notify_changed(&self, account_id: u32, collection: SyncCollection, changes: u32) {
        if self.is_enabled() {
            let _ = self.writer.try_send(SwapSignal::Changed(
                SwapTarget::new(account_id, collection),
                changes,
            ));
        }
    }

    pub fn notify_refresh_messages(
        &self,
        account_id: u32,
        changes: u32,
        cache: &Arc<MessageStoreCache>,
    ) {
        self.notify_refresh(
            SwapTarget::messages(account_id),
            changes,
            Snapshot::Messages(cache.clone()),
        );
    }

    pub fn notify_refresh_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
        changes: u32,
        cache: &Arc<DavResources>,
    ) {
        self.notify_refresh(
            SwapTarget::new(account_id, collection),
            changes,
            Snapshot::Resources(cache.clone()),
        );
    }

    fn notify_refresh(&self, target: SwapTarget, changes: u32, snapshot: Snapshot) {
        if self.is_enabled() {
            let _ = self
                .writer
                .try_send(SwapSignal::Refresh(target, changes, snapshot));
        }
    }

    pub fn forget(&self, account_id: u32) {
        if self.is_enabled() {
            let _ = self.writer.try_send(SwapSignal::Forget(account_id));
        }
    }

    pub(crate) fn record_write(&self) {
        self.writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshots_written(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    pub async fn flush(&self) {
        if !self.is_enabled() {
            return;
        }
        let (ack, ack_rx) = oneshot::channel();
        if self.writer.send(SwapSignal::Flush(ack)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    pub async fn stop(&self) {
        if !self.is_enabled() {
            return;
        }
        let (ack, ack_rx) = oneshot::channel();
        if self.writer.send(SwapSignal::Stop(ack)).await.is_err() {
            return;
        }

        let timeout = self.shutdown_timeout();
        match tokio::time::timeout(timeout, ack_rx).await {
            Ok(Ok(0)) | Ok(Err(_)) => (),
            Ok(Ok(unwritten)) => {
                trc::event!(
                    Store(trc::StoreEvent::SwapError),
                    Total = unwritten,
                    Details = "Shut down before every pending cache snapshot could be written",
                );
            }
            Err(_) => {
                trc::event!(
                    Store(trc::StoreEvent::SwapError),
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
                writer,
                writes: AtomicU64::new(0),
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
        match &self.backend {
            SwapBackend::Disabled => Ok(None),
            SwapBackend::File(store) => store.load(key).await,
            SwapBackend::Blob(store) => store.load(key).await,
            #[cfg(feature = "redis")]
            SwapBackend::Redis(store) => Box::pin(store.load(key)).await,
        }
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        match &self.backend {
            SwapBackend::Disabled => Ok(()),
            SwapBackend::File(store) => store.store(key, data).await,
            SwapBackend::Blob(store) => store.store(key, data).await,
            #[cfg(feature = "redis")]
            SwapBackend::Redis(store) => Box::pin(store.store(key, data)).await,
        }
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        match &self.backend {
            SwapBackend::Disabled => Ok(()),
            SwapBackend::File(store) => store.remove(key).await,
            SwapBackend::Blob(store) => store.remove(key).await,
            #[cfg(feature = "redis")]
            SwapBackend::Redis(store) => Box::pin(store.remove(key)).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_DISPATCH_FUTURE: usize = 2048;

    #[test]
    fn dispatch_futures_stay_small() {
        let (tier, _rx) = SwapTier::disabled();
        let key = SwapKey::messages(1);
        let data = Vec::new();

        for (name, size) in [
            ("load", std::mem::size_of_val(&tier.load(key))),
            ("store", std::mem::size_of_val(&tier.store(key, &data))),
            ("remove", std::mem::size_of_val(&tier.remove(key))),
            (
                "remove_account",
                std::mem::size_of_val(&tier.remove_account(1)),
            ),
        ] {
            assert!(
                size <= MAX_DISPATCH_FUTURE,
                "SwapTier::{name} future is {size} bytes, over the {MAX_DISPATCH_FUTURE} byte \
                 budget. It is awaited from get_cached_messages, so its size lands in every \
                 caller of that function. Box the backend arm that grew instead of raising \
                 this limit."
            );
        }
    }
}
