/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(feature = "redis")]
use super::pointer::MAX_CALL_BYTES;
use super::{
    SwapKey,
    pointer::{ChunkAssembler, ChunkLayout, SwapPointer, index_batches},
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
#[cfg(all(feature = "enterprise", feature = "redis"))]
use store::InMemoryStore;
#[cfg(feature = "keep")]
use store::backend::keep::swap::KeepSwapClient;
#[cfg(feature = "redis")]
use store::backend::redis::RedisStore;
use store::{CacheSwapStore, rand};
use trc::AddContext;

const LOAD_ATTEMPTS: usize = 2;
const MIN_CHUNK_SIZE: u64 = 4096;
const MAX_CHUNK_SIZE: u64 = 1024 * 1024;
#[cfg(feature = "redis")]
const MAX_KEYS_PER_CALL: u32 = 1024;
#[cfg(feature = "keep")]
const KEEP_MAX_CALL_BYTES: usize = 1024 * 1024;
#[cfg(feature = "keep")]
const KEEP_MAX_KEYS_PER_CALL: u32 = 256;
#[cfg(feature = "keep")]
const KEEP_BYTES_PER_SEC: u64 = 200 * 1024 * 1024;
const NANOS_PER_SEC: u64 = 1_000_000_000;

pub struct InMemorySwapStore {
    store: CacheSwapStore,
    chunk_size: u32,
    retention: u64,
    max_size: usize,
    pace: BytePace,
}

struct BytePace {
    started: Instant,
    next_ns: AtomicU64,
}

#[derive(Clone, Copy)]
enum ChunkStore<'x> {
    #[cfg(feature = "redis")]
    Redis(&'x RedisStore),
    #[cfg(feature = "keep")]
    Keep(&'x KeepSwapClient),
}

struct ChunkKeys {
    base: String,
}

impl InMemorySwapStore {
    pub fn new(store: CacheSwapStore, chunk_size: u64, retention: u64, max_size: u64) -> Self {
        InMemorySwapStore {
            store,
            chunk_size: Self::clamp_chunk_size(chunk_size),
            retention: retention.max(1),
            max_size: max_size as usize,
            pace: BytePace::new(),
        }
    }

    fn clamp_chunk_size(chunk_size: u64) -> u32 {
        chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE) as u32
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        let keys = ChunkKeys::new(key);
        let store = self.chunk_store(keys.route())?;
        let mut previous = None;

        for _ in 0..LOAD_ATTEMPTS {
            let Some(pointer) = read_pointer(store, &keys).await? else {
                return Ok(None);
            };
            if previous == Some(pointer) {
                break;
            }

            let Some((layout, length)) = pointer.chunks().zip(
                usize::try_from(pointer.length())
                    .ok()
                    .filter(|length| *length <= self.max_size),
            ) else {
                return Ok(None);
            };

            if let Some(data) =
                read_generation(store, &self.pace, &keys, &pointer, layout, length).await?
            {
                return Ok(Some(data));
            }

            previous = Some(pointer);
        }

        trc::event!(
            Cache(trc::CacheEvent::SwapMiss),
            AccountId = key.account_id,
            Collection = key.collection.as_str(),
            Details = "Stored cache snapshot generation is missing or does not match its pointer",
        );

        Ok(None)
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let keys = ChunkKeys::new(key);
        let store = self.chunk_store(keys.route())?;
        let layout = ChunkLayout::new(data.len() as u64, self.chunk_size).ok_or_else(|| {
            trc::EventType::Cache(trc::CacheEvent::SwapError)
                .into_err()
                .details("Cache snapshot has too many chunks for the in-memory swap tier")
                .ctx(trc::Key::Size, data.len())
        })?;
        let generation = rand::random();
        let pointer = SwapPointer::new(rand::random(), generation, data.len() as u64, Some(layout));
        let expires = Some(self.retention);

        let max_call_bytes = store.max_call_bytes();
        let mut items = Vec::with_capacity(layout.chunks_per_batch(max_call_bytes) as usize);
        for (range, payload) in layout.split(data, max_call_bytes) {
            self.pace.wait(store, payload.len()).await;
            items.clear();
            items.extend(
                range
                    .zip(payload.chunks(layout.size() as usize))
                    .map(|(index, chunk)| (keys.chunk(generation, index), chunk)),
            );
            store
                .key_set_many(&items, expires)
                .await
                .caused_by(trc::location!())?;
        }

        let previous = read_pointer(store, &keys).await?;
        store
            .key_set_many(&[(keys.pointer(), pointer.encode().as_slice())], expires)
            .await
            .caused_by(trc::location!())?;

        if let Some(previous) = previous.filter(|previous| previous.generation() != generation)
            && let Err(err) = unlink_generation(store, &keys, &previous).await
        {
            trc::error!(
                err.details("Failed to remove a superseded cache snapshot generation")
                    .ctx(trc::Key::AccountId, key.account_id)
                    .ctx(trc::Key::Collection, key.collection.as_str())
            );
        }

        Ok(())
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        let keys = ChunkKeys::new(key);
        let store = self.chunk_store(keys.route())?;
        let previous = read_pointer(store, &keys).await?;

        store
            .key_unlink_many(&[keys.pointer()])
            .await
            .caused_by(trc::location!())?;

        match previous {
            Some(previous) => unlink_generation(store, &keys, &previous).await,
            None => Ok(()),
        }
    }

    #[cfg_attr(
        not(all(feature = "enterprise", feature = "redis")),
        allow(unused_variables)
    )]
    fn chunk_store(&self, route: &[u8]) -> trc::Result<ChunkStore<'_>> {
        match &self.store {
            #[cfg(feature = "redis")]
            CacheSwapStore::Redis(store) => Ok(ChunkStore::Redis(store)),
            #[cfg(feature = "keep")]
            CacheSwapStore::Keep(client) => Ok(ChunkStore::Keep(client)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", feature = "redis"))]
            CacheSwapStore::Sharded(store) => match store.get_store(route) {
                InMemoryStore::Redis(store) => Ok(ChunkStore::Redis(store)),
                _ => Err(unsupported()),
            },
            // SPDX-SnippetEnd
            #[allow(unreachable_patterns)]
            _ => Err(unsupported()),
        }
    }
}

impl BytePace {
    fn new() -> Self {
        BytePace {
            started: Instant::now(),
            next_ns: AtomicU64::new(0),
        }
    }

    fn reserve(&self, now_ns: u64, cost_ns: u64) -> u64 {
        let previous = self
            .next_ns
            .update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.max(now_ns).saturating_add(cost_ns)
            });
        previous.max(now_ns)
    }

    async fn wait(&self, store: ChunkStore<'_>, bytes: usize) {
        if let Some(rate) = store.bytes_per_sec() {
            let cost_ns = (bytes as u64).saturating_mul(NANOS_PER_SEC) / rate;
            let now_ns = self.started.elapsed().as_nanos() as u64;
            let due_ns = self.reserve(now_ns, cost_ns);
            if due_ns > now_ns {
                tokio::time::sleep(Duration::from_nanos(due_ns - now_ns)).await;
            }
        }
    }
}

impl ChunkStore<'_> {
    fn max_call_bytes(self) -> usize {
        match self {
            #[cfg(feature = "redis")]
            ChunkStore::Redis(_) => MAX_CALL_BYTES,
            #[cfg(feature = "keep")]
            ChunkStore::Keep(_) => KEEP_MAX_CALL_BYTES,
        }
    }

    fn max_keys_per_call(self) -> u32 {
        match self {
            #[cfg(feature = "redis")]
            ChunkStore::Redis(_) => MAX_KEYS_PER_CALL,
            #[cfg(feature = "keep")]
            ChunkStore::Keep(_) => KEEP_MAX_KEYS_PER_CALL,
        }
    }

    fn bytes_per_sec(self) -> Option<u64> {
        match self {
            #[cfg(feature = "redis")]
            ChunkStore::Redis(_) => None,
            #[cfg(feature = "keep")]
            ChunkStore::Keep(_) => Some(KEEP_BYTES_PER_SEC),
        }
    }

    async fn key_set_many(
        self,
        items: &[(Vec<u8>, &[u8])],
        expires: Option<u64>,
    ) -> trc::Result<()> {
        match self {
            #[cfg(feature = "redis")]
            ChunkStore::Redis(store) => store.key_set_many(items, expires).await,
            #[cfg(feature = "keep")]
            ChunkStore::Keep(store) => store.key_set_many(items, expires).await,
        }
    }

    async fn key_get_many(self, keys: &[Vec<u8>]) -> trc::Result<Vec<Option<Vec<u8>>>> {
        match self {
            #[cfg(feature = "redis")]
            ChunkStore::Redis(store) => store.key_get_many(keys).await,
            #[cfg(feature = "keep")]
            ChunkStore::Keep(store) => store.key_get_many(keys).await,
        }
    }

    async fn key_unlink_many(self, keys: &[Vec<u8>]) -> trc::Result<()> {
        match self {
            #[cfg(feature = "redis")]
            ChunkStore::Redis(store) => store.key_unlink_many(keys).await,
            #[cfg(feature = "keep")]
            ChunkStore::Keep(store) => store.key_unlink_many(keys).await,
        }
    }
}

async fn read_pointer(store: ChunkStore<'_>, keys: &ChunkKeys) -> trc::Result<Option<SwapPointer>> {
    store
        .key_get_many(&[keys.pointer()])
        .await
        .caused_by(trc::location!())
        .map(|values| {
            values
                .into_iter()
                .next()
                .flatten()
                .as_deref()
                .and_then(SwapPointer::parse)
        })
}

async fn read_generation(
    store: ChunkStore<'_>,
    pace: &BytePace,
    keys: &ChunkKeys,
    pointer: &SwapPointer,
    layout: ChunkLayout,
    length: usize,
) -> trc::Result<Option<Vec<u8>>> {
    let mut assembler = ChunkAssembler::new(layout, length);
    let max_call_bytes = store.max_call_bytes();
    let mut batch = Vec::with_capacity(layout.chunks_per_batch(max_call_bytes) as usize);

    for range in layout.batches(max_call_bytes) {
        pace.wait(store, range.len() * layout.size() as usize).await;
        batch.clear();
        batch.extend(range.map(|index| keys.chunk(pointer.generation(), index)));

        for chunk in store
            .key_get_many(&batch)
            .await
            .caused_by(trc::location!())?
        {
            match chunk {
                Some(chunk) if assembler.push(&chunk) => (),
                _ => return Ok(None),
            }
        }
    }

    Ok(assembler.finish())
}

async fn unlink_generation(
    store: ChunkStore<'_>,
    keys: &ChunkKeys,
    pointer: &SwapPointer,
) -> trc::Result<()> {
    let Some(layout) = pointer.chunks() else {
        return Ok(());
    };

    let max_keys_per_call = store.max_keys_per_call();
    let mut batch = Vec::with_capacity(layout.count().min(max_keys_per_call) as usize);
    for range in index_batches(layout.count(), max_keys_per_call) {
        batch.clear();
        batch.extend(range.map(|index| keys.chunk(pointer.generation(), index)));
        store
            .key_unlink_many(&batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

impl ChunkKeys {
    fn new(key: SwapKey) -> Self {
        ChunkKeys {
            base: format!(
                "{{swap:{}:{}:{}}}",
                key.account_id,
                u8::from(key.collection),
                key.part.code()
            ),
        }
    }

    fn route(&self) -> &[u8] {
        self.base.as_bytes()
    }

    fn pointer(&self) -> Vec<u8> {
        format!("{}:p", self.base).into_bytes()
    }

    fn chunk(&self, generation: u64, index: u32) -> Vec<u8> {
        format!("{}:{generation:x}:{index}", self.base).into_bytes()
    }
}

fn unsupported() -> trc::Error {
    trc::EventType::Cache(trc::CacheEvent::SwapError)
        .into_err()
        .details("The cache swap tier requires a Stalwart Keep or Redis in-memory store")
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/cache/swap/redis/tests.rs"]
mod tests;
