/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapKey, frame::HEADER_LEN};
use store::InMemoryStore;
use trc::AddContext;

pub struct RedisSwapStore {
    store: InMemoryStore,
    chunk_size: usize,
    retention: u64,
    max_size: usize,
}

impl RedisSwapStore {
    pub fn new(store: InMemoryStore, chunk_size: u64, retention: u64, max_size: u64) -> Self {
        RedisSwapStore {
            store,
            chunk_size: (chunk_size as usize).max(HEADER_LEN + 1),
            retention: retention.max(1),
            max_size: max_size as usize,
        }
    }

    fn chunk_count(&self, total: usize) -> Option<u32> {
        if total > self.max_size {
            return None;
        }
        Some(total.div_ceil(self.chunk_size) as u32)
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        let prefix = key.redis_prefix();

        let Some(head) = self
            .chunks_get(&prefix, 1)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };

        let Some(chunks) = framed_len(&head).and_then(|total| self.chunk_count(total)) else {
            return Ok(None);
        };
        if chunks <= 1 {
            return Ok(Some(head));
        }

        self.chunks_get(&prefix, chunks)
            .await
            .caused_by(trc::location!())
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let prefix = key.redis_prefix();
        let previous_chunks = self.stored_chunk_count(&prefix).await;

        self.write_chunks(&prefix, data).await?;

        let written = data.len().div_ceil(self.chunk_size) as u32;
        if previous_chunks > written {
            self.delete_chunks(&prefix, written, previous_chunks)
                .await?;
        }

        Ok(())
    }

    async fn write_chunks(&self, prefix: &[u8], data: &[u8]) -> trc::Result<()> {
        match &self.store {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store
                .chunks_set(prefix, data, self.chunk_size, Some(self.retention))
                .await
                .caused_by(trc::location!()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store
                .chunks_set(prefix, data, self.chunk_size, Some(self.retention))
                .await
                .caused_by(trc::location!()),
            // SPDX-SnippetEnd
            _ => Err(unsupported()),
        }
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        let prefix = key.redis_prefix();

        let chunks = self.stored_chunk_count(&prefix).await.max(1);
        self.delete_chunks(&prefix, 0, chunks).await
    }

    async fn delete_chunks(&self, prefix: &[u8], from: u32, to: u32) -> trc::Result<()> {
        match &self.store {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store
                .chunks_delete(prefix, from, to)
                .await
                .caused_by(trc::location!()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store
                .chunks_delete(prefix, from, to)
                .await
                .caused_by(trc::location!()),
            // SPDX-SnippetEnd
            _ => Err(unsupported()),
        }
    }

    async fn stored_chunk_count(&self, prefix: &[u8]) -> u32 {
        self.chunks_get(prefix, 1)
            .await
            .ok()
            .flatten()
            .as_deref()
            .and_then(framed_len)
            .and_then(|total| self.chunk_count(total))
            .unwrap_or(0)
    }

    async fn chunks_get(&self, prefix: &[u8], count: u32) -> trc::Result<Option<Vec<u8>>> {
        match &self.store {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.chunks_get(prefix, count).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            InMemoryStore::Sharded(store) => store.chunks_get(prefix, count).await,
            // SPDX-SnippetEnd
            _ => Err(unsupported()),
        }
    }
}

impl SwapKey {
    pub fn redis_prefix(&self) -> Vec<u8> {
        format!(
            "swap:{}:{}:{}",
            self.account_id,
            u8::from(self.collection),
            self.part.code()
        )
        .into_bytes()
    }
}

fn framed_len(head: &[u8]) -> Option<usize> {
    if head.len() < HEADER_LEN {
        return None;
    }
    u32::from_le_bytes(head[20..24].try_into().ok()?)
        .checked_add(HEADER_LEN as u32)
        .map(|total| total as usize)
}

fn unsupported() -> trc::Error {
    trc::EventType::Store(trc::StoreEvent::SwapError)
        .into_err()
        .details("The cache swap tier requires a Redis in-memory store")
}
