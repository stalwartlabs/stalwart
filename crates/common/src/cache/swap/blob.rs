/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapKey, pointer::SwapPointer};
use store::write::blob_codec::{BlobKeyring, BlobOpts};
use store::{
    BlobStore, Store, rand,
    write::{BatchBuilder, BlobLink, BlobOp, blob::BlobLinkValue, now},
};
use trc::AddContext;
use types::blob_hash::BlobHash;

const LOAD_ATTEMPTS: usize = 2;

pub struct BlobSwapStore {
    blob: BlobStore,
    data: Store,
    retention: u64,
    max_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobSlot {
    First,
    Second,
}

impl BlobSwapStore {
    pub fn new(blob: BlobStore, data: Store, retention: u64, max_size: u64) -> Self {
        BlobSwapStore {
            blob,
            data,
            retention: retention.max(1),
            max_size: max_size as usize,
        }
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        let mut previous = None;

        for _ in 0..LOAD_ATTEMPTS {
            let Some((pointer, slot)) = self.read_pointer(key).await? else {
                return Ok(None);
            };
            if previous == Some(pointer) {
                break;
            }

            if pointer.length() > self.max_size as u64 {
                trc::event!(
                    Cache(trc::CacheEvent::SwapError),
                    AccountId = key.account_id,
                    Collection = key.collection.as_str(),
                    Size = pointer.length(),
                    Limit = self.max_size,
                    Details =
                        "Cache snapshot in the blob store exceeds the configured maximum size",
                );
                return Ok(None);
            }

            if let Some(data) = self.read_slot(key, slot).await?
                && data.len() as u64 == pointer.length()
            {
                return Ok(Some(data));
            }

            previous = Some(pointer);
        }

        trc::event!(
            Cache(trc::CacheEvent::SwapMiss),
            AccountId = key.account_id,
            Collection = key.collection.as_str(),
            Details =
                "Cache snapshot slot in the blob store is missing or does not match its pointer",
        );

        Ok(None)
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let pointer_hash = key.blob_hash();
        let current = self.read_pointer(key).await?.map(|(_, slot)| slot);
        let slot = current.map_or(BlobSlot::First, BlobSlot::other);
        let slot_hash = key.slot_hash(slot);

        self.blob
            .put_blob(slot_hash.as_slice(), data, &BlobOpts::PLAIN)
            .await
            .caused_by(trc::location!())?;
        let pointer =
            SwapPointer::new(rand::random(), slot.generation(), data.len() as u64, None).encode();
        self.link(&[
            (slot_hash, data.len()),
            (pointer_hash.clone(), pointer.len()),
        ])
        .await?;

        self.blob
            .put_blob(pointer_hash.as_slice(), &pointer, &BlobOpts::PLAIN)
            .await
            .caused_by(trc::location!())?;

        if let Some(superseded) = current
            && let Err(err) = self.delete(&[key.slot_hash(superseded)]).await
        {
            trc::error!(
                err.details("Failed to remove a superseded cache snapshot slot")
                    .ctx(trc::Key::AccountId, key.account_id)
                    .ctx(trc::Key::Collection, key.collection.as_str())
            );
        }

        Ok(())
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        self.delete(&[
            key.blob_hash(),
            key.slot_hash(BlobSlot::First),
            key.slot_hash(BlobSlot::Second),
        ])
        .await
    }

    async fn read_pointer(&self, key: SwapKey) -> trc::Result<Option<(SwapPointer, BlobSlot)>> {
        match self
            .blob
            .get_blob(
                key.blob_hash().as_slice(),
                0..usize::MAX,
                &BlobKeyring::default(),
            )
            .await
        {
            Ok(pointer) => Ok(pointer
                .as_deref()
                .and_then(SwapPointer::parse)
                .and_then(|pointer| Some((pointer, BlobSlot::of(&pointer)?)))),
            Err(err) if BlobSwapStore::is_unreadable(&err) => Ok(None),
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }

    async fn read_slot(&self, key: SwapKey, slot: BlobSlot) -> trc::Result<Option<Vec<u8>>> {
        match self
            .blob
            .get_blob(
                key.slot_hash(slot).as_slice(),
                0..usize::MAX,
                &BlobKeyring::default(),
            )
            .await
        {
            Ok(data) => Ok(data),
            Err(err) if BlobSwapStore::is_unreadable(&err) => Ok(None),
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }

    fn is_unreadable(err: &trc::Error) -> bool {
        err.matches(trc::EventType::Store(trc::StoreEvent::DecompressError))
            || err.matches(trc::EventType::Store(trc::StoreEvent::DecryptError))
    }

    async fn link(&self, blobs: &[(BlobHash, usize)]) -> trc::Result<()> {
        let until = self.expires_at();
        let mut batch = BatchBuilder::new();
        for (hash, size) in blobs {
            batch
                .set(
                    BlobOp::Link {
                        hash: hash.clone(),
                        to: BlobLink::Temporary { until },
                    },
                    BlobLinkValue::new(*size),
                )
                .set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
        }

        self.data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    async fn delete(&self, hashes: &[BlobHash]) -> trc::Result<()> {
        for hash in hashes {
            self.blob
                .delete_blob(hash.as_slice())
                .await
                .caused_by(trc::location!())?;
        }

        let window = self.expires_at();
        let mut batch = BatchBuilder::new();
        for hash in hashes {
            for until in [window, window.saturating_sub(self.retention)] {
                batch.clear(BlobOp::Link {
                    hash: hash.clone(),
                    to: BlobLink::Temporary { until },
                });
            }
            batch.clear(BlobOp::Commit { hash: hash.clone() });
        }

        self.data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    fn expires_at(&self) -> u64 {
        (now() + self.retention).div_ceil(self.retention) * self.retention
    }
}

impl BlobSlot {
    fn of(pointer: &SwapPointer) -> Option<Self> {
        match (pointer.generation(), pointer.chunks()) {
            (0, None) => Some(BlobSlot::First),
            (1, None) => Some(BlobSlot::Second),
            _ => None,
        }
    }

    fn generation(self) -> u64 {
        match self {
            BlobSlot::First => 0,
            BlobSlot::Second => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            BlobSlot::First => BlobSlot::Second,
            BlobSlot::Second => BlobSlot::First,
        }
    }
}

impl SwapKey {
    pub fn blob_hash(&self) -> BlobHash {
        BlobHash::generate(format!(
            "STALWART_SWAP_{}_{}_{}",
            self.account_id,
            u8::from(self.collection),
            self.part.code()
        ))
    }

    pub fn slot_hash(&self, slot: BlobSlot) -> BlobHash {
        BlobHash::generate(format!(
            "STALWART_SWAP_{}_{}_{}_{}",
            self.account_id,
            u8::from(self.collection),
            self.part.code(),
            slot.generation()
        ))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/cache/swap/blob/tests.rs"]
mod tests;
