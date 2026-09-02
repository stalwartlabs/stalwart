/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::SwapKey;
use registry::schema::enums::CompressionAlgo;
use store::{
    BlobStore, Store,
    write::{BatchBuilder, BlobLink, BlobOp, now},
};
use trc::AddContext;
use types::blob_hash::BlobHash;

pub struct BlobSwapStore {
    blob: BlobStore,
    data: Store,
    retention: u64,
}

impl BlobSwapStore {
    pub fn new(blob: BlobStore, data: Store, retention: u64) -> Self {
        BlobSwapStore {
            blob,
            data,
            retention: retention.max(1),
        }
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        self.blob
            .get_blob(key.blob_hash().as_slice(), 0..usize::MAX)
            .await
            .caused_by(trc::location!())
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let hash = key.blob_hash();

        self.blob
            .put_blob(hash.as_slice(), data, CompressionAlgo::None)
            .await
            .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        batch
            .set(
                BlobOp::Link {
                    hash: hash.clone(),
                    to: BlobLink::Temporary {
                        until: self.expires_at(),
                    },
                },
                Vec::new(),
            )
            .set(BlobOp::Commit { hash }, Vec::new());

        self.data
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        let hash = key.blob_hash();

        self.blob
            .delete_blob(hash.as_slice())
            .await
            .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        let window = self.expires_at();
        for until in [window, window.saturating_sub(self.retention)] {
            batch.clear(BlobOp::Link {
                hash: hash.clone(),
                to: BlobLink::Temporary { until },
            });
        }
        batch.clear(BlobOp::Commit { hash });

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

impl SwapKey {
    pub fn blob_hash(&self) -> BlobHash {
        BlobHash::generate(format!(
            "STALWART_SWAP_{}_{}_{}",
            self.account_id,
            u8::from(self.collection),
            self.part.code()
        ))
    }
}
