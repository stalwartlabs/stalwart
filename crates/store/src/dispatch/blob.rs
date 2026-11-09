/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    BlobStore, Store,
    write::blob_codec::{BlobKeyring, BlobOpts},
};
use std::{ops::Range, time::Instant};

use trc::{AddContext, StoreEvent};

impl BlobStore {
    pub async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
        keys: &BlobKeyring,
    ) -> trc::Result<Option<Vec<u8>>> {
        #[cfg(stalwart_tests)]
        {
            crate::dispatch::StoreOps::count_blob_get();
            crate::dispatch::ops::wait(crate::dispatch::Latency::BlobGet).await;
        }

        let start_time = Instant::now();
        let result = self.get_raw_blob(key).await.caused_by(trc::location!())?;

        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_blob_get_bytes(&result);

        trc::event!(
            Store(StoreEvent::BlobRead),
            Key = key,
            Elapsed = start_time.elapsed(),
            Size = result.as_ref().map_or(0, |data| data.len()),
        );

        let Some(data) = result else {
            return Ok(None);
        };

        let mut data = keys.decode(key, data)?;

        if range.start == 0 {
            if range.end > data.len() {
                Ok(Some(data))
            } else {
                data.truncate(range.end);
                Ok(Some(data))
            }
        } else {
            Ok(Some(
                data.get(range.start..range.end)
                    .unwrap_or_default()
                    .to_vec(),
            ))
        }
    }

    pub async fn get_raw_blob(&self, key: &[u8]) -> trc::Result<Option<Vec<u8>>> {
        match &self {
            BlobStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.get_blob(key, 0..usize::MAX).await,
                Store::Ephemeral(store) => store.get_blob(key, 0..usize::MAX).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.get_blob(key, 0..usize::MAX).await,
                // SPDX-SnippetEnd
                Store::None => Err(trc::StoreEvent::NotConfigured.into()),
            },
            BlobStore::Fs(store) => store.get_blob(key, 0..usize::MAX).await,
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => store.get_blob(key, 0..usize::MAX).await,
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => store.get_blob(key, 0..usize::MAX).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            BlobStore::Sharded(store) => store.get_blob(key, 0..usize::MAX).await,
            // SPDX-SnippetEnd
        }
    }

    pub fn put_blob(
        &self,
        key: &[u8],
        data: &[u8],
        opts: &BlobOpts,
    ) -> impl Future<Output = trc::Result<()>> {
        self.write_blob(key, opts.encode(key, data))
    }

    pub async fn replace_blob(&self, key: &[u8], data: &[u8], opts: &BlobOpts) -> trc::Result<()> {
        let data = opts.encode(key, data)?;
        match self.shard_for(key) {
            BlobStore::Fs(store) => store
                .replace_blob(key, &data)
                .await
                .caused_by(trc::location!()),
            store => store.write_blob(key, Ok(data)).await,
        }
    }

    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    fn shard_for(&self, key: &[u8]) -> &BlobStore {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            BlobStore::Sharded(store) => store.get_store(key),
            // SPDX-SnippetEnd
            store => store,
        }
    }

    async fn write_blob(&self, key: &[u8], data: trc::Result<Vec<u8>>) -> trc::Result<()> {
        let data = data?;
        #[cfg(stalwart_tests)]
        {
            crate::dispatch::StoreOps::count_blob_put(data.len());
            crate::dispatch::ops::wait(crate::dispatch::Latency::BlobPut).await;
        }

        let start_time = Instant::now();
        let size = data.len();
        let result = match &self {
            BlobStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.put_blob(key, data).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.put_blob(key, &data).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.put_blob(key, &data).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.put_blob(key, &data).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.put_blob(key, data).await,
                Store::Ephemeral(store) => store.put_blob(key, &data).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.put_blob(key, &data).await,
                // SPDX-SnippetEnd
                Store::None => Err(trc::StoreEvent::NotConfigured.into()),
            },
            BlobStore::Fs(store) => store.put_blob(key, &data).await,
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => store.put_blob(key, data).await,
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => store.put_blob(key, data).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            BlobStore::Sharded(store) => store.put_blob(key, data).await,
            // SPDX-SnippetEnd
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::BlobWrite),
            Key = key,
            Elapsed = start_time.elapsed(),
            Size = size,
        );

        result
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_blob_delete();

        let start_time = Instant::now();
        let result = match &self {
            BlobStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.delete_blob(key).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.delete_blob(key).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.delete_blob(key).await,
                Store::Ephemeral(store) => store.delete_blob(key).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.delete_blob(key).await,
                // SPDX-SnippetEnd
                Store::None => Err(trc::StoreEvent::NotConfigured.into()),
            },
            BlobStore::Fs(store) => store.delete_blob(key).await,
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => store.delete_blob(key).await,
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => store.delete_blob(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            BlobStore::Sharded(store) => store.delete_blob(key).await,
            // SPDX-SnippetEnd
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::BlobWrite),
            Key = key,
            Elapsed = start_time.elapsed(),
        );

        result
    }

    pub async fn delete_blobs(&self, keys: &[&[u8]]) -> trc::Result<()> {
        match self {
            #[cfg(feature = "rocks")]
            BlobStore::Store(Store::RocksDb(store)) => {
                delete_blobs_timed(keys, store.delete_blobs(keys)).await
            }
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => delete_blobs_timed(keys, store.delete_blobs(keys)).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            BlobStore::Sharded(store) => store.delete_blobs(keys).await,
            // SPDX-SnippetEnd
            _ => {
                for key in keys {
                    self.delete_blob(key).await?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(any(feature = "rocks", feature = "s3"))]
async fn delete_blobs_timed(
    keys: &[&[u8]],
    delete: impl Future<Output = trc::Result<()>>,
) -> trc::Result<()> {
    #[cfg(stalwart_tests)]
    crate::dispatch::StoreOps::count_blob_delete();

    let start_time = Instant::now();
    let result = delete.await.caused_by(trc::location!());

    trc::event!(
        Store(StoreEvent::BlobWrite),
        Total = keys.len(),
        Elapsed = start_time.elapsed(),
    );

    result
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/dispatch/blob/tests.rs"]
mod tests;
