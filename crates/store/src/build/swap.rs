/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{BlobStore, InMemoryStore, registry::bootstrap::Bootstrap};
use registry::schema::structs;

const NO_FILESYSTEM: &str = "The filesystem blob store cannot back the cache swap tier because \
                             it skips writes whose length is unchanged, which silently discards \
                             a snapshot after a flag change. Configure the local file cache swap \
                             backend instead";

#[allow(unreachable_patterns)]
impl BlobStore {
    pub async fn build_cache_swap(
        _bp: &mut Bootstrap,
        config: structs::BlobSwapStore,
        configured: &BlobStore,
    ) -> Result<Self, String> {
        match config {
            structs::BlobSwapStore::Default => {
                if matches!(configured, BlobStore::Fs(_)) {
                    Err(NO_FILESYSTEM.to_string())
                } else {
                    Ok(configured.clone())
                }
            }
            #[cfg(feature = "foundation")]
            structs::BlobSwapStore::FoundationDb(store) => {
                crate::backend::foundationdb::FdbStore::open(store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "postgres")]
            structs::BlobSwapStore::PostgreSql(store) => {
                crate::backend::postgres::PostgresStore::open(store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "mysql")]
            structs::BlobSwapStore::MySql(store) => crate::backend::mysql::MysqlStore::open(store)
                .await
                .map(BlobStore::Store),
            #[cfg(feature = "s3")]
            structs::BlobSwapStore::S3(store) => crate::backend::s3::S3Store::open(store).await,
            #[cfg(feature = "azure")]
            structs::BlobSwapStore::Azure(store) => {
                crate::backend::azure::AzureStore::open(store).await
            }
            structs::BlobSwapStore::FileSystem(_) => Err(NO_FILESYSTEM.to_string()),
            _ => {
                Err("Binary was not compiled with the selected cache swap blob backend".to_string())
            }
        }
    }
}

#[allow(unreachable_patterns)]
impl InMemoryStore {
    pub async fn build_cache_swap(
        _bp: &mut Bootstrap,
        config: structs::RedisSwapStore,
        configured: &InMemoryStore,
    ) -> Result<Self, String> {
        match config {
            structs::RedisSwapStore::Default => {
                if configured.supports_chunked_keys() {
                    Ok(configured.clone())
                } else {
                    Err(
                        "The default cache swap store requires a Redis in-memory backend, \
                         either directly or as every shard of a sharded store"
                            .to_string(),
                    )
                }
            }
            #[cfg(feature = "redis")]
            structs::RedisSwapStore::Redis(store) => {
                crate::backend::redis::RedisStore::open_single(store).await
            }
            #[cfg(feature = "redis")]
            structs::RedisSwapStore::RedisCluster(store) => {
                crate::backend::redis::RedisStore::open_cluster(store).await
            }
            #[cfg(feature = "redis")]
            structs::RedisSwapStore::RedisSentinel(store) => {
                crate::backend::redis::RedisStore::open_sentinel(store).await
            }
            _ => Err(
                "Binary was not compiled with the selected cache swap Redis backend".to_string(),
            ),
        }
    }
}
