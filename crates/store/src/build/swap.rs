/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{BlobStore, CacheSwapStore, InMemoryStore, registry::bootstrap::Bootstrap};
use registry::schema::structs;

const NO_FILESYSTEM: &str = "The filesystem blob store cannot back the cache swap tier because \
                             it skips writes whose length is unchanged, which silently discards \
                             a snapshot after a flag change. Configure the local file cache swap \
                             backend instead";
const NO_CHUNKED_KEYS: &str = "The default cache swap store requires a Stalwart Keep or Redis \
                               in-memory backend, or a sharded store with Redis as every shard";

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
            _ => {
                Err("Binary was not compiled with the selected cache swap blob backend".to_string())
            }
        }
    }
}

#[allow(unreachable_patterns)]
impl InMemoryStore {
    #[cfg_attr(not(feature = "keep"), allow(unused_variables))]
    pub async fn build_cache_swap(
        bp: &mut Bootstrap,
        config: structs::InMemorySwapStore,
        configured: &InMemoryStore,
    ) -> Result<CacheSwapStore, String> {
        match config {
            structs::InMemorySwapStore::Default => match configured {
                #[cfg(feature = "keep")]
                InMemoryStore::Keep(_) => {
                    match bp.setting_infallible::<structs::InMemoryStore>().await {
                        structs::InMemoryStore::Keep(store) => {
                            crate::backend::keep::swap::KeepSwapClient::open(store)
                                .await
                                .map(CacheSwapStore::Keep)
                        }
                        _ => Err(NO_CHUNKED_KEYS.to_string()),
                    }
                }
                configured => configured.clone().try_into(),
            },
            #[cfg(feature = "redis")]
            structs::InMemorySwapStore::Redis(store) => {
                crate::backend::redis::RedisStore::open_single(store)
                    .await?
                    .try_into()
            }
            #[cfg(feature = "redis")]
            structs::InMemorySwapStore::RedisCluster(store) => {
                crate::backend::redis::RedisStore::open_cluster(store)
                    .await?
                    .try_into()
            }
            #[cfg(feature = "redis")]
            structs::InMemorySwapStore::RedisSentinel(store) => {
                crate::backend::redis::RedisStore::open_sentinel(store)
                    .await?
                    .try_into()
            }
            #[cfg(feature = "keep")]
            structs::InMemorySwapStore::Keep(store) => {
                crate::backend::keep::swap::KeepSwapClient::open(store)
                    .await
                    .map(CacheSwapStore::Keep)
            }
            _ => Err(
                "Binary was not compiled with the selected cache swap store backend".to_string(),
            ),
        }
    }
}

#[allow(unreachable_patterns)]
impl TryFrom<InMemoryStore> for CacheSwapStore {
    type Error = String;

    fn try_from(store: InMemoryStore) -> Result<Self, String> {
        match store {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => Ok(CacheSwapStore::Redis(store)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", feature = "redis"))]
            InMemoryStore::Sharded(store) if store.stores.iter().all(InMemoryStore::is_redis) => {
                Ok(CacheSwapStore::Sharded(store))
            }
            // SPDX-SnippetEnd
            _ => Err(NO_CHUNKED_KEYS.to_string()),
        }
    }
}
