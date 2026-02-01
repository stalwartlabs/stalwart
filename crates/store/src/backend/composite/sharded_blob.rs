/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{BlobStore, Store, backend::fs::FsStore};
use registry::schema::structs::{BlobStoreBase, ShardedBlobStore};
use std::{ops::Range, sync::Arc};

pub struct ShardedBlob {
    pub stores: Vec<BlobStore>,
}

#[allow(unreachable_patterns)]
impl ShardedBlob {
    pub async fn open(config: ShardedBlobStore) -> Result<BlobStore, String> {
        if config.stores.len() >= 2 {
            let mut stores = Vec::new();

            for store in config.stores {
                let result = match store {
                    #[cfg(feature = "s3")]
                    BlobStoreBase::S3(s3_store) => {
                        crate::backend::s3::S3Store::open(s3_store).await
                    }
                    #[cfg(feature = "azure")]
                    BlobStoreBase::Azure(azure_store) => {
                        crate::backend::azure::AzureStore::open(azure_store).await
                    }
                    BlobStoreBase::FileSystem(file_system_store) => {
                        FsStore::open(file_system_store).await
                    }
                    #[cfg(feature = "foundation")]
                    BlobStoreBase::FoundationDb(foundation_db_store) => {
                        crate::backend::foundationdb::FdbStore::open(foundation_db_store)
                            .await
                            .map(BlobStore::Store)
                    }
                    #[cfg(feature = "postgres")]
                    BlobStoreBase::PostgreSql(postgre_sql_store) => {
                        crate::backend::postgres::PostgresStore::open(postgre_sql_store)
                            .await
                            .map(BlobStore::Store)
                    }
                    #[cfg(feature = "mysql")]
                    BlobStoreBase::MySql(my_sql_store) => {
                        crate::backend::mysql::MysqlStore::open(my_sql_store)
                            .await
                            .map(BlobStore::Store)
                    }
                    _ => Err(
                        "Binary was not compiled with the selected blob store backend".to_string(),
                    ),
                };

                stores.push(result?);
            }
            Ok(BlobStore::Sharded(Arc::new(ShardedBlob { stores })))
        } else {
            Err("At least two blob stores are required for sharded blob store".to_string())
        }
    }

    #[inline(always)]
    fn get_store(&self, key: &[u8]) -> &BlobStore {
        &self.stores[xxhash_rust::xxh3::xxh3_64(key) as usize % self.stores.len()]
    }

    pub async fn get_blob(
        &self,
        key: &[u8],
        read_range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        async move {
            match self.get_store(key) {
                BlobStore::Store(store) => match store {
                    #[cfg(feature = "sqlite")]
                    Store::SQLite(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "foundation")]
                    Store::FoundationDb(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "rocks")]
                    Store::RocksDb(store) => store.get_blob(key, read_range).await,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(all(
                        feature = "enterprise",
                        any(feature = "postgres", feature = "mysql")
                    ))]
                    Store::SQLReadReplica(store) => store.get_blob(key, read_range).await,
                    // SPDX-SnippetEnd
                    Store::None => Err(trc::StoreEvent::NotConfigured.into()),
                },
                BlobStore::Fs(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "s3")]
                BlobStore::S3(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "azure")]
                BlobStore::Azure(store) => store.get_blob(key, read_range).await,
                BlobStore::Sharded(_) => unimplemented!(),
            }
        }
        .await
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        async move {
            match self.get_store(key) {
                BlobStore::Store(store) => match store {
                    #[cfg(feature = "sqlite")]
                    Store::SQLite(store) => store.put_blob(key, data).await,
                    #[cfg(feature = "foundation")]
                    Store::FoundationDb(store) => store.put_blob(key, data).await,
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.put_blob(key, data).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.put_blob(key, data).await,
                    #[cfg(feature = "rocks")]
                    Store::RocksDb(store) => store.put_blob(key, data).await,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(all(
                        feature = "enterprise",
                        any(feature = "postgres", feature = "mysql")
                    ))]
                    // SPDX-SnippetEnd
                    Store::SQLReadReplica(store) => store.put_blob(key, data).await,
                    Store::None => Err(trc::StoreEvent::NotConfigured.into()),
                },
                BlobStore::Fs(store) => store.put_blob(key, data).await,
                #[cfg(feature = "s3")]
                BlobStore::S3(store) => store.put_blob(key, data).await,
                #[cfg(feature = "azure")]
                BlobStore::Azure(store) => store.put_blob(key, data).await,
                BlobStore::Sharded(_) => unimplemented!(),
            }
        }
        .await
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        async move {
            match self.get_store(key) {
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
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(all(
                        feature = "enterprise",
                        any(feature = "postgres", feature = "mysql")
                    ))]
                    Store::SQLReadReplica(store) => store.delete_blob(key).await,
                    // SPDX-SnippetEnd
                    Store::None => Err(trc::StoreEvent::NotConfigured.into()),
                },
                BlobStore::Fs(store) => store.delete_blob(key).await,
                #[cfg(feature = "s3")]
                BlobStore::S3(store) => store.delete_blob(key).await,
                #[cfg(feature = "azure")]
                BlobStore::Azure(store) => store.delete_blob(key).await,
                BlobStore::Sharded(_) => unimplemented!(),
            }
        }
        .await
    }

    pub fn into_single(self) -> BlobStore {
        self.stores.into_iter().next().unwrap()
    }
}
