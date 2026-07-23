/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

#[cfg(feature = "redis")]
use registry::schema::structs::InMemoryStoreBase;
use registry::schema::structs::ShardedInMemoryStore;

use crate::{
    Deserialize, InMemoryStore, Value,
    dispatch::lookup::{KeyValue, LookupKey},
};
use std::sync::Arc;

#[derive(Debug)]
pub struct ShardedInMemory {
    pub stores: Vec<InMemoryStore>,
}

#[allow(unreachable_patterns)]
impl ShardedInMemory {
    pub async fn open(config: ShardedInMemoryStore) -> Result<InMemoryStore, String> {
        if config.stores.len() >= 2 {
            let mut stores = Vec::new();

            for store in config.stores {
                let result = match store {
                    #[cfg(feature = "redis")]
                    InMemoryStoreBase::Redis(redis_store) => {
                        crate::backend::redis::RedisStore::open_single(redis_store).await
                    }
                    #[cfg(feature = "redis")]
                    InMemoryStoreBase::RedisCluster(redis_cluster_store) => {
                        crate::backend::redis::RedisStore::open_cluster(redis_cluster_store).await
                    }
                    _ => Err(
                        "Binary was not compiled with the selected in-memory backend".to_string(),
                    ),
                };

                stores.push(result?);
            }

            Ok(InMemoryStore::Sharded(Arc::new(ShardedInMemory { stores })))
        } else {
            Err(
                "At least two in-memory stores are required for sharded in-memory store"
                    .to_string(),
            )
        }
    }

    #[inline(always)]
    fn get_store(&self, key: &[u8]) -> &InMemoryStore {
        &self.stores[xxhash_rust::xxh3::xxh3_64(key) as usize % self.stores.len()]
    }

    pub async fn key_set(&self, kv: KeyValue<Vec<u8>>) -> trc::Result<()> {
        Box::pin(async move {
            match self.get_store(&kv.key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn counter_incr(&self, kv: KeyValue<i64>) -> trc::Result<i64> {
        Box::pin(async move {
            match self.get_store(&kv.key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn key_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_delete(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn counter_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_delete(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    #[allow(unused_variables)]
    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        Box::pin(async move {
            #[cfg(feature = "redis")]
            for store in &self.stores {
                match store {
                    InMemoryStore::Redis(store) => store.key_delete_prefix(prefix).await?,
                    InMemoryStore::Static(_) => {
                        return Err(trc::StoreEvent::NotSupported.into_err());
                    }
                    _ => return Err(trc::StoreEvent::NotSupported.into_err()),
                }
            }

            Ok(())
        })
        .await
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
        &self,
        key: impl Into<LookupKey<'_>>,
    ) -> trc::Result<Option<T>> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_get(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn counter_get(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<i64> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.counter_get(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn key_exists(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_exists(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub fn into_single(self) -> InMemoryStore {
        self.stores.into_iter().next().unwrap()
    }
}
