/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{InMemoryStore, LookupStores, registry::bootstrap::Bootstrap};
use registry::schema::structs::{LookupStore, StoreLookup};
use std::collections::hash_map::Entry;

impl LookupStores {
    pub async fn build(bp: &mut Bootstrap) -> Self {
        let mut stores = LookupStores::default();
        stores.parse_stores(bp).await;
        stores.parse_static(bp).await;
        stores.parse_http(bp).await;
        stores
    }

    #[allow(unreachable_patterns)]
    pub async fn parse_stores(&mut self, bp: &mut Bootstrap) {
        for store in bp.list_infallible::<StoreLookup>().await {
            let id = store.id;
            let store = store.object;

            let result = match store.store {
                #[cfg(feature = "postgres")]
                LookupStore::PostgreSql(postgre_sql_store) => {
                    crate::backend::postgres::PostgresStore::open(postgre_sql_store)
                        .await
                        .map(InMemoryStore::Store)
                }
                #[cfg(feature = "mysql")]
                LookupStore::MySql(my_sql_store) => {
                    crate::backend::mysql::MysqlStore::open(my_sql_store)
                        .await
                        .map(InMemoryStore::Store)
                }
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                LookupStore::Sharded(sharded_in_memory_store) => {
                    crate::backend::composite::sharded_lookup::ShardedInMemory::open(
                        sharded_in_memory_store,
                    )
                    .await
                }
                // SPDX-SnippetEnd
                #[cfg(feature = "redis")]
                LookupStore::Redis(redis_store) => {
                    crate::backend::redis::RedisStore::open_single(redis_store).await
                }
                #[cfg(feature = "redis")]
                LookupStore::RedisCluster(redis_cluster_store) => {
                    crate::backend::redis::RedisStore::open_cluster(redis_cluster_store).await
                }
                _ => Err(
                    "Binary was not compiled with the selected lookup store backend".to_string(),
                ),
            };

            match result {
                Ok(lookup) => match self.stores.entry(store.namespace.as_str().into()) {
                    Entry::Vacant(entry) => {
                        entry.insert(lookup);
                    }
                    Entry::Occupied(_) => {
                        bp.build_error(
                            id,
                            format!(
                                "A lookup store with the {} namespace already exists",
                                store.namespace
                            ),
                        );
                    }
                },
                Err(err) => {
                    bp.build_error(id, err);
                }
            }
        }
    }
}
