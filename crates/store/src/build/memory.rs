/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{InMemoryStore, backend::local::LocalStore, registry::bootstrap::Bootstrap};
use registry::schema::{prelude::ObjectType, structs};
use std::sync::Arc;

#[allow(unreachable_patterns)]
impl InMemoryStore {
    pub async fn build(bp: &mut Bootstrap) -> Option<Self> {
        let result = match bp.setting_infallible::<structs::InMemoryStore>().await {
            structs::InMemoryStore::Default => {
                if matches!(
                    bp.setting_infallible::<structs::Coordinator>().await,
                    structs::Coordinator::Disabled
                ) {
                    return Some(InMemoryStore::Local(Arc::new(LocalStore::default())));
                }
                Err(concat!(
                    "The local in-memory store cannot be used when a cluster coordinator ",
                    "is configured, use a Stalwart Keep or Redis in-memory store or disable the coordinator"
                )
                .to_string())
            }
            #[cfg(feature = "redis")]
            structs::InMemoryStore::Redis(redis_store) => {
                crate::backend::redis::RedisStore::open_single(redis_store).await
            }
            #[cfg(feature = "redis")]
            structs::InMemoryStore::RedisCluster(redis_cluster_store) => {
                crate::backend::redis::RedisStore::open_cluster(redis_cluster_store).await
            }
            #[cfg(feature = "redis")]
            structs::InMemoryStore::RedisSentinel(redis_sentinel_store) => {
                crate::backend::redis::RedisStore::open_sentinel(redis_sentinel_store).await
            }
            #[cfg(feature = "keep")]
            structs::InMemoryStore::Keep(keep_store) => {
                crate::backend::keep::KeepStore::open(keep_store)
                    .await
                    .map(InMemoryStore::from)
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            structs::InMemoryStore::Sharded(store) => {
                crate::backend::composite::sharded_lookup::ShardedInMemory::open(store).await
            }
            // SPDX-SnippetEnd
            _ => Err("Binary was not compiled with the selected in-memory backend".to_string()),
        };

        match result {
            Ok(store) => Some(store),
            Err(err) => {
                bp.build_error(ObjectType::InMemoryStore.singleton(), err);
                None
            }
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn downgrade_store(self) -> InMemoryStore {
        match self {
            InMemoryStore::Sharded(_) => InMemoryStore::default(),
            other => other,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn is_enterprise(&self) -> bool {
        matches!(self, InMemoryStore::Sharded(_))
    }
    // SPDX-SnippetEnd
}
