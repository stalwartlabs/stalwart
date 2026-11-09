/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Coordinator;
use registry::schema::{prelude::ObjectType, structs};
#[cfg(feature = "keep")]
use std::sync::Arc;
use store::{InMemoryStore, registry::bootstrap::Bootstrap};

#[allow(unreachable_patterns)]
impl Coordinator {
    pub async fn build(bp: &mut Bootstrap, _in_memory: &InMemoryStore) -> Option<Self> {
        let result = match bp.setting_infallible::<structs::Coordinator>().await {
            structs::Coordinator::Disabled => Ok(Coordinator::None),
            #[cfg(any(feature = "redis", feature = "keep"))]
            structs::Coordinator::Default => match _in_memory {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(redis) => Ok(Coordinator::Redis(redis.clone())),
                #[cfg(feature = "keep")]
                InMemoryStore::Keep(keep) => Ok(Coordinator::Keep(keep.clone())),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", feature = "redis"))]
                InMemoryStore::Sharded(sharded) => sharded
                    .stores
                    .iter()
                    .find_map(|store| match store {
                        InMemoryStore::Redis(redis) => Some(Coordinator::Redis(redis.clone())),
                        _ => None,
                    })
                    .ok_or_else(default_coordinator_error),
                // SPDX-SnippetEnd
                _ => Err(default_coordinator_error()),
            },
            #[cfg(feature = "kafka")]
            structs::Coordinator::Kafka(kafka_coordinator) => {
                crate::backend::kafka::KafkaPubSub::open(kafka_coordinator, bp.node_id()).await
            }
            #[cfg(feature = "nats")]
            structs::Coordinator::Nats(nats_coordinator) => {
                crate::backend::nats::NatsPubSub::open(nats_coordinator).await
            }
            #[cfg(feature = "zenoh")]
            structs::Coordinator::Zenoh(zenoh_coordinator) => {
                crate::backend::zenoh::ZenohPubSub::open(zenoh_coordinator).await
            }
            #[cfg(feature = "redis")]
            structs::Coordinator::Redis(redis_store) => {
                store::backend::redis::RedisStore::open_single(redis_store)
                    .await
                    .map(unwrap_redis)
            }
            #[cfg(feature = "redis")]
            structs::Coordinator::RedisCluster(redis_cluster_store) => {
                store::backend::redis::RedisStore::open_cluster(redis_cluster_store)
                    .await
                    .map(unwrap_redis)
            }
            #[cfg(feature = "redis")]
            structs::Coordinator::RedisSentinel(redis_sentinel_store) => {
                store::backend::redis::RedisStore::open_sentinel(redis_sentinel_store)
                    .await
                    .map(unwrap_redis)
            }
            #[cfg(feature = "keep")]
            structs::Coordinator::Keep(keep_store) => {
                store::backend::keep::KeepStore::open(keep_store)
                    .await
                    .map(|keep| Coordinator::Keep(Arc::new(keep)))
            }
            _ => Err("Binary was not compiled with the selected coordinator backend".to_string()),
        };

        match result {
            Ok(store) => Some(store),
            Err(err) => {
                bp.build_error(ObjectType::Coordinator.singleton(), err);
                None
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self, Coordinator::None)
    }
}

#[cfg(any(feature = "redis", feature = "keep"))]
fn default_coordinator_error() -> String {
    "Default coordinator requires a Stalwart Keep, Redis, Redis Cluster, Redis Sentinel or sharded Redis in-memory store".to_string()
}

#[cfg(feature = "redis")]
fn unwrap_redis(store: InMemoryStore) -> Coordinator {
    if let InMemoryStore::Redis(redis) = store {
        Coordinator::Redis(redis)
    } else {
        unreachable!()
    }
}
