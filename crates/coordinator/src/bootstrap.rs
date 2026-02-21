/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Coordinator;
use registry::schema::{prelude::ObjectType, structs};
use store::{InMemoryStore, registry::bootstrap::Bootstrap};

#[allow(unreachable_patterns)]
impl Coordinator {
    pub async fn build(bp: &mut Bootstrap, in_memory: &InMemoryStore) -> Option<Self> {
        let result = match bp.setting_infallible::<structs::Coordinator>().await {
            structs::Coordinator::Disabled => Ok(Coordinator::None),
            #[cfg(feature = "redis")]
            structs::Coordinator::Default => {
                if let InMemoryStore::Redis(redis) = &in_memory {
                    Ok(Coordinator::Redis(redis.clone()))
                } else {
                    Err(
                        "Default coordinator requires Redis or Redis Cluster in-memory backend"
                            .to_string(),
                    )
                }
            }
            #[cfg(feature = "kafka")]
            structs::Coordinator::Kafka(kafka_coordinator) => {
                crate::backend::kafka::KafkaPubSub::open(kafka_coordinator).await
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
}

#[cfg(feature = "redis")]
fn unwrap_redis(store: InMemoryStore) -> Coordinator {
    if let InMemoryStore::Redis(redis) = store {
        Coordinator::Redis(redis)
    } else {
        unreachable!()
    }
}
