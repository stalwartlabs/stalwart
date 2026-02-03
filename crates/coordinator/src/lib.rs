/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[allow(unused_imports)]
use std::sync::Arc;

pub mod backend;
pub mod bootstrap;
pub mod dispatch;

#[derive(Clone, Default)]
pub enum Coordinator {
    #[cfg(feature = "redis")]
    Redis(Arc<store::backend::redis::RedisStore>),
    #[cfg(feature = "nats")]
    Nats(Arc<backend::nats::NatsPubSub>),
    #[cfg(feature = "zenoh")]
    Zenoh(Arc<backend::zenoh::ZenohPubSub>),
    #[cfg(feature = "kafka")]
    Kafka(Arc<backend::kafka::KafkaPubSub>),
    #[default]
    None,
}

pub enum PubSubStream {
    #[cfg(feature = "redis")]
    Redis(crate::backend::redis::pubsub::RedisPubSubStream),
    #[cfg(feature = "redis")]
    RedisCluster(crate::backend::redis::pubsub::RedisClusterPubSubStream),
    #[cfg(feature = "nats")]
    Nats(crate::backend::nats::pubsub::NatsPubSubStream),
    #[cfg(feature = "zenoh")]
    Zenoh(crate::backend::zenoh::pubsub::ZenohPubSubStream),
    #[cfg(feature = "kafka")]
    Kafka(crate::backend::kafka::pubsub::KafkaPubSubStream),
    Unimplemented,
}

pub enum Msg {
    #[cfg(feature = "redis")]
    Redis(redis::Msg),
    #[cfg(feature = "nats")]
    Nats(async_nats::Message),
    #[cfg(feature = "zenoh")]
    Zenoh(Vec<u8>),
    #[cfg(feature = "kafka")]
    Kafka(Vec<u8>),
    Unimplemented,
}
