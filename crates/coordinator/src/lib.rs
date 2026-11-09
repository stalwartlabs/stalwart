/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use std::marker::PhantomData;
#[allow(unused_imports)]
use std::sync::Arc;

pub mod backend;
pub mod bootstrap;
pub mod dispatch;

#[derive(Clone, Default)]
pub enum Coordinator {
    #[cfg(feature = "redis")]
    Redis(Arc<store::backend::redis::RedisStore>),
    #[cfg(feature = "keep")]
    Keep(Arc<store::backend::keep::KeepStore>),
    #[cfg(feature = "nats")]
    Nats(Arc<backend::nats::NatsPubSub>),
    #[cfg(feature = "zenoh")]
    Zenoh(Arc<backend::zenoh::ZenohPubSub>),
    #[cfg(feature = "kafka")]
    Kafka(Arc<backend::kafka::KafkaPubSub>),
    #[default]
    None,
}

pub enum Publisher {
    #[cfg(feature = "redis")]
    Redis(backend::redis::pubsub::RedisPublisher),
    #[cfg(feature = "keep")]
    Keep(backend::keep::KeepPublisher),
    #[cfg(feature = "nats")]
    Nats(backend::nats::pubsub::NatsPublisher),
    #[cfg(feature = "zenoh")]
    Zenoh(backend::zenoh::pubsub::ZenohPublisher),
    #[cfg(feature = "kafka")]
    Kafka(backend::kafka::pubsub::KafkaPublisher),
    Unimplemented,
}

pub enum Subscription {
    #[cfg(feature = "redis")]
    Redis(backend::redis::pubsub::RedisSubscription),
    #[cfg(feature = "keep")]
    Keep(store::backend::keep::keep_client::Subscription),
    #[cfg(feature = "nats")]
    Nats(async_nats::Subscriber),
    #[cfg(feature = "zenoh")]
    Zenoh(backend::zenoh::pubsub::ZenohSubscription),
    #[cfg(feature = "kafka")]
    Kafka(backend::kafka::pubsub::KafkaSubscription),
    Unimplemented,
}

pub enum PubSubStream<'x> {
    #[cfg(feature = "redis")]
    Redis(&'x mut backend::redis::pubsub::RedisSubscription),
    #[cfg(feature = "keep")]
    Keep(&'x mut store::backend::keep::keep_client::Subscription),
    #[cfg(feature = "nats")]
    Nats(&'x mut async_nats::Subscriber),
    #[cfg(feature = "zenoh")]
    Zenoh(&'x backend::zenoh::pubsub::ZenohSubscription),
    #[cfg(feature = "kafka")]
    Kafka(backend::kafka::pubsub::KafkaStream<'x>),
    Unimplemented(PhantomData<&'x ()>),
}

pub enum Msg<'x> {
    #[cfg(feature = "redis")]
    Redis(redis::Msg),
    #[cfg(feature = "keep")]
    Keep(store::backend::keep::keep_client::Delivery<'x>),
    #[cfg(feature = "nats")]
    Nats(async_nats::Message),
    #[cfg(feature = "zenoh")]
    Zenoh(backend::zenoh::pubsub::ZenohMsg),
    #[cfg(feature = "kafka")]
    Kafka(rdkafka::message::BorrowedMessage<'x>),
    Unimplemented(PhantomData<&'x ()>),
}

pub enum MsgKind {
    Payload,
    CatchUp,
    Ignore,
}
