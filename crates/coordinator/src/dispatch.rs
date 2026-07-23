/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Coordinator, Msg, PubSubStream};

#[allow(unused_variables)]
impl Coordinator {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        match self {
            #[cfg(feature = "redis")]
            Coordinator::Redis(store) => {
                crate::backend::redis::pubsub::redis_publish(store, topic, message).await
            }
            #[cfg(feature = "nats")]
            Coordinator::Nats(store) => store.publish(topic, message).await,
            #[cfg(feature = "zenoh")]
            Coordinator::Zenoh(store) => store.publish(topic, message).await,
            #[cfg(feature = "kafka")]
            Coordinator::Kafka(store) => store.publish(topic, message).await,
            Coordinator::None => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        match self {
            #[cfg(feature = "redis")]
            Coordinator::Redis(store) => {
                crate::backend::redis::pubsub::redis_subscribe(store, topic).await
            }
            #[cfg(feature = "nats")]
            Coordinator::Nats(store) => store.subscribe(topic).await,
            #[cfg(feature = "zenoh")]
            Coordinator::Zenoh(store) => store.subscribe(topic).await,
            #[cfg(feature = "kafka")]
            Coordinator::Kafka(store) => store.subscribe(topic).await,
            Coordinator::None => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Coordinator::None)
    }
}

impl PubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        match self {
            #[cfg(feature = "redis")]
            PubSubStream::Redis(stream) => stream.next().await,
            #[cfg(feature = "redis")]
            PubSubStream::RedisCluster(stream) => stream.next().await,
            #[cfg(feature = "nats")]
            PubSubStream::Nats(stream) => stream.next().await,
            #[cfg(feature = "zenoh")]
            PubSubStream::Zenoh(stream) => stream.next().await,
            #[cfg(feature = "kafka")]
            PubSubStream::Kafka(stream) => stream.next().await,
            PubSubStream::Unimplemented => None,
        }
    }
}

impl Msg {
    pub fn payload(&self) -> &[u8] {
        match self {
            #[cfg(feature = "redis")]
            Msg::Redis(msg) => msg.get_payload_bytes(),
            #[cfg(feature = "nats")]
            Msg::Nats(msg) => msg.payload.as_ref(),
            #[cfg(feature = "zenoh")]
            Msg::Zenoh(msg) => msg.as_slice(),
            #[cfg(feature = "kafka")]
            Msg::Kafka(msg) => msg.as_slice(),
            Msg::Unimplemented => &[],
        }
    }

    pub fn topic(&self) -> &str {
        match self {
            #[cfg(feature = "redis")]
            Msg::Redis(msg) => msg.get_channel_name(),
            #[cfg(feature = "nats")]
            Msg::Nats(msg) => msg.subject.as_str(),
            #[cfg(feature = "zenoh")]
            Msg::Zenoh(_) => "",
            #[cfg(feature = "kafka")]
            Msg::Kafka(_) => "",
            Msg::Unimplemented => "",
        }
    }
}
