/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Coordinator, Msg, MsgKind, PubSubStream, Publisher, Subscription};
use std::marker::PhantomData;
#[cfg(feature = "keep")]
use store::backend::keep::keep_client::Delivery;

#[allow(unused_variables)]
impl Coordinator {
    pub fn publisher(&self, topic: &'static str) -> Option<Publisher> {
        match self {
            #[cfg(feature = "redis")]
            Coordinator::Redis(store) => Some(Publisher::Redis(
                crate::backend::redis::pubsub::RedisPublisher::new(store.clone(), topic),
            )),
            #[cfg(feature = "keep")]
            Coordinator::Keep(store) => Some(crate::backend::keep::keep_publisher(store, topic)),
            #[cfg(feature = "nats")]
            Coordinator::Nats(pubsub) => Some(Publisher::Nats(pubsub.publisher(topic))),
            #[cfg(feature = "zenoh")]
            Coordinator::Zenoh(pubsub) => Some(Publisher::Zenoh(
                crate::backend::zenoh::pubsub::ZenohPublisher::new(pubsub.clone(), topic),
            )),
            #[cfg(feature = "kafka")]
            Coordinator::Kafka(pubsub) => Some(Publisher::Kafka(pubsub.publisher(topic))),
            Coordinator::None => None,
        }
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<Subscription> {
        match self {
            #[cfg(feature = "redis")]
            Coordinator::Redis(store) => {
                crate::backend::redis::pubsub::redis_subscribe(store, topic).await
            }
            #[cfg(feature = "keep")]
            Coordinator::Keep(store) => crate::backend::keep::keep_subscribe(store, topic).await,
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

#[allow(unused_variables)]
impl Publisher {
    #[allow(clippy::ptr_arg)]
    pub async fn publish(&mut self, payload: &mut Vec<u8>) -> trc::Result<()> {
        match self {
            #[cfg(feature = "redis")]
            Publisher::Redis(publisher) => publisher.publish(payload).await,
            #[cfg(feature = "keep")]
            Publisher::Keep(publisher) => publisher.publish(payload).await,
            #[cfg(feature = "nats")]
            Publisher::Nats(publisher) => publisher.publish(payload).await,
            #[cfg(feature = "zenoh")]
            Publisher::Zenoh(publisher) => publisher.publish(payload).await,
            #[cfg(feature = "kafka")]
            Publisher::Kafka(publisher) => publisher.publish(payload).await,
            Publisher::Unimplemented => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }
}

impl Subscription {
    pub fn stream(&mut self) -> PubSubStream<'_> {
        match self {
            #[cfg(feature = "redis")]
            Subscription::Redis(subscription) => PubSubStream::Redis(subscription),
            #[cfg(feature = "keep")]
            Subscription::Keep(subscription) => PubSubStream::Keep(subscription),
            #[cfg(feature = "nats")]
            Subscription::Nats(subscriber) => PubSubStream::Nats(subscriber),
            #[cfg(feature = "zenoh")]
            Subscription::Zenoh(subscriber) => PubSubStream::Zenoh(subscriber),
            #[cfg(feature = "kafka")]
            Subscription::Kafka(subscription) => PubSubStream::Kafka(subscription.stream()),
            Subscription::Unimplemented => PubSubStream::Unimplemented(PhantomData),
        }
    }
}

impl<'x> PubSubStream<'x> {
    pub async fn next(&mut self) -> Option<Msg<'_>> {
        match self {
            #[cfg(feature = "redis")]
            PubSubStream::Redis(subscription) => subscription.next().await,
            #[cfg(feature = "keep")]
            PubSubStream::Keep(subscription) => subscription.next().await.map(Msg::Keep),
            #[cfg(feature = "nats")]
            PubSubStream::Nats(subscriber) => {
                crate::backend::nats::pubsub::nats_next(subscriber).await
            }
            #[cfg(feature = "zenoh")]
            PubSubStream::Zenoh(subscriber) => {
                crate::backend::zenoh::pubsub::zenoh_next(subscriber).await
            }
            #[cfg(feature = "kafka")]
            PubSubStream::Kafka(stream) => crate::backend::kafka::pubsub::kafka_next(stream).await,
            PubSubStream::Unimplemented(_) => None,
        }
    }
}

impl Msg<'_> {
    pub fn payload(&self) -> &[u8] {
        match self {
            #[cfg(feature = "redis")]
            Msg::Redis(msg) => msg.get_payload_bytes(),
            #[cfg(feature = "keep")]
            Msg::Keep(Delivery::Event { payload, .. }) => payload,
            #[cfg(feature = "keep")]
            Msg::Keep(_) => &[],
            #[cfg(feature = "nats")]
            Msg::Nats(msg) => msg.payload.as_ref(),
            #[cfg(feature = "zenoh")]
            Msg::Zenoh(msg) => msg.payload(),
            #[cfg(feature = "kafka")]
            Msg::Kafka(msg) => rdkafka::Message::payload(msg).unwrap_or_default(),
            Msg::Unimplemented(_) => &[],
        }
    }

    pub fn kind(&self) -> MsgKind {
        #[cfg(feature = "keep")]
        if let Msg::Keep(delivery) = self {
            return match delivery {
                Delivery::Event { .. } => MsgKind::Payload,
                delivery if delivery.needs_catch_up() => MsgKind::CatchUp,
                _ => MsgKind::Ignore,
            };
        }

        MsgKind::Payload
    }
}
