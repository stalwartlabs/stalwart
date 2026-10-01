/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ZenohPubSub;
use crate::{Msg, PubSubStream};
use std::sync::Arc;
use trc::{ClusterEvent, Error, EventType};
use zenoh::pubsub::Publisher;

pub struct ZenohPubSubStream {
    subs: zenoh::pubsub::Subscriber<zenoh::handlers::FifoChannelHandler<zenoh::sample::Sample>>,
}

impl ZenohPubSub {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        let publisher = match self.cached_publisher(topic) {
            Some(publisher) => publisher,
            None => {
                let publisher = self.session.declare_publisher(topic).await.map_err(|err| {
                    Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err)
                })?;
                self.cache_publisher(topic, publisher)
            }
        };
        publisher
            .put(message)
            .await
            .map_err(|err| Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err))
    }

    fn cached_publisher(&self, topic: &'static str) -> Option<Arc<Publisher<'static>>> {
        self.publishers
            .lock()
            .iter()
            .find(|(cached, _)| *cached == topic)
            .map(|(_, publisher)| publisher.clone())
    }

    fn cache_publisher(
        &self,
        topic: &'static str,
        publisher: Publisher<'static>,
    ) -> Arc<Publisher<'static>> {
        let mut publishers = self.publishers.lock();
        if let Some((_, cached)) = publishers.iter().find(|(cached, _)| *cached == topic) {
            return cached.clone();
        }
        let publisher = Arc::new(publisher);
        publishers.push((topic, publisher.clone()));
        publisher
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        self.session
            .declare_subscriber(topic)
            .await
            .map(|subs| PubSubStream::Zenoh(ZenohPubSubStream { subs }))
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })
    }
}

impl ZenohPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        self.subs
            .recv_async()
            .await
            .map(|sample| Msg::Zenoh(sample.payload().to_bytes().into_owned()))
            .ok()
    }
}
