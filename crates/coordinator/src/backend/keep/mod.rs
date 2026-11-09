/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Publisher, Subscription};
use store::backend::keep::{
    KeepStore, into_error,
    keep_client::{Client, Topic},
};

pub struct KeepPublisher {
    client: Client,
    topic: Topic,
}

fn topic(name: &str) -> Option<Topic> {
    hashify::map!(name.as_bytes(), Topic, "stwt.agora" => Topic::BROADCAST).copied()
}

pub(crate) fn keep_publisher(store: &KeepStore, name: &'static str) -> Publisher {
    match topic(name) {
        Some(topic) => Publisher::Keep(KeepPublisher {
            client: store.client().clone(),
            topic,
        }),
        None => Publisher::Unimplemented,
    }
}

pub(crate) async fn keep_subscribe(
    store: &KeepStore,
    name: &'static str,
) -> trc::Result<Subscription> {
    let topic = topic(name).ok_or_else(|| {
        trc::StoreEvent::NotSupported
            .into_err()
            .details("Stalwart Keep has no topic for this channel")
            .ctx(trc::Key::Key, name)
    })?;
    store
        .client()
        .subscribe(topic)
        .await
        .map(Subscription::Keep)
        .map_err(into_error)
}

impl KeepPublisher {
    pub async fn publish(&self, payload: &[u8]) -> trc::Result<()> {
        self.client
            .publish_confirmed(self.topic, payload)
            .await
            .map_err(into_error)
    }
}
