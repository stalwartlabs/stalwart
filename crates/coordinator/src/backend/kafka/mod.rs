/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::Coordinator;
use rdkafka::{
    ClientConfig, ClientContext, TopicPartitionList,
    consumer::{BaseConsumer, ConsumerContext, Rebalance, StreamConsumer},
    error::KafkaResult,
    producer::FutureProducer,
};
use registry::schema::structs::KafkaCoordinator;

pub mod pubsub;

pub(super) type LoggingConsumer = StreamConsumer<CustomContext>;

pub struct KafkaPubSub {
    consumer_builder: ClientConfig,
    producer: FutureProducer,
}

impl KafkaPubSub {
    pub async fn open(config: KafkaCoordinator) -> Result<Coordinator, String> {
        if config.brokers.is_empty() {
            return Err("No Kafka brokers specified".to_string());
        }

        let brokers = config.brokers.join(",");
        let mut consumer_builder = ClientConfig::new();

        consumer_builder
            .set("group.id", config.group_id)
            .set("bootstrap.servers", &brokers)
            .set("enable.partition.eof", "false")
            .set(
                "session.timeout.ms",
                config.timeout_session.as_millis().to_string(),
            )
            .set("enable.auto.commit", "true");

        let producer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set(
                "message.timeout.ms",
                config.timeout_message.as_millis().to_string(),
            )
            .create()
            .map_err(|err| format!("Failed to create Kafka producer: {}", err))?;

        Ok(Coordinator::Kafka(Arc::new(KafkaPubSub {
            consumer_builder,
            producer,
        })))
    }
}

impl std::fmt::Debug for KafkaPubSub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaPubSub").finish()
    }
}

pub(super) struct CustomContext;

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, _: &BaseConsumer<Self>, _: &Rebalance) {}

    fn post_rebalance(&self, _: &BaseConsumer<Self>, _: &Rebalance) {}

    fn commit_callback(&self, _: KafkaResult<()>, _: &TopicPartitionList) {}
}
