/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Msg, Subscription};
use deadpool::managed::Manager;
use futures::StreamExt;
use redis::{
    AsyncCommands, PushInfo, Value,
    aio::{MultiplexedConnection, PubSub, PubSubSink, PubSubStream},
    cluster::ClusterConfig,
    cluster_async::ClusterConnection,
};
use std::{fmt::Display, pin::Pin, sync::Arc, time::Duration};
use store::backend::redis::{RedisPool, RedisStore};
use tokio::{
    sync::mpsc::UnboundedReceiver,
    time::{Instant, Sleep},
};

#[cfg(not(stalwart_tests))]
const PING_WHEN_IDLE_FOR: Duration = Duration::from_secs(15);
#[cfg(stalwart_tests)]
const PING_WHEN_IDLE_FOR: Duration = Duration::from_millis(200);

pub enum RedisSubscription {
    Single(SingleSubscription),
    Cluster {
        _conn: ClusterConnection,
        rx: UnboundedReceiver<PushInfo>,
    },
}

pub struct SingleSubscription {
    sink: PubSubSink,
    stream: PubSubStream,
    idle: Pin<Box<Sleep>>,
    has_received: bool,
    response_timeout: Duration,
}

pub struct RedisPublisher {
    store: Arc<RedisStore>,
    topic: &'static str,
    connection: Option<PublishConnection>,
}

enum PublishConnection {
    Multiplexed(MultiplexedConnection),
    Cluster(ClusterConnection),
}

impl RedisPublisher {
    pub(crate) fn new(store: Arc<RedisStore>, topic: &'static str) -> Self {
        RedisPublisher {
            store,
            topic,
            connection: None,
        }
    }

    pub async fn publish(&mut self, payload: &[u8]) -> trc::Result<()> {
        let connection = match &mut self.connection {
            Some(connection) => connection,
            None => self
                .connection
                .insert(PublishConnection::open(&self.store).await?),
        };
        let result = match connection {
            PublishConnection::Multiplexed(connection) => {
                connection.publish(self.topic, payload).await
            }
            PublishConnection::Cluster(connection) => connection.publish(self.topic, payload).await,
        };
        if result.is_err() {
            self.connection = None;
        }
        result.map_err(into_error)
    }
}

impl PublishConnection {
    async fn open(store: &RedisStore) -> trc::Result<Self> {
        match &store.pool {
            RedisPool::Single(pool) => pool.manager().create().await.map(Self::Multiplexed),
            RedisPool::Cluster(pool) => pool.manager().create().await.map(Self::Cluster),
            RedisPool::Sentinel(pool) => pool.manager().create().await.map(Self::Multiplexed),
        }
    }
}

pub(crate) async fn redis_subscribe(
    redis: &RedisStore,
    topic: &'static str,
) -> trc::Result<Subscription> {
    let timeout = redis.pool.connect_timeout();
    tokio::time::timeout(timeout, subscribe(redis, topic, timeout))
        .await
        .unwrap_or_else(|_| Err(into_error("Timed out subscribing to channel")))
}

async fn subscribe(
    redis: &RedisStore,
    topic: &'static str,
    response_timeout: Duration,
) -> trc::Result<Subscription> {
    match &redis.pool {
        RedisPool::Single(pool) => {
            let mut pubsub = pool
                .manager()
                .client
                .get_async_pubsub()
                .await
                .map_err(into_error)?;
            pubsub.subscribe(topic).await.map_err(into_error)?;

            Ok(Subscription::Redis(RedisSubscription::Single(
                SingleSubscription::new(pubsub, response_timeout),
            )))
        }
        RedisPool::Cluster(pool) => {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

            let mut _conn = pool
                .manager()
                .client
                .get_async_connection_with_config(ClusterConfig::default().set_push_sender(tx))
                .await
                .map_err(into_error)?;

            _conn.subscribe(topic).await.map_err(into_error)?;

            Ok(Subscription::Redis(RedisSubscription::Cluster {
                _conn,
                rx,
            }))
        }
        RedisPool::Sentinel(pool) => {
            let client = pool
                .manager()
                .client
                .lock()
                .await
                .async_get_client()
                .await
                .map_err(into_error)?;

            let mut pubsub = client.get_async_pubsub().await.map_err(into_error)?;
            pubsub.subscribe(topic).await.map_err(into_error)?;

            Ok(Subscription::Redis(RedisSubscription::Single(
                SingleSubscription::new(pubsub, response_timeout),
            )))
        }
    }
}

impl RedisSubscription {
    pub async fn next<'x>(&mut self) -> Option<Msg<'x>> {
        match self {
            RedisSubscription::Single(subscription) => subscription.next().await.map(Msg::Redis),
            RedisSubscription::Cluster { rx, .. } => loop {
                if let Some(msg) = redis::Msg::from_push_info(rx.recv().await?) {
                    return Some(Msg::Redis(msg));
                }
            },
        }
    }
}

impl SingleSubscription {
    fn new(pubsub: PubSub, response_timeout: Duration) -> Self {
        let (sink, stream) = pubsub.split();
        SingleSubscription {
            sink,
            stream,
            idle: Box::pin(tokio::time::sleep(PING_WHEN_IDLE_FOR)),
            has_received: false,
            response_timeout,
        }
    }

    async fn next(&mut self) -> Option<redis::Msg> {
        loop {
            tokio::select! {
                message = self.stream.next() => {
                    self.has_received = true;
                    return message;
                }
                _ = self.idle.as_mut() => {
                    if !std::mem::take(&mut self.has_received) && !self.is_alive().await {
                        return None;
                    }
                    self.idle.as_mut().reset(Instant::now() + PING_WHEN_IDLE_FOR);
                }
            }
        }
    }

    async fn is_alive(&mut self) -> bool {
        let err = match tokio::time::timeout(self.response_timeout, self.sink.ping::<Value>()).await
        {
            Ok(Ok(_)) => return true,
            Ok(Err(err)) => into_error(err),
            Err(_) => into_error("Ping timed out"),
        };
        trc::event!(
            Cluster(trc::ClusterEvent::SubscriberError),
            CausedBy = err,
            Details = "Subscriber connection is not responding"
        );
        false
    }
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::RedisError.reason(err)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/coordinator/src/backend/redis/pubsub/tests.rs"]
mod tests;
