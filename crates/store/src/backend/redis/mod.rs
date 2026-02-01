/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::InMemoryStore;
use deadpool::{
    Runtime,
    managed::{Manager, Pool},
};
use redis::{
    Client, ProtocolVersion,
    cluster::{ClusterClient, ClusterClientBuilder},
};
use registry::{
    schema::{enums::RedisProtocol, structs},
    types::duration::Duration,
};
use std::{fmt::Display, sync::Arc};

pub mod lookup;
pub mod pool;

#[derive(Debug)]
pub struct RedisStore {
    pub pool: RedisPool,
}

pub struct RedisConnectionManager {
    pub client: Client,
    timeout: std::time::Duration,
}

pub struct RedisClusterConnectionManager {
    pub client: ClusterClient,
    timeout: std::time::Duration,
}

pub enum RedisPool {
    Single(Pool<RedisConnectionManager>),
    Cluster(Pool<RedisClusterConnectionManager>),
}

impl RedisStore {
    pub async fn open_single(config: structs::RedisStore) -> Result<InMemoryStore, String> {
        Ok(InMemoryStore::Redis(Arc::new(RedisStore {
            pool: RedisPool::Single(build_pool(
                RedisConnectionManager {
                    client: Client::open(config.url)
                        .map_err(|err| format!("Failed to open Redis client: {err:?}"))?,
                    timeout: config.timeout.into_inner(),
                },
                config.pool_max_connections,
                config.pool_timeout_create,
                config.pool_timeout_wait,
                config.pool_timeout_recycle,
            )?),
        })))
    }

    pub async fn open_cluster(config: structs::RedisClusterStore) -> Result<InMemoryStore, String> {
        let mut builder = ClusterClientBuilder::new(config.urls.into_iter());
        if let Some(value) = config.auth_username {
            builder = builder.username(value);
        }
        if let Some(value) = config.auth_secret {
            builder = builder.password(value);
        }
        if let Some(value) = config.max_retries {
            builder = builder.retries(value as u32);
        }
        if let Some(value) = config.max_retry_wait {
            builder = builder.max_retry_wait(value.as_millis());
        }
        if let Some(value) = config.min_retry_wait {
            builder = builder.min_retry_wait(value.as_millis());
        }
        if config.read_from_replicas {
            builder = builder.read_from_replicas();
        }
        if matches!(config.protocol_version, RedisProtocol::Resp3) {
            builder = builder.use_protocol(ProtocolVersion::RESP3);
        }

        let client = builder
            .build()
            .map_err(|err| format!("Failed to open Redis client: {err:?}"))?;

        Ok(InMemoryStore::Redis(Arc::new(RedisStore {
            pool: RedisPool::Cluster(build_pool(
                RedisClusterConnectionManager {
                    client,
                    timeout: config.timeout.into_inner(),
                },
                config.pool_max_connections,
                config.pool_timeout_create,
                config.pool_timeout_wait,
                config.pool_timeout_recycle,
            )?),
        })))
    }
}

fn build_pool<M: Manager>(
    manager: M,
    max_size: u64,
    create_timeout: Option<Duration>,
    wait_timeout: Option<Duration>,
    recycle_timeout: Option<Duration>,
) -> Result<Pool<M>, String> {
    Pool::builder(manager)
        .runtime(Runtime::Tokio1)
        .max_size(max_size as usize)
        .create_timeout(create_timeout.map(|v| v.into_inner()))
        .wait_timeout(wait_timeout.map(|v| v.into_inner()))
        .recycle_timeout(recycle_timeout.map(|v| v.into_inner()))
        .build()
        .map_err(|err| format!("Failed to build pool: {err}"))
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::RedisError.reason(err)
}

impl std::fmt::Debug for RedisPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(_) => f.debug_tuple("Single").finish(),
            Self::Cluster(_) => f.debug_tuple("Cluster").finish(),
        }
    }
}
