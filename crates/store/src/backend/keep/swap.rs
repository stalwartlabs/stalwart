/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{client_config, connect_with_retry, into_error, optional_ttl};
use keep_client::{Client, ClientConfig, Error};
use keep_proto::Status;
use registry::schema::structs;
use std::num::NonZeroU8;

const SWAP_CONNECTIONS: usize = 1;

#[derive(Clone)]
pub struct KeepSwapClient(Client);

impl KeepSwapClient {
    pub async fn open(config: structs::KeepStore) -> Result<Self, String> {
        connect_with_retry(&ClientConfig {
            connections: SWAP_CONNECTIONS,
            shard_connections: NonZeroU8::MIN,
            ..client_config(config).await?
        })
        .await
        .map(KeepSwapClient)
    }

    pub async fn key_set_many(
        &self,
        items: &[(Vec<u8>, &[u8])],
        expires: Option<u64>,
    ) -> trc::Result<()> {
        let ttl = optional_ttl(expires)?;
        self.0.set_many(items, ttl).await.map_err(swap_write_error)
    }

    pub async fn key_get_many(&self, keys: &[Vec<u8>]) -> trc::Result<Vec<Option<Vec<u8>>>> {
        self.0.get_many(keys).await.map_err(into_error)
    }

    pub async fn key_unlink_many(&self, keys: &[Vec<u8>]) -> trc::Result<()> {
        self.0.delete_many(keys).await.map_err(into_error)
    }
}

#[cold]
fn swap_write_error(err: Error) -> trc::Error {
    match err {
        Error::Server {
            status: Status::Full,
            ..
        } => trc::EventType::Cache(trc::CacheEvent::SwapSkip)
            .into_err()
            .reason(err),
        err => into_error(err),
    }
}
