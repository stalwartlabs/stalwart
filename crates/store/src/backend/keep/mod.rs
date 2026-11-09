/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use keep_client::{
    Client, ClientConfig, ClusterSecret, Discovery, Error, Identity, Routing, StreamMode, Tls, Ttl,
};
use registry::schema::{
    enums::KeepStreamMode,
    structs::{self, KeepTls},
};
use std::{
    borrow::Cow,
    fmt::{self, Display},
    num::NonZeroU8,
    time::{Duration, Instant},
};

pub use keep_client;

pub mod lookup;
pub mod swap;

const MAX_KEY_LEN: usize = u8::MAX as usize;
const HASHED_HEAD_LEN: usize = MAX_KEY_LEN - blake3::OUT_LEN;
const CONNECT_PATIENCE: Duration = Duration::from_secs(30);
const CONNECT_RETRY: Duration = Duration::from_millis(500);

pub struct KeepStore {
    client: Client,
}

struct KeepKey<'x>(Cow<'x, [u8]>);

impl KeepStore {
    pub async fn open(config: structs::KeepStore) -> Result<Self, String> {
        Ok(KeepStore {
            client: connect_with_retry(&client_config(config).await?).await?,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

async fn client_config(config: structs::KeepStore) -> Result<ClientConfig, String> {
    let secret = config
        .secret
        .secret()
        .await?
        .map(|secret| {
            ClusterSecret::from_hex(secret.trim()).ok_or_else(|| {
                "The Stalwart Keep cluster secret must be 32 hexadecimal digits".to_string()
            })
        })
        .transpose()?;
    let (routing, shard_connections) = if secret.is_some() {
        (
            Routing::Shard,
            u8::try_from(config.shard_connections)
                .ok()
                .and_then(NonZeroU8::new)
                .ok_or_else(|| {
                    "Invalid number of connections per Stalwart Keep shard".to_string()
                })?,
        )
    } else {
        (Routing::None, NonZeroU8::MIN)
    };
    Ok(ClientConfig {
        endpoints: config
            .hosts
            .into_inner()
            .into_iter()
            .map(String::into_boxed_str)
            .collect(),
        discovery: if config.cluster_discovery {
            Discovery::Cluster
        } else {
            Discovery::Static
        },
        connections: usize::try_from(config.connections)
            .map_err(|_| "Invalid number of Stalwart Keep connections".to_string())?,
        shard_connections,
        routing,
        stream: match config.stream_mode {
            KeepStreamMode::Everywhere => StreamMode::Everywhere,
            KeepStreamMode::Owner => StreamMode::Owner,
        },
        secret,
        connect_timeout: config.connect_timeout.into_inner(),
        attempt_timeout: config.attempt_timeout.into_inner(),
        deadline: config.deadline.into_inner(),
        tls: match config.tls {
            KeepTls::Disabled => None,
            KeepTls::RawPublicKeys(tls) => Some(Tls::RawPublicKeys {
                key: tls.key_path.into_boxed_str(),
                servers: tls.server_keys_path.into_boxed_str(),
            }),
            KeepTls::Authority(tls) => Some(Tls::Authority {
                ca: tls.ca_path.into_boxed_str(),
                server_name: tls.server_name.map(String::into_boxed_str),
                identity: Some(Identity {
                    chain: tls.cert_path.into_boxed_str(),
                    key: tls.key_path.into_boxed_str(),
                }),
            }),
        },
        ..ClientConfig::default()
    })
}

async fn connect_with_retry(config: &ClientConfig) -> Result<Client, String> {
    let give_up = Instant::now() + CONNECT_PATIENCE;
    loop {
        match Client::connect(config).await {
            Ok(client) => return Ok(client),
            Err(Error::Connect(_) | Error::Unavailable | Error::Unknown(_))
                if Instant::now() < give_up =>
            {
                tokio::time::sleep(CONNECT_RETRY).await;
            }
            Err(err) => return Err(format!("Failed to connect to Stalwart Keep: {err}")),
        }
    }
}

impl<'x> KeepKey<'x> {
    fn new(key: &'x [u8]) -> Self {
        match key.split_at_checked(HASHED_HEAD_LEN) {
            Some((head, _)) if key.len() > MAX_KEY_LEN => {
                let mut hashed = Vec::with_capacity(MAX_KEY_LEN);
                hashed.extend_from_slice(head);
                hashed.extend_from_slice(blake3::hash(key).as_bytes());
                KeepKey(Cow::Owned(hashed))
            }
            _ => KeepKey(Cow::Borrowed(key)),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn ttl(secs: u64) -> trc::Result<Ttl> {
    Ttl::from_secs(u32::try_from(secs).unwrap_or(u32::MAX)).ok_or_else(zero_ttl)
}

fn optional_ttl(expires: Option<u64>) -> trc::Result<Option<Ttl>> {
    expires.map(ttl).transpose()
}

#[cold]
fn zero_ttl() -> trc::Error {
    trc::StoreEvent::KeepError
        .into_err()
        .details("Expiration must be at least one second")
}

#[cold]
pub fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::KeepError.reason(err)
}

impl fmt::Debug for KeepStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeepStore")
            .field("routed", &self.client.is_routed())
            .finish()
    }
}
