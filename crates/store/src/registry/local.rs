/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use registry::schema::structs::DataStore;
use std::{net::IpAddr, path::PathBuf};
use utils::snowflake::SnowflakeIdGenerator;

pub(crate) enum RegistryInit {
    Ok(DataStore),
    Err(String),
    Bootstrap,
}

impl RegistryStoreInner {
    pub(crate) fn new(local_path: PathBuf) -> Self {
        let env_hostname = std::env::var("STALWART_HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| {
                let host = gethostname::gethostname();
                let host = host.to_string_lossy();
                if host.parse::<IpAddr>().is_err() {
                    host.to_lowercase()
                } else {
                    "localhost".to_string()
                }
            });

        Self {
            local_path,
            store: Store::None,
            id_generator: SnowflakeIdGenerator::new(),
            node_id: 0,
            env_recovery_mode: std::env::var("STALWART_RECOVERY_MODE")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            env_recovery_admin: std::env::var("STALWART_RECOVERY_ADMIN")
                .ok()
                .and_then(|v| {
                    v.split_once(':')
                        .map(|(a, p)| (a.trim().to_string(), p.trim().to_string()))
                })
                .filter(|(a, p)| !a.is_empty() && !p.is_empty()),
            env_cluster_role: std::env::var("STALWART_ROLE")
                .ok()
                .filter(|r| !r.is_empty()),
            env_push_shard_id: std::env::var("STALWART_PUSH_SHARD")
                .ok()
                .and_then(|id| id.parse::<u32>().ok().and_then(|v| v.checked_sub(1)))
                .unwrap_or(0),
            env_public_url: std::env::var("STALWART_PUBLIC_URL")
                .ok()
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|u| !u.is_empty())
                .or_else(|| {
                    std::env::var("STALWART_HTTPS_PORT").ok().and_then(|p| {
                        p.parse::<u16>()
                            .ok()
                            .map(|port| format!("https://{}:{}", env_hostname, port))
                    })
                }),
            env_hostname,
        }
    }

    pub(crate) async fn read_data_store(&self) -> RegistryInit {
        match tokio::fs::read_to_string(&self.local_path).await {
            Ok(contents) => match serde_json::from_str::<DataStore>(&contents) {
                Ok(data_store) => RegistryInit::Ok(data_store),
                Err(err) => RegistryInit::Err(format!(
                    "Failed to parse data store settings at {}: {}",
                    self.local_path.display(),
                    err
                )),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => RegistryInit::Bootstrap,
            Err(err) => RegistryInit::Err(format!(
                "Failed to read data store settings at {}: {}",
                self.local_path.display(),
                err
            )),
        }
    }
}

impl RegistryStore {
    pub async fn write_data_store(&self, data_store: &DataStore) -> trc::Result<()> {
        let json_text = serde_json::to_string(data_store).map_err(|err| {
            trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                .into_err()
                .caused_by(trc::location!())
                .reason(err)
        })?;
        tokio::fs::write(&self.0.local_path, json_text)
            .await
            .map_err(|err| {
                trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                    .into_err()
                    .caused_by(trc::location!())
                    .reason(err)
            })
    }
}
