/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Core, Server,
    config::{
        server::{Listeners, tls::parse_certificates},
        storage::Storage,
        telemetry::Telemetry,
    },
    ipc::RegistryChange,
};
use ahash::AHashMap;
use directory::Directories;
use registry::schema::{prelude::ObjectType, structs::BlockedIp};
use std::sync::Arc;
use store::{InMemoryStore, LookupStores, registry::bootstrap::Bootstrap, write::now};

pub struct ReloadResult {
    pub bootstrap: Bootstrap,
    pub new_core: Option<Core>,
    pub tracers: Option<Telemetry>,
}

impl Server {
    pub async fn reload_registry(&self, change: RegistryChange) -> trc::Result<ReloadResult> {
        let todo = "check the different events triggering this, spam filter reload, etc. make sure all are used";
        let mut bootstrap = Bootstrap::init(self.registry().clone()).await;
        let object = match change {
            RegistryChange::Insert(id) => {
                if matches!(id.object(), ObjectType::BlockedIp) {
                    if let Some(ip) = bootstrap.get_infallible::<BlockedIp>(id.id()).await
                        && ip.expires_at.is_none_or(|ip| ip.timestamp() > now() as i64)
                    {
                        let mut ips = self.inner.data.blocked_ips.write();
                        if let Some(ip) = ip.address.try_to_ip() {
                            ips.blocked_ip_addresses.insert(ip);
                        } else {
                            ips.blocked_ip_networks.push(ip.address);
                        }
                    }
                    return Ok(ReloadResult {
                        bootstrap,
                        new_core: None,
                        tracers: None,
                    });
                } else {
                    id.object()
                }
            }
            RegistryChange::Delete(id) => id.object(),
            RegistryChange::Reload(object) => object,
        };

        let mut result = ReloadResult {
            bootstrap,
            new_core: None,
            tracers: None,
        };

        match object {
            ObjectType::Certificate => {
                let mut certificates = AHashMap::new();
                parse_certificates(
                    &mut result.bootstrap,
                    &mut certificates,
                    &mut Default::default(),
                )
                .await;
                self.inner
                    .data
                    .tls_certificates
                    .store(Arc::new(certificates));
            }
            ObjectType::MemoryLookupKey | ObjectType::MemoryLookupKeyValue => {
                let mut lookup = LookupStores {
                    stores: self.inner.data.lookup_stores.load().as_ref().clone(),
                };
                lookup
                    .stores
                    .retain(|_, store| !matches!(store, InMemoryStore::Static(_)));
                lookup.parse_static(&mut result.bootstrap).await;
            }
            ObjectType::HttpLookup => {
                let mut lookup = LookupStores {
                    stores: self.inner.data.lookup_stores.load().as_ref().clone(),
                };
                lookup
                    .stores
                    .retain(|_, store| !matches!(store, InMemoryStore::Http(_)));
                lookup.parse_http(&mut result.bootstrap).await;
            }
            ObjectType::StoreLookup => {
                let mut lookup = LookupStores {
                    stores: self.inner.data.lookup_stores.load().as_ref().clone(),
                };
                lookup.stores.retain(|_, store| {
                    matches!(store, InMemoryStore::Static(_) | InMemoryStore::Http(_))
                });
                lookup.parse_stores(&mut result.bootstrap).await;
            }
            _ => {
                // Load stores
                let directory = Directories::build(&mut result.bootstrap).await;
                let storage = &self.core.storage;
                let storage = Storage {
                    registry: storage.registry.clone(),
                    data: storage.data.clone(),
                    blob: storage.blob.clone(),
                    search: storage.search.clone(),
                    metrics: storage.metrics.clone(),
                    tracing: storage.tracing.clone(),
                    memory: storage.memory.clone(),
                    coordinator: storage.coordinator.clone(),
                    directory: directory.default_directory,
                    directories: directory.directories,
                };

                // Parse tracers
                let tracers = Telemetry::parse(&mut result.bootstrap, &storage).await;

                if result.bootstrap.errors.is_empty() {
                    let core = Box::pin(Core::parse(&mut result.bootstrap, storage)).await;

                    if result.bootstrap.errors.is_empty() {
                        let mut servers = Listeners::parse(&mut result.bootstrap).await;
                        servers
                            .parse_tcp_acceptors(&mut result.bootstrap, self.inner.clone())
                            .await;

                        if result.bootstrap.errors.is_empty() {
                            result.new_core = Some(core);
                            result.tracers = Some(tracers);
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}
