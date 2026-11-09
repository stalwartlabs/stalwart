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
    ipc::{QueueEvent, RegistryChange},
    network::security::{BlockedIps, IpWithTtl},
};
use ahash::AHashMap;
use directory::Directories;
use registry::{
    schema::{prelude::ObjectType, structs::BlockedIp},
    types::error::{Error, Warning},
};
use std::sync::Arc;
use store::{LookupStores, registry::bootstrap::Bootstrap, write::now};

#[cfg(feature = "enterprise")]
use store::Store;

pub struct ReloadResult {
    pub errors: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub replaced_core: bool,
}

impl Server {
    pub async fn reload_registry(&self, change: RegistryChange) -> trc::Result<ReloadResult> {
        Box::pin(self.reload(change)).await
    }

    async fn reload(&self, change: RegistryChange) -> trc::Result<ReloadResult> {
        let mut bootstrap = Bootstrap::new(self.registry().clone()).await;
        let object = match change {
            RegistryChange::Insert(id) => {
                if matches!(id.object(), ObjectType::BlockedIp) {
                    if let Some(ip) = bootstrap.get_infallible::<BlockedIp>(id.id()).await {
                        let expires_at = ip
                            .expires_at
                            .as_ref()
                            .map(|dt| dt.timestamp() as u64)
                            .unwrap_or(u64::MAX);

                        if expires_at > now() {
                            let mut ips = self.inner.data.blocked_ips.write();
                            if let Some(ip) = ip.address.try_to_ip() {
                                ips.block(ip, expires_at);
                            } else {
                                ips.blocked_ip_networks
                                    .push(IpWithTtl::new(ip.address, expires_at));
                            }
                        }
                    }
                    return Ok(bootstrap.into());
                } else {
                    id.object()
                }
            }
            RegistryChange::Delete(id) => id.object(),
            RegistryChange::Reload(object) => object,
        };

        match object {
            ObjectType::Certificate => {
                let mut certificates = AHashMap::new();
                parse_certificates(&mut bootstrap, &mut certificates, &mut Default::default())
                    .await;
                self.inner
                    .data
                    .tls_certificates
                    .store(Arc::new(certificates));
            }
            ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::HttpLookup
            | ObjectType::StoreLookup => {
                let lookup = LookupStores::build(&mut bootstrap).await;

                if bootstrap.errors.is_empty() {
                    self.inner.data.lookup_stores.store(Arc::new(lookup.stores));
                }
            }

            ObjectType::BlockedIp => {
                let blocked_ips = BlockedIps::parse(&mut bootstrap).await;
                if bootstrap.errors.is_empty() {
                    *self.inner.data.blocked_ips.write() = blocked_ips;
                }
            }
            ObjectType::Application => {
                self.inner.data.applications.reload(&mut bootstrap).await;
                if bootstrap.errors.is_empty() {
                    self.inner.data.applications.unpack_all(self, false).await;
                }
            }
            _ => {
                // Load stores
                let directory = Directories::build(&mut bootstrap).await;
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let (metrics, tracing) = if self.core.is_enterprise_edition() {
                    (
                        self.core.storage.metrics.clone(),
                        self.core.storage.tracing.clone(),
                    )
                } else {
                    (
                        Store::build_metrics(&mut bootstrap)
                            .await
                            .unwrap_or_default(),
                        Store::build_tracing(&mut bootstrap)
                            .await
                            .unwrap_or_default(),
                    )
                };
                // SPDX-SnippetEnd
                let storage = &self.core.storage;
                let storage = Storage {
                    registry: storage.registry.clone(),
                    data: bootstrap.data_store.clone(),
                    blob: storage.blob.clone(),
                    search: storage.search.clone(),
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    metrics,
                    #[cfg(feature = "enterprise")]
                    tracing,
                    // SPDX-SnippetEnd
                    memory: storage.memory.clone(),
                    coordinator: storage.coordinator.clone(),
                    directory: directory.default_directory,
                    directories: directory.directories,
                };

                // Parse tracers
                let tracers = Telemetry::parse(
                    &mut bootstrap,
                    &storage,
                    self.inner.ipc.index_queue_notify(),
                )
                .await;

                if bootstrap.errors.is_empty() {
                    let core = Core::parse(&mut bootstrap, storage).await;

                    if bootstrap.errors.is_empty() {
                        let mut servers = Listeners::parse(&mut bootstrap).await;
                        servers
                            .parse_tcp_acceptors(&mut bootstrap, self.inner.clone())
                            .await;

                        if bootstrap.errors.is_empty() {
                            // Update core
                            self.inner.shared_core.store(core.into());

                            // Update tracers

                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            tracers.update(self.inner.shared_core.load().is_enterprise_edition());
                            // SPDX-SnippetEnd
                            #[cfg(not(feature = "enterprise"))]
                            tracers.update(false);

                            // Reload queue settings
                            self.inner
                                .ipc
                                .queue_tx
                                .send(QueueEvent::ReloadSettings)
                                .await
                                .ok();

                            return Ok(ReloadResult {
                                errors: bootstrap.errors,
                                warnings: bootstrap.warnings,
                                replaced_core: true,
                            });
                        }
                    }
                }
            }
        }

        Ok(bootstrap.into())
    }
}

impl ReloadResult {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn log(&self) {
        for error in &self.errors {
            error.log();
        }
        for warning in &self.warnings {
            warning.log();
        }
    }
}

impl From<Bootstrap> for ReloadResult {
    fn from(bootstrap: Bootstrap) -> Self {
        Self {
            errors: bootstrap.errors,
            warnings: bootstrap.warnings,
            replaced_core: false,
        }
    }
}
