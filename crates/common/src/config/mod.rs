/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::{mailstore::jmap::JmapConfig, smtp::SmtpConfig, storage::Storage};
use crate::{
    Core, Network, Security,
    auth::oauth::config::OAuthConfig,
    config::mailstore::{imap::ImapConfig, scripts::Scripting, spamfilter::SpamFilterConfig},
    expr::*,
};
use arc_swap::ArcSwap;
use coordinator::Coordinator;
use directory::{Directories, Directory};
use groupware::GroupwareConfig;
use hyper::HeaderMap;
use ring::signature::{EcdsaKeyPair, RsaKeyPair};
use std::sync::Arc;
use store::{BlobBackend, BlobStore, InMemoryStore, SearchStore, Store, Stores};
use telemetry::Metrics;

pub mod groupware;
pub mod inner;
pub mod mailstore;
pub mod network;
pub mod server;
pub mod smtp;
pub mod storage;
pub mod telemetry;

impl Core {
    pub async fn parse(
        bp: &mut Bootstrap,
        mut stores: Stores,
        config_manager: ConfigManager,
    ) -> Self {
        let mut data = config
            .value_require("storage.data")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error("storage.data", format!("Data store {id:?} not found"));
                    None
                }
            })
            .unwrap_or_default();

        #[cfg(not(feature = "enterprise"))]
        let is_enterprise = false;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let enterprise =
            crate::enterprise::Enterprise::parse(config, &config_manager, &stores, &data).await;

        #[cfg(feature = "enterprise")]
        let is_enterprise = enterprise.is_some();

        #[cfg(feature = "enterprise")]
        if !is_enterprise {
            if data.is_enterprise_store() {
                config
                    .new_build_error("storage.data", "SQL read replicas is an Enterprise feature");
                data = Store::None;
            }
            stores.disable_enterprise_only();
        }
        // SPDX-SnippetEnd

        let mut blob = config
            .value_require("storage.blob")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.blob_stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error("storage.blob", format!("Blob store {id:?} not found"));
                    None
                }
            })
            .unwrap_or_default();
        let mut lookup = config
            .value_require("storage.lookup")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.in_memory_stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error(
                        "storage.lookup",
                        format!("In-memory store {id:?} not found"),
                    );
                    None
                }
            })
            .unwrap_or_default();
        let mut fts = config
            .value_require("storage.fts")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.search_stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error(
                        "storage.fts",
                        format!("Full-text store {id:?} not found"),
                    );
                    None
                }
            })
            .unwrap_or_default();
        let pubsub = Coordinator::None; /*config
        .value("cluster.coordinator")
        .map(|id| id.to_string())
        .and_then(|id| {
        if let Some(store) = stores.pubsub_stores.get(&id) {
        store.clone().into()
        } else {
        config.new_parse_error(
        "cluster.coordinator",
        format!("Coordinator backend {id:?} not found"),
        );
        None
        }
        })
        .unwrap_or_default();*/
        let mut directories =
            Directories::parse(config, &stores, data.clone(), is_enterprise).await;
        let directory = config
            .value_require("storage.directory")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(directory) = directories.directories.get(&id) {
                    directory.clone().into()
                } else {
                    config.new_parse_error(
                        "storage.directory",
                        format!("Directory {id:?} not found"),
                    );
                    None
                }
            })
            .unwrap_or_else(|| Arc::new(Directory::default()));
        directories
            .directories
            .insert("*".to_string(), directory.clone());

        // If any of the stores are missing, disable all stores to avoid data loss
        if matches!(data, Store::None)
            || matches!(&blob.backend, BlobBackend::Store(Store::None))
            || matches!(lookup, InMemoryStore::Store(Store::None))
            || matches!(fts, SearchStore::Store(Store::None))
        {
            data = Store::default();
            blob = BlobStore::default();
            lookup = InMemoryStore::default();
            fts = SearchStore::default();
            config.new_build_error(
                "storage.*",
                "One or more stores are missing, disabling all stores",
            )
        }

        Self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            enterprise,
            // SPDX-SnippetEnd
            sieve: Scripting::parse(bp).await,
            network: Network::parse(bp).await,
            smtp: SmtpConfig::parse(bp).await,
            jmap: JmapConfig::parse(bp).await,
            imap: ImapConfig::parse(bp).await,
            oauth: OAuthConfig::parse(bp).await,
            metrics: Metrics::parse(bp.await),
            spam: SpamFilterConfig::parse(bp).await,
            groupware: GroupwareConfig::parse(bp).await,
            storage: Storage {
                data,
                blob,
                fts,
                lookup,
                pubsub,
                directory,
                directories: directories.directories,
                purge_schedules: stores.purge_schedules,
                stores: stores.stores,
                lookups: stores.in_memory_stores,
                blobs: stores.blob_stores,
                ftss: stores.search_stores,
            },
        }
    }

    pub fn into_shared(self) -> ArcSwap<Self> {
        ArcSwap::from_pointee(self)
    }
}

pub fn build_rsa_keypair(pem: &str) -> Result<RsaKeyPair, String> {
    match rustls_pemfile::read_one(&mut pem.as_bytes()) {
        Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
            RsaKeyPair::from_der(key.secret_pkcs1_der())
                .map_err(|err| format!("Failed to parse PKCS1 RSA key: {err}"))
        }
        Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
            RsaKeyPair::from_pkcs8(key.secret_pkcs8_der())
                .map_err(|err| format!("Failed to parse PKCS8 RSA key: {err}"))
        }
        Err(err) => Err(format!("Failed to read PEM: {err}")),
        Ok(Some(key)) => Err(format!("Unsupported key type: {key:?}")),
        Ok(None) => Err("No RSA key found in PEM".to_string()),
    }
}

pub fn build_ecdsa_pem(
    alg: &'static ring::signature::EcdsaSigningAlgorithm,
    pem: &str,
) -> Result<EcdsaKeyPair, String> {
    match rustls_pemfile::read_one(&mut pem.as_bytes()) {
        Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => EcdsaKeyPair::from_pkcs8(
            alg,
            key.secret_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}")),
        Err(err) => Err(format!("Failed to read PEM: {err}")),
        Ok(Some(key)) => Err(format!("Unsupported key type: {key:?}")),
        Ok(None) => Err("No ECDSA key found in PEM".to_string()),
    }
}
