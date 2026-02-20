/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::{mailstore::jmap::JmapConfig, smtp::SmtpConfig, storage::Storage};
use crate::{
    Core, Network,
    auth::oauth::config::OAuthConfig,
    config::mailstore::{
        email::EmailConfig, imap::ImapConfig, scripts::Scripting, spamfilter::SpamFilterConfig,
    },
};
use arc_swap::ArcSwap;
use groupware::GroupwareConfig;
use hyper::HeaderMap;
use ring::signature::{EcdsaKeyPair, RsaKeyPair};
use store::registry::bootstrap::Bootstrap;
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
    pub async fn parse(bp: &mut Bootstrap, mut storage: Storage) -> Self {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let enterprise = {
            let enterprise = crate::enterprise::Enterprise::parse(bp).await;
            if enterprise.is_none() {
                use registry::schema::prelude::Object;
                use store::Store;

                if storage.data.is_enterprise() {
                    bp.build_error(
                        Object::DataStore.singleton(),
                        "Disabling enterprise-only data store.",
                    );
                    storage.data = storage.data.downgrade_store();
                }
                if storage.blob.is_enterprise() {
                    bp.build_error(
                        Object::BlobStore.singleton(),
                        "Disabling enterprise-only blob store.",
                    );
                    storage.blob = storage.blob.downgrade_store();
                }
                if storage.memory.is_enterprise() {
                    bp.build_error(
                        Object::InMemoryStore.singleton(),
                        "Disabling enterprise-only in-memory store.",
                    );
                    storage.memory = storage.memory.downgrade_store();
                }
                storage.metrics = Store::None;
                storage.metrics = Store::None;
                storage.directories.clear();
            }
            enterprise
        };
        // SPDX-SnippetEnd

        Self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            enterprise,
            // SPDX-SnippetEnd
            sieve: Scripting::parse(bp).await,
            network: Network::parse(bp).await,
            smtp: Box::pin(SmtpConfig::parse(bp)).await,
            jmap: JmapConfig::parse(bp).await,
            imap: ImapConfig::parse(bp).await,
            oauth: OAuthConfig::parse(bp).await,
            metrics: Metrics::parse(bp).await,
            spam: SpamFilterConfig::parse(bp).await,
            email: EmailConfig::parse(bp).await,
            groupware: GroupwareConfig::parse(bp).await,
            storage,
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
