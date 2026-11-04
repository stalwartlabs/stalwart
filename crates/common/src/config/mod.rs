/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Cursor;

use self::{
    mailstore::jmap::JmapConfig, metadata::MetadataConfig, smtp::SmtpConfig, storage::Storage,
};
use crate::{
    Core, Network,
    auth::oauth::config::OAuthConfig,
    config::mailstore::{
        email::EmailConfig, imap::ImapConfig, scripts::Scripting, spamfilter::SpamFilterConfig,
    },
};
use arc_swap::ArcSwap;
use blob::BlobConfig;
use groupware::GroupwareConfig;
use hyper::HeaderMap;
use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::EncodePrivateKey;
use rsa::{
    RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs8::DecodePrivateKey as _,
    traits::PublicKeyParts,
};
use store::registry::bootstrap::Bootstrap;
use telemetry::Metrics;

pub mod blob;
pub mod groupware;
pub mod inner;
pub mod mailstore;
pub mod metadata;
pub mod network;
pub mod resource;
pub mod server;
pub mod smtp;
pub mod storage;
pub mod telemetry;

impl Core {
    pub async fn parse(bp: &mut Bootstrap, storage: Storage) -> Box<Self> {
        Box::pin(Self::build(bp, storage)).await
    }

    async fn build(bp: &mut Bootstrap, storage: Storage) -> Box<Self> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let mut storage = storage;
        #[cfg(feature = "enterprise")]
        let enterprise = {
            let enterprise = crate::enterprise::Enterprise::parse(bp).await;
            if enterprise.is_none() && !bp.registry.is_recovery_mode() {
                use directory::Directory;
                use registry::{
                    schema::{prelude::ObjectType, structs::Authentication},
                    types::id::ObjectId,
                };
                use store::Store;

                if storage.data.is_enterprise() {
                    bp.build_warning(
                        ObjectType::DataStore.singleton(),
                        "Read replicas require an Enterprise licence, using the primary data store only.",
                    );
                    storage.data = storage.data.downgrade_store();
                }
                if storage.blob.is_enterprise() {
                    bp.build_warning(
                        ObjectType::BlobStore.singleton(),
                        "Sharded blob stores require an Enterprise licence, the configured store remains in use.",
                    );
                }
                if storage.memory.is_enterprise() {
                    bp.build_warning(
                        ObjectType::InMemoryStore.singleton(),
                        "Sharded in-memory stores require an Enterprise licence, the configured store remains in use.",
                    );
                }
                if let Some(Directory::Ldap(ldap)) = storage.directory.as_deref()
                    && ldap.has_failover()
                {
                    let object_id = bp
                        .setting_infallible::<Authentication>()
                        .await
                        .directory_id
                        .map_or_else(
                            || ObjectType::Authentication.singleton(),
                            |id| ObjectId::new(ObjectType::Directory, id),
                        );
                    bp.build_warning(
                        object_id,
                        "Disabling enterprise-only LDAP failover servers.",
                    );
                    ldap.disable_failover();
                }
                storage.metrics = Store::None;
                storage.tracing = Store::None;
                storage.directories.clear();
            }
            enterprise
        };
        // SPDX-SnippetEnd

        let metadata = MetadataConfig::parse(bp).await;
        let email = EmailConfig::parse(bp).await;
        let blob = BlobConfig::parse(bp).await;

        Box::new(Self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            enterprise,
            // SPDX-SnippetEnd
            sieve: Scripting::parse(bp, &email.limits).await,
            network: Network::parse(bp).await,
            smtp: SmtpConfig::parse(bp).await,
            jmap: JmapConfig::parse(bp, &metadata).await,
            imap: ImapConfig::parse(bp).await,
            oauth: OAuthConfig::parse(bp).await,
            metrics: Metrics::parse(bp).await,
            spam: SpamFilterConfig::parse(bp).await,
            email,
            groupware: GroupwareConfig::parse(bp).await,
            metadata,
            blob,
            storage,
        })
    }

    pub fn into_shared(self) -> ArcSwap<Self> {
        ArcSwap::from_pointee(self)
    }
}

const RSA_MIN_MODULUS_BITS: usize = 2048;
const RSA_MAX_MODULUS_BITS: usize = 8192;

fn no_key_found(pem: &str, expected: &str) -> String {
    if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
        format!(
            "No usable {expected} private key found in PEM: the key is password-protected, \
             which is not supported. Decrypt it first with 'openssl pkcs8 -topk8 -nocrypt'."
        )
    } else {
        format!("No usable {expected} private key found in PEM")
    }
}

pub struct RsaSigningKey {
    pub pkcs1_der: Vec<u8>,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

pub fn build_rsa_keypair(pem: &str) -> Result<RsaSigningKey, String> {
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        let key = match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            rustls_pemfile::Item::Pkcs1Key(key) => {
                RsaPrivateKey::from_pkcs1_der(key.secret_pkcs1_der())
                    .map_err(|err| format!("Failed to parse PKCS1 RSA key: {err}"))?
            }
            rustls_pemfile::Item::Pkcs8Key(key) => {
                RsaPrivateKey::from_pkcs8_der(key.secret_pkcs8_der())
                    .map_err(|err| format!("Failed to parse PKCS8 RSA key: {err}"))?
            }
            _ => continue,
        };

        let bits = key.n().bits();
        if !(RSA_MIN_MODULUS_BITS..=RSA_MAX_MODULUS_BITS).contains(&bits) {
            return Err(format!(
                "RSA key modulus is {bits} bits, expected between {RSA_MIN_MODULUS_BITS} and {RSA_MAX_MODULUS_BITS}"
            ));
        }

        let pkcs1_der = key
            .to_pkcs1_der()
            .map_err(|err| format!("Failed to encode RSA key as PKCS1: {err}"))?;

        return Ok(RsaSigningKey {
            pkcs1_der: pkcs1_der.as_bytes().to_vec(),
            modulus: key.n().to_bytes_be(),
            exponent: key.e().to_bytes_be(),
        });
    }

    Err(no_key_found(pem, "RSA"))
}

#[derive(Clone, Copy)]
pub enum EcKeyCurve {
    P256,
    P384,
}

pub struct EcdsaSigningKey {
    pub pkcs8_der: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub fn build_ecdsa_pem(curve: EcKeyCurve, pem: &str) -> Result<EcdsaSigningKey, String> {
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        let pkcs8 = match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            rustls_pemfile::Item::Pkcs8Key(key) => key.secret_pkcs8_der().to_vec(),
            rustls_pemfile::Item::Sec1Key(key) => curve
                .sec1_to_pkcs8(key.secret_sec1_der())?
                .as_bytes()
                .to_vec(),
            _ => continue,
        };

        let (x, y) = curve.public_coordinates(&pkcs8)?;

        return Ok(EcdsaSigningKey {
            pkcs8_der: pkcs8,
            x,
            y,
        });
    }

    Err(no_key_found(pem, "ECDSA"))
}

impl EcKeyCurve {
    fn sec1_to_pkcs8(self, der: &[u8]) -> Result<pkcs8::SecretDocument, String> {
        match self {
            EcKeyCurve::P256 => p256::SecretKey::from_sec1_der(der)
                .map_err(|err| format!("Failed to parse SEC1 ECDSA key: {err}"))?
                .to_pkcs8_der()
                .map_err(|err| format!("Failed to convert SEC1 ECDSA key to PKCS8: {err}")),
            EcKeyCurve::P384 => p384::SecretKey::from_sec1_der(der)
                .map_err(|err| format!("Failed to parse SEC1 ECDSA key: {err}"))?
                .to_pkcs8_der()
                .map_err(|err| format!("Failed to convert SEC1 ECDSA key to PKCS8: {err}")),
        }
    }

    fn public_coordinates(self, pkcs8: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        use pkcs8::DecodePrivateKey;

        match self {
            EcKeyCurve::P256 => {
                let point = p256::SecretKey::from_pkcs8_der(pkcs8)
                    .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}"))?
                    .public_key()
                    .to_sec1_point(false);
                Ok((
                    point.x().map(|x| x.to_vec()).unwrap_or_default(),
                    point.y().map(|y| y.to_vec()).unwrap_or_default(),
                ))
            }
            EcKeyCurve::P384 => {
                let point = p384::SecretKey::from_pkcs8_der(pkcs8)
                    .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}"))?
                    .public_key()
                    .to_sec1_point(false);
                Ok((
                    point.x().map(|x| x.to_vec()).unwrap_or_default(),
                    point.y().map(|y| y.to_vec()).unwrap_or_default(),
                ))
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/config/tests.rs"]
mod tests;
