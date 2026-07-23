/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Cursor;

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
use pkcs8::EncodePrivateKey;
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
            if enterprise.is_none() && !bp.registry.is_recovery_mode() {
                use registry::schema::prelude::ObjectType;
                use store::Store;

                if storage.data.is_enterprise() {
                    bp.build_error(
                        ObjectType::DataStore.singleton(),
                        "Disabling enterprise-only data store.",
                    );
                    storage.data = storage.data.downgrade_store();
                }
                if storage.blob.is_enterprise() {
                    bp.build_error(
                        ObjectType::BlobStore.singleton(),
                        "Disabling enterprise-only blob store.",
                    );
                    storage.blob = storage.blob.downgrade_store();
                }
                if storage.memory.is_enterprise() {
                    bp.build_error(
                        ObjectType::InMemoryStore.singleton(),
                        "Disabling enterprise-only in-memory store.",
                    );
                    storage.memory = storage.memory.downgrade_store();
                }
                storage.metrics = Store::None;
                storage.tracing = Store::None;
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
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            rustls_pemfile::Item::Pkcs1Key(key) => {
                return RsaKeyPair::from_der(key.secret_pkcs1_der())
                    .map_err(|err| format!("Failed to parse PKCS1 RSA key: {err}"));
            }
            rustls_pemfile::Item::Pkcs8Key(key) => {
                return RsaKeyPair::from_pkcs8(key.secret_pkcs8_der())
                    .map_err(|err| format!("Failed to parse PKCS8 RSA key: {err}"));
            }
            _ => continue, // Skip certificates, DH params, etc.
        }
    }

    Err("No RSA key found in PEM".to_string())
}

#[derive(Clone, Copy)]
pub enum EcKeyCurve {
    P256,
    P384,
}

pub fn build_ecdsa_pem(
    alg: &'static ring::signature::EcdsaSigningAlgorithm,
    curve: EcKeyCurve,
    pem: &str,
) -> Result<EcdsaKeyPair, String> {
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            rustls_pemfile::Item::Pkcs8Key(key) => {
                return EcdsaKeyPair::from_pkcs8(
                    alg,
                    key.secret_pkcs8_der(),
                    &ring::rand::SystemRandom::new(),
                )
                .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}"));
            }
            rustls_pemfile::Item::Sec1Key(key) => {
                let pkcs8 = curve.sec1_to_pkcs8(key.secret_sec1_der())?;
                return EcdsaKeyPair::from_pkcs8(
                    alg,
                    pkcs8.as_bytes(),
                    &ring::rand::SystemRandom::new(),
                )
                .map_err(|err| format!("Failed to parse SEC1 ECDSA key: {err}"));
            }
            _ => continue, // Skip certificates, DH params, etc.
        }
    }

    Err("No usable ECDSA private key found in PEM (expected PKCS8 or SEC1)".to_string())
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
}

#[cfg(test)]
mod tests {
    use super::{EcKeyCurve, build_ecdsa_pem};
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING};

    const P256_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ9a6n/cu7XaQez5ZX8z8jDFkkfsMB1P9Vbqzbaes2zOoAoGCCqGSM49
AwEHoUQDQgAEPCbID7bo+8Nk1vIsTFhVKwRWvb9GWTzzwS75Dd8iZuFl23Twn6Sp
V2ZO1FC0WyXxcVOMZN2sJFlCjtaQS+p5Zg==
-----END EC PRIVATE KEY-----";

    const P256_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn1rqf9y7tdpB7Pll
fzPyMMWSR+wwHU/1VurNtp6zbM6hRANCAAQ8JsgPtuj7w2TW8ixMWFUrBFa9v0ZZ
PPPBLvkN3yJm4WXbdPCfpKlXZk7UULRbJfFxU4xk3awkWUKO1pBL6nlm
-----END PRIVATE KEY-----";

    const P384_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAeecJf8ju/70Nf5nbI4DeRo/+Z3VWXUvB+GwuUczew7fyMbyc6B3EE
BskOIqvqu6egBwYFK4EEACKhZANiAAQQjDW03Xn2h9ZmmCMRx+uRaLLfg4o2XITE
pwACH9EY4IjTe9LNNp5CTjERd+RlpWxkYopmDS5Trzycz9sDxxSzzXmq90vomJqt
fTnNHPFHuR2SAiwuzUf26rcPwa7DCWk=
-----END EC PRIVATE KEY-----";

    const P384_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAeecJf8ju/70Nf5nbI
4DeRo/+Z3VWXUvB+GwuUczew7fyMbyc6B3EEBskOIqvqu6ehZANiAAQQjDW03Xn2
h9ZmmCMRx+uRaLLfg4o2XITEpwACH9EY4IjTe9LNNp5CTjERd+RlpWxkYopmDS5T
rzycz9sDxxSzzXmq90vomJqtfTnNHPFHuR2SAiwuzUf26rcPwa7DCWk=
-----END PRIVATE KEY-----";

    #[test]
    fn ecdsa_pem_accepts_sec1_and_pkcs8() {
        build_ecdsa_pem(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            EcKeyCurve::P256,
            P256_SEC1,
        )
        .expect("P-256 SEC1 key should parse");
        build_ecdsa_pem(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            EcKeyCurve::P256,
            P256_PKCS8,
        )
        .expect("P-256 PKCS8 key should parse");
        build_ecdsa_pem(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            EcKeyCurve::P384,
            P384_SEC1,
        )
        .expect("P-384 SEC1 key should parse");
        build_ecdsa_pem(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            EcKeyCurve::P384,
            P384_PKCS8,
        )
        .expect("P-384 PKCS8 key should parse");
    }

    #[test]
    fn ecdsa_pem_rejects_keyless_pem() {
        let err = build_ecdsa_pem(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            EcKeyCurve::P256,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        )
        .unwrap_err();
        assert!(err.contains("No usable ECDSA private key"), "{err}");
    }
}
