/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::error::Material;
use crate::api::config::default_config_dir;
use std::{fmt, fs, path::PathBuf, time::SystemTime};

const DEFAULT_CERTIFICATE: &str = "cert.pem";
const DEFAULT_KEY: &str = "key.pem";
const LEGACY_DEFAULT: &str = "fdb.pem";
const DEFAULT_VERIFY_PEERS: &str = "Check.Valid=1";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum TlsMode {
    #[default]
    DefaultFiles,
    Explicit(TlsConfig),
}

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsConfig {
    pub certificate: Option<PemSource>,
    pub key: Option<PemSource>,
    pub key_password: Option<Box<str>>,
    pub ca: Option<PemSource>,
    pub verify_peers: Box<[Box<str>]>,
    pub plaintext: Plaintext,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PemSource {
    Path(PathBuf),
    Pem(Box<[u8]>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Plaintext {
    #[default]
    Allowed,
    Refused,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("certificate", &self.certificate)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field(
                "key_password",
                &self.key_password.as_ref().map(|_| "<redacted>"),
            )
            .field("ca", &self.ca)
            .field("verify_peers", &self.verify_peers)
            .field("plaintext", &self.plaintext)
            .finish()
    }
}

pub(crate) struct Sources {
    pub(crate) certificate: Option<PemSource>,
    pub(crate) key: Option<PemSource>,
    pub(crate) ca: Option<PemSource>,
    pub(crate) password: Option<Box<str>>,
    pub(crate) verify_peers: Box<[Box<str>]>,
    pub(crate) plaintext: Plaintext,
    pub(crate) unpaired: Option<Material>,
}

pub(crate) type Stamps = [Option<(SystemTime, u64)>; 3];

impl Sources {
    pub(crate) fn resolve(config: &TlsConfig) -> Self {
        let unpaired = match (&config.certificate, &config.key) {
            (Some(_), None) => Some(Material::Key),
            (None, Some(_)) => Some(Material::Certificate),
            _ => None,
        };
        Self {
            certificate: config.certificate.clone(),
            key: config.key.clone(),
            unpaired,
            ca: config.ca.clone(),
            password: config
                .key_password
                .clone()
                .filter(|password| !password.is_empty()),
            verify_peers: if config.verify_peers.is_empty() {
                default_verify_peers()
            } else {
                config.verify_peers.clone()
            },
            plaintext: config.plaintext,
        }
    }

    pub(crate) fn default_files() -> Self {
        Self {
            certificate: default_file(DEFAULT_CERTIFICATE),
            key: default_file(DEFAULT_KEY),
            unpaired: None,
            ca: None,
            password: None,
            verify_peers: default_verify_peers(),
            plaintext: Plaintext::Allowed,
        }
    }

    pub(crate) fn stamps(&self) -> Stamps {
        [&self.certificate, &self.key, &self.ca].map(|source| match source {
            Some(PemSource::Path(path)) => fs::metadata(path)
                .ok()
                .and_then(|meta| Some((meta.modified().ok()?, meta.len()))),
            _ => None,
        })
    }
}

fn default_verify_peers() -> Box<[Box<str>]> {
    Box::new([DEFAULT_VERIFY_PEERS.into()])
}

fn default_file(name: &str) -> Option<PemSource> {
    let dir = default_config_dir();
    [name, LEGACY_DEFAULT]
        .into_iter()
        .map(|file| dir.join(file))
        .find(|path| path.is_file())
        .map(PemSource::Path)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/tls/config/tests.rs"]
mod tests;
