/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::bootstrap::Bootstrap;
use registry::schema::structs::{
    FoundationDbCluster, FoundationDbClusterManual, FoundationDbTlsManual, PublicTextOptional,
    SecretKeyEnvironmentVariable, SecretKeyFile, SecretTextOptional,
};
use std::path::PathBuf;
use trc::{Key, StoreEvent};

pub(crate) enum OpenReport<'x> {
    Event,
    Bootstrap(&'x mut Bootstrap),
}

pub(crate) enum ClusterLocation<'x> {
    DefaultFile,
    File(&'x str),
    Manual(&'x FoundationDbClusterManual),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pem {
    Bytes(Box<[u8]>),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManualTls {
    pub(crate) certificate: Option<Pem>,
    pub(crate) key: Option<Pem>,
    pub(crate) password: Option<Box<str>>,
    pub(crate) ca: Option<Pem>,
    pub(crate) verify_peers: Box<[Box<str>]>,
    pub(crate) refuse_plaintext: bool,
}

impl<'x> ClusterLocation<'x> {
    pub(crate) fn new(cluster: &'x FoundationDbCluster) -> Self {
        match cluster {
            FoundationDbCluster::File(file) => match file.path.as_deref() {
                Some(path) if !path.is_empty() => ClusterLocation::File(path),
                _ => ClusterLocation::DefaultFile,
            },
            FoundationDbCluster::Manual(manual) => ClusterLocation::Manual(manual),
        }
    }
}

impl OpenReport<'_> {
    pub(crate) fn opened(&mut self, notice: trc::Error) {
        match self {
            OpenReport::Event => {
                trc::error!(notice);
            }
            OpenReport::Bootstrap(bp) => bp.notices.push(notice),
        }
    }
}

pub(crate) fn cluster_opened(path: Option<String>, connection: Option<String>) -> trc::Error {
    let id = connection
        .as_deref()
        .and_then(|connection| connection.split_once('@'))
        .map(|(key, _)| key.to_string());
    StoreEvent::FoundationdbClusterOpened
        .into_err()
        .ctx_opt(Key::Path, path)
        .ctx_opt(Key::Id, id)
        .ctx_opt(Key::Details, connection)
}

impl ManualTls {
    pub(crate) async fn resolve(config: &FoundationDbTlsManual) -> Result<Self, String> {
        let certificate = public_pem(&config.certificate, "certificate")?;
        let key = secret_pem(&config.private_key)?;
        let password = config
            .private_key_password
            .secret()
            .await
            .map_err(|err| format!("Invalid FoundationDB private key password: {err}"))?
            .map(Box::from);
        match (&certificate, &key) {
            (Some(_), None) => {
                return Err("FoundationDB TLS certificate configured without a private key".into());
            }
            (None, Some(_)) => {
                return Err("FoundationDB TLS private key configured without a certificate".into());
            }
            (None, None) if password.is_some() => {
                return Err(
                    "FoundationDB TLS key password configured without a private key".into(),
                );
            }
            _ => {}
        }
        Ok(ManualTls {
            certificate,
            key,
            password,
            ca: public_pem(&config.ca_certificate, "CA certificate")?,
            verify_peers: config
                .verify_peers
                .iter()
                .map(|rule| Box::from(rule.as_str()))
                .collect(),
            refuse_plaintext: config.disable_plaintext_connection,
        })
    }
}

fn public_pem(value: &PublicTextOptional, material: &str) -> Result<Option<Pem>, String> {
    match value {
        PublicTextOptional::None => Ok(None),
        PublicTextOptional::Text(text) => Ok(Some(Pem::Bytes(text.value.as_bytes().into()))),
        PublicTextOptional::EnvironmentVariable(var) => env_pem(var, material).map(Some),
        PublicTextOptional::File(file) => file_pem(file, material).map(Some),
    }
}

fn secret_pem(value: &SecretTextOptional) -> Result<Option<Pem>, String> {
    match value {
        SecretTextOptional::None => Ok(None),
        SecretTextOptional::Text(text) => Ok(Some(Pem::Bytes(text.secret().as_bytes().into()))),
        SecretTextOptional::EnvironmentVariable(var) => env_pem(var, "private key").map(Some),
        SecretTextOptional::File(file) => file_pem(file, "private key").map(Some),
    }
}

fn env_pem(var: &SecretKeyEnvironmentVariable, material: &str) -> Result<Pem, String> {
    var.secret()
        .map(|value| Pem::Bytes(value.into_bytes().into_boxed_slice()))
        .map_err(|err| format!("Invalid FoundationDB TLS {material}: {err}"))
}

fn file_pem(file: &SecretKeyFile, material: &str) -> Result<Pem, String> {
    let path = file.file_path.trim();
    if path.is_empty() {
        Err(format!(
            "Invalid FoundationDB TLS {material}: file path cannot be empty"
        ))
    } else {
        Ok(Pem::Path(PathBuf::from(path)))
    }
}
