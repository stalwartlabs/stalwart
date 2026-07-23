/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod account;
pub mod directory;
pub mod http;
pub mod jose;
pub mod order;
pub mod renew;
pub mod resolver;

use crate::network::dns::update::DnsUpdater;
use chrono::{DateTime, Utc};
use registry::schema::enums::AcmeChallengeType;
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};
use store::registry::write::RegistryWriteResult;

pub type AcmeResult<T> = Result<T, AcmeError>;

pub enum AcmeError {
    Http(reqwest::Error),
    HttpStatus(String),
    Json(serde_json::Error),
    Crypto(String),
    Invalid(String),
    NotDue(String),
    Dns(String),
    AuthInvalid(String),
    OrderInvalid(String),
    ChallengeNotSupported {
        requested: ChallengeType,
        supported: Vec<Challenge>,
    },
    Internal(trc::Error),
    Registry(RegistryWriteResult),
    OrderTimeout {
        max_retries: u32,
    },
    AuthTimeout {
        max_retries: u32,
    },
    Backoff {
        max_retries: u32,
        wait: Option<Duration>,
    },
}

#[derive(
    rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, Clone, serde::Serialize, Deserialize,
)]
pub struct SerializedCert {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct PemCert {
    pub certificate: String,
    pub private_key: String,
}

pub struct ParsedCert {
    pub sans: Vec<String>,
    pub issuer: String,
    pub valid_not_before: DateTime<Utc>,
    pub valid_not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone, Copy)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "dns-persist-01")]
    DnsPersist01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    #[serde(flatten)]
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub error: Option<Problem>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Valid { certificate: String },
    Invalid,
    Processing,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub status: AuthStatus,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
    Deactivated,
}

pub struct AcmeDnsParameters {
    pub updater: DnsUpdater,
    pub origin: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    pub url: String,
    pub token: Option<String>,
    pub error: Option<Problem>,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub detail: Option<String>,
}

pub struct StaticResolver {
    pub key: Option<Arc<CertifiedKey>>,
}

impl Debug for StaticResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticResolver").finish()
    }
}

impl From<reqwest::Error> for AcmeError {
    fn from(err: reqwest::Error) -> Self {
        AcmeError::Http(err)
    }
}

impl From<serde_json::Error> for AcmeError {
    fn from(err: serde_json::Error) -> Self {
        AcmeError::Json(err)
    }
}

impl From<trc::Error> for AcmeError {
    fn from(err: trc::Error) -> Self {
        AcmeError::Internal(err)
    }
}

impl From<AcmeChallengeType> for ChallengeType {
    fn from(value: AcmeChallengeType) -> Self {
        match value {
            AcmeChallengeType::Http01 => ChallengeType::Http01,
            AcmeChallengeType::Dns01 => ChallengeType::Dns01,
            AcmeChallengeType::TlsAlpn01 => ChallengeType::TlsAlpn01,
            AcmeChallengeType::DnsPersist01 => ChallengeType::DnsPersist01,
        }
    }
}

impl Display for AuthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthStatus::Pending => write!(f, "pending"),
            AuthStatus::Valid => write!(f, "valid"),
            AuthStatus::Invalid => write!(f, "invalid"),
            AuthStatus::Revoked => write!(f, "revoked"),
            AuthStatus::Expired => write!(f, "expired"),
            AuthStatus::Deactivated => write!(f, "deactivated"),
        }
    }
}

impl Auth {
    pub fn into_error(self) -> String {
        let mut errors = format!("Status: {}", self.status);
        for challenge in self.challenges {
            if let Some(error) = challenge.error {
                errors.push_str(&format!(
                    "; Challenge type: {}, error: {}",
                    challenge.typ.as_str(),
                    error
                ));
            }
        }

        errors
    }
}

impl Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(typ) = &self.typ {
            if let Some(detail) = &self.detail {
                write!(f, "{}: {}", typ, detail)
            } else {
                write!(f, "{}", typ)
            }
        } else if let Some(detail) = &self.detail {
            write!(f, "{}", detail)
        } else {
            write!(f, "Unknown error")
        }
    }
}

impl Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Http(err) => write!(f, "HTTP error: {}", err),
            AcmeError::HttpStatus(status) => write!(f, "HTTP error: {}", status),
            AcmeError::Json(err) => write!(f, "JSON error: {}", err),
            AcmeError::Dns(err) => write!(f, "DNS error: {}", err),
            AcmeError::Crypto(err) => write!(f, "Cryptographic error: {}", err),
            AcmeError::Invalid(err) => write!(f, "Invalid request: {}", err),
            AcmeError::NotDue(err) => write!(f, "{}", err),
            AcmeError::AuthInvalid(status) => write!(f, "Authentication failed: {:?}", status),
            AcmeError::OrderTimeout { .. } => write!(f, "Order processing timed out"),
            AcmeError::OrderInvalid(reason) => write!(f, "Order is invalid: {}", reason),
            AcmeError::AuthTimeout { .. } => write!(f, "Authentication timed out"),
            AcmeError::ChallengeNotSupported {
                requested,
                supported,
            } => {
                write!(
                    f,
                    "Challenge type {:?} not supported. Supported types: {:?}",
                    requested, supported
                )
            }
            AcmeError::Internal(err) => write!(f, "Internal error: {}", err),
            AcmeError::Registry(err) => write!(f, "Registry error: {:?}", err),
            AcmeError::Backoff { wait, .. } => {
                if let Some(time) = wait {
                    write!(f, "Rate limited. Retry after {} seconds", time.as_secs())
                } else {
                    write!(f, "Rate limited. Retry after some time")
                }
            }
        }
    }
}
