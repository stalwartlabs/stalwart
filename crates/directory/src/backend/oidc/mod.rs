/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use utils::Client;

pub mod config;
pub mod lookup;

pub struct OidcConfig {
    pub issue_url: String,
    pub require_aud: Option<String>,
    pub require_scopes: Vec<String>,
    pub claim_email: String,
    pub claim_name: Option<String>,
    pub claim_groups: Option<String>,
    pub default_domain: Option<String>,
}

pub struct OidcDiscovery {
    pub url: String,
    pub document: DiscoveryDocument,
}

#[derive(Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

struct CachedKey {
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

struct JwksCache {
    keys: AHashMap<String, Arc<CachedKey>>,
    last_updated: Instant,
}

pub struct OpenIdDirectory {
    config: OidcConfig,
    pub discovery: OidcDiscovery,
    http: Client,
    cache: RwLock<JwksCache>,
}

#[derive(Debug)]
pub enum OidcError {
    TokenValidation(String),
    AuthorizationFailed(String),
    Network(String),
    Provider(String),
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcError::TokenValidation(msg) => write!(f, "Token validation error: {msg}"),
            OidcError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {msg}"),
            OidcError::Network(msg) => write!(f, "Network error: {msg}"),
            OidcError::Provider(msg) => write!(f, "Provider error: {msg}"),
        }
    }
}

impl std::error::Error for OidcError {}
