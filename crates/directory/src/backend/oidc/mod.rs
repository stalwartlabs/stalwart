/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Account;
use ahash::AHashMap;
use jsonwebtoken::{DecodingKey, Validation};
use parking_lot::RwLock;
use registry::schema::enums::OidcUnscopedTokenPolicy;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use utils::{
    HttpLimitResponse,
    outbound::{OutboundClient, OutboundPolicy},
};

pub mod config;
pub mod jwks;
pub mod lookup;

pub const OPENID_CONFIGURATION_PATH: &str = "/.well-known/openid-configuration";
pub const OAUTH_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

pub(crate) const METADATA_MAX_SIZE: usize = 256 * 1024;
pub(crate) const CLAIMS_MAX_SIZE: usize = 64 * 1024;
pub(crate) const ERROR_MAX_SIZE: usize = 512;

pub(crate) async fn read_body(
    response: reqwest::Response,
    limit: usize,
    what: &str,
) -> Result<Vec<u8>, OidcError> {
    match response.bytes_with_limit(limit).await {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(OidcError::Provider(format!(
            "{what} response exceeds {limit} bytes"
        ))),
        Err(err) => Err(OidcError::Network(format!("{what} request failed: {err}"))),
    }
}

pub fn openid_configuration_url(issuer: &str) -> String {
    let issuer = issuer.trim_end_matches('/');
    let mut url = String::with_capacity(issuer.len() + OPENID_CONFIGURATION_PATH.len());
    url.push_str(issuer);
    url.push_str(OPENID_CONFIGURATION_PATH);
    url
}

pub struct OidcConfig {
    pub issuer_url: String,
    pub claim_username: String,
    pub claim_name: Option<String>,
    pub claim_groups: Option<String>,
    pub username_domain: Option<String>,
    pub allow_invalid_certs: bool,
    pub outbound_policy: OutboundPolicy,
    pub accepted_audiences: Box<[Box<str>]>,
    pub opaque_validation: OpaqueValidation,
    pub unscoped_tokens: OidcUnscopedTokenPolicy,
    pub skip_audience_validation: bool,
    pub allow_id_token_claims: bool,
    pub lenient_issuer_match: bool,
}

pub enum OpaqueValidation {
    Reject,
    UserInfo,
    Introspection(IntrospectionAuth),
}

pub enum IntrospectionAuth {
    Basic { authorization: Box<str> },
    Post { credentials: Box<str> },
    Unauthenticated,
}

pub struct OidcDiscovery {
    pub document: DiscoveryDocument,
    pub metadata_url: String,
    pub conformance: Conformance,
    pub web_document: Arc<[u8]>,
}

impl OidcDiscovery {
    pub fn configuration_url(&self) -> &str {
        &self.metadata_url
    }
}

#[derive(Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_metadata_document_supported: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Conformance {
    pub gaps: ConformanceGaps,
    pub scopes: ExternalScopes,
}

impl Conformance {
    pub fn serves_oauth_public(&self, required: ExternalScopes) -> bool {
        self.gaps.is_empty() && self.scopes.contains(required)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConformanceGaps(u16);

impl ConformanceGaps {
    pub const ISSUER: Self = Self(1 << 0);
    pub const CONTENT_TYPE: Self = Self(1 << 1);
    pub const REGISTRATION_ENDPOINT: Self = Self(1 << 2);
    pub const AUTHORIZATION_ENDPOINT: Self = Self(1 << 3);
    pub const TOKEN_ENDPOINT: Self = Self(1 << 4);
    pub const RESPONSE_TYPE_CODE: Self = Self(1 << 5);
    pub const GRANT_TYPES: Self = Self(1 << 6);
    pub const AUTH_METHOD_NONE: Self = Self(1 << 7);
    pub const PKCE_S256: Self = Self(1 << 8);
    pub const ISS_PARAMETER: Self = Self(1 << 9);

    const NAMES: [(Self, &'static str); 10] = [
        (Self::ISSUER, "issuer is not a valid https identifier"),
        (
            Self::CONTENT_TYPE,
            "metadata is not served as application/json",
        ),
        (Self::REGISTRATION_ENDPOINT, "registration_endpoint"),
        (Self::AUTHORIZATION_ENDPOINT, "authorization_endpoint"),
        (Self::TOKEN_ENDPOINT, "token_endpoint"),
        (Self::RESPONSE_TYPE_CODE, "response_types_supported: code"),
        (
            Self::GRANT_TYPES,
            "grant_types_supported: authorization_code, refresh_token",
        ),
        (
            Self::AUTH_METHOD_NONE,
            "token_endpoint_auth_methods_supported: none",
        ),
        (Self::PKCE_S256, "code_challenge_methods_supported: S256"),
        (
            Self::ISS_PARAMETER,
            "authorization_response_iss_parameter_supported",
        ),
    ];

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn insert(&mut self, gap: Self) {
        self.0 |= gap.0;
    }

    pub fn contains(self, gap: Self) -> bool {
        self.0 & gap.0 == gap.0
    }

    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(gap, _)| self.contains(*gap))
            .map(|(_, name)| name)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExternalScopes(u8);

impl ExternalScopes {
    pub const NONE: Self = Self(0);
    pub const MAIL: Self = Self(1 << 0);
    pub const CONTACTS: Self = Self(1 << 1);
    pub const CALENDARS: Self = Self(1 << 2);
    pub const FILES: Self = Self(1 << 3);
    pub const SECURITY: Self = Self(1 << 4);
    pub const SETTINGS: Self = Self(1 << 5);
    pub const FULL: Self = Self(1 << 6);
    pub const ALL: Self = Self(Self::MAIL.0 | Self::CONTACTS.0 | Self::CALENDARS.0 | Self::FILES.0);

    const NAMES: [(Self, &'static str); 4] = [
        (Self::MAIL, "urn:ietf:params:oauth:scope:mail"),
        (Self::CONTACTS, "urn:ietf:params:oauth:scope:contacts"),
        (Self::CALENDARS, "urn:ietf:params:oauth:scope:calendars"),
        (Self::FILES, "urn:ietf:params:oauth:scope:files"),
    ];

    pub fn from_name(name: &str) -> Self {
        hashify::map!(
            name.as_bytes(),
            ExternalScopes,
            "urn:ietf:params:oauth:scope:mail" => ExternalScopes::MAIL,
            "urn:ietf:params:oauth:scope:contacts" => ExternalScopes::CONTACTS,
            "urn:ietf:params:oauth:scope:calendars" => ExternalScopes::CALENDARS,
            "urn:ietf:params:oauth:scope:files" => ExternalScopes::FILES,
            "urn:stalwart:oauth:scope:security" => ExternalScopes::SECURITY,
            "urn:stalwart:oauth:scope:settings" => ExternalScopes::SETTINGS,
            "urn:stalwart:oauth:scope:full" => ExternalScopes::FULL,
        )
        .copied()
        .unwrap_or_default()
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn insert(&mut self, scopes: Self) {
        self.0 |= scopes.0;
    }

    pub fn contains(self, scopes: Self) -> bool {
        self.0 & scopes.0 == scopes.0
    }

    pub fn difference(self, scopes: Self) -> Self {
        Self(self.0 & !scopes.0)
    }

    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(scope, _)| self.contains(*scope))
            .map(|(_, name)| name)
    }
}

pub struct TokenContext<'x> {
    pub is_resource: &'x (dyn Fn(&str) -> bool + Sync),
    pub is_first_party: &'x (dyn Fn(&str) -> bool + Sync),
}

pub struct ExternalToken {
    pub account: Account,
    pub access: TokenAccess,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAccess {
    Unrestricted,
    Scoped(ExternalScopes),
}

pub(crate) struct CachedKey {
    decoding_key: DecodingKey,
    validation: Validation,
}

pub(crate) struct KeySet {
    keys: AHashMap<Box<str>, CachedKey>,
}

struct JwksState {
    keys: Arc<KeySet>,
    fetched_at: Instant,
    attempted_at: Instant,
    max_age: Duration,
}

pub struct OpenIdDirectory {
    config: OidcConfig,
    pub discovery: OidcDiscovery,
    issuers: Box<[String]>,
    http: OutboundClient,
    jwks: RwLock<JwksState>,
    jwks_refresh: tokio::sync::Mutex<()>,
}

#[derive(Debug)]
pub enum OidcError {
    TokenValidation(String),
    TokenExpired(String),
    AuthorizationFailed(String),
    Network(String),
    Provider(String),
    Config(String),
}

impl OidcError {
    pub fn is_transient(&self) -> bool {
        matches!(self, OidcError::Network(_) | OidcError::Provider(_))
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcError::TokenValidation(msg) => write!(f, "Token validation error: {msg}"),
            OidcError::TokenExpired(msg) => write!(f, "Token expired: {msg}"),
            OidcError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {msg}"),
            OidcError::Network(msg) => write!(f, "Network error: {msg}"),
            OidcError::Provider(msg) => write!(f, "Provider error: {msg}"),
            OidcError::Config(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for OidcError {}
