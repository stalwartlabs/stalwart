/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::oauth::client::RequestOrigin;
use http_proto::{HttpRequest, HttpSessionData, request::fetch_body};
use hyper::header::{CONTENT_TYPE, HOST};
use serde::{Deserialize, Serialize};
use utils::map::vec_map::VecMap;

pub mod auth;
pub mod authorize;
pub mod logout;
pub mod openid;
pub mod registration;
pub mod token;

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
)]
#[rkyv(compare(PartialEq))]
pub enum OAuthStatus {
    Authorized,
    TokenIssued,
    Pending,
    Denied,
    ConsentPending,
}

const MAX_POST_LEN: usize = 2048;
pub(crate) const TOKEN_ENDPOINT_AUTH_METHODS: &[&str] =
    &["none", "client_secret_post", "client_secret_basic"];

pub struct OAuth {
    pub key: String,
    pub expiry_user_code: u64,
    pub expiry_auth_code: u64,
    pub expiry_token: u64,
    pub expiry_refresh_token: u64,
    pub expiry_refresh_token_renew: u64,
    pub max_auth_attempts: u32,
    pub metadata: String,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct OAuthCode {
    pub status: OAuthStatus,
    pub account_id: u32,
    pub credential_version: u64,
    pub client_id: String,
    pub nonce: Option<String>,
    pub params: String,
    pub code_challenge: PkceCodeChallenge,
    pub scope: Option<String>,
}

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
)]
#[rkyv(compare(PartialEq))]
pub enum PkceCodeChallenge {
    None,
    S256(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthGet {
    code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthPost {
    code: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthRequest {
    client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeAuthRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeAuthForm {
    code: String,
    email: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub device_code: Option<String>,
    pub client_id: Option<String>,
    pub refresh_token: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenResponse {
    Granted(OAuthResponse),
    Error { error: ErrorType },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorType {
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
    #[serde(rename = "invalid_client")]
    InvalidClient,
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,
    #[serde(rename = "authorization_pending")]
    AuthorizationPending,
    #[serde(rename = "slow_down")]
    SlowDown,
    #[serde(rename = "access_denied")]
    AccessDenied,
    #[serde(rename = "expired_token")]
    ExpiredToken,
    #[serde(rename = "invalid_target")]
    InvalidTarget,
    #[serde(rename = "unsupported_response_type")]
    UnsupportedResponseType,
}

impl ErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorType::InvalidGrant => "invalid_grant",
            ErrorType::InvalidClient => "invalid_client",
            ErrorType::InvalidScope => "invalid_scope",
            ErrorType::InvalidRequest => "invalid_request",
            ErrorType::UnauthorizedClient => "unauthorized_client",
            ErrorType::UnsupportedGrantType => "unsupported_grant_type",
            ErrorType::AuthorizationPending => "authorization_pending",
            ErrorType::SlowDown => "slow_down",
            ErrorType::AccessDenied => "access_denied",
            ErrorType::ExpiredToken => "expired_token",
            ErrorType::InvalidTarget => "invalid_target",
            ErrorType::UnsupportedResponseType => "unsupported_response_type",
        }
    }
}

impl TokenResponse {
    pub fn error(error: ErrorType) -> Self {
        TokenResponse::Error { error }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, TokenResponse::Error { .. })
    }
}

#[derive(Debug)]
pub struct FormData {
    fields: VecMap<String, String>,
}

impl FormData {
    pub async fn from_request(
        req: &mut HttpRequest,
        max_len: usize,
        session_id: u64,
    ) -> trc::Result<Self> {
        match (
            req.headers()
                .get(CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .and_then(|val| val.parse::<mime::Mime>().ok()),
            fetch_body(req, max_len, session_id).await,
        ) {
            (Some(content_type), Some(body)) => {
                let mut fields = VecMap::new();
                if let Some(boundary) = content_type.get_param(mime::BOUNDARY) {
                    for mut field in
                        form_data::FormData::new(&body[..], boundary.as_str()).flatten()
                    {
                        let value = String::from_utf8_lossy(&field.bytes().unwrap_or_default())
                            .into_owned();
                        fields.append(field.name, value);
                    }
                } else {
                    for (key, value) in http_proto::form_urlencoded::parse(&body) {
                        fields.append(key.into_owned(), value.into_owned());
                    }
                }
                Ok(FormData { fields })
            }
            _ => Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("Invalid post request")),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|v| v.as_str())
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.fields.remove(key)
    }

    pub fn has_field(&self, key: &str) -> bool {
        self.fields.get(key).is_some_and(|v| !v.is_empty())
    }

    pub fn fields(&self) -> impl Iterator<Item = (&String, &String)> {
        self.fields.iter()
    }
}

pub fn request_origin<'x>(req: &'x HttpRequest, session: &HttpSessionData) -> RequestOrigin<'x> {
    RequestOrigin {
        is_tls: session.is_tls,
        authority: req
            .headers()
            .get(HOST)
            .and_then(|host| host.to_str().ok())
            .or_else(|| req.uri().authority().map(|authority| authority.as_str()))
            .unwrap_or_default(),
    }
}

impl store::write::ArchiveCompression for OAuthCode {
    const COMPRESSION: store::write::Compression = store::write::Compression::None;
}
