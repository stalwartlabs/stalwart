/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    registration::{check_client_name, is_https_url, loopback_redirect_parts},
    scope::OAuthScopes,
};
use crate::{KV_OAUTH_CIMD, KV_RATE_LIMIT_CIMD, Server, USER_AGENT};
use registry::schema::{enums::OAuthClientMetadataPolicy, prelude::Duration, structs::Rate};
use reqwest::{
    Method, StatusCode, Url,
    header::{ACCEPT, CACHE_CONTROL},
};
use serde::{Deserialize, de::IgnoredAny};
use std::time::Duration as StdDuration;
use store::{
    Serialize,
    dispatch::lookup::KeyValue,
    write::{Archive, ArchiveBytes, Archiver},
};
use trc::{AddContext, AuthEvent};
use utils::{
    HttpLimitResponse, error_chain,
    http::http_client_builder,
    outbound::{OutboundClient, OutboundError, OutboundPolicy, Redirects},
};

pub const CIMD_MAX_DOCUMENT_SIZE: usize = 5 * 1024;
const CIMD_FETCH_TIMEOUT: StdDuration = StdDuration::from_secs(5);
const CIMD_MIN_TTL: u64 = 5 * 60;
const CIMD_MAX_TTL: u64 = 24 * 60 * 60;
const CIMD_MAX_REDIRECT_URIS: usize = 16;
const CIMD_MAX_REDIRECT_URI_LEN: usize = 2048;
const CIMD_DOMAIN_RATE: Rate = Rate {
    count: 30,
    period: Duration(StdDuration::from_secs(60)),
};

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, Clone, PartialEq, Eq)]
pub struct CimdClient {
    pub client_host: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: OAuthScopes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CimdError {
    Disabled,
    InvalidUrl(&'static str),
    DomainNotAllowed,
    Outbound(OutboundError),
    Fetch,
    Status(u16),
    TooLarge,
    InvalidDocument(&'static str),
}

#[derive(Deserialize)]
struct CimdDocument {
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    client_secret: Option<IgnoredAny>,
    #[serde(default)]
    client_secret_expires_at: Option<IgnoredAny>,
    #[serde(default)]
    jwks: Option<serde_json::Value>,
}

impl Server {
    pub fn check_cimd_policy(&self, client_id: &str) -> Result<Url, CimdError> {
        cimd_policy_allows(
            self.core.oauth.client_metadata_documents,
            client_id,
            self.core.network.resources.registrable_domain.as_deref(),
        )
    }

    pub async fn cimd_client(
        &self,
        client_id: &str,
        url: Url,
    ) -> trc::Result<Result<CimdClient, CimdError>> {
        if let Some(stored) = self
            .in_memory_store()
            .key_get::<Archive<ArchiveBytes>>(KeyValue::<()>::build_key(
                KV_OAUTH_CIMD,
                client_id.as_bytes(),
            ))
            .await
            .caused_by(trc::location!())?
            && let Ok(client) = stored.deserialize::<CimdClient>()
        {
            return Ok(Ok(client));
        }

        let host = url.host_str().unwrap_or_default();
        let domain = psl::domain_str(host).unwrap_or(host);
        if let Some(reset) = self
            .core
            .storage
            .memory
            .is_rate_allowed(KV_RATE_LIMIT_CIMD, domain.as_bytes(), &CIMD_DOMAIN_RATE)
            .await
            .caused_by(trc::location!())?
        {
            return Err(trc::LimitEvent::TooManyRequests
                .into_err()
                .ctx(trc::Key::Expires, reset)
                .ctx(trc::Key::Limit, CIMD_DOMAIN_RATE.count)
                .details("Too many client metadata document fetches for this domain"));
        }

        let client_host = host.to_string();
        let (body, ttl) = match fetch_cimd_document(url).await {
            Ok(result) => result,
            Err(err) => return Ok(Err(err)),
        };
        let client = match validate_cimd_document(client_id, client_host, &body) {
            Ok(client) => client,
            Err(err) => return Ok(Err(err)),
        };

        let value = Archiver::new(client.clone())
            .untrusted()
            .serialize()
            .caused_by(trc::location!())?;
        self.in_memory_store()
            .key_set(KeyValue::with_prefix(KV_OAUTH_CIMD, client_id.as_bytes(), value).expires(ttl))
            .await
            .caused_by(trc::location!())?;

        Ok(Ok(client))
    }
}

pub fn cimd_policy_allows(
    policy: OAuthClientMetadataPolicy,
    client_id: &str,
    registrable_domain: Option<&str>,
) -> Result<Url, CimdError> {
    match policy {
        OAuthClientMetadataPolicy::Disabled => Err(CimdError::Disabled),
        OAuthClientMetadataPolicy::SameDomain => {
            let url = check_cimd_url(client_id)?;
            if registrable_domain.is_some_and(|expected| {
                url.host_str()
                    .and_then(psl::domain_str)
                    .is_some_and(|domain| domain.eq_ignore_ascii_case(expected))
            }) {
                Ok(url)
            } else {
                Err(CimdError::DomainNotAllowed)
            }
        }
        OAuthClientMetadataPolicy::Any => check_cimd_url(client_id),
    }
}

pub fn check_cimd_url(client_id: &str) -> Result<Url, CimdError> {
    let rest = client_id
        .strip_prefix("https://")
        .ok_or(CimdError::InvalidUrl("Client id must use the https scheme"))?;
    if client_id.contains(['#', '\\']) {
        return Err(CimdError::InvalidUrl(
            "Client id must not contain a fragment",
        ));
    }
    if client_id.contains('?') {
        return Err(CimdError::InvalidUrl(
            "Client id must not contain a query component",
        ));
    }
    let (authority, path) = rest
        .split_once('/')
        .ok_or(CimdError::InvalidUrl("Client id must contain a path"))?;
    if authority.is_empty() || authority.contains('@') {
        return Err(CimdError::InvalidUrl(
            "Client id must not contain a userinfo component",
        ));
    }
    if path.split('/').any(is_dot_segment) {
        return Err(CimdError::InvalidUrl(
            "Client id must not contain dot path segments",
        ));
    }

    let url = Url::parse(client_id).map_err(|_| CimdError::InvalidUrl("Invalid client id URL"))?;
    if url.domain().is_some_and(|domain| !domain.is_empty()) {
        Ok(url)
    } else {
        Err(CimdError::InvalidUrl(
            "Client id must contain a domain name, not an IP address literal",
        ))
    }
}

pub(crate) fn is_dot_segment(segment: &str) -> bool {
    hashify::set_ignore_case!(
        segment.as_bytes(),
        ".",
        "..",
        "%2e",
        "%2e%2e",
        ".%2e",
        "%2e.",
    )
}

pub fn validate_cimd_document(
    client_id: &str,
    client_host: String,
    body: &[u8],
) -> Result<CimdClient, CimdError> {
    if body.len() > CIMD_MAX_DOCUMENT_SIZE {
        return Err(CimdError::TooLarge);
    }
    let document = serde_json::from_slice::<CimdDocument>(body)
        .map_err(|_| CimdError::InvalidDocument("Document is not a valid JSON object"))?;

    if document.client_id.as_deref() != Some(client_id) {
        return Err(CimdError::InvalidDocument(
            "client_id does not match the document URL",
        ));
    }
    if document.client_secret.is_some() || document.client_secret_expires_at.is_some() {
        return Err(CimdError::InvalidDocument(
            "Document must not contain a client secret",
        ));
    }
    if document.token_endpoint_auth_method.as_deref() != Some("none") {
        return Err(CimdError::InvalidDocument(
            "token_endpoint_auth_method must be \"none\"",
        ));
    }
    if document.jwks.as_ref().is_some_and(has_private_key) {
        return Err(CimdError::InvalidDocument(
            "Document must not contain private key material",
        ));
    }

    let redirect_uris = document
        .redirect_uris
        .filter(|uris| !uris.is_empty() && uris.len() <= CIMD_MAX_REDIRECT_URIS)
        .ok_or(CimdError::InvalidDocument(
            "redirect_uris must list between 1 and 16 URIs",
        ))?;
    if !redirect_uris
        .iter()
        .all(|uri| is_valid_cimd_redirect_uri(uri))
    {
        return Err(CimdError::InvalidDocument(
            "redirect_uris must be https or loopback URIs without a fragment, of at most 2048 bytes",
        ));
    }

    let post_logout_redirect_uris = document.post_logout_redirect_uris.unwrap_or_default();
    if post_logout_redirect_uris.len() > CIMD_MAX_REDIRECT_URIS {
        return Err(CimdError::InvalidDocument(
            "post_logout_redirect_uris must not list more than 16 URIs",
        ));
    }
    if !post_logout_redirect_uris
        .iter()
        .all(|uri| is_valid_cimd_redirect_uri(uri))
    {
        return Err(CimdError::InvalidDocument(
            "post_logout_redirect_uris must be https or loopback URIs without a fragment, of at most 2048 bytes",
        ));
    }

    let client_name = match document.client_name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => {
            check_client_name(name).map_err(CimdError::InvalidDocument)?;
            Some(name.to_string())
        }
        _ => None,
    };

    Ok(CimdClient {
        client_host,
        client_name,
        redirect_uris,
        post_logout_redirect_uris,
        scopes: document
            .scope
            .as_deref()
            .map_or(OAuthScopes::INTEROPERABLE, |scope| {
                OAuthScopes::parse(scope).interoperable()
            }),
    })
}

fn is_valid_cimd_redirect_uri(uri: &str) -> bool {
    uri.len() <= CIMD_MAX_REDIRECT_URI_LEN
        && !uri.contains(['#', '\\'])
        && (is_https_url(uri) || loopback_redirect_parts(uri).is_some())
}

fn has_private_key(jwks: &serde_json::Value) -> bool {
    jwks.get("keys")
        .and_then(|keys| keys.as_array())
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                key.as_object().is_some_and(|key| {
                    ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                        .iter()
                        .any(|member| key.contains_key(*member))
                })
            })
        })
}

async fn fetch_cimd_document(url: Url) -> Result<(Vec<u8>, u64), CimdError> {
    let display_url = url.to_string();
    let response = OutboundClient::new(
        http_client_builder(cfg!(stalwart_tests))
            .user_agent(USER_AGENT)
            .timeout(CIMD_FETCH_TIMEOUT),
        OutboundPolicy::PublicOnly,
        Redirects::None,
    )
    .request_url(Method::GET, url)
    .map_err(CimdError::Outbound)?
    .header(ACCEPT, "application/json")
    .send()
    .await
    .map_err(|err| {
        trc::event!(
            Auth(AuthEvent::Error),
            Url = display_url.clone(),
            Reason = error_chain(&err),
            Details = "Failed to fetch client metadata document",
        );
        CimdError::Fetch
    })?;

    if response.status() != StatusCode::OK {
        return Err(CimdError::Status(response.status().as_u16()));
    }
    let ttl = cache_ttl(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
    );
    let body = response
        .bytes_with_limit(CIMD_MAX_DOCUMENT_SIZE)
        .await
        .map_err(|err| {
            trc::event!(
                Auth(AuthEvent::Error),
                Url = display_url,
                Reason = err.to_string(),
                Details = "Failed to read client metadata document",
            );
            CimdError::Fetch
        })?
        .ok_or(CimdError::TooLarge)?;

    Ok((body, ttl))
}

fn cache_ttl(cache_control: Option<&str>) -> u64 {
    cache_control
        .and_then(|value| {
            value.split(',').find_map(|directive| {
                let (name, value) = directive.split_once('=')?;
                if name.trim().eq_ignore_ascii_case("max-age") {
                    value.trim().trim_matches('"').parse::<u64>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(CIMD_MIN_TTL)
        .clamp(CIMD_MIN_TTL, CIMD_MAX_TTL)
}

impl CimdError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CimdError::Disabled => "Client metadata documents are disabled",
            CimdError::InvalidUrl(reason) | CimdError::InvalidDocument(reason) => reason,
            CimdError::DomainNotAllowed => "Client metadata document domain is not allowed",
            CimdError::Outbound(err) => err.as_str(),
            CimdError::Fetch => "Failed to fetch the client metadata document",
            CimdError::Status(_) => "Client metadata document request did not return 200 OK",
            CimdError::TooLarge => "Client metadata document is too large",
        }
    }
}

impl store::write::ArchiveCompression for CimdClient {
    const COMPRESSION: store::write::Compression = store::write::Compression::None;
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/cimd/tests.rs"]
mod tests;
