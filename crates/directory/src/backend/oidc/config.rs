/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Directory;
use crate::backend::oidc::{
    Conformance, ConformanceGaps, DiscoveryDocument, ExternalScopes, IntrospectionAuth, JwksState,
    METADATA_MAX_SIZE, OAUTH_METADATA_PATH, OidcConfig, OidcDiscovery, OidcError, OpaqueValidation,
    OpenIdDirectory,
    jwks::{FetchedKeys, fetch_jwks},
    openid_configuration_url, read_body,
};
use compact_str::{CompactString, format_compact};
use encodify::base64::STANDARD;
use parking_lot::RwLock;
use registry::schema::{
    enums::{OidcIntrospectionAuth, OidcOpaqueTokenValidation, OidcUnscopedTokenPolicy},
    structs,
};
use reqwest::{
    Method, StatusCode, Url,
    header::{CONTENT_TYPE, HeaderMap},
};
use serde::Serialize;
use std::time::{Duration, Instant};
use trc::AuthEvent;
use utils::{
    http::http_client_builder,
    outbound::{OutboundClient, OutboundPolicy, Redirects},
};

const DISCOVERY_RETRY_FOR: Duration = Duration::from_secs(30);
const DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(3);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

struct Metadata {
    document: DiscoveryDocument,
    url: String,
    is_json: bool,
}

enum MetadataFetch {
    Found(Box<Metadata>),
    Failed(String),
}

#[derive(Serialize)]
struct WebDiscoveryDocument<'x> {
    #[serde(flatten)]
    document: &'x DiscoveryDocument,
    stalwart_required_scopes: &'x [&'x str],
}

impl OpenIdDirectory {
    pub async fn open(config: structs::OidcDirectory) -> Result<Directory, String> {
        let opaque_validation = match config.opaque_token_validation {
            OidcOpaqueTokenValidation::None => OpaqueValidation::Reject,
            OidcOpaqueTokenValidation::UserInfo => OpaqueValidation::UserInfo,
            OidcOpaqueTokenValidation::Introspection => {
                OpaqueValidation::Introspection(introspection_auth(&config).await?)
            }
        };

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let outbound_policy = if config.trusted_provider {
            OutboundPolicy::Trusted
        } else {
            OutboundPolicy::for_tenant(config.member_tenant_id)
        };
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        let outbound_policy = OutboundPolicy::Trusted;

        if matches!(opaque_validation, OpaqueValidation::UserInfo)
            && config.unscoped_tokens == OidcUnscopedTokenPolicy::Reject
        {
            trc::event!(
                Auth(AuthEvent::Warning),
                Url = CompactString::from(config.issuer_url.as_str()),
                Reason = "Opaque tokens validated through UserInfo carry no scopes and are always rejected while unscopedTokens is set to reject"
            );
        }

        Self::new(OidcConfig {
            issuer_url: config.issuer_url,
            claim_username: config.claim_username,
            claim_name: config.claim_name,
            claim_groups: config.claim_groups,
            username_domain: config.username_domain,
            allow_invalid_certs: config.allow_invalid_certs,
            outbound_policy,
            accepted_audiences: config
                .accepted_audiences
                .into_iter()
                .map(String::into_boxed_str)
                .collect(),
            opaque_validation,
            unscoped_tokens: config.unscoped_tokens,
            skip_audience_validation: config.skip_audience_validation,
            allow_id_token_claims: config.allow_id_token_claims,
            lenient_issuer_match: config.lenient_issuer_match,
        })
        .await
        .map(Directory::OpenId)
        .map_err(|err| err.to_string())
    }

    pub async fn new(config: OidcConfig) -> Result<Self, OidcError> {
        let http = OutboundClient::new(
            http_client_builder(config.allow_invalid_certs)
                .user_agent("Stalwart/1.0")
                .timeout(HTTP_TIMEOUT),
            config.outbound_policy,
            Redirects::None,
        );

        let started_at = Instant::now();
        let (discovery, issuers, keys) = loop {
            match Self::discover(&http, &config).await {
                Ok(discovery) => break discovery,
                Err(err) if err.is_transient() && started_at.elapsed() < DISCOVERY_RETRY_FOR => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = CompactString::from(config.issuer_url.as_str()),
                        Reason = format_compact!(
                            "{err}, retrying in {} seconds",
                            DISCOVERY_RETRY_INTERVAL.as_secs()
                        )
                    );
                    tokio::time::sleep(DISCOVERY_RETRY_INTERVAL).await;
                }
                Err(err) => return Err(err),
            }
        };

        Ok(Self {
            config,
            discovery,
            issuers,
            http,
            jwks: RwLock::new(JwksState::new(keys)),
            jwks_refresh: tokio::sync::Mutex::new(()),
        })
    }

    async fn discover(
        http: &OutboundClient,
        config: &OidcConfig,
    ) -> Result<(OidcDiscovery, Box<[String]>, FetchedKeys), OidcError> {
        let Metadata {
            mut document,
            url,
            is_json,
        } = fetch_metadata(http, &config.issuer_url).await?;

        if !issuer_matches(
            &config.issuer_url,
            &document.issuer,
            config.lenient_issuer_match,
        ) {
            return Err(OidcError::Config(format!(
                "Issuer mismatch: metadata at '{url}' says '{}' but the configured issuer is '{}'",
                document.issuer, config.issuer_url,
            )));
        }

        let oidc_url = openid_configuration_url(&document.issuer);
        if (document.userinfo_endpoint.is_none() || document.end_session_endpoint.is_none())
            && url != oidc_url
        {
            let reason = match fetch_document(http, &oidc_url, false).await {
                Ok(MetadataFetch::Found(oidc)) if oidc.document.issuer == document.issuer => {
                    if document.userinfo_endpoint.is_none() {
                        document.userinfo_endpoint = oidc.document.userinfo_endpoint;
                    }
                    if document.end_session_endpoint.is_none() {
                        document.end_session_endpoint = oidc.document.end_session_endpoint;
                    }
                    None
                }
                Ok(MetadataFetch::Found(_)) => Some(format_compact!(
                    "the OpenID configuration has a different issuer"
                )),
                Ok(MetadataFetch::Failed(reason)) => Some(format_compact!("{reason}")),
                Err(err) => Some(format_compact!("{err}")),
            };
            if let Some(reason) = reason {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = CompactString::from(oidc_url.as_str()),
                    Reason = format_compact!(
                        "Could not complete userinfo_endpoint and end_session_endpoint: {reason}"
                    )
                );
            }
        }

        if matches!(config.opaque_validation, OpaqueValidation::Introspection(_))
            && document.introspection_endpoint.is_none()
        {
            return Err(OidcError::Config(
                "opaqueTokenValidation is set to introspection but the IdP metadata has no introspection_endpoint".to_string(),
            ));
        }

        if let Some(supported) = &document.claims_supported {
            let check = |name: &str, label: &str| {
                if !supported.iter().any(|c| c == name) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = CompactString::from(config.issuer_url.as_str()),
                        Reason = format_compact!(
                            "Configured {label} claim '{name}' is not in claims_supported from the IdP"
                        )
                    );
                }
            };
            check(&config.claim_username, "claimUsername");
            if let Some(n) = &config.claim_name {
                check(n, "claimName");
            }
            if let Some(g) = &config.claim_groups {
                check(g, "claimGroups");
            }
        }

        let conformance = conformance(&document, is_json);
        log_conformance(&document.issuer, conformance);

        let mut issuers = Vec::with_capacity(2);
        issuers.push(document.issuer.clone());
        if config.lenient_issuer_match {
            issuers.push(match document.issuer.strip_suffix('/') {
                Some(issuer) => issuer.to_string(),
                None => format!("{}/", document.issuer),
            });
        }

        let keys = fetch_jwks(http, &document.jwks_uri, &issuers).await?;

        let web_document = serde_json::to_vec(&WebDiscoveryDocument {
            document: &document,
            stalwart_required_scopes: &required_scopes(config, &document),
        })
        .map_err(|err| OidcError::Provider(format!("Failed to serialize metadata: {err}")))?
        .into();

        Ok((
            OidcDiscovery {
                document,
                metadata_url: url,
                conformance,
                web_document,
            },
            issuers.into_boxed_slice(),
            keys,
        ))
    }
}

async fn introspection_auth(config: &structs::OidcDirectory) -> Result<IntrospectionAuth, String> {
    if config.introspection_auth_method == OidcIntrospectionAuth::None {
        return Ok(IntrospectionAuth::Unauthenticated);
    }
    let secret = config.introspection_client_secret.secret().await?;
    let (Some(client_id), Some(secret)) = (
        config
            .introspection_client_id
            .as_deref()
            .filter(|id| !id.is_empty()),
        secret.as_deref().filter(|secret| !secret.is_empty()),
    ) else {
        return Err(
            "introspectionClientId and introspectionClientSecret are required for the selected introspectionAuthMethod"
                .to_string(),
        );
    };

    let client_id = form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>();
    let secret = form_urlencoded::byte_serialize(secret.as_bytes()).collect::<String>();
    Ok(match config.introspection_auth_method {
        OidcIntrospectionAuth::ClientSecretPost => IntrospectionAuth::Post {
            credentials: format!("&client_id={client_id}&client_secret={secret}").into_boxed_str(),
        },
        _ => IntrospectionAuth::Basic {
            authorization: format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
                .into_boxed_str(),
        },
    })
}

async fn fetch_metadata(http: &OutboundClient, issuer: &str) -> Result<Metadata, OidcError> {
    let oauth_url = oauth_metadata_url(issuer)?;
    let oauth_failure = match fetch_document(http, &oauth_url, true).await? {
        MetadataFetch::Found(metadata) => return Ok(*metadata),
        MetadataFetch::Failed(reason) => reason,
    };

    let oidc_url = openid_configuration_url(issuer);
    match fetch_document(http, &oidc_url, false).await? {
        MetadataFetch::Found(metadata) => Ok(*metadata),
        MetadataFetch::Failed(oidc_failure) => Err(OidcError::Provider(format!(
            "Metadata not found: {oauth_url}: {oauth_failure}; {oidc_url}: {oidc_failure}"
        ))),
    }
}

async fn fetch_document(
    http: &OutboundClient,
    url: &str,
    require_json: bool,
) -> Result<MetadataFetch, OidcError> {
    let response = http
        .request(Method::GET, url)
        .map_err(|err| OidcError::Config(format!("Invalid metadata URL '{url}': {err}")))?
        .send()
        .await
        .map_err(|e| OidcError::Network(format!("Metadata fetch from '{url}' failed: {e}")))?;

    let status = response.status();
    if status != StatusCode::OK {
        return Ok(MetadataFetch::Failed(format!("HTTP {status}")));
    }
    let is_json = is_json_content(response.headers());
    if require_json && !is_json {
        return Ok(MetadataFetch::Failed(
            "Content-Type is not application/json".to_string(),
        ));
    }
    let bytes = read_body(response, METADATA_MAX_SIZE, "Metadata").await?;
    Ok(match serde_json::from_slice::<DiscoveryDocument>(&bytes) {
        Ok(document) => MetadataFetch::Found(Box::new(Metadata {
            document,
            url: url.to_string(),
            is_json,
        })),
        Err(err) => MetadataFetch::Failed(format!("Invalid metadata: {err}")),
    })
}

fn oauth_metadata_url(issuer: &str) -> Result<String, OidcError> {
    let mut url = Url::parse(issuer)
        .map_err(|err| OidcError::Config(format!("Invalid issuer URL '{issuer}': {err}")))?;
    let path = url.path();
    let mut metadata_path = String::with_capacity(OAUTH_METADATA_PATH.len() + path.len());
    metadata_path.push_str(OAUTH_METADATA_PATH);
    metadata_path.push_str(path.strip_suffix('/').unwrap_or(path));
    url.set_path(&metadata_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.into())
}

fn is_json_content(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
}

fn issuer_matches(configured: &str, discovered: &str, lenient: bool) -> bool {
    configured == discovered
        || (lenient
            && configured.strip_suffix('/').unwrap_or(configured)
                == discovered.strip_suffix('/').unwrap_or(discovered))
}

fn is_public_issuer(issuer: &str) -> bool {
    Url::parse(issuer).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.as_str() == issuer
                || (url.path() == "/" && url.as_str().strip_suffix('/') == Some(issuer)))
    })
}

fn conformance(document: &DiscoveryDocument, is_json: bool) -> Conformance {
    let contains = |list: &Option<Vec<String>>, value: &str| {
        list.as_ref()
            .is_some_and(|list| list.iter().any(|item| item == value))
    };

    let mut gaps = ConformanceGaps::default();
    for (gap, failed) in [
        (ConformanceGaps::ISSUER, !is_public_issuer(&document.issuer)),
        (ConformanceGaps::CONTENT_TYPE, !is_json),
        (
            ConformanceGaps::REGISTRATION_ENDPOINT,
            document
                .registration_endpoint
                .as_deref()
                .is_none_or(str::is_empty),
        ),
        (
            ConformanceGaps::AUTHORIZATION_ENDPOINT,
            document.authorization_endpoint.is_empty(),
        ),
        (
            ConformanceGaps::TOKEN_ENDPOINT,
            document.token_endpoint.is_empty(),
        ),
        (
            ConformanceGaps::RESPONSE_TYPE_CODE,
            !contains(&document.response_types_supported, "code"),
        ),
        (
            ConformanceGaps::GRANT_TYPES,
            !contains(&document.grant_types_supported, "authorization_code")
                || !contains(&document.grant_types_supported, "refresh_token"),
        ),
        (
            ConformanceGaps::AUTH_METHOD_NONE,
            !contains(&document.token_endpoint_auth_methods_supported, "none"),
        ),
        (
            ConformanceGaps::PKCE_S256,
            !contains(&document.code_challenge_methods_supported, "S256"),
        ),
        (
            ConformanceGaps::ISS_PARAMETER,
            document.authorization_response_iss_parameter_supported != Some(true),
        ),
    ] {
        if failed {
            gaps.insert(gap);
        }
    }

    let mut scopes = ExternalScopes::NONE;
    for scope in document.scopes_supported.iter().flatten() {
        scopes.insert(ExternalScopes::from_name(scope));
    }

    Conformance { gaps, scopes }
}

fn log_conformance(issuer: &str, conformance: Conformance) {
    let mut missing = String::new();
    for name in conformance.gaps.names() {
        if !missing.is_empty() {
            missing.push_str(", ");
        }
        missing.push_str(name);
    }
    let mut missing_scopes = String::new();
    for name in ExternalScopes::ALL.difference(conformance.scopes).names() {
        if !missing_scopes.is_empty() {
            missing_scopes.push_str(", ");
        }
        missing_scopes.push_str(name);
    }

    if !conformance.gaps.is_empty() || !conformance.scopes.contains(ExternalScopes::MAIL) {
        if !missing_scopes.is_empty() {
            if !missing.is_empty() {
                missing.push_str(", ");
            }
            missing.push_str("scopes_supported: ");
            missing.push_str(&missing_scopes);
        }
        trc::event!(
            Auth(AuthEvent::Warning),
            Url = CompactString::from(issuer),
            Reason = format_compact!(
                "The identity provider does not conform to OAuth Public, PACC documents for its domains will only advertise password authentication. Missing: {missing}"
            )
        );
    } else if !missing_scopes.is_empty() {
        trc::event!(
            Auth(AuthEvent::Warning),
            Url = CompactString::from(issuer),
            Reason = format_compact!(
                "The identity provider does not support {missing_scopes}, PACC documents for its domains will only advertise password authentication while the matching services are published"
            )
        );
    }
}

fn required_scopes<'x>(config: &'x OidcConfig, document: &DiscoveryDocument) -> Vec<&'x str> {
    let mut scopes = Vec::with_capacity(4);
    scopes.push("openid");
    let email_fallback =
        (config.claim_username != "email" && config.username_domain.is_none()).then_some("email");
    for claim in [
        Some(config.claim_username.as_str()),
        email_fallback,
        config.claim_name.as_deref(),
        config.claim_groups.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let Some((scope, is_standard)) = hashify::map!(
            claim.as_bytes(),
            (&'static str, bool),
            "email" => ("email", true),
            "email_verified" => ("email", true),
            "preferred_username" => ("profile", true),
            "name" => ("profile", true),
            "given_name" => ("profile", true),
            "family_name" => ("profile", true),
            "nickname" => ("profile", true),
            "groups" => ("groups", false),
        ) else {
            continue;
        };
        let is_supported = match &document.scopes_supported {
            Some(supported) => supported.iter().any(|item| item == scope),
            None => *is_standard,
        };
        if is_supported && !scopes.contains(scope) {
            scopes.push(scope);
        }
    }
    scopes
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/directory/src/backend/oidc/config/tests.rs"]
mod tests;
