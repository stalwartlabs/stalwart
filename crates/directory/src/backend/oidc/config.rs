/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Directory;
use crate::backend::oidc::lookup::fetch_jwks_keys;
use crate::backend::oidc::{
    CachedKey, DiscoveryDocument, JwksCache, OidcConfig, OidcDiscovery, OidcError, OpenIdDirectory,
};
use ahash::AHashMap;
use compact_str::{CompactString, format_compact};
use registry::schema::structs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use trc::AuthEvent;
use utils::Client;

const DISCOVERY_RETRY_FOR: Duration = Duration::from_secs(30);
const DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(3);

impl OpenIdDirectory {
    pub async fn open(config: structs::OidcDirectory) -> Result<Directory, String> {
        Self::new(OidcConfig {
            issue_url: config.issuer_url,
            require_aud: config.require_audience,
            require_scopes: config.require_scopes.into_inner(),
            claim_email: config.claim_username,
            claim_name: config.claim_name,
            claim_groups: config.claim_groups,
            default_domain: config.username_domain,
        })
        .await
        .map(Directory::OpenId)
        .map_err(|err| err.to_string())
    }

    pub async fn new(config: OidcConfig) -> Result<Self, OidcError> {
        let http = utils::http::http_client_builder(false)
            .user_agent("Stalwart/1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OidcError::Network(format!("HTTP client build failed: {e}")))?;

        let started_at = Instant::now();
        let (document, keys) = loop {
            match Self::discover(&http, &config).await {
                Ok(discovery) => break discovery,
                Err(err) if err.is_transient() && started_at.elapsed() < DISCOVERY_RETRY_FOR => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = CompactString::from(&config.issue_url),
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
            discovery: OidcDiscovery {
                url: config.issue_url.clone(),
                document,
            },
            config,
            http,
            cache: RwLock::new(JwksCache {
                keys,
                last_updated: Instant::now(),
            }),
        })
    }

    async fn discover(
        http: &Client,
        config: &OidcConfig,
    ) -> Result<(DiscoveryDocument, AHashMap<String, Arc<CachedKey>>), OidcError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issue_url.trim_end_matches('/')
        );
        let discovery_bytes = http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("Discovery fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| OidcError::Provider(format!("Discovery HTTP error: {e}")))?
            .bytes()
            .await
            .map_err(|e| OidcError::Provider(format!("Discovery HTTP error: {e}")))?;
        let discovery: DiscoveryDocument = serde_json::from_slice(&discovery_bytes)
            .map_err(|e| OidcError::Provider(format!("Discovery JSON parse error: {e}")))?;

        let normalised_issue = config.issue_url.trim_end_matches('/');
        let normalised_issuer = discovery.issuer.trim_end_matches('/');
        if normalised_issuer != normalised_issue {
            return Err(OidcError::Config(format!(
                "Issuer mismatch: discovery document says '{}' but configured issue_url is '{}'",
                discovery.issuer, config.issue_url,
            )));
        }

        if let Some(supported) = &discovery.scopes_supported {
            for scope in &config.require_scopes {
                if !supported.contains(scope) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = CompactString::from(&config.issue_url),
                        Reason = format_compact!(
                            "Required scope '{}' is not in scopes_supported from the IdP",
                            scope
                        )
                    );
                }
            }
        }

        if let Some(supported) = &discovery.claims_supported {
            let check = |name: &str, label: &str| {
                if !supported.iter().any(|c| c == name) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = CompactString::from(&config.issue_url),
                        Reason = format_compact!(
                            "Configured {} claim '{}' is not in claims_supported from the IdP",
                            label,
                            name
                        )
                    );
                }
            };
            check(&config.claim_email, "claim_email");
            if let Some(n) = &config.claim_name {
                check(n, "claim_name");
            }
            if let Some(g) = &config.claim_groups {
                check(g, "claim_groups");
            }
        }

        /*{
            let cache = Arc::clone(&cache);
            let http = http.clone();
            let jwks_uri = discovery.jwks_uri.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    match fetch_jwks_keys(&http, &jwks_uri).await {
                        Ok(new_keys) => {
                            let mut guard = cache.write().await;
                            guard.keys = new_keys;
                            guard.last_updated = Instant::now();
                        }
                        Err(e) => {
                            trc::event!(
                                Auth(AuthEvent::Warning),
                                Url = jwks_uri.to_string(),
                                Reason = format!("Background JWKS refresh failed: {e}")
                            );
                        }
                    }
                }
            });
        }*/

        let keys = fetch_jwks_keys(http, &discovery.jwks_uri).await?;

        Ok((discovery, keys))
    }
}
