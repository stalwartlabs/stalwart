/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Account, Credentials,
    backend::oidc::{CachedKey, OidcError, OpenIdDirectory},
};
use ahash::AHashMap;
use jsonwebtoken::{
    Algorithm, DecodingKey, Header, Validation, decode, decode_header,
    jwk::{self, JwkSet},
};
use reqwest::Client;
use serde_json::Value;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use trc::AuthEvent;

impl OpenIdDirectory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        match credentials {
            Credentials::Bearer { token, .. } => if let Ok(header) = decode_header(token) {
                self.authenticate_jwt(token, header).await
            } else {
                #[cfg(feature = "test_mode")]
                let token = token.strip_prefix(".").unwrap_or(token);
                self.authenticate_opaque(token).await
            }
            .map_err(|err| match err {
                OidcError::AuthorizationFailed(reason) => {
                    AuthEvent::Failed.into_err().reason(reason)
                }
                err => AuthEvent::Error.into_err().reason(err),
            }),
            _ => Err(AuthEvent::Error
                .into_err()
                .reason("Unsupported credentials type for OIDC backend")),
        }
    }

    async fn authenticate_jwt(&self, token: &str, header: Header) -> Result<Account, OidcError> {
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(OidcError::TokenValidation(
                "Unsupported algorithm".to_string(),
            ));
        }

        let candidates = self.get_key(header.kid.as_deref()).await?;
        let mut last_err = None;
        for cached in &candidates {
            let dk = &cached.decoding_key;
            let alg = cached.algorithm;
            let mut validation = Validation::new(alg);

            if let Some(aud) = &self.config.require_aud {
                validation.set_audience(&[aud]);
            } else {
                validation.validate_aud = false;
            }

            validation.set_issuer(&[&self.discovery.document.issuer]);
            validation.leeway = 60;

            match decode::<serde_json::Value>(token, dk, &validation) {
                Ok(token_data) => {
                    if self.config.require_aud.is_some() && token_data.claims.get("aud").is_none() {
                        last_err = Some(jsonwebtoken::errors::Error::from(
                            jsonwebtoken::errors::ErrorKind::InvalidAudience,
                        ));
                        continue;
                    }

                    self.validate_scopes(&token_data.claims)?;

                    let mut claims = token_data.claims;
                    let jwt_email = self.resolve_email(&claims).ok();
                    let missing_profile = self
                        .config
                        .claim_name
                        .as_ref()
                        .is_some_and(|claim| claims.get(claim).is_none())
                        || self
                            .config
                            .claim_groups
                            .as_ref()
                            .is_some_and(|claim| claims.get(claim).is_none());

                    if jwt_email.is_none() || missing_profile {
                        match self.fetch_userinfo(token).await {
                            Ok(userinfo) => {
                                if let (Some(base), Value::Object(extra)) =
                                    (claims.as_object_mut(), userinfo)
                                {
                                    for (key, value) in extra {
                                        base.entry(key).or_insert_with(|| value);
                                    }
                                }
                            }
                            Err(err) if jwt_email.is_none() => return Err(err),
                            Err(_) => {}
                        }
                    }

                    let email = match jwt_email {
                        Some(email) => email,
                        None => self.resolve_email(&claims)?,
                    };
                    return self.build_account(email, &claims);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(OidcError::TokenValidation(format!(
            "JWT validation failed: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    async fn authenticate_opaque(&self, token: &str) -> Result<Account, OidcError> {
        let claims = self.fetch_userinfo(token).await?;
        self.build_account(self.resolve_email(&claims)?, &claims)
    }

    async fn get_key(&self, kid: Option<&str>) -> Result<Vec<Arc<CachedKey>>, OidcError> {
        {
            let guard = self.cache.read().await;

            if let Some(kid) = kid {
                if let Some(cached) = guard.keys.get(kid) {
                    return Ok(vec![cached.clone()]);
                }

                if guard.last_updated.elapsed() < Duration::from_secs(300) {
                    return Err(OidcError::TokenValidation("Unknown key id".to_string()));
                }
            } else {
                let all: Vec<_> = guard.keys.values().cloned().collect();
                if !all.is_empty() {
                    return Ok(all);
                }
            }
        }

        let new_keys = fetch_jwks_keys(&self.http, &self.discovery.document.jwks_uri).await?;
        {
            let mut guard = self.cache.write().await;
            guard.keys = new_keys;
            guard.last_updated = Instant::now();
        }

        let guard = self.cache.read().await;
        if let Some(kid) = kid {
            if let Some(cached) = guard.keys.get(kid) {
                Ok(vec![cached.clone()])
            } else {
                Err(OidcError::TokenValidation(
                    "Unknown key id after refresh".to_string(),
                ))
            }
        } else {
            let all: Vec<_> = guard.keys.values().cloned().collect();
            if all.is_empty() {
                Err(OidcError::Provider(
                    "JWKS contains no usable keys".to_string(),
                ))
            } else {
                Ok(all)
            }
        }
    }

    async fn fetch_userinfo(&self, token: &str) -> Result<serde_json::Value, OidcError> {
        let resp = self
            .http
            .get(&self.discovery.document.userinfo_endpoint)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("UserInfo request failed: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let reason = resp.text().await.unwrap_or_default();
            return Err(OidcError::AuthorizationFailed(format!(
                "Token rejected by UserInfo endpoint with status {status}: {reason}"
            )));
        }
        if !status.is_success() {
            return Err(OidcError::Provider(format!(
                "UserInfo returned HTTP {status}"
            )));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| OidcError::Provider(format!("UserInfo HTTP error: {e}")))?;

        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| OidcError::Provider(format!("UserInfo JSON parse error: {e}")))
    }

    fn validate_scopes(&self, claims: &serde_json::Value) -> Result<(), OidcError> {
        if !self.config.require_scopes.is_empty() {
            let token_scopes = extract_scopes(claims);

            for required in &self.config.require_scopes {
                if !token_scopes.iter().any(|s| s == required) {
                    return Err(OidcError::AuthorizationFailed(format!(
                        "Missing required scope '{required}', present scopes: {token_scopes:?}"
                    )));
                }
            }
        }

        Ok(())
    }

    fn build_account(
        &self,
        email: String,
        claims: &serde_json::Value,
    ) -> Result<Account, OidcError> {
        Ok(Account {
            email,
            email_aliases: Vec::new(),
            secret: None,
            groups: self.config.claim_groups.as_ref().map(|groups_claim| {
                claims
                    .get(groups_claim)
                    .map(extract_string_list)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|group| match &self.config.default_domain {
                        Some(domain) if !group.contains('@') => format!("{group}@{domain}"),
                        _ => group,
                    })
                    .collect()
            }),
            description: self
                .config
                .claim_name
                .as_ref()
                .and_then(|name_claim| claims.get(name_claim))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    fn resolve_email(&self, claims: &serde_json::Value) -> Result<String, OidcError> {
        if let Some(val) = claims
            .get(&self.config.claim_email)
            .and_then(|v| v.as_str())
        {
            if val.contains('@') {
                return Ok(val.to_string());
            }
            if let Some(domain) = &self.config.default_domain {
                return Ok(format!("{val}@{domain}"));
            }
        }

        if self.config.claim_email != "email"
            && let Some(val) = claims.get("email").and_then(|v| v.as_str())
            && val.contains('@')
        {
            return Ok(val.to_string());
        }

        Err(OidcError::AuthorizationFailed(
            "Could not determine a valid email address for account".to_string(),
        ))
    }
}

pub(super) async fn fetch_jwks_keys(
    http: &Client,
    jwks_uri: &str,
) -> Result<AHashMap<String, Arc<CachedKey>>, OidcError> {
    let jwks_bytes = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| OidcError::Network(format!("JWKS fetch failed: {e}")))?
        .error_for_status()
        .map_err(|e| OidcError::Provider(format!("JWKS HTTP error: {e}")))?
        .bytes()
        .await
        .map_err(|e| OidcError::Provider(format!("JWKS HTTP error: {e}")))?;
    let jwks: JwkSet = serde_json::from_slice(&jwks_bytes)
        .map_err(|e| OidcError::Provider(format!("JWKS JSON parse error: {e}")))?;

    let mut map = AHashMap::new();
    let mut synthetic_id: u64 = 0;

    for key in &jwks.keys {
        if let Some(pk_use) = &key.common.public_key_use
            && pk_use != &jwk::PublicKeyUse::Signature
        {
            continue;
        }

        let algorithm = match &key.algorithm {
            jwk::AlgorithmParameters::RSA(_) => match key.common.key_algorithm {
                Some(jwk::KeyAlgorithm::RS256) => Algorithm::RS256,
                Some(jwk::KeyAlgorithm::RS384) => Algorithm::RS384,
                Some(jwk::KeyAlgorithm::RS512) => Algorithm::RS512,
                Some(jwk::KeyAlgorithm::PS256) => Algorithm::PS256,
                Some(jwk::KeyAlgorithm::PS384) => Algorithm::PS384,
                Some(jwk::KeyAlgorithm::PS512) => Algorithm::PS512,
                None => Algorithm::RS256,
                Some(other) => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = jwks_uri.to_string(),
                        Reason = format!("Unsupported RSA key algorithm {:?}", other)
                    );
                    continue;
                }
            },
            jwk::AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
                jwk::EllipticCurve::P256 => Algorithm::ES256,
                jwk::EllipticCurve::P384 => Algorithm::ES384,
                _ => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = jwks_uri.to_string(),
                        Reason = format!("Unsupported EC curve {:?}", ec.curve)
                    );
                    continue;
                }
            },
            jwk::AlgorithmParameters::OctetKeyPair(_) => Algorithm::EdDSA,
            jwk::AlgorithmParameters::OctetKey(_) => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = jwks_uri.to_string(),
                    Reason = format!(
                        "Symmetric (HMAC) key found in JWKS (kid={:?}), skipping — HMAC is not accepted",
                        key.common.key_id
                    )
                );
                continue;
            }
        };

        let decoding_key = match DecodingKey::from_jwk(key) {
            Ok(decoding_key) => decoding_key,
            Err(e) => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = jwks_uri.to_string(),
                    Reason = format!(
                        "Failed to build DecodingKey from JWK (kid={:?}): {e}",
                        key.common.key_id
                    )
                );
                continue;
            }
        };

        map.insert(
            match &key.common.key_id {
                Some(id) => id.clone(),
                None => {
                    let id = format!("_synthetic_{synthetic_id}");
                    synthetic_id += 1;
                    id
                }
            },
            CachedKey {
                decoding_key,
                algorithm,
            }
            .into(),
        );
    }

    Ok(map)
}

fn extract_scopes(claims: &serde_json::Value) -> Vec<String> {
    match claims.get("scope") {
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(|s| s.to_string()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn extract_string_list(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_json::Value::String(s) => s.split_whitespace().map(|s| s.to_string()).collect(),
        _ => Vec::new(),
    }
}
