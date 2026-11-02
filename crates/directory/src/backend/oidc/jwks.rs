/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::backend::oidc::{
    CachedKey, JwksState, KeySet, METADATA_MAX_SIZE, OidcError, OpenIdDirectory, read_body,
};
use ahash::AHashMap;
use compact_str::{CompactString, format_compact};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    jwk::{self, JwkSet},
};
use reqwest::{
    Method,
    header::{CACHE_CONTROL, HeaderMap},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use trc::AuthEvent;
use utils::{error_chain, outbound::OutboundClient};

const JWKS_DEFAULT_MAX_AGE: Duration = Duration::from_secs(3600);
const JWKS_MIN_MAX_AGE: Duration = Duration::from_secs(300);
const JWKS_MAX_MAX_AGE: Duration = Duration::from_secs(86400);
const JWKS_RETRY_INTERVAL: Duration = Duration::from_secs(300);
const VALIDATION_LEEWAY: u64 = 60;
const REQUIRED_CLAIMS: [&str; 2] = ["exp", "iss"];

pub(crate) struct FetchedKeys {
    pub keys: KeySet,
    pub max_age: Duration,
}

enum KeyLookup {
    Current(Arc<KeySet>),
    Stale(Arc<KeySet>),
    Missing { retry: bool },
}

impl KeySet {
    pub(crate) fn candidates<'x>(
        &'x self,
        kid: Option<&str>,
    ) -> impl Iterator<Item = (&'x DecodingKey, &'x Validation)> {
        let by_kid = kid.and_then(|kid| self.keys.get(kid));
        let all = kid.is_none().then(|| self.keys.values());
        by_kid
            .into_iter()
            .chain(all.into_iter().flatten())
            .map(|key| (&key.decoding_key, &key.validation))
    }

    fn has_candidates(&self, kid: Option<&str>) -> bool {
        match kid {
            Some(kid) => self.keys.contains_key(kid),
            None => !self.keys.is_empty(),
        }
    }
}

impl JwksState {
    pub(crate) fn new(fetched: FetchedKeys) -> Self {
        let now = Instant::now();
        JwksState {
            keys: Arc::new(fetched.keys),
            fetched_at: now,
            attempted_at: now,
            max_age: fetched.max_age,
        }
    }
}

impl OpenIdDirectory {
    pub(crate) async fn signing_keys(&self, kid: Option<&str>) -> Result<Arc<KeySet>, OidcError> {
        match self.lookup_keys(kid) {
            KeyLookup::Current(keys) => Ok(keys),
            KeyLookup::Missing { retry: false } => Err(missing_key(kid)),
            KeyLookup::Stale(keys) => {
                let Ok(_guard) = self.jwks_refresh.try_lock() else {
                    return Ok(keys);
                };
                match self.lookup_keys(kid) {
                    KeyLookup::Stale(keys) => Ok(self.refresh_keys().await.unwrap_or(keys)),
                    KeyLookup::Current(keys) => Ok(keys),
                    KeyLookup::Missing { .. } => Err(missing_key(kid)),
                }
            }
            KeyLookup::Missing { retry: true } => {
                let _guard = self.jwks_refresh.lock().await;
                match self.lookup_keys(kid) {
                    KeyLookup::Current(keys) | KeyLookup::Stale(keys) => Ok(keys),
                    KeyLookup::Missing { retry: false } => Err(missing_key(kid)),
                    KeyLookup::Missing { retry: true } => {
                        let keys = self.refresh_keys().await?;
                        if keys.has_candidates(kid) {
                            Ok(keys)
                        } else {
                            Err(missing_key(kid))
                        }
                    }
                }
            }
        }
    }

    fn lookup_keys(&self, kid: Option<&str>) -> KeyLookup {
        let now = Instant::now();
        let state = self.jwks.read();
        let retry = now.saturating_duration_since(state.attempted_at) >= JWKS_RETRY_INTERVAL;
        if !state.keys.has_candidates(kid) {
            KeyLookup::Missing { retry }
        } else if retry && now.saturating_duration_since(state.fetched_at) >= state.max_age {
            KeyLookup::Stale(state.keys.clone())
        } else {
            KeyLookup::Current(state.keys.clone())
        }
    }

    async fn refresh_keys(&self) -> Result<Arc<KeySet>, OidcError> {
        self.jwks.write().attempted_at = Instant::now();
        match fetch_jwks(&self.http, &self.discovery.document.jwks_uri, &self.issuers).await {
            Ok(fetched) => {
                let keys = Arc::new(fetched.keys);
                let mut state = self.jwks.write();
                state.keys = keys.clone();
                state.fetched_at = Instant::now();
                state.max_age = fetched.max_age;
                Ok(keys)
            }
            Err(err) => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = CompactString::from(self.discovery.document.jwks_uri.as_str()),
                    Reason = format_compact!("JWKS refresh failed, keeping cached keys: {err}")
                );
                Err(err)
            }
        }
    }
}

fn missing_key(kid: Option<&str>) -> OidcError {
    if kid.is_some() {
        OidcError::TokenValidation("Unknown key id".to_string())
    } else {
        OidcError::Provider("JWKS contains no usable keys".to_string())
    }
}

pub(crate) async fn fetch_jwks(
    http: &OutboundClient,
    jwks_uri: &str,
    issuers: &[String],
) -> Result<FetchedKeys, OidcError> {
    let response = http
        .request(Method::GET, jwks_uri)
        .map_err(|err| OidcError::Config(format!("Invalid JWKS URL: {err}")))?
        .send()
        .await
        .map_err(|e| OidcError::Network(format!("JWKS fetch failed: {}", error_chain(&e))))?
        .error_for_status()
        .map_err(|e| OidcError::Provider(format!("JWKS HTTP error: {e}")))?;
    let max_age = cache_max_age(response.headers());
    let jwks_bytes = read_body(response, METADATA_MAX_SIZE, "JWKS").await?;
    let jwks: JwkSet = serde_json::from_slice(&jwks_bytes)
        .map_err(|e| OidcError::Provider(format!("JWKS JSON parse error: {e}")))?;

    let mut keys = AHashMap::with_capacity(jwks.keys.len());
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
                        Url = CompactString::from(jwks_uri),
                        Reason = format_compact!("Unsupported RSA key algorithm {:?}", other)
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
                        Url = CompactString::from(jwks_uri),
                        Reason = format_compact!("Unsupported EC curve {:?}", ec.curve)
                    );
                    continue;
                }
            },
            jwk::AlgorithmParameters::OctetKeyPair(_) => Algorithm::EdDSA,
            jwk::AlgorithmParameters::OctetKey(_) => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = CompactString::from(jwks_uri),
                    Reason = format_compact!(
                        "Symmetric (HMAC) key found in JWKS (kid={:?}), skipping, HMAC is not accepted",
                        key.common.key_id
                    )
                );
                continue;
            }
            _ => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = CompactString::from(jwks_uri),
                    Reason = format_compact!(
                        "Unrecognised key type in JWKS (kid={:?}), skipping",
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
                    Url = CompactString::from(jwks_uri),
                    Reason = format_compact!(
                        "Failed to build DecodingKey from JWK (kid={:?}): {e}",
                        key.common.key_id
                    )
                );
                continue;
            }
        };

        let kid: Box<str> = match &key.common.key_id {
            Some(id) => id.as_str().into(),
            None => {
                let id = format!("_synthetic_{synthetic_id}").into_boxed_str();
                synthetic_id += 1;
                id
            }
        };

        keys.insert(
            kid,
            CachedKey {
                decoding_key,
                validation: validation(algorithm, issuers),
            },
        );
    }

    Ok(FetchedKeys {
        keys: KeySet { keys },
        max_age,
    })
}

fn validation(algorithm: Algorithm, issuers: &[String]) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.validate_aud = false;
    validation.set_issuer(issuers);
    validation.set_required_spec_claims(&REQUIRED_CLAIMS);
    validation.leeway = VALIDATION_LEEWAY;
    validation
}

fn cache_max_age(headers: &HeaderMap) -> Duration {
    headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').find_map(|directive| {
                let (name, seconds) = directive.trim().split_once('=')?;
                if name.trim().eq_ignore_ascii_case("max-age") {
                    seconds.trim().trim_matches('"').parse::<u64>().ok()
                } else {
                    None
                }
            })
        })
        .map_or(JWKS_DEFAULT_MAX_AGE, |seconds| {
            Duration::from_secs(seconds).clamp(JWKS_MIN_MAX_AGE, JWKS_MAX_MAX_AGE)
        })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/directory/src/backend/oidc/jwks/tests.rs"]
mod tests;
