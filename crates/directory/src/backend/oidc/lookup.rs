/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Account, Credentials,
    backend::oidc::{
        CLAIMS_MAX_SIZE, ERROR_MAX_SIZE, ExternalScopes, ExternalToken, IntrospectionAuth,
        OidcError, OpaqueValidation, OpenIdDirectory, TokenAccess, TokenContext, read_body,
    },
};
use jsonwebtoken::{Algorithm, Header, decode, decode_header, errors::ErrorKind};
use registry::schema::enums::OidcUnscopedTokenPolicy;
use reqwest::{
    Method, StatusCode,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};
use serde_json::Value;
use trc::AuthEvent;
use utils::HttpLimitResponse;

const CLIENT_CLAIMS: [&str; 4] = ["azp", "client_id", "cid", "appid"];
const ACCESS_TOKEN_CLAIMS: [&str; 5] = ["scope", "scp", "client_id", "cid", "appid"];
const NON_ACCESS_MARKERS: [(&str, &str); 12] = [
    ("typ", "id"),
    ("typ", "refresh"),
    ("typ", "offline"),
    ("token_use", "id"),
    ("token_use", "id_token"),
    ("token_use", "refresh"),
    ("token_use", "refresh_token"),
    ("tokenType", "id-token"),
    ("tokenType", "refresh-token"),
    ("type", "id-token"),
    ("token_type", "id_token"),
    ("token_type", "refresh_token"),
];

impl OpenIdDirectory {
    pub async fn authenticate(&self, _credentials: &Credentials) -> trc::Result<Account> {
        Err(AuthEvent::Error
            .into_err()
            .reason("Unsupported credentials type for OIDC backend"))
    }

    pub fn accepts_issuer(&self, issuer: &str) -> bool {
        self.issuers.iter().any(|accepted| accepted == issuer)
    }

    pub async fn authenticate_token(
        &self,
        token: &str,
        ctx: &TokenContext<'_>,
    ) -> trc::Result<ExternalToken> {
        if token.is_empty() {
            return Err(AuthEvent::Failed.into_err().reason("Empty token rejected"));
        }

        if let Ok(header) = decode_header(token) {
            self.authenticate_jwt(token, header, ctx).await
        } else {
            #[cfg(stalwart_tests)]
            let token = token.strip_prefix(".").unwrap_or(token);
            self.authenticate_opaque(token, ctx).await
        }
        .map_err(|err| match err {
            OidcError::AuthorizationFailed(reason) | OidcError::TokenValidation(reason) => {
                AuthEvent::Failed.into_err().reason(reason)
            }
            OidcError::TokenExpired(reason) => AuthEvent::TokenExpired.into_err().reason(reason),
            err => AuthEvent::Error.into_err().reason(err),
        })
    }

    async fn authenticate_jwt(
        &self,
        token: &str,
        header: Header,
        ctx: &TokenContext<'_>,
    ) -> Result<ExternalToken, OidcError> {
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(OidcError::TokenValidation(
                "Unsupported algorithm".to_string(),
            ));
        }

        let kid = header.kid.as_deref();
        let keys = self.signing_keys(kid).await?;
        let mut last_err = None;
        let mut claims = None;
        for (decoding_key, validation) in keys.candidates(kid) {
            match decode::<Value>(token, decoding_key, validation) {
                Ok(token_data) => {
                    claims = Some(token_data.claims);
                    break;
                }
                Err(err) => last_err = Some(err),
            }
        }
        drop(keys);

        let Some(mut claims) = claims else {
            return Err(match last_err {
                Some(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature
                    ) =>
                {
                    OidcError::TokenExpired(format!("JWT validation failed: {err}"))
                }
                Some(err) => OidcError::TokenValidation(format!("JWT validation failed: {err}")),
                None => OidcError::TokenValidation("Unknown key id".to_string()),
            });
        };

        check_token_type(
            header.typ.as_deref(),
            &claims,
            self.config.allow_id_token_claims,
        )?;
        self.check_audience(&claims, ctx)?;
        let access = self.token_access(client_claim(&claims)?, token_scopes(&claims), ctx)?;
        let expires_at = claims.get("exp").and_then(Value::as_u64);

        let username = self.resolve_username(&claims);
        let missing_username = is_claim_missing(&claims, Some(&self.config.claim_username));
        if (username.is_err()
            || missing_username
            || is_claim_missing(&claims, self.config.claim_name.as_deref())
            || is_claim_missing(&claims, self.config.claim_groups.as_deref()))
            && let Some(endpoint) = self.discovery.document.userinfo_endpoint.as_deref()
        {
            match self.fetch_userinfo(endpoint, token).await {
                Ok(Value::Object(userinfo)) => {
                    if let Value::Object(base) = &mut claims {
                        for (key, value) in userinfo {
                            if base.get(&key).is_none_or(Value::is_null) {
                                base.insert(key, value);
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(err) if username.is_err() => return Err(err),
                Err(_) => {}
            }
        }

        let username = match username {
            Ok(username) if !missing_username => username,
            _ => self.resolve_username(&claims)?,
        };

        Ok(ExternalToken {
            account: self.build_account(username, &claims),
            access,
            expires_at,
        })
    }

    async fn authenticate_opaque(
        &self,
        token: &str,
        ctx: &TokenContext<'_>,
    ) -> Result<ExternalToken, OidcError> {
        match &self.config.opaque_validation {
            OpaqueValidation::Reject => Err(OidcError::TokenValidation(
                "Opaque access tokens are not accepted, only JWT access tokens are validated"
                    .to_string(),
            )),
            OpaqueValidation::UserInfo => {
                let access = self.token_access(None, ExternalScopes::NONE, ctx)?;
                let endpoint = self
                    .discovery
                    .document
                    .userinfo_endpoint
                    .as_deref()
                    .ok_or_else(|| {
                        OidcError::Config("The IdP metadata has no userinfo_endpoint".to_string())
                    })?;
                let claims = self.fetch_userinfo(endpoint, token).await?;
                let username = self.resolve_username(&claims)?;
                Ok(ExternalToken {
                    account: self.build_account(username, &claims),
                    access,
                    expires_at: None,
                })
            }
            OpaqueValidation::Introspection(auth) => self.introspect(token, auth, ctx).await,
        }
    }

    async fn introspect(
        &self,
        token: &str,
        auth: &IntrospectionAuth,
        ctx: &TokenContext<'_>,
    ) -> Result<ExternalToken, OidcError> {
        let endpoint = self
            .discovery
            .document
            .introspection_endpoint
            .as_deref()
            .ok_or_else(|| {
                OidcError::Config("The IdP metadata has no introspection_endpoint".to_string())
            })?;

        let mut body = String::with_capacity(token.len() + 64);
        body.push_str("token=");
        body.extend(form_urlencoded::byte_serialize(token.as_bytes()));
        body.push_str("&token_type_hint=access_token");
        let mut request = self
            .http
            .request(Method::POST, endpoint)
            .map_err(|err| OidcError::Config(format!("Invalid introspection URL: {err}")))?
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json");
        match auth {
            IntrospectionAuth::Basic { authorization } => {
                request = request.header(AUTHORIZATION, authorization.as_ref());
            }
            IntrospectionAuth::Post { credentials } => body.push_str(credentials),
            IntrospectionAuth::Unauthenticated => {}
        }

        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("Introspection request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(OidcError::Provider(format!(
                "Introspection endpoint returned HTTP {status}"
            )));
        }
        let bytes = read_body(response, CLAIMS_MAX_SIZE, "Introspection").await?;
        let claims = serde_json::from_slice::<Value>(&bytes)
            .map_err(|e| OidcError::Provider(format!("Introspection JSON parse error: {e}")))?;

        if claims.get("active").and_then(Value::as_bool) != Some(true) {
            return Err(OidcError::TokenValidation(
                "Token is not active".to_string(),
            ));
        }
        if has_non_access_marker(&claims) {
            return Err(OidcError::TokenValidation(
                "Introspected token is not an access token".to_string(),
            ));
        }
        if let Some(issuer) = claims.get("iss").and_then(Value::as_str)
            && !self.accepts_issuer(issuer)
        {
            return Err(OidcError::TokenValidation(format!(
                "Introspected token was issued by '{issuer}'"
            )));
        }

        self.check_audience(&claims, ctx)?;
        let access = self.token_access(client_claim(&claims)?, token_scopes(&claims), ctx)?;
        let username = self.resolve_username(&claims)?;

        Ok(ExternalToken {
            account: self.build_account(username, &claims),
            access,
            expires_at: claims.get("exp").and_then(Value::as_u64),
        })
    }

    fn check_audience(&self, claims: &Value, ctx: &TokenContext<'_>) -> Result<(), OidcError> {
        if self.config.skip_audience_validation {
            return Ok(());
        }
        let is_accepted = |audience: &str| {
            self.config
                .accepted_audiences
                .iter()
                .any(|accepted| accepted.as_ref() == audience)
                || (ctx.is_resource)(audience)
        };
        let accepted = match claims.get("aud") {
            Some(Value::String(audience)) => is_accepted(audience),
            Some(Value::Array(audiences)) => {
                audiences.iter().filter_map(Value::as_str).any(is_accepted)
            }
            _ => false,
        };
        if accepted {
            Ok(())
        } else {
            Err(OidcError::AuthorizationFailed(format!(
                "Token audience {} matches neither a resource identifier of this server nor acceptedAudiences",
                claims.get("aud").unwrap_or(&Value::Null)
            )))
        }
    }

    fn token_access(
        &self,
        client_id: Option<&str>,
        scopes: ExternalScopes,
        ctx: &TokenContext<'_>,
    ) -> Result<TokenAccess, OidcError> {
        if client_id.is_some_and(|client_id| (ctx.is_first_party)(client_id)) {
            Ok(TokenAccess::Unrestricted)
        } else if !scopes.is_empty() {
            Ok(TokenAccess::Scoped(scopes))
        } else {
            match self.config.unscoped_tokens {
                OidcUnscopedTokenPolicy::Reject => Err(OidcError::AuthorizationFailed(
                    "Token carries none of the urn:ietf:params:oauth:scope:{mail,contacts,calendars,files} or urn:stalwart:oauth:scope:{full,security,settings} scopes and unscopedTokens is set to reject".to_string(),
                )),
                OidcUnscopedTokenPolicy::Interoperable => {
                    Ok(TokenAccess::Scoped(ExternalScopes::ALL))
                }
                OidcUnscopedTokenPolicy::Full => Ok(TokenAccess::Unrestricted),
            }
        }
    }

    async fn fetch_userinfo(&self, endpoint: &str, token: &str) -> Result<Value, OidcError> {
        let resp = self
            .http
            .request(Method::GET, endpoint)
            .map_err(|err| OidcError::Config(format!("Invalid UserInfo URL: {err}")))?
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("UserInfo request failed: {e}")))?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let reason = resp
                .bytes_with_limit(ERROR_MAX_SIZE)
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            return Err(OidcError::AuthorizationFailed(format!(
                "Token rejected by UserInfo endpoint with status {status}: {}",
                String::from_utf8_lossy(&reason)
            )));
        }
        if !status.is_success() {
            return Err(OidcError::Provider(format!(
                "UserInfo returned HTTP {status}"
            )));
        }

        let bytes = read_body(resp, CLAIMS_MAX_SIZE, "UserInfo").await?;

        serde_json::from_slice::<Value>(&bytes)
            .map_err(|e| OidcError::Provider(format!("UserInfo JSON parse error: {e}")))
    }

    fn build_account(&self, email: String, claims: &Value) -> Account {
        Account {
            email,
            email_aliases: Vec::new(),
            secret: None,
            groups: self
                .config
                .claim_groups
                .as_ref()
                .and_then(|groups_claim| claims.get(groups_claim))
                .and_then(extract_string_list)
                .map(|groups| {
                    groups
                        .into_iter()
                        .map(|group| match &self.config.username_domain {
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
                .filter(|name| !name.is_empty())
                .map(|s| s.to_string()),
        }
    }

    fn resolve_username(&self, claims: &Value) -> Result<String, OidcError> {
        if let Some(val) = claims
            .get(&self.config.claim_username)
            .and_then(|v| v.as_str())
        {
            if val.contains('@') {
                return Ok(val.to_string());
            }
            if let Some(domain) = &self.config.username_domain {
                return Ok(format!("{val}@{domain}"));
            }
        }

        if self.config.claim_username != "email"
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

fn check_token_type(
    header_typ: Option<&str>,
    claims: &Value,
    allow_id_token_claims: bool,
) -> Result<(), OidcError> {
    let claim_is = |name: &str, value: &str| claim_equals(claims, name, value);

    if has_non_access_marker(claims) {
        Err(OidcError::TokenValidation(
            "ID and refresh tokens are not accepted as access tokens".to_string(),
        ))
    } else if header_typ.is_some_and(|typ| {
        typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt")
    }) || claim_is("typ", "bearer")
        || claim_is("token_use", "access")
        || claim_is("tokenType", "access-token")
        || allow_id_token_claims
    {
        Ok(())
    } else if claims.get("nonce").is_some() || claims.get("at_hash").is_some() {
        Err(OidcError::TokenValidation(
            "Token carries ID token claims (nonce or at_hash), enable allowIdTokenClaims if the IdP issues such access tokens".to_string(),
        ))
    } else if ACCESS_TOKEN_CLAIMS
        .iter()
        .any(|claim| claims.get(claim).is_some_and(|value| !value.is_null()))
    {
        Ok(())
    } else {
        Err(OidcError::TokenValidation(
            "Token has no scope or client_id claim and may be an ID token, enable allowIdTokenClaims if the IdP issues such access tokens".to_string(),
        ))
    }
}

fn claim_equals(claims: &Value, name: &str, value: &str) -> bool {
    claims
        .get(name)
        .and_then(Value::as_str)
        .is_some_and(|claim| claim.eq_ignore_ascii_case(value))
}

fn has_non_access_marker(claims: &Value) -> bool {
    NON_ACCESS_MARKERS
        .iter()
        .any(|(name, value)| claim_equals(claims, name, value))
}

fn client_claim(claims: &Value) -> Result<Option<&str>, OidcError> {
    let mut client_id = None;
    for value in CLIENT_CLAIMS
        .iter()
        .filter_map(|claim| claims.get(claim).and_then(Value::as_str))
    {
        match client_id {
            None => client_id = Some(value),
            Some(previous) if previous == value => {}
            Some(_) => {
                return Err(OidcError::TokenValidation(
                    "Token carries conflicting client claims".to_string(),
                ));
            }
        }
    }
    Ok(client_id)
}

fn token_scopes(claims: &Value) -> ExternalScopes {
    let mut scopes = ExternalScopes::NONE;
    match claims
        .get("scope")
        .filter(|value| !value.is_null())
        .or_else(|| claims.get("scp"))
    {
        Some(Value::String(names)) => {
            for name in names.split_ascii_whitespace() {
                scopes.insert(ExternalScopes::from_name(name));
            }
        }
        Some(Value::Array(names)) => {
            for name in names.iter().filter_map(Value::as_str) {
                scopes.insert(ExternalScopes::from_name(name));
            }
        }
        _ => {}
    }
    scopes
}

fn extract_string_list(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Array(arr) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
        ),
        Value::String(s) => Some(s.split_whitespace().map(|s| s.to_string()).collect()),
        Value::Object(map) => Some(map.keys().cloned().collect()),
        _ => None,
    }
}

fn is_claim_missing(claims: &Value, claim: Option<&str>) -> bool {
    claim.is_some_and(|claim| claims.get(claim).is_none_or(Value::is_null))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/directory/src/backend/oidc/lookup/tests.rs"]
mod tests;
