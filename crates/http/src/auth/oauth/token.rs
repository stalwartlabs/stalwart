/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedOAuthStatus, ArchivedPkceCodeChallenge, ErrorType, FormData, MAX_POST_LEN, OAuthCode,
    OAuthResponse, OAuthStatus, TokenResponse, authorize::issuer,
    registration::ClientRegistrationHandler, request_origin,
};
use crate::{api::BASIC_CHALLENGE, auth::authenticate::HttpHeaders};
use common::{
    KV_OAUTH, Server,
    auth::{
        RECOVERY_ADMIN_ID,
        oauth::{
            GrantType,
            client::{ResolveContext, ResolveMode, ResolvedClient},
            grant::{GrantDeletion, GrantRotation, NewOAuthGrant, RECOVERY_ADMIN_GRANT_ID},
            oidc::StandardClaims,
            registration::GRANT_TYPE_DEVICE_CODE,
            scope::OAuthScopes,
            token::{RefreshTokenParams, TokenGrant},
        },
    },
    cache::invalidate::CacheInvalidationBuilder,
};
use encodify::base64::{STANDARD, URL_SAFE_NO_PAD};
use http_proto::*;
use hyper::{StatusCode, header::WWW_AUTHENTICATE};
use percent_encoding::percent_decode_str;
use registry::schema::enums::OAuthGrantType;
use sha2::{Digest, Sha256, digest::Output};
use std::{borrow::Cow, future::Future, net::IpAddr};
use store::{
    dispatch::lookup::KeyValue,
    write::{Archive, ArchiveBytes, now},
};
use trc::AddContext;

pub trait TokenHandler: Sync + Send {
    fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_token_introspect(
        &self,
        req: &mut HttpRequest,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_token_revocation(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn consume_oauth_code(&self, code: &str) -> impl Future<Output = trc::Result<bool>> + Send;

    fn authenticate_token_client(
        &self,
        client_id: &str,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
    ) -> impl Future<Output = trc::Result<Result<ResolvedClient, ErrorType>>> + Send;

    fn resolve_token_client(
        &self,
        client_id: &str,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        grant: OAuthGrantType,
    ) -> impl Future<Output = trc::Result<Result<ResolvedClient, ErrorType>>> + Send;

    fn authorization_code_grant(
        &self,
        params: &FormData,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        issuer: &str,
    ) -> impl Future<Output = trc::Result<TokenResponse>> + Send;

    fn device_code_grant(
        &self,
        params: &FormData,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        issuer: &str,
    ) -> impl Future<Output = trc::Result<TokenResponse>> + Send;

    fn refresh_token_grant(
        &self,
        params: &FormData,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<TokenResponse>> + Send;

    fn issue_new_grant(
        &self,
        request: NewGrantRequest<'_>,
    ) -> impl Future<Output = trc::Result<TokenResponse>> + Send;

    fn grant_response(&self, response: GrantResponse<'_>) -> trc::Result<OAuthResponse>;
}

impl TokenHandler for Server {
    async fn consume_oauth_code(&self, code: &str) -> trc::Result<bool> {
        self.in_memory_store()
            .key_delete(KeyValue::<()>::build_key(KV_OAUTH, code.as_bytes()))
            .await
    }

    async fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let params = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let credentials = ClientCredentials::new(req, &params);
        let origin = request_origin(req, &session);
        let issuer = issuer(self, origin);
        let ctx = ResolveContext {
            mode: ResolveMode::Token,
            origin: Some(origin),
            remote_ip: session.remote_ip,
        };
        let grant_type = params.get("grant_type").unwrap_or_default();

        let response = if credentials.is_ambiguous {
            TokenResponse::error(ErrorType::InvalidRequest)
        } else if grant_type.eq_ignore_ascii_case("authorization_code") {
            self.authorization_code_grant(&params, &credentials, &ctx, &issuer)
                .await?
        } else if grant_type.eq_ignore_ascii_case(GRANT_TYPE_DEVICE_CODE) {
            self.device_code_grant(&params, &credentials, &ctx, &issuer)
                .await?
        } else if grant_type.eq_ignore_ascii_case("refresh_token") {
            self.refresh_token_grant(&params, &credentials, &ctx, session.session_id)
                .await?
        } else {
            TokenResponse::error(ErrorType::UnsupportedGrantType)
        };

        Ok(token_response(response, credentials.used_basic))
    }

    async fn handle_token_introspect(
        &self,
        req: &mut HttpRequest,
        session_id: u64,
    ) -> trc::Result<HttpResponse> {
        // Parse token
        let token = FormData::from_request(req, 1024, session_id)
            .await?
            .remove("token")
            .ok_or_else(|| {
                trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("Client ID is missing.")
            })?;

        self.introspect_access_token(&token)
            .await
            .map(|response| JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn handle_token_revocation(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let params = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let credentials = ClientCredentials::new(req, &params);
        let token = match params.get("token") {
            Some(token) if !token.is_empty() && !credentials.is_ambiguous => token,
            _ => {
                return Ok(token_response(
                    TokenResponse::error(ErrorType::InvalidRequest),
                    credentials.used_basic,
                ));
            }
        };
        let Some(client_id) = credentials.client_id.as_deref() else {
            return Ok(token_response(
                TokenResponse::error(ErrorType::InvalidClient),
                credentials.used_basic,
            ));
        };

        let Some((account_id, grant)) = self
            .decode_access_token(None, token)
            .ok()
            .filter(|info| {
                matches!(
                    info.grant_type,
                    GrantType::AccessToken | GrantType::RefreshToken
                )
            })
            .and_then(|info| info.grant.map(|grant| (info.account_id, grant)))
        else {
            return Ok(revocation_response());
        };
        let Some(stored) = self.oauth_grant(grant.id).await?.filter(|stored| {
            stored.account_id() == account_id && stored.grant.client_id == client_id
        }) else {
            return Ok(revocation_response());
        };

        let ctx = ResolveContext {
            mode: ResolveMode::Token,
            origin: Some(request_origin(req, &session)),
            remote_ip: session.remote_ip,
        };
        if let Err(error) = self
            .authenticate_token_client(client_id, &credentials, &ctx)
            .await?
        {
            return Ok(token_response(
                TokenResponse::error(error),
                credentials.used_basic,
            ));
        }

        let mut invalidator = CacheInvalidationBuilder::default();
        self.delete_oauth_grant(stored, GrantDeletion::Unconditional, &mut invalidator)
            .await?;
        self.invalidate_caches(invalidator).await?;

        Ok(revocation_response())
    }

    async fn authenticate_token_client(
        &self,
        client_id: &str,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
    ) -> trc::Result<Result<ResolvedClient, ErrorType>> {
        let client = match self.resolve_oauth_client(client_id, ctx).await? {
            Ok(client) => client,
            Err(_) => return Ok(Err(ErrorType::InvalidClient)),
        };
        if let Some(error) = self
            .verify_client_secret(&client, credentials.client_secret.as_deref(), ctx.remote_ip)
            .await?
        {
            Ok(Err(error))
        } else {
            Ok(Ok(client))
        }
    }

    async fn resolve_token_client(
        &self,
        client_id: &str,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        grant: OAuthGrantType,
    ) -> trc::Result<Result<ResolvedClient, ErrorType>> {
        match self
            .authenticate_token_client(client_id, credentials, ctx)
            .await?
        {
            Ok(client) if !client.allows_grant(grant) => Ok(Err(ErrorType::UnauthorizedClient)),
            result => Ok(result),
        }
    }

    async fn authorization_code_grant(
        &self,
        params: &FormData,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        issuer: &str,
    ) -> trc::Result<TokenResponse> {
        let (Some(code), Some(client_id), Some(redirect_uri)) = (
            params.get("code"),
            credentials.client_id.as_deref(),
            params.get("redirect_uri").filter(|uri| !uri.is_empty()),
        ) else {
            return Ok(TokenResponse::error(ErrorType::InvalidRequest));
        };

        let Some(auth_code_) = self
            .in_memory_store()
            .key_get::<Archive<ArchiveBytes>>(KeyValue::<()>::build_key(KV_OAUTH, code.as_bytes()))
            .await?
        else {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        };
        let oauth = auth_code_
            .unarchive::<OAuthCode>()
            .caused_by(trc::location!())?;
        if oauth.status != OAuthStatus::Authorized
            || client_id != oauth.client_id
            || redirect_uri != oauth.params
        {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }

        let client = match self
            .resolve_token_client(
                client_id,
                credentials,
                ctx,
                OAuthGrantType::AuthorizationCode,
            )
            .await?
        {
            Ok(client) => client,
            Err(error) => return Ok(TokenResponse::error(error)),
        };

        if !verify_pkce(
            &oauth.code_challenge,
            params.get("code_verifier"),
            client.is_confidential(),
        ) || !self.consume_oauth_code(code).await?
        {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }

        self.issue_new_grant(NewGrantRequest {
            account_id: oauth.account_id.into(),
            credential_version: oauth.credential_version.into(),
            client_id: oauth.client_id.as_str(),
            client: &client,
            scope: oauth.scope.as_ref().map(|s| s.as_str()),
            nonce: oauth.nonce.as_ref().map(|s| s.as_str()),
            issuer,
            remote_ip: ctx.remote_ip,
        })
        .await
    }

    async fn device_code_grant(
        &self,
        params: &FormData,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        issuer: &str,
    ) -> trc::Result<TokenResponse> {
        let (Some(device_code), Some(client_id)) =
            (params.get("device_code"), credentials.client_id.as_deref())
        else {
            return Ok(TokenResponse::error(ErrorType::InvalidRequest));
        };

        let Some(auth_code_) = self
            .in_memory_store()
            .key_get::<Archive<ArchiveBytes>>(KeyValue::<()>::build_key(
                KV_OAUTH,
                device_code.as_bytes(),
            ))
            .await?
        else {
            return Ok(TokenResponse::error(ErrorType::ExpiredToken));
        };
        let oauth = auth_code_
            .unarchive::<OAuthCode>()
            .caused_by(trc::location!())?;
        if oauth.client_id != client_id {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }

        let client = match self
            .resolve_token_client(client_id, credentials, ctx, OAuthGrantType::DeviceCode)
            .await?
        {
            Ok(client) => client,
            Err(error) => return Ok(TokenResponse::error(error)),
        };

        match oauth.status {
            ArchivedOAuthStatus::Authorized => {
                if oauth.params.is_empty() && self.consume_oauth_code(device_code).await? {
                    self.issue_new_grant(NewGrantRequest {
                        account_id: oauth.account_id.into(),
                        credential_version: oauth.credential_version.into(),
                        client_id: oauth.client_id.as_str(),
                        client: &client,
                        scope: oauth.scope.as_ref().map(|s| s.as_str()),
                        nonce: oauth.nonce.as_ref().map(|s| s.as_str()),
                        issuer,
                        remote_ip: ctx.remote_ip,
                    })
                    .await
                } else {
                    Ok(TokenResponse::error(ErrorType::InvalidGrant))
                }
            }
            ArchivedOAuthStatus::Pending => {
                Ok(TokenResponse::error(ErrorType::AuthorizationPending))
            }
            ArchivedOAuthStatus::Denied => Ok(TokenResponse::error(ErrorType::AccessDenied)),
            ArchivedOAuthStatus::TokenIssued => Ok(TokenResponse::error(ErrorType::ExpiredToken)),
            ArchivedOAuthStatus::ConsentPending => {
                Ok(TokenResponse::error(ErrorType::InvalidGrant))
            }
        }
    }

    async fn refresh_token_grant(
        &self,
        params: &FormData,
        credentials: &ClientCredentials<'_>,
        ctx: &ResolveContext<'_>,
        session_id: u64,
    ) -> trc::Result<TokenResponse> {
        let (Some(refresh_token), Some(client_id)) = (
            params.get("refresh_token"),
            credentials.client_id.as_deref(),
        ) else {
            return Ok(TokenResponse::error(ErrorType::InvalidRequest));
        };

        let token_info = match self
            .validate_access_token(GrantType::RefreshToken.into(), refresh_token)
            .await
        {
            Ok(token_info) => token_info,
            Err(err) => {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to validate refresh token")
                        .span_id(session_id)
                );
                return Ok(TokenResponse::error(ErrorType::InvalidGrant));
            }
        };

        let Some(presented) = token_info.grant else {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        };
        let Some(stored) = self
            .oauth_grant(presented.id)
            .await?
            .filter(|stored| stored.account_id() == token_info.account_id)
        else {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        };
        if stored.grant.client_id != client_id {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }

        let client = match self
            .resolve_token_client(client_id, credentials, ctx, OAuthGrantType::RefreshToken)
            .await?
        {
            Ok(client) => client,
            Err(error) => return Ok(TokenResponse::error(error)),
        };
        if client.kind() != stored.grant.client_kind
            || (!matches!(client, ResolvedClient::Cimd(None))
                && client.allowed_scopes().is_some_and(|allowed| {
                    !allowed.contains(OAuthScopes::from_registry(stored.grant.scopes.iter()))
                }))
        {
            let mut invalidator = CacheInvalidationBuilder::default();
            self.delete_oauth_grant(stored, GrantDeletion::Unconditional, &mut invalidator)
                .await?;
            self.invalidate_caches(invalidator).await?;
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }

        let granted_scope = token_info.claims.as_deref().unwrap_or_default();
        if params
            .get("scope")
            .is_some_and(|requested| !is_scope_subset(requested, granted_scope))
        {
            return Ok(TokenResponse::error(ErrorType::InvalidScope));
        }

        if token_info.credential_expired
            && !client.is_first_party()
            && stored.is_current(presented.generation)
        {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }

        match self
            .rotate_oauth_grant(stored, presented.generation)
            .await?
        {
            GrantRotation::Issue { next, rotated_at } => {
                let account = self
                    .account(token_info.account_id)
                    .await
                    .caused_by(trc::location!())?;
                self.grant_response(GrantResponse {
                    account_id: token_info.account_id,
                    account_name: account.name(),
                    credential_version: token_info.credential_version,
                    refresh: next,
                    rotated_at,
                    scope: granted_scope,
                    id_token: None,
                })
                .map(TokenResponse::Granted)
            }
            GrantRotation::Revoked | GrantRotation::Rejected => {
                Ok(TokenResponse::error(ErrorType::InvalidGrant))
            }
        }
    }

    async fn issue_new_grant(&self, request: NewGrantRequest<'_>) -> trc::Result<TokenResponse> {
        let account_id = request.account_id;
        let scope = request.scope.unwrap_or_default();
        let scopes = OAuthScopes::parse(scope);
        let access_token = self
            .access_token(account_id)
            .await
            .caused_by(trc::location!())?;
        let credential_version = access_token.credential_version();
        if credential_version != request.credential_version
            || (!request.client.is_first_party() && access_token.is_main_credential_expired())
        {
            return Ok(TokenResponse::error(ErrorType::InvalidGrant));
        }
        let grant_id = match self
            .create_oauth_grant(NewOAuthGrant {
                account_id,
                client_id: request.client_id,
                client_name: request.client.display_name(),
                client_kind: request.client.kind(),
                scopes: scopes.interoperable(),
                remote_ip: request.remote_ip,
            })
            .await
        {
            Ok(grant_id) => grant_id,
            Err(_) if account_id == RECOVERY_ADMIN_ID => RECOVERY_ADMIN_GRANT_ID,
            Err(err) => return Err(err),
        };

        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let id_token = if scopes.contains(OAuthScopes::OPENID) {
            match self.issue_id_token(
                account_id.to_string(),
                request.issuer,
                request.client_id,
                StandardClaims {
                    nonce: request.nonce.map(str::to_string),
                    preferred_username: account.name().to_string().into(),
                    email: account.name().to_string().into(),
                    email_verified: true,
                    name: account.description().map(|d| d.to_string()),
                },
            ) {
                Ok(id_token) => Some(id_token),
                Err(err) => {
                    trc::error!(err);
                    None
                }
            }
        } else {
            None
        };

        self.grant_response(GrantResponse {
            account_id,
            account_name: account.name(),
            credential_version,
            refresh: TokenGrant {
                id: grant_id,
                generation: 0,
            },
            rotated_at: now(),
            scope,
            id_token,
        })
        .map(|mut response| {
            if grant_id == RECOVERY_ADMIN_GRANT_ID {
                response.refresh_token = None;
            }
            TokenResponse::Granted(response)
        })
    }

    fn grant_response(&self, response: GrantResponse<'_>) -> trc::Result<OAuthResponse> {
        let account_name = response.account_name;

        Ok(OAuthResponse {
            access_token: self.encode_grant_access_token(
                response.account_id,
                account_name,
                response.refresh.id,
                response.credential_version,
            )?,
            token_type: "bearer".to_string(),
            expires_in: self.core.oauth.oauth_expiry_token,
            refresh_token: self
                .encode_refresh_token(RefreshTokenParams {
                    account_id: response.account_id,
                    account_name,
                    grant: response.refresh,
                    rotated_at: response.rotated_at,
                    credential_version: response.credential_version,
                    scope: Some(response.scope),
                })?
                .into(),
            scope: response.scope.to_string(),
            username: account_name.to_string(),
            id_token: response.id_token,
        })
    }
}

fn is_scope_subset(requested: &str, granted: &str) -> bool {
    let granted_scopes = OAuthScopes::parse(granted);
    requested.split_ascii_whitespace().all(|name| {
        let scope = OAuthScopes::from_name(name);
        if scope.is_empty() {
            granted
                .split_ascii_whitespace()
                .any(|granted| granted == name)
        } else {
            granted_scopes.contains(scope)
        }
    })
}

pub struct NewGrantRequest<'x> {
    account_id: u32,
    credential_version: u64,
    client_id: &'x str,
    client: &'x ResolvedClient,
    scope: Option<&'x str>,
    nonce: Option<&'x str>,
    issuer: &'x str,
    remote_ip: IpAddr,
}

pub struct GrantResponse<'x> {
    account_id: u32,
    account_name: &'x str,
    credential_version: u64,
    refresh: TokenGrant,
    rotated_at: u64,
    scope: &'x str,
    id_token: Option<String>,
}

fn revocation_response() -> HttpResponse {
    HttpResponse::new(StatusCode::OK).with_no_store()
}

pub(crate) fn token_response(response: TokenResponse, used_basic: bool) -> HttpResponse {
    let status = match &response {
        TokenResponse::Granted(_) => StatusCode::OK,
        TokenResponse::Error {
            error: ErrorType::InvalidClient,
        } => StatusCode::UNAUTHORIZED,
        TokenResponse::Error { .. } => StatusCode::BAD_REQUEST,
    };
    let response = JsonResponse::with_status(status, response)
        .no_cache()
        .into_http_response();
    if status == StatusCode::UNAUTHORIZED && used_basic {
        response.with_header(WWW_AUTHENTICATE, BASIC_CHALLENGE)
    } else {
        response
    }
}

pub struct ClientCredentials<'x> {
    pub client_id: Option<Cow<'x, str>>,
    pub client_secret: Option<Cow<'x, str>>,
    pub used_basic: bool,
    pub is_ambiguous: bool,
}

impl<'x> ClientCredentials<'x> {
    pub fn new(req: &'x HttpRequest, params: &'x FormData) -> Self {
        Self::parse(
            params.get("client_id"),
            params.get("client_secret"),
            req.authorization_basic(),
        )
    }

    fn parse(body_id: Option<&'x str>, body_secret: Option<&'x str>, basic: Option<&str>) -> Self {
        let mut credentials = ClientCredentials {
            client_id: body_id.filter(|id| !id.is_empty()).map(Cow::Borrowed),
            client_secret: body_secret
                .filter(|secret| !secret.is_empty())
                .map(Cow::Borrowed),
            used_basic: basic.is_some(),
            is_ambiguous: false,
        };
        let Some(basic) = basic else {
            return credentials;
        };
        credentials.is_ambiguous = credentials.client_secret.is_some();

        if let Ok(creds) = STANDARD.decode_to_string(basic)
            && let Some((id, secret)) = creds.split_once(':')
        {
            if !id.is_empty() {
                let id = form_decode(id);
                match &credentials.client_id {
                    Some(body_id) => credentials.is_ambiguous |= body_id.as_ref() != id,
                    None => credentials.client_id = Some(Cow::Owned(id)),
                }
            }
            if credentials.client_secret.is_none() && !secret.is_empty() {
                credentials.client_secret = Some(Cow::Owned(form_decode(secret)));
            }
        }

        credentials
    }
}

fn form_decode(value: &str) -> String {
    let value = if value.contains('+') {
        Cow::Owned(value.replace('+', " "))
    } else {
        Cow::Borrowed(value)
    };
    percent_decode_str(&value).decode_utf8_lossy().into_owned()
}

const PKCE_S256_LEN: usize = URL_SAFE_NO_PAD.encoded_len(size_of::<Output<Sha256>>());

fn verify_pkce(
    stored: &ArchivedPkceCodeChallenge,
    verifier: Option<&str>,
    is_confidential: bool,
) -> bool {
    let is_valid_pkce_challenge = |challenge: &str| {
        (43..=128).contains(&challenge.len())
            && challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    };
    let constant_time_eq = |a: &[u8], b: &[u8]| {
        if a.len() != b.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    };

    match (stored, verifier) {
        (ArchivedPkceCodeChallenge::None, None) => is_confidential,
        (ArchivedPkceCodeChallenge::S256(expected), Some(verifier))
            if is_valid_pkce_challenge(verifier) =>
        {
            let digest = Sha256::digest(verifier.as_bytes());
            let mut computed = [0u8; PKCE_S256_LEN];
            URL_SAFE_NO_PAD
                .encode_str(digest, &mut computed)
                .is_ok_and(|computed| constant_time_eq(expected.as_bytes(), computed.as_bytes()))
        }
        _ => false,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/http/src/auth/oauth/token/tests.rs"]
mod tests;
