/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedOAuthStatus, ArchivedPkceCodeChallenge, ErrorType, FormData, MAX_POST_LEN, OAuthCode,
    OAuthResponse, OAuthStatus, TokenResponse, registration::ClientRegistrationHandler,
};
use crate::auth::authenticate::HttpHeaders;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use common::{
    KV_OAUTH, Server,
    auth::{
        AccessToken,
        oauth::{GrantType, oidc::StandardClaims},
    },
};
use http_proto::*;
use hyper::StatusCode;
use sha2::{Digest, Sha256};
use std::{borrow::Cow, future::Future};
use store::{
    dispatch::lookup::KeyValue,
    write::{AlignedBytes, Archive},
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
        access_token: &AccessToken,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        issuer: String,
        nonce: Option<String>,
        scope: Option<String>,
        with_refresh_token: bool,
        with_id_token: bool,
    ) -> impl Future<Output = trc::Result<OAuthResponse>> + Send;
}

impl TokenHandler for Server {
    // Token endpoint
    async fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        // Parse form
        let params = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let grant_type = params.get("grant_type").unwrap_or_default();
        let (client_id_cred, client_secret_cred) = client_credentials(req, &params);

        let mut response = TokenResponse::error(ErrorType::InvalidGrant);

        let issuer = self.core.network.http.url_https.to_string();

        if grant_type.eq_ignore_ascii_case("authorization_code") {
            response = if let (Some(code), Some(client_id), Some(redirect_uri)) = (
                params.get("code"),
                client_id_cred.as_deref(),
                params.get("redirect_uri"),
            ) {
                // Obtain code
                match self
                    .in_memory_store()
                    .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                        KV_OAUTH,
                        code.as_bytes(),
                    ))
                    .await?
                {
                    Some(auth_code_) => {
                        let oauth = auth_code_
                            .unarchive::<OAuthCode>()
                            .caused_by(trc::location!())?;
                        if client_id != oauth.client_id || redirect_uri != oauth.params {
                            TokenResponse::error(ErrorType::InvalidClient)
                        } else if !verify_pkce(&oauth.code_challenge, params.get("code_verifier")) {
                            TokenResponse::error(ErrorType::InvalidGrant)
                        } else if oauth.status == OAuthStatus::Authorized {
                            // Validate client id
                            if let Some(error) = self
                                .validate_client_registration(
                                    client_id,
                                    redirect_uri.into(),
                                    oauth.account_id.into(),
                                )
                                .await?
                            {
                                TokenResponse::error(error)
                            } else if let Some(error) = self
                                .verify_client_secret(client_id, client_secret_cred.as_deref())
                                .await?
                            {
                                TokenResponse::error(error)
                            } else {
                                // Mark this token as issued
                                self.in_memory_store()
                                    .key_delete(KeyValue::<()>::build_key(
                                        KV_OAUTH,
                                        code.as_bytes(),
                                    ))
                                    .await?;

                                // Issue token
                                self.issue_token(
                                    oauth.account_id.into(),
                                    &oauth.client_id,
                                    issuer,
                                    oauth.nonce.as_ref().map(|s| s.as_str().into()),
                                    oauth.scope.as_ref().map(|s| s.as_str().into()),
                                    true,
                                    true,
                                )
                                .await
                                .map(TokenResponse::Granted)
                                .map_err(|err| {
                                    trc::AuthEvent::Error
                                        .into_err()
                                        .details(err)
                                        .caused_by(trc::location!())
                                })?
                            }
                        } else {
                            TokenResponse::error(ErrorType::InvalidGrant)
                        }
                    }
                    None => TokenResponse::error(ErrorType::AccessDenied),
                }
            } else {
                TokenResponse::error(ErrorType::InvalidClient)
            };
        } else if grant_type.eq_ignore_ascii_case("urn:ietf:params:oauth:grant-type:device_code") {
            response = TokenResponse::error(ErrorType::ExpiredToken);

            if let (Some(device_code), Some(client_id)) =
                (params.get("device_code"), params.get("client_id"))
            {
                // Obtain code
                if let Some(auth_code_) = self
                    .in_memory_store()
                    .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                        KV_OAUTH,
                        device_code.as_bytes(),
                    ))
                    .await?
                {
                    let oauth = auth_code_
                        .unarchive::<OAuthCode>()
                        .caused_by(trc::location!())?;
                    response = if oauth.client_id != client_id {
                        TokenResponse::error(ErrorType::InvalidClient)
                    } else {
                        match oauth.status {
                            ArchivedOAuthStatus::Authorized => {
                                if let Some(error) = self
                                    .validate_client_registration(
                                        client_id,
                                        None,
                                        oauth.account_id.into(),
                                    )
                                    .await?
                                {
                                    TokenResponse::error(error)
                                } else {
                                    // Mark this token as issued
                                    self.in_memory_store()
                                        .key_delete(KeyValue::<()>::build_key(
                                            KV_OAUTH,
                                            device_code.as_bytes(),
                                        ))
                                        .await?;

                                    // Issue token
                                    self.issue_token(
                                        oauth.account_id.into(),
                                        &oauth.client_id,
                                        issuer,
                                        oauth.nonce.as_ref().map(|s| s.as_str().into()),
                                        oauth.scope.as_ref().map(|s| s.as_str().into()),
                                        true,
                                        true,
                                    )
                                    .await
                                    .map(TokenResponse::Granted)
                                    .map_err(|err| {
                                        trc::AuthEvent::Error
                                            .into_err()
                                            .details(err)
                                            .caused_by(trc::location!())
                                    })?
                                }
                            }
                            ArchivedOAuthStatus::Pending => {
                                TokenResponse::error(ErrorType::AuthorizationPending)
                            }
                            ArchivedOAuthStatus::TokenIssued => {
                                TokenResponse::error(ErrorType::ExpiredToken)
                            }
                        }
                    };
                }
            }
        } else if grant_type.eq_ignore_ascii_case("refresh_token") {
            if let Some(refresh_token) = params.get("refresh_token") {
                if let Some(client_id) = client_id_cred.as_deref()
                    && let Some(error) = self
                        .verify_client_secret(client_id, client_secret_cred.as_deref())
                        .await?
                {
                    return Ok(JsonResponse::with_status(
                        StatusCode::BAD_REQUEST,
                        TokenResponse::error(error),
                    )
                    .into_http_response());
                }
                response = match self
                    .validate_access_token(GrantType::RefreshToken.into(), refresh_token)
                    .await
                {
                    Ok(token_info) => self
                        .issue_token(
                            token_info.account_id,
                            "",
                            issuer,
                            None,
                            None,
                            token_info.expires_in
                                <= self.core.oauth.oauth_expiry_refresh_token_renew,
                            false,
                        )
                        .await
                        .map(TokenResponse::Granted)
                        .map_err(|err| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details(err)
                                .caused_by(trc::location!())
                        })?,
                    Err(err) => {
                        trc::error!(
                            err.caused_by(trc::location!())
                                .details("Failed to validate refresh token")
                                .span_id(session.session_id)
                        );
                        TokenResponse::error(ErrorType::InvalidGrant)
                    }
                };
            } else {
                response = TokenResponse::error(ErrorType::InvalidRequest);
            }
        }

        Ok(JsonResponse::with_status(
            if response.is_error() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            },
            response,
        )
        .into_http_response())
    }

    async fn handle_token_introspect(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
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

        self.introspect_access_token(&token, access_token)
            .await
            .map(|response| JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        issuer: String,
        nonce: Option<String>,
        scope: Option<String>,
        with_refresh_token: bool,
        with_id_token: bool,
    ) -> trc::Result<OAuthResponse> {
        let credential_version = self
            .access_token(account_id)
            .await
            .caused_by(trc::location!())?
            .credential_version();
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let account_name = account.name();

        Ok(OAuthResponse {
            access_token: self
                .encode_access_token(
                    GrantType::AccessToken,
                    account_id,
                    account_name,
                    self.core.oauth.oauth_expiry_token,
                    None,
                    credential_version.into(),
                )
                .await?,
            token_type: "bearer".to_string(),
            expires_in: self.core.oauth.oauth_expiry_token,
            refresh_token: if with_refresh_token {
                self.encode_access_token(
                    GrantType::RefreshToken,
                    account_id,
                    account_name,
                    self.core.oauth.oauth_expiry_refresh_token,
                    None,
                    credential_version.into(),
                )
                .await?
                .into()
            } else {
                None
            },
            id_token: if with_id_token {
                match self.issue_id_token(
                    account_id.to_string(),
                    issuer,
                    client_id,
                    StandardClaims {
                        nonce,
                        preferred_username: account.name().to_string().into(),
                        email: account.name().to_string().into(),
                        description: account.description().map(|d| d.to_string()),
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
            },
            scope,
        })
    }
}

fn client_credentials<'x>(
    req: &'x HttpRequest,
    params: &'x FormData,
) -> (Option<Cow<'x, str>>, Option<Cow<'x, str>>) {
    let mut client_id = params.get("client_id").map(Cow::Borrowed);
    let mut client_secret = params.get("client_secret").map(Cow::Borrowed);

    if (client_id.is_none() || client_secret.is_none())
        && let Some((id, secret)) = req
            .authorization_basic()
            .and_then(|token| STANDARD.decode(token).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|creds| {
                creds
                    .split_once(':')
                    .map(|(id, secret)| (id.to_string(), secret.to_string()))
            })
    {
        if client_id.is_none() {
            client_id = Some(Cow::Owned(id));
        }
        if client_secret.is_none() {
            client_secret = Some(Cow::Owned(secret));
        }
    }

    (client_id, client_secret)
}

fn verify_pkce(stored: &ArchivedPkceCodeChallenge, verifier: Option<&str>) -> bool {
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
        (ArchivedPkceCodeChallenge::None, None) => true,
        (ArchivedPkceCodeChallenge::Plain(expected), Some(verifier))
            if is_valid_pkce_challenge(verifier) =>
        {
            constant_time_eq(expected.as_bytes(), verifier.as_bytes())
        }
        (ArchivedPkceCodeChallenge::S256(expected), Some(verifier))
            if is_valid_pkce_challenge(verifier) =>
        {
            let digest = Sha256::digest(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(digest);
            constant_time_eq(expected.as_bytes(), computed.as_bytes())
        }
        _ => false,
    }
}
