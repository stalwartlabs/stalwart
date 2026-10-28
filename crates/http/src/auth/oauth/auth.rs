/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DeviceAuthResponse, ErrorType, FormData, MAX_POST_LEN, OAuthCode, PkceCodeChallenge,
    TokenResponse,
    authorize::{
        Authorization, AuthorizationError, granted_scope, is_resource_path, issuer,
        resource_origin, scope_labels, validate_authorization,
    },
    logout::END_SESSION_PATH,
    request_origin,
    token::{ClientCredentials, TokenHandler, token_response},
};
use crate::auth::oauth::{
    OAuthStatus, TOKEN_ENDPOINT_AUTH_METHODS,
    openid::{OidcMetadataRequest, OpenIdHandler},
};
use common::{
    KV_OAUTH, Server,
    auth::{
        AuthRequest,
        authentication::UsernameParts,
        oauth::{
            DEVICE_CODE_LEN, USER_CODE_ALPHABET, USER_CODE_LEN,
            client::{RequestOrigin, ResolveContext, ResolveMode, ResolvedClient},
            supported_scopes,
        },
    },
};
use directory::Credentials;
use http_proto::*;
use hyper::{StatusCode, body::Bytes};
use registry::schema::enums::OAuthGrantType;
use std::{borrow::Cow, future::Future};
use store::{
    Serialize, blake3,
    dispatch::lookup::KeyValue,
    write::{Archive, Archiver},
};
use store::{
    rand::{
        RngExt,
        distr::{Alphanumeric, StandardUniform},
        rng,
    },
    write::ArchiveBytes,
};
use trc::AddContext;

#[derive(Debug, serde::Serialize)]
pub struct ProtectedResourceMetadata<'x> {
    pub resource: String,
    pub authorization_servers: [Cow<'x, str>; 1],
    pub scopes_supported: &'static [&'static str],
    pub bearer_methods_supported: &'static [&'static str],
}

#[derive(Debug, serde::Serialize)]
pub struct OAuthMetadata<'x> {
    pub issuer: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub end_session_endpoint: String,
    pub grant_types_supported: &'static [&'static str],
    pub response_types_supported: &'static [&'static str],
    pub scopes_supported: &'static [&'static str],
    pub token_endpoint_auth_methods_supported: &'static [&'static str],
    pub revocation_endpoint_auth_methods_supported: &'static [&'static str],
    pub code_challenge_methods_supported: &'static [&'static str],
    pub authorization_response_iss_parameter_supported: bool,
    pub client_id_metadata_document_supported: bool,
    pub protected_resources: &'x [Box<str>],
}

pub trait OAuthApiHandler: Sync + Send {
    fn handle_discover_request(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        account_name: &str,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_login_request(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        body: Vec<u8>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_client_info_request(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        query: &str,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oauth_metadata(
        &self,
        origin: RequestOrigin<'_>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oauth_protected_resource(
        &self,
        origin: RequestOrigin<'_>,
        path: &str,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum LoginRequest {
    #[serde(rename_all = "camelCase")]
    AuthCode {
        account_name: String,
        account_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        mfa_token: Option<String>,
        query: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        consent: Option<bool>,
    },
    #[serde(rename_all = "camelCase")]
    AuthDevice {
        #[serde(default)]
        account_name: String,
        #[serde(default)]
        account_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        mfa_token: Option<String>,
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        consent: Option<bool>,
    },
    #[serde(rename_all = "camelCase")]
    AuthConsent {
        token: String,
        query: String,
        consent: bool,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum LoginResponse {
    Authenticated {
        location: String,
    },
    Redirect {
        location: String,
    },
    Invalid {
        error: ErrorType,
        description: Cow<'static, str>,
    },
    Verified,
    Denied,
    MfaRequired,
    ConsentRequired {
        token: String,
    },
    Expired,
    Failure,
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub name: Option<String>,
    pub logo: Option<String>,
    pub client_host: Option<String>,
    pub redirect_host: Option<String>,
    pub scopes: Vec<&'static str>,
    pub verified: bool,
    pub consent_required: bool,
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ClientInfoResponse {
    Client(ClientInfo),
    Error {
        error: ErrorType,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<&'static str>,
        redirect: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        location: Option<String>,
    },
}

impl OAuthApiHandler for Server {
    async fn handle_discover_request(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        account_name: &str,
    ) -> trc::Result<HttpResponse> {
        let username = UsernameParts::new(account_name.trim());
        let auth_as = username.auth_as();
        let is_recovery_admin = self
            .registry()
            .recovery_admin()
            .is_some_and(|(user, _)| user.trim().eq_ignore_ascii_case(auth_as.address()));

        if !is_recovery_admin
            && let Some(domain_name) = auth_as.domain().filter(|domain| !domain.is_empty())
            && let Some(endpoint) = self
                .get_directory_for_domain(domain_name)
                .await?
                .and_then(|directory| directory.oidc_discovery_document())
        {
            Ok(HttpResponse::new(StatusCode::OK)
                .with_content_type("application/json; charset=utf-8")
                .with_binary_body(Bytes::from_owner(endpoint.web_document.clone()))
                .with_no_store())
        } else {
            self.handle_oidc_metadata(
                OidcMetadataRequest::Discover {
                    is_tls: session.is_tls,
                },
                origin,
            )
            .await
        }
    }

    async fn handle_login_request(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        body: Vec<u8>,
    ) -> trc::Result<HttpResponse> {
        let request = serde_json::from_slice::<LoginRequest>(&body).map_err(|err| {
            trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
        })?;

        let response = match request {
            LoginRequest::AuthCode {
                account_name,
                account_secret,
                mfa_token,
                query,
                consent,
            } => {
                self.authorize_code(
                    session,
                    origin,
                    LoginCredentials {
                        account_name,
                        account_secret,
                        mfa_token,
                    },
                    &query,
                    consent,
                )
                .await?
            }
            LoginRequest::AuthConsent {
                token,
                query,
                consent,
            } => {
                self.confirm_consent(session, origin, &token, &query, consent)
                    .await?
            }
            LoginRequest::AuthDevice {
                account_name,
                account_secret,
                mfa_token,
                code,
                consent,
            } => {
                approve_device(
                    self,
                    session,
                    account_name,
                    account_secret,
                    mfa_token,
                    &code,
                    consent,
                )
                .await?
            }
        };

        Ok(JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn handle_client_info_request(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        query: &str,
    ) -> trc::Result<HttpResponse> {
        let user_code = form_urlencoded::parse(query.as_bytes())
            .find_map(|(name, value)| (name == "user_code").then_some(value));
        let response = if let Some(user_code) = user_code {
            device_client_info(self, &user_code, session)
                .await?
                .map(ClientInfoResponse::Client)
                .unwrap_or_else(|| ClientInfoResponse::Error {
                    error: ErrorType::InvalidGrant,
                    description: Some("The device code is invalid or has expired."),
                    redirect: false,
                    location: None,
                })
        } else {
            let issuer = issuer(self, origin);
            match validate_authorization(
                self,
                query,
                &ResolveContext {
                    mode: ResolveMode::Authorize,
                    origin: Some(origin),
                    remote_ip: session.remote_ip,
                },
                &issuer,
            )
            .await?
            {
                Ok(authorization) => {
                    let client = &authorization.client;
                    ClientInfoResponse::Client(ClientInfo {
                        name: client.display_name().map(str::to_string),
                        logo: client.display_logo().map(str::to_string),
                        client_host: client.client_host().map(str::to_string),
                        redirect_host: authorization.redirect_host(),
                        scopes: authorization.scope_labels(),
                        verified: client.is_verified(),
                        consent_required: client.requires_consent(),
                    })
                }
                Err(AuthorizationError::Invalid { error, description }) => {
                    ClientInfoResponse::Error {
                        error,
                        description: Some(description),
                        redirect: false,
                        location: None,
                    }
                }
                Err(AuthorizationError::Redirect { location }) => ClientInfoResponse::Error {
                    error: ErrorType::InvalidRequest,
                    description: None,
                    redirect: true,
                    location: Some(location),
                },
            }
        };

        Ok(JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let mut form_data = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let credentials = ClientCredentials::new(req, &form_data);
        let Some(client_id) = credentials
            .client_id
            .as_deref()
            .filter(|_| !credentials.is_ambiguous)
            .map(str::to_string)
        else {
            return Ok(token_response(
                TokenResponse::error(ErrorType::InvalidRequest),
                credentials.used_basic,
            ));
        };
        let client = match self
            .resolve_token_client(
                &client_id,
                &credentials,
                &ResolveContext {
                    mode: ResolveMode::Token,
                    origin: Some(request_origin(req, session)),
                    remote_ip: session.remote_ip,
                },
                OAuthGrantType::DeviceCode,
            )
            .await?
        {
            Ok(client) => client,
            Err(error) => {
                return Ok(token_response(
                    TokenResponse::error(error),
                    credentials.used_basic,
                ));
            }
        };
        let used_basic = credentials.used_basic;
        drop(credentials);
        let scope = match granted_scope(form_data.get("scope"), client.allowed_scopes()) {
            Ok(scope) => scope,
            Err(error) => return Ok(token_response(TokenResponse::error(error), used_basic)),
        };
        let nonce = form_data.remove("nonce");

        // Generate device code
        let device_code = rng()
            .sample_iter(Alphanumeric)
            .take(DEVICE_CODE_LEN)
            .map(char::from)
            .collect::<String>();

        // Generate user code
        let mut user_code = String::with_capacity(USER_CODE_LEN + 1);
        for (pos, ch) in rng()
            .sample_iter(StandardUniform)
            .take(USER_CODE_LEN)
            .map(|v: u64| char::from(USER_CODE_ALPHABET[v as usize % USER_CODE_ALPHABET.len()]))
            .enumerate()
        {
            if pos == USER_CODE_LEN / 2 {
                user_code.push('-');
            }
            user_code.push(ch);
        }

        // Add OAuth status
        let oauth_code = Archiver::new(OAuthCode {
            status: OAuthStatus::Pending,
            account_id: u32::MAX,
            credential_version: 0,
            client_id,
            nonce,
            params: device_code.clone(),
            code_challenge: PkceCodeChallenge::None,
            scope,
        })
        .untrusted()
        .serialize()
        .caused_by(trc::location!())?;

        // Insert device code
        self.in_memory_store()
            .key_set(
                KeyValue::with_prefix(KV_OAUTH, device_code.as_bytes(), oauth_code.clone())
                    .expires(self.core.oauth.oauth_expiry_user_code),
            )
            .await?;

        // Insert user code
        self.in_memory_store()
            .key_set(
                KeyValue::with_prefix(KV_OAUTH, user_code.as_bytes(), oauth_code)
                    .expires(self.core.oauth.oauth_expiry_user_code),
            )
            .await?;

        // Build response
        let base_url = &self.core.network.http.url_https;
        Ok(JsonResponse::new(DeviceAuthResponse {
            verification_uri: format!("{base_url}/device"),
            verification_uri_complete: format!("{base_url}/device/?code={user_code}"),
            device_code,
            user_code,
            expires_in: self.core.oauth.oauth_expiry_user_code,
            interval: 5,
        })
        .no_cache()
        .into_http_response())
    }

    async fn handle_oauth_metadata(&self, origin: RequestOrigin<'_>) -> trc::Result<HttpResponse> {
        let base_url = issuer(self, origin);
        let resources = &self.core.network.resources;

        Ok(JsonResponse::new(OAuthMetadata {
            authorization_endpoint: format!("{base_url}/login",),
            token_endpoint: format!("{base_url}/auth/token"),
            device_authorization_endpoint: format!("{base_url}/auth/device"),
            introspection_endpoint: format!("{base_url}/auth/introspect"),
            revocation_endpoint: format!("{base_url}/auth/revoke"),
            end_session_endpoint: format!("{base_url}{END_SESSION_PATH}"),
            registration_endpoint: format!("{base_url}/auth/register"),
            grant_types_supported: &[
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            response_types_supported: &["code"],
            scopes_supported: supported_scopes(resources.serves_files),
            token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS,
            revocation_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS,
            code_challenge_methods_supported: &["S256"],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
            protected_resources: &resources.identifiers,
            issuer: base_url.into_owned(),
        })
        .into_http_response()
        .with_cors_unrestricted())
    }

    async fn handle_oauth_protected_resource(
        &self,
        origin: RequestOrigin<'_>,
        path: &str,
    ) -> trc::Result<HttpResponse> {
        let Some(mut resource) = resource_origin(self, origin).filter(|_| is_resource_path(path))
        else {
            return Err(trc::ResourceEvent::NotFound.into_err());
        };
        resource.push_str(path);
        let authorization_server = match self.external_issuer_for_host(origin.authority).await? {
            Some(issuer) => Cow::Owned(issuer),
            None => issuer(self, origin),
        };

        Ok(JsonResponse::new(ProtectedResourceMetadata {
            resource,
            authorization_servers: [authorization_server],
            scopes_supported: supported_scopes(self.core.network.resources.serves_files),
            bearer_methods_supported: &["header"],
        })
        .into_http_response()
        .with_cors_unrestricted())
    }
}

async fn device_client_info(
    server: &Server,
    user_code: &str,
    session: &HttpSessionData,
) -> trc::Result<Option<ClientInfo>> {
    if !is_user_code(user_code) {
        return Ok(None);
    }
    let Some(stored) = server
        .in_memory_store()
        .key_get::<Archive<ArchiveBytes>>(KeyValue::<()>::build_key(KV_OAUTH, user_code.as_bytes()))
        .await?
    else {
        return Ok(None);
    };
    let oauth = stored
        .unarchive::<OAuthCode>()
        .caused_by(trc::location!())?;
    if oauth.status != OAuthStatus::Pending {
        return Ok(None);
    }

    match server
        .resolve_oauth_client(
            oauth.client_id.as_str(),
            &ResolveContext {
                mode: ResolveMode::Token,
                origin: None,
                remote_ip: session.remote_ip,
            },
        )
        .await?
    {
        Ok(client) if client.allows_grant(OAuthGrantType::DeviceCode) => Ok(Some(ClientInfo {
            name: client.display_name().map(str::to_string),
            logo: client.display_logo().map(str::to_string),
            client_host: None,
            redirect_host: None,
            scopes: scope_labels(&client, oauth.scope.as_ref().map(|scope| scope.as_str())),
            verified: client.is_verified(),
            consent_required: true,
        })),
        _ => Ok(None),
    }
}

struct LoginAccount {
    account_id: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    tenant_id: Option<u32>,
    // SPDX-SnippetEnd
    credential_version: u64,
}

async fn authenticate_login(
    server: &Server,
    session: &HttpSessionData,
    client: &ResolvedClient,
    username: String,
    secret: String,
    mfa_token: Option<String>,
) -> trc::Result<Result<LoginAccount, LoginResponse>> {
    match server
        .authenticate(&AuthRequest {
            credentials: Credentials::Basic {
                username,
                secret,
                mfa_token,
            },
            session_id: session.session_id,
            remote_ip: session.remote_ip,
        })
        .await
    {
        Ok(authenticated) => {
            let access_token = authenticated.access_token;
            let account_id = access_token.account_id();
            if !client.is_first_party() && access_token.is_main_credential_expired() {
                trc::event!(
                    Auth(trc::AuthEvent::CredentialExpired),
                    AccountId = account_id,
                    SpanId = session.session_id,
                    Reason = "Main credential expired, refusing sign-in to third-party client.",
                );
                return Ok(Err(LoginResponse::Expired));
            }

            Ok(Ok(LoginAccount {
                account_id,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                tenant_id: access_token.tenant_id(),
                // SPDX-SnippetEnd
                credential_version: access_token.credential_version(),
            }))
        }
        Err(err) => {
            let response = match *err.as_ref() {
                trc::EventType::Auth(trc::AuthEvent::MfaRequired) => LoginResponse::MfaRequired,
                trc::EventType::Auth(_) | trc::EventType::Security(_) => LoginResponse::Failure,
                _ => return Err(err),
            };
            trc::error!(err.span_id(session.session_id));
            Ok(Err(response))
        }
    }
}

struct LoginCredentials {
    account_name: String,
    account_secret: String,
    mfa_token: Option<String>,
}

trait ConsentHandler: Sync + Send {
    fn validate_login_query(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        query: &str,
        issuer: &str,
    ) -> impl Future<Output = trc::Result<Result<Authorization, LoginResponse>>> + Send;

    fn authorize_code(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        credentials: LoginCredentials,
        query: &str,
        consent: Option<bool>,
    ) -> impl Future<Output = trc::Result<LoginResponse>> + Send;

    fn request_consent(
        &self,
        authorization: Authorization,
        login: &LoginAccount,
        query: &str,
    ) -> impl Future<Output = trc::Result<LoginResponse>> + Send;

    fn confirm_consent(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        token: &str,
        query: &str,
        consent: bool,
    ) -> impl Future<Output = trc::Result<LoginResponse>> + Send;

    fn take_pending_consent(
        &self,
        token: &str,
        query: &str,
    ) -> impl Future<Output = trc::Result<Option<(u32, u64)>>> + Send;

    fn issue_auth_code(
        &self,
        authorization: Authorization,
        account_id: u32,
        credential_version: u64,
        issuer: &str,
    ) -> impl Future<Output = trc::Result<LoginResponse>> + Send;
}

impl ConsentHandler for Server {
    async fn validate_login_query(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        query: &str,
        issuer: &str,
    ) -> trc::Result<Result<Authorization, LoginResponse>> {
        validate_authorization(
            self,
            query,
            &ResolveContext {
                mode: ResolveMode::Authorize,
                origin: Some(origin),
                remote_ip: session.remote_ip,
            },
            issuer,
        )
        .await
        .map(|result| {
            result.map_err(|err| match err {
                AuthorizationError::Invalid { error, description } => LoginResponse::Invalid {
                    error,
                    description: description.into(),
                },
                AuthorizationError::Redirect { location } => LoginResponse::Redirect { location },
            })
        })
    }

    async fn authorize_code(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        credentials: LoginCredentials,
        query: &str,
        consent: Option<bool>,
    ) -> trc::Result<LoginResponse> {
        let issuer = issuer(self, origin);
        let authorization = match self
            .validate_login_query(session, origin, query, &issuer)
            .await?
        {
            Ok(authorization) => authorization,
            Err(response) => return Ok(response),
        };
        let login = match authenticate_login(
            self,
            session,
            &authorization.client,
            credentials.account_name,
            credentials.account_secret,
            credentials.mfa_token,
        )
        .await?
        {
            Ok(login) => login,
            Err(response) => return Ok(response),
        };

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if !authorization.client.allows_tenant(login.tenant_id) {
            return Ok(LoginResponse::Redirect {
                location: authorization.error_location(ErrorType::AccessDenied, &issuer),
            });
        }
        // SPDX-SnippetEnd

        match consent {
            Some(true) => {}
            Some(false) => {
                return Ok(LoginResponse::Redirect {
                    location: authorization.error_location(ErrorType::AccessDenied, &issuer),
                });
            }
            None if !authorization.client.requires_consent() => {}
            None if !authorization.prompt_consent
                && self
                    .has_oauth_grant(
                        login.account_id,
                        &authorization.client_id,
                        authorization.client.kind(),
                        authorization.consent_scopes(),
                    )
                    .await? => {}
            None => {
                return self.request_consent(authorization, &login, query).await;
            }
        }

        self.issue_auth_code(
            authorization,
            login.account_id,
            login.credential_version,
            &issuer,
        )
        .await
    }

    async fn request_consent(
        &self,
        authorization: Authorization,
        login: &LoginAccount,
        query: &str,
    ) -> trc::Result<LoginResponse> {
        let token = rng()
            .sample_iter(Alphanumeric)
            .take(DEVICE_CODE_LEN)
            .map(char::from)
            .collect::<String>();
        let value = Archiver::new(OAuthCode {
            status: OAuthStatus::ConsentPending,
            account_id: login.account_id,
            credential_version: login.credential_version,
            client_id: authorization.client_id,
            nonce: None,
            params: query_digest(query).to_hex().to_string(),
            code_challenge: PkceCodeChallenge::None,
            scope: None,
        })
        .untrusted()
        .serialize()
        .caused_by(trc::location!())?;

        self.in_memory_store()
            .key_set(
                KeyValue::with_prefix(KV_OAUTH, token.as_bytes(), value)
                    .expires(self.core.oauth.oauth_expiry_auth_code),
            )
            .await?;

        Ok(LoginResponse::ConsentRequired { token })
    }

    async fn confirm_consent(
        &self,
        session: &HttpSessionData,
        origin: RequestOrigin<'_>,
        token: &str,
        query: &str,
        consent: bool,
    ) -> trc::Result<LoginResponse> {
        let Some((account_id, credential_version)) =
            self.take_pending_consent(token, query).await?
        else {
            return Ok(LoginResponse::Invalid {
                error: ErrorType::InvalidRequest,
                description: "The sign-in has expired. Please start again from the application."
                    .into(),
            });
        };
        let issuer = issuer(self, origin);
        let authorization = match self
            .validate_login_query(session, origin, query, &issuer)
            .await?
        {
            Ok(authorization) => authorization,
            Err(response) => return Ok(response),
        };

        if consent {
            self.issue_auth_code(authorization, account_id, credential_version, &issuer)
                .await
        } else {
            Ok(LoginResponse::Redirect {
                location: authorization.error_location(ErrorType::AccessDenied, &issuer),
            })
        }
    }

    async fn take_pending_consent(
        &self,
        token: &str,
        query: &str,
    ) -> trc::Result<Option<(u32, u64)>> {
        if token.len() != DEVICE_CODE_LEN || !token.bytes().all(|ch| ch.is_ascii_alphanumeric()) {
            return Ok(None);
        }
        let key = KeyValue::<()>::build_key(KV_OAUTH, token.as_bytes());
        let Some(stored) = self
            .in_memory_store()
            .key_get::<Archive<ArchiveBytes>>(key.as_slice())
            .await?
        else {
            return Ok(None);
        };
        let pending = stored
            .unarchive::<OAuthCode>()
            .caused_by(trc::location!())?;
        if pending.status != OAuthStatus::ConsentPending
            || pending.params != query_digest(query).to_hex().as_str()
            || !self.in_memory_store().key_delete(key.as_slice()).await?
        {
            return Ok(None);
        }

        Ok(Some((
            pending.account_id.into(),
            pending.credential_version.into(),
        )))
    }

    async fn issue_auth_code(
        &self,
        authorization: Authorization,
        account_id: u32,
        credential_version: u64,
        issuer: &str,
    ) -> trc::Result<LoginResponse> {
        let client_code = rng()
            .sample_iter(Alphanumeric)
            .take(DEVICE_CODE_LEN)
            .map(char::from)
            .collect::<String>();
        let location = authorization.code_location(&client_code, issuer);

        let value = Archiver::new(OAuthCode {
            status: OAuthStatus::Authorized,
            account_id,
            credential_version,
            client_id: authorization.client_id,
            nonce: authorization.nonce,
            params: authorization.redirect_uri,
            code_challenge: authorization.code_challenge,
            scope: authorization.scope,
        })
        .untrusted()
        .serialize()
        .caused_by(trc::location!())?;

        self.in_memory_store()
            .key_set(
                KeyValue::with_prefix(KV_OAUTH, client_code.as_bytes(), value)
                    .expires(self.core.oauth.oauth_expiry_auth_code),
            )
            .await?;

        Ok(LoginResponse::Authenticated { location })
    }
}

async fn approve_device(
    server: &Server,
    session: &HttpSessionData,
    account_name: String,
    account_secret: String,
    mfa_token: Option<String>,
    code: &str,
    consent: Option<bool>,
) -> trc::Result<LoginResponse> {
    let Some(consent) = consent.filter(|_| is_user_code(code)) else {
        return Ok(LoginResponse::Failure);
    };
    let Some(stored) = server
        .in_memory_store()
        .key_get::<Archive<ArchiveBytes>>(KeyValue::<()>::build_key(KV_OAUTH, code.as_bytes()))
        .await?
    else {
        return Ok(LoginResponse::Failure);
    };
    let oauth = stored
        .unarchive::<OAuthCode>()
        .caused_by(trc::location!())?;
    if oauth.status != OAuthStatus::Pending {
        return Ok(LoginResponse::Failure);
    }

    let denied = || {
        (
            OAuthStatus::Denied,
            u32::MAX,
            0,
            server.core.oauth.oauth_expiry_user_code,
            LoginResponse::Denied,
        )
    };
    let (status, account_id, credential_version, expiry, response) = if consent {
        match server
            .resolve_oauth_client(
                oauth.client_id.as_str(),
                &ResolveContext {
                    mode: ResolveMode::Token,
                    origin: None,
                    remote_ip: session.remote_ip,
                },
            )
            .await?
        {
            Ok(client) => match authenticate_login(
                server,
                session,
                &client,
                account_name,
                account_secret,
                mfa_token,
            )
            .await?
            {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                Ok(login) if !client.allows_tenant(login.tenant_id) => denied(),
                // SPDX-SnippetEnd
                Ok(login) => (
                    OAuthStatus::Authorized,
                    login.account_id,
                    login.credential_version,
                    server.core.oauth.oauth_expiry_auth_code,
                    LoginResponse::Verified,
                ),
                Err(LoginResponse::Expired) => {
                    let (status, account_id, credential_version, expiry, _) = denied();
                    (
                        status,
                        account_id,
                        credential_version,
                        expiry,
                        LoginResponse::Expired,
                    )
                }
                Err(response) => return Ok(response),
            },
            Err(_) => denied(),
        }
    } else {
        denied()
    };

    let value = Archiver::new(OAuthCode {
        status,
        account_id,
        credential_version,
        client_id: oauth.client_id.to_string(),
        nonce: oauth.nonce.as_ref().map(|nonce| nonce.to_string()),
        params: String::new(),
        code_challenge: PkceCodeChallenge::None,
        scope: oauth.scope.as_ref().map(|scope| scope.to_string()),
    })
    .untrusted()
    .serialize()
    .caused_by(trc::location!())?;

    if !server
        .in_memory_store()
        .key_delete(KeyValue::<()>::build_key(KV_OAUTH, code.as_bytes()))
        .await?
    {
        return Ok(LoginResponse::Failure);
    }
    server
        .in_memory_store()
        .key_set(KeyValue::with_prefix(KV_OAUTH, oauth.params.as_bytes(), value).expires(expiry))
        .await?;

    Ok(response)
}

fn query_digest(query: &str) -> blake3::Hash {
    blake3::hash(query.as_bytes())
}

fn is_user_code(code: &str) -> bool {
    code.len() == USER_CODE_LEN + 1
        && code.bytes().enumerate().all(|(pos, ch)| {
            if pos == USER_CODE_LEN / 2 {
                ch == b'-'
            } else {
                USER_CODE_ALPHABET.contains(&ch)
            }
        })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/http/src/auth/oauth/auth/tests.rs"]
mod tests;
