/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DeviceAuthResponse, FormData, MAX_POST_LEN, OAuthCode, PkceCodeChallenge};
use crate::auth::oauth::{
    OAuthStatus, openid::OpenIdHandler, registration::ClientRegistrationHandler,
};
use common::{
    KV_OAUTH, Server,
    auth::{
        AuthRequest,
        oauth::{
            CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN, SUPPORTED_SCOPES, USER_CODE_ALPHABET,
            USER_CODE_LEN,
            client_id::{decode_client_id, scopes_to_mask},
            registration::redirect_uri_matches,
        },
    },
};
use directory::Credentials;
use http_proto::*;
use std::future::Future;
use store::{
    Serialize,
    dispatch::lookup::KeyValue,
    write::{Archive, Archiver},
};
use store::{
    rand::{
        Rng,
        distr::{Alphanumeric, StandardUniform},
        rng,
    },
    write::AlignedBytes,
};
use trc::AddContext;
use utils::DomainPart;

#[derive(Debug, serde::Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: [String; 1],
    pub scopes_supported: &'static [&'static str],
    pub bearer_methods_supported: &'static [&'static str],
}

#[derive(Debug, serde::Serialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub introspection_endpoint: String,
    pub grant_types_supported: &'static [&'static str],
    pub response_types_supported: &'static [&'static str],
    pub scopes_supported: &'static [&'static str],
    pub token_endpoint_auth_methods_supported: &'static [&'static str],
    pub code_challenge_methods_supported: &'static [&'static str],
    pub authorization_response_iss_parameter_supported: bool,
}

pub trait OAuthApiHandler: Sync + Send {
    fn handle_discover_request(
        &self,
        session: &HttpSessionData,
        account_name: &str,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_login_request(
        &self,
        session: &HttpSessionData,
        body: Vec<u8>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oauth_metadata(&self) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oauth_protected_resource(
        &self,
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
        client_id: String,
        #[serde(default)]
        redirect_uri: Option<String>,
        #[serde(default)]
        nonce: Option<String>,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        code_challenge: Option<String>,
        #[serde(default)]
        code_challenge_method: Option<String>,
        #[serde(default)]
        state: Option<String>,
        #[serde(default)]
        resource: Vec<String>,
    },
    #[serde(rename_all = "camelCase")]
    AuthDevice {
        account_name: String,
        account_secret: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        mfa_token: Option<String>,
        code: String,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum LoginResponse {
    Authenticated { client_code: String, iss: String },
    Verified,
    MfaRequired,
    Failure,
}

impl OAuthApiHandler for Server {
    async fn handle_discover_request(
        &self,
        session: &HttpSessionData,
        account_name: &str,
    ) -> trc::Result<HttpResponse> {
        let account_name = account_name.trim().to_lowercase();
        if let Some(domain_name) = account_name.try_domain_part()
            && let Some(endpoint) = self
                .get_directory_for_domain(domain_name)
                .await?
                .and_then(|directory| directory.oidc_discovery_document())
        {
            Ok(JsonResponse::new(&endpoint.document)
                .no_cache()
                .into_http_response())
        } else {
            self.handle_oidc_metadata(!session.is_tls).await
        }
    }

    async fn handle_login_request(
        &self,
        session: &HttpSessionData,
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
                client_id,
                redirect_uri,
                nonce,
                scope,
                code_challenge,
                code_challenge_method,
                resource,
                ..
            } => {
                // Validate clientId
                if client_id.len() > CLIENT_ID_MAX_LEN {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .details("Client ID is too long."));
                } else if redirect_uri
                    .as_ref()
                    .is_some_and(|uri| uri.starts_with("http://"))
                {
                    #[cfg(not(feature = "dev_mode"))]
                    if !self.registry().is_recovery_mode() && code_challenge.is_none() {
                        return Err(trc::AuthEvent::Error
                            .into_err()
                            .details("Redirect URI must be HTTPS."));
                    }
                }

                // Resolve the client and validate the redirect URI against the registration.
                // Stateless client ids are self-describing; otherwise fall back to the registry.
                let redirect_uri = redirect_uri.ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("A redirect URI is required.")
                })?;
                let stateless_client =
                    decode_client_id(self.core.oauth.oauth_key.as_bytes(), &client_id);
                let granted_scope = match &stateless_client {
                    Some(meta) => {
                        if !meta
                            .redirect_uris
                            .iter()
                            .any(|uri| redirect_uri_matches(uri, &redirect_uri))
                        {
                            return Err(trc::AuthEvent::Error
                                .into_err()
                                .details("Redirect URI does not match the client registration."));
                        }
                        grant_scope(scope.as_deref(), meta.scope_mask)
                    }
                    None => scope,
                };

                // Validate Resource Indicators (RFC 8707)
                for resource in &resource {
                    if !is_known_resource(
                        [self.core.network.server_name.as_str()]
                            .into_iter()
                            .chain(
                                self.core
                                    .network
                                    .info
                                    .services
                                    .values()
                                    .filter_map(|v| v.hostname.as_deref()),
                            )
                            .chain(
                                self.core
                                    .network
                                    .info
                                    .mxs
                                    .iter()
                                    .filter_map(|mx| mx.hostname.as_deref()),
                            ),
                        resource,
                    ) {
                        return Err(trc::AuthEvent::Error
                            .into_err()
                            .details(format!("Unknown resource indicator: {}", resource)));
                    }
                }

                // Parse and validate PKCE challenge (RFC 7636).
                let pkce_challenge = match code_challenge {
                    Some(challenge) => match code_challenge_method.as_deref().unwrap_or("plain") {
                        "S256" => PkceCodeChallenge::S256(challenge),
                        "plain" if stateless_client.is_none() => {
                            PkceCodeChallenge::Plain(challenge)
                        }
                        _ => {
                            return Err(trc::AuthEvent::Error
                                .into_err()
                                .details("Unsupported PKCE code_challenge_method."));
                        }
                    },
                    None => {
                        if stateless_client.is_some() {
                            return Err(trc::AuthEvent::Error.into_err().details(
                                "A PKCE code_challenge with the S256 method is required.",
                            ));
                        }
                        PkceCodeChallenge::None
                    }
                };

                // Authenticate
                match self
                    .authenticate(&AuthRequest {
                        credentials: Credentials::Basic {
                            username: account_name,
                            secret: account_secret,
                            mfa_token,
                        },
                        session_id: session.session_id,
                        remote_ip: session.remote_ip,
                    })
                    .await
                {
                    Ok(access_token) => {
                        // Registry-backed clients are validated once the account is known
                        if stateless_client.is_none()
                            && self
                                .validate_client_registration(
                                    &client_id,
                                    Some(redirect_uri.as_str()),
                                    access_token.account_id(),
                                )
                                .await?
                                .is_some()
                        {
                            return Err(trc::AuthEvent::Error
                                .into_err()
                                .details("Invalid client registration."));
                        }

                        // Generate client code
                        let client_code = rng()
                            .sample_iter(Alphanumeric)
                            .take(DEVICE_CODE_LEN)
                            .map(char::from)
                            .collect::<String>();

                        // Serialize OAuth code
                        let value = Archiver::new(OAuthCode {
                            status: OAuthStatus::Authorized,
                            account_id: access_token.account_id(),
                            client_id,
                            nonce,
                            params: redirect_uri,
                            code_challenge: pkce_challenge,
                            scope: granted_scope,
                            resources: resource,
                        })
                        .untrusted()
                        .serialize()
                        .caused_by(trc::location!())?;

                        // Insert client code
                        self.in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(KV_OAUTH, client_code.as_bytes(), value)
                                    .expires(self.core.oauth.oauth_expiry_auth_code),
                            )
                            .await?;

                        LoginResponse::Authenticated {
                            client_code,
                            iss: self.core.network.http.url_https.clone(),
                        }
                    }
                    Err(err) => match *err.as_ref() {
                        trc::EventType::Auth(trc::AuthEvent::MfaRequired) => {
                            trc::error!(err.span_id(session.session_id));
                            LoginResponse::MfaRequired
                        }
                        trc::EventType::Auth(_) => {
                            trc::error!(err.span_id(session.session_id));
                            LoginResponse::Failure
                        }
                        trc::EventType::Security(_) => {
                            trc::error!(err.span_id(session.session_id));
                            LoginResponse::Failure
                        }
                        _ => {
                            return Err(err);
                        }
                    },
                }
            }
            LoginRequest::AuthDevice {
                account_name,
                account_secret,
                mfa_token,
                code,
            } => {
                // Obtain code
                let mut result = LoginResponse::Failure;
                if let Some(auth_code_) = self
                    .in_memory_store()
                    .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                        KV_OAUTH,
                        code.as_bytes(),
                    ))
                    .await?
                {
                    let oauth = auth_code_
                        .unarchive::<OAuthCode>()
                        .caused_by(trc::location!())?;
                    if oauth.status == OAuthStatus::Pending {
                        // Authenticate
                        match self
                            .authenticate(&AuthRequest {
                                credentials: Credentials::Basic {
                                    username: account_name,
                                    secret: account_secret,
                                    mfa_token,
                                },
                                session_id: session.session_id,
                                remote_ip: session.remote_ip,
                            })
                            .await
                        {
                            Ok(access_token) => {
                                let new_oauth_code = OAuthCode {
                                    status: OAuthStatus::Authorized,
                                    account_id: access_token.account_id(),
                                    client_id: oauth.client_id.to_string(),
                                    nonce: oauth.nonce.as_ref().map(|s| s.to_string()),
                                    params: Default::default(),
                                    code_challenge: PkceCodeChallenge::None,
                                    scope: oauth.scope.as_ref().map(|s| s.to_string()),
                                    resources: oauth
                                        .resources
                                        .iter()
                                        .map(|s| s.to_string())
                                        .collect(),
                                };

                                // Delete issued user code
                                self.in_memory_store()
                                    .key_delete(KeyValue::<()>::build_key(
                                        KV_OAUTH,
                                        code.as_bytes(),
                                    ))
                                    .await?;

                                // Update device code status
                                self.in_memory_store()
                                    .key_set(
                                        KeyValue::with_prefix(
                                            KV_OAUTH,
                                            oauth.params.as_bytes(),
                                            Archiver::new(new_oauth_code)
                                                .untrusted()
                                                .serialize()
                                                .caused_by(trc::location!())?,
                                        )
                                        .expires(self.core.oauth.oauth_expiry_auth_code),
                                    )
                                    .await?;

                                result = LoginResponse::Verified;
                            }
                            Err(err) => match *err.as_ref() {
                                trc::EventType::Auth(trc::AuthEvent::MfaRequired) => {
                                    trc::error!(err.span_id(session.session_id));
                                    result = LoginResponse::MfaRequired;
                                }
                                trc::EventType::Auth(_) => {
                                    trc::error!(err.span_id(session.session_id));
                                    result = LoginResponse::Failure;
                                }
                                trc::EventType::Security(_) => {
                                    trc::error!(err.span_id(session.session_id));
                                    result = LoginResponse::Failure;
                                }
                                _ => {
                                    return Err(err);
                                }
                            },
                        }
                    }
                }

                result
            }
        };

        Ok(JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        // Parse form
        let mut form_data = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let client_id = form_data
            .remove("client_id")
            .filter(|client_id| client_id.len() <= CLIENT_ID_MAX_LEN)
            .ok_or_else(|| {
                trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("Client ID is missing.")
            })?;
        let nonce = form_data.remove("nonce");
        let scope = form_data
            .remove("scope")
            .and_then(|scope| grant_scope(Some(&scope), u64::MAX));

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
            client_id,
            nonce,
            params: device_code.clone(),
            code_challenge: PkceCodeChallenge::None,
            scope,
            resources: Vec::new(),
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

    async fn handle_oauth_metadata(&self) -> trc::Result<HttpResponse> {
        let base_url = &self.core.network.http.url_https;

        Ok(JsonResponse::new(OAuthMetadata {
            authorization_endpoint: format!("{base_url}/login",),
            token_endpoint: format!("{base_url}/auth/token"),
            device_authorization_endpoint: format!("{base_url}/auth/device"),
            introspection_endpoint: format!("{base_url}/auth/introspect"),
            registration_endpoint: format!("{base_url}/auth/register"),
            grant_types_supported: &[
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            response_types_supported: &["code"],
            scopes_supported: SUPPORTED_SCOPES,
            token_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            code_challenge_methods_supported: &["S256"],
            authorization_response_iss_parameter_supported: true,
            issuer: base_url.to_string(),
        })
        .into_http_response()
        .with_cors_unrestricted())
    }

    async fn handle_oauth_protected_resource(&self) -> trc::Result<HttpResponse> {
        let base_url = &self.core.network.http.url_https;

        Ok(JsonResponse::new(ProtectedResourceMetadata {
            resource: base_url.to_string(),
            authorization_servers: [base_url.to_string()],
            scopes_supported: SUPPORTED_SCOPES,
            bearer_methods_supported: &["header"],
        })
        .into_http_response()
        .with_cors_unrestricted())
    }
}

fn grant_scope(requested: Option<&str>, registered_mask: u64) -> Option<String> {
    let mut granted = String::new();
    for scope in requested.unwrap_or_default().split_ascii_whitespace() {
        let bit = scopes_to_mask(scope);
        if bit != 0 && registered_mask & bit == bit {
            if !granted.is_empty() {
                granted.push(' ');
            }
            granted.push_str(scope);
        }
    }

    (!granted.is_empty()).then_some(granted)
}

fn is_known_resource<'x>(hostnames: impl IntoIterator<Item = &'x str>, uri: &str) -> bool {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return false;
    };
    let supported = hashify::tiny_map!(scheme.as_bytes(),
        b"http" => true,
        b"https" => true,
        b"smtp" => true,
        b"smtps" => true,
        b"imap" => true,
        b"imaps" => true,
        b"pop3" => true,
        b"pop3s" => true,
        b"caldav" => true,
        b"caldavs" => true,
        b"webdav" => true,
        b"webdavs" => true,
        b"carddav" => true,
        b"carddavs" => true,
        b"sieve" => true,
        b"sieves" => true
    )
    .unwrap_or(false);

    let authority = rest.split_once('/').map_or(rest, |(auth, _)| auth);
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.as_bytes().iter().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(host, _)| host);

    supported
        && hostnames
            .into_iter()
            .any(|hostname| host.eq_ignore_ascii_case(hostname))
}
