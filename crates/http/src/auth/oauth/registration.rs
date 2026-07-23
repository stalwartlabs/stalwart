/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ErrorType;
use crate::auth::authenticate::Authenticator;
use common::{
    Server,
    auth::{
        BuildAccessToken,
        oauth::{
            client_id::{ClientMeta, decode_client_id, encode_client_id, scopes_to_mask},
            registration::{
                ClientRegistrationError, ClientRegistrationRequest, ClientRegistrationResponse,
                TokenEndpointAuthMethod, redirect_uri_matches, validate_grant_metadata,
                validate_redirect_uri,
            },
        },
    },
};
use directory::core::secret::{hash_secret, verify_secret_hash};
use http_proto::{request::fetch_body, *};
use hyper::StatusCode;
use registry::schema::{
    enums::{PasswordHashAlgorithm, Permission},
    prelude::{ObjectType, Property, UTCDateTime},
    structs::OAuthClient,
};
use std::future::Future;
use store::{
    rand::{Rng, distr::Alphanumeric, rng},
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::now,
};
use trc::{AddContext, AuthEvent};
use types::id::Id;

pub trait ClientRegistrationHandler: Sync + Send {
    fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn validate_client_registration(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<ErrorType>>> + Send;

    fn verify_client_secret(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> impl Future<Output = trc::Result<Option<ErrorType>>> + Send;
}
impl ClientRegistrationHandler for Server {
    async fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        // Parse request
        let body = fetch_body(req, 20 * 1024, session.session_id).await;
        let request = serde_json::from_slice::<ClientRegistrationRequest>(
            body.as_deref().unwrap_or_default(),
        )
        .map_err(|err| {
            trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
        })?;

        // Validate redirect URIs and grant metadata (RFC 7591 + OAuth Public Clients profile)
        if request.redirect_uris.is_empty() {
            return Ok(registration_error(
                ClientRegistrationError::invalid_redirect_uri(
                    "At least one redirect URI is required.",
                ),
            ));
        }
        for uri in &request.redirect_uris {
            if let Err(err) = validate_redirect_uri(uri) {
                return Ok(registration_error(err));
            }
        }
        if let Err(err) = validate_grant_metadata(&request) {
            return Ok(registration_error(err));
        }

        let is_public = matches!(
            request.token_endpoint_auth_method,
            None | Some(TokenEndpointAuthMethod::None)
        );

        if is_public {
            // Public client: issue a stateless, self-describing client id with no database write
            if self.core.oauth.allow_anonymous_client_registration {
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;
            } else {
                let (_, access_token) = self.authenticate_headers(req, &session).await?;
                access_token.enforce_permission(Permission::OAuthClientRegistration)?;
            }

            let client_id = encode_client_id(
                self.core.oauth.oauth_key.as_bytes(),
                &ClientMeta {
                    redirect_uris: request.redirect_uris.clone(),
                    scope_mask: scopes_to_mask(request.scope.as_deref().unwrap_or_default()),
                    client_name: request.client_name.clone(),
                },
            )
            .map_err(|err| {
                trc::AuthEvent::Error
                    .into_err()
                    .details("Failed to encode client id.")
                    .reason(err)
                    .caused_by(trc::location!())
            })?;

            trc::event!(
                Auth(AuthEvent::ClientRegistration),
                Id = client_id.clone(),
                RemoteIp = session.remote_ip
            );

            return Ok(JsonResponse::with_status(
                StatusCode::CREATED,
                ClientRegistrationResponse {
                    client_id_issued_at: Some(now()),
                    client_id,
                    request,
                    ..Default::default()
                },
            )
            .no_cache()
            .into_http_response());
        }

        // Confidential client: authenticate and persist the registration
        let (_, access_token) = self.authenticate_headers(req, &session).await?;
        access_token.enforce_permission(Permission::OAuthClientRegistration)?;
        let tenant_id = access_token.tenant_id();

        // Generate client ID
        let client_id = rng()
            .sample_iter(Alphanumeric)
            .take(20)
            .map(|ch| char::from(ch.to_ascii_lowercase()))
            .collect::<String>();

        // Generate client secret
        let client_secret = rng()
            .sample_iter(Alphanumeric)
            .take(48)
            .map(char::from)
            .collect::<String>();
        let secret_hash = hash_secret(
            PasswordHashAlgorithm::Argon2id,
            client_secret.clone().into_bytes(),
        )
        .await
        .caused_by(trc::location!())?;

        let result = self
            .registry()
            .write(RegistryWrite::insert(
                &OAuthClient {
                    client_id: client_id.clone(),
                    description: request.client_name.clone(),
                    contacts: request.contacts.clone().into(),
                    member_tenant_id: tenant_id.map(|id| Id::new(id as u64)),
                    redirect_uris: request.redirect_uris.clone().into(),
                    logo: request.logo_uri.clone(),
                    secret: Some(secret_hash),
                    created_at: UTCDateTime::now(),
                    ..Default::default()
                }
                .into(),
            ))
            .await
            .caused_by(trc::location!())?;

        if !matches!(result, RegistryWriteResult::Success(_)) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to register OAuth client.")
                .reason(result.to_string())
                .caused_by(trc::location!()));
        }

        trc::event!(
            Auth(AuthEvent::ClientRegistration),
            Id = client_id.to_string(),
            RemoteIp = session.remote_ip
        );

        Ok(JsonResponse::with_status(
            StatusCode::CREATED,
            ClientRegistrationResponse {
                client_id,
                client_secret: Some(client_secret),
                client_id_issued_at: Some(now()),
                client_secret_expires_at: Some(0),
                request,
                ..Default::default()
            },
        )
        .no_cache()
        .into_http_response())
    }

    async fn validate_client_registration(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        account_id: u32,
    ) -> trc::Result<Option<ErrorType>> {
        // Stateless client ids are self-describing and validated at the authorization endpoint
        if decode_client_id(self.core.oauth.oauth_key.as_bytes(), client_id).is_some() {
            return Ok(None);
        }
        if !self.core.oauth.require_client_authentication {
            return Ok(None);
        }

        // Fetch client registration
        let found_registration = if let Some(client_id) = self
            .registry()
            .primary_key(
                ObjectType::OAuthClient.into(),
                Property::ClientId,
                client_id.as_bytes().to_vec(),
            )
            .await?
        {
            if let Some(redirect_uri) = redirect_uri {
                let client = self
                    .registry()
                    .object::<OAuthClient>(client_id.id())
                    .await?
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("OAuth client not found.")
                            .caused_by(trc::location!())
                            .ctx(trc::Key::Id, client_id.id().id())
                    })?;
                if client
                    .redirect_uris
                    .iter()
                    .any(|uri| redirect_uri_matches(uri, redirect_uri))
                {
                    return Ok(None);
                }
            } else {
                // Device flow does not require a redirect URI

                return Ok(None);
            }

            true
        } else {
            false
        };

        // Check if the account is allowed to override client registration
        if self
            .access_token(account_id)
            .await
            .caused_by(trc::location!())?
            .build()
            .has_permission(Permission::OAuthClientOverride)
        {
            return Ok(None);
        }

        Ok(Some(if found_registration {
            ErrorType::InvalidClient
        } else {
            ErrorType::InvalidRequest
        }))
    }

    async fn verify_client_secret(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> trc::Result<Option<ErrorType>> {
        // Stateless and unregistered clients have no secret to verify
        if decode_client_id(self.core.oauth.oauth_key.as_bytes(), client_id).is_some() {
            return Ok(None);
        }
        let Some(client_id) = self
            .registry()
            .primary_key(
                ObjectType::OAuthClient.into(),
                Property::ClientId,
                client_id.as_bytes().to_vec(),
            )
            .await?
        else {
            return Ok(None);
        };
        let Some(client) = self
            .registry()
            .object::<OAuthClient>(client_id.id())
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };

        match client.secret.as_deref() {
            Some(hash) if !hash.is_empty() => match client_secret {
                Some(secret)
                    if verify_secret_hash(hash, secret.as_bytes())
                        .await
                        .caused_by(trc::location!())? =>
                {
                    Ok(None)
                }
                _ => Ok(Some(ErrorType::InvalidClient)),
            },
            _ => Ok(None),
        }
    }
}

fn registration_error(error: ClientRegistrationError) -> HttpResponse {
    JsonResponse::with_status(StatusCode::BAD_REQUEST, error)
        .no_cache()
        .into_http_response()
}
