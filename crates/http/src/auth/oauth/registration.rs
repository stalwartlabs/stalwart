/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ErrorType;
use crate::auth::authenticate::Authenticator;
use common::{
    Server,
    auth::oauth::{
        CLIENT_ID_MAX_LEN, SCOPE_FULL,
        client::ResolvedClient,
        client_id::{ClientMeta, encode_client_id},
        registration::{
            ClientRegistrationError, ClientRegistrationRequest, ClientRegistrationResponse,
            TokenEndpointAuthMethod, parse_grant_type, parse_oauth_scope, validate_client_name,
            validate_grant_metadata, validate_oauth_client, validate_public_client_metadata,
            validate_redirect_uri,
        },
        scope::OAuthScopes,
    },
};
use compact_str::CompactString;
use directory::core::secret::{hash_secret, verify_secret_hash};
use http_proto::{request::fetch_body, *};
use hyper::StatusCode;
use jmap::registry::mapping::oauth_client::is_superuser;
use registry::schema::{
    enums::{OAuthGrantType, PasswordHashAlgorithm, Permission},
    prelude::UTCDateTime,
    structs::OAuthClient,
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use jmap::registry::mapping::principal::validate_tenant_quota;
#[cfg(feature = "enterprise")]
use registry::schema::enums::TenantStorageQuota;
// SPDX-SnippetEnd
use std::{future::Future, net::IpAddr};
use store::{
    rand::{RngExt, distr::Alphanumeric, rng},
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::now,
};
use trc::{AddContext, AuthEvent};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use types::id::Id;
// SPDX-SnippetEnd

pub trait ClientRegistrationHandler: Sync + Send {
    fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn verify_client_secret(
        &self,
        client: &ResolvedClient,
        client_secret: Option<&str>,
        remote_ip: IpAddr,
    ) -> impl Future<Output = trc::Result<Option<ErrorType>>> + Send;
}

impl ClientRegistrationHandler for Server {
    async fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let body = fetch_body(req, 20 * 1024, session.session_id).await;
        let mut request = serde_json::from_slice::<ClientRegistrationRequest>(
            body.as_deref().unwrap_or_default(),
        )
        .map_err(|err| {
            trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
        })?;

        if request.redirect_uris.is_empty() {
            return Ok(registration_error(
                ClientRegistrationError::invalid_redirect_uri(
                    "At least one redirect URI is required.",
                ),
            ));
        }
        if let Err(err) =
            validate_grant_metadata(&request).and_then(|_| validate_client_name(&request))
        {
            return Ok(registration_error(err));
        }

        if matches!(
            request.token_endpoint_auth_method,
            None | Some(TokenEndpointAuthMethod::None)
        ) {
            if let Err(err) = validate_public_client_metadata(&request) {
                return Ok(registration_error(err));
            }

            self.is_http_anonymous_request_allowed(session.remote_ip)
                .await?;

            let scopes = OAuthScopes::parse(request.scope.as_deref().unwrap_or_default());
            if scopes.contains(OAuthScopes::FULL)
                && let Some(scope) = &mut request.scope
            {
                *scope = scope
                    .split_ascii_whitespace()
                    .filter(|name| *name != SCOPE_FULL)
                    .fold(String::with_capacity(scope.len()), |mut out, name| {
                        if !out.is_empty() {
                            out.push(' ');
                        }
                        out.push_str(name);
                        out
                    });
            }
            let client_id = encode_client_id(
                self.core.oauth.oauth_key.as_bytes(),
                &ClientMeta {
                    redirect_uris: request.redirect_uris.clone(),
                    scopes: scopes.without(OAuthScopes::FULL),
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
            if client_id.len() > CLIENT_ID_MAX_LEN {
                return Ok(registration_error(
                    ClientRegistrationError::invalid_client_metadata(
                        "The client metadata is too large to be encoded in a client id.",
                    ),
                ));
            }

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

        for uri in &request.redirect_uris {
            if let Err(err) = validate_redirect_uri(uri) {
                return Ok(registration_error(err));
            }
        }
        if !matches!(
            request.token_endpoint_auth_method,
            Some(
                TokenEndpointAuthMethod::ClientSecretBasic
                    | TokenEndpointAuthMethod::ClientSecretPost
            )
        ) {
            return Ok(registration_error(
                ClientRegistrationError::invalid_client_metadata(
                    "token_endpoint_auth_method must be none, client_secret_basic or client_secret_post.",
                ),
            ));
        }

        let access_token = self.authenticate_headers(req, &session).await?.access_token;
        access_token.enforce_permission(Permission::SysOAuthClientCreate)?;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let tenant_id = access_token.tenant_id();
        // SPDX-SnippetEnd

        let mut scopes = Vec::new();
        for scope in request
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .filter_map(parse_oauth_scope)
        {
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        let mut grant_types = Vec::new();
        for grant_type in &request.grant_types {
            match parse_grant_type(grant_type) {
                Some(grant_type) if !grant_types.contains(&grant_type) => {
                    grant_types.push(grant_type)
                }
                Some(_) => {}
                None => {
                    return Ok(registration_error(
                        ClientRegistrationError::invalid_client_metadata("Unsupported grant type."),
                    ));
                }
            }
        }
        if grant_types.is_empty() {
            grant_types = vec![
                OAuthGrantType::AuthorizationCode,
                OAuthGrantType::RefreshToken,
            ];
        }

        let client_id = rng()
            .sample_iter(Alphanumeric)
            .take(20)
            .map(|ch| char::from(ch.to_ascii_lowercase()))
            .collect::<String>();
        let mut client = OAuthClient {
            client_id: client_id.clone(),
            description: request.client_name.clone(),
            contacts: request.contacts.clone().into(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            member_tenant_id: tenant_id.map(|id| Id::new(id as u64)),
            // SPDX-SnippetEnd
            redirect_uris: request.redirect_uris.clone().into(),
            logo: request.logo_uri.clone(),
            created_at: UTCDateTime::now(),
            scopes: scopes.into(),
            grant_types: grant_types.into(),
            ..Default::default()
        };

        if let Err((_, err)) = validate_oauth_client(&client, is_superuser(&access_token)) {
            return Ok(registration_error(err));
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if validate_tenant_quota(self, tenant_id, TenantStorageQuota::MaxOauthClients)
            .await?
            .is_err()
        {
            return Ok(registration_error(
                ClientRegistrationError::invalid_client_metadata(
                    "The tenant has reached its OAuth client quota.",
                ),
            ));
        }
        // SPDX-SnippetEnd

        let client_secret = rng()
            .sample_iter(Alphanumeric)
            .take(48)
            .map(char::from)
            .collect::<String>();
        client.secret = Some(
            hash_secret(
                &self.inner.data.password_verifier,
                PasswordHashAlgorithm::Argon2id,
                client_secret.clone().into_bytes(),
            )
            .await
            .caused_by(trc::location!())?,
        );

        let result = self
            .registry()
            .write(RegistryWrite::insert(&client.into()))
            .await
            .caused_by(trc::location!())?;

        if !matches!(result, RegistryWriteResult::Success(_)) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to register OAuth client.")
                .reason(result)
                .caused_by(trc::location!()));
        }

        trc::event!(
            Auth(AuthEvent::ClientRegistration),
            Id = CompactString::from(&client_id),
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

    async fn verify_client_secret(
        &self,
        client: &ResolvedClient,
        client_secret: Option<&str>,
        remote_ip: IpAddr,
    ) -> trc::Result<Option<ErrorType>> {
        match (client.secret_hash(), client_secret) {
            (Some(hash), Some(secret))
                if verify_secret_hash(
                    &self.inner.data.password_verifier,
                    hash,
                    secret.as_bytes(),
                )
                .await
                .caused_by(trc::location!())? =>
            {
                Ok(None)
            }
            (Some(_), secret) => {
                if secret.is_some()
                    && self.has_auth_fail2ban()
                    && self.is_auth_fail2banned(remote_ip, None).await?
                {
                    Err(trc::SecurityEvent::AuthenticationBan
                        .into_err()
                        .ctx(trc::Key::RemoteIp, remote_ip))
                } else {
                    Ok(Some(ErrorType::InvalidClient))
                }
            }
            (None, _) => Ok(None),
        }
    }
}

fn registration_error(error: ClientRegistrationError) -> HttpResponse {
    JsonResponse::with_status(StatusCode::BAD_REQUEST, error)
        .no_cache()
        .into_http_response()
}
