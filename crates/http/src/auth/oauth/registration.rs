/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use super::ErrorType;
use crate::auth::authenticate::Authenticator;
use common::{
    Server,
    auth::{
        BuildAccessToken,
        oauth::registration::{ClientRegistrationRequest, ClientRegistrationResponse},
    },
};
use http_proto::{request::fetch_body, *};
use registry::{
    schema::{
        enums::Permission,
        prelude::{Object, Property},
        structs::OAuthClient,
    },
    types::datetime::UTCDateTime,
};
use store::{
    ahash::AHashSet,
    rand::{Rng, distr::Alphanumeric, rng},
    registry::{RegistryQuery, write::RegistryWrite},
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
}
impl ClientRegistrationHandler for Server {
    async fn handle_oauth_registration_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let tenant_id = if !self.core.oauth.allow_anonymous_client_registration {
            // Authenticate request
            let (_, access_token) = self.authenticate_headers(req, &session).await?;

            // Validate permissions
            access_token.enforce_permission(Permission::OauthClientRegistration)?;
            access_token.tenant_id()
        } else {
            self.is_http_anonymous_request_allowed(&session.remote_ip)
                .await?;
            None
        };

        // Parse request
        let body = fetch_body(req, 20 * 1024, session.session_id).await;
        let request = serde_json::from_slice::<ClientRegistrationRequest>(
            body.as_deref().unwrap_or_default(),
        )
        .map_err(|err| {
            trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
        })?;

        // Generate client ID
        let client_id = rng()
            .sample_iter(Alphanumeric)
            .take(20)
            .map(|ch| char::from(ch.to_ascii_lowercase()))
            .collect::<String>();

        self.registry()
            .write(RegistryWrite::insert(&OAuthClient {
                client_id: client_id.clone(),
                created_at: UTCDateTime::now(),
                description: request.client_name.clone(),
                contacts: request.contacts.clone(),
                member_tenant_id: tenant_id.map(|id| Id::new(id as u64)),
                redirect_uris: request.redirect_uris.clone(),
                logo: request.logo_uri.clone(),
                ..Default::default()
            }))
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Auth(AuthEvent::ClientRegistration),
            Id = client_id.to_string(),
            RemoteIp = session.remote_ip
        );

        Ok(JsonResponse::new(ClientRegistrationResponse {
            client_id,
            request,
            ..Default::default()
        })
        .no_cache()
        .into_http_response())
    }

    async fn validate_client_registration(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        account_id: u32,
    ) -> trc::Result<Option<ErrorType>> {
        if !self.core.oauth.require_client_authentication {
            return Ok(None);
        }

        // Fetch client registration
        let found_registration = if let Some(client_id) = self
            .registry()
            .query::<AHashSet<u64>>(
                RegistryQuery::new(Object::OAuthClient).equal(Property::ClientId, client_id),
            )
            .await?
            .iter()
            .next()
        {
            if let Some(redirect_uri) = redirect_uri {
                let client = self
                    .registry()
                    .object::<OAuthClient>(Id::new(*client_id))
                    .await?
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("OAuth client not found.")
                            .caused_by(trc::location!())
                            .ctx(trc::Key::Id, *client_id)
                    })?;
                if client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
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
            .has_permission(Permission::OauthClientOverride)
        {
            return Ok(None);
        }

        Ok(Some(if found_registration {
            ErrorType::InvalidClient
        } else {
            ErrorType::InvalidRequest
        }))
    }
}
