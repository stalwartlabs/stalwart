/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod telemetry;
// SPDX-SnippetEnd
pub mod diagnose;

use crate::{
    api::diagnose::{DeliveryStage, spawn_delivery_diagnose},
    auth::{
        authenticate::Authenticator, oauth::auth::OAuthApiHandler, permissions::AccountApiHandler,
    },
};
use common::{
    Server,
    auth::{AccessToken, oauth::GrantType},
    manager::application::Resource,
};
use groupware::calendar::itip::{ItipIngest, RsvpRequest};
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse,
    request::{decode_path_element, fetch_body},
};
use hyper::{
    Method, StatusCode,
    header::{self, CONTENT_ENCODING},
};
use jmap::api::{ToJmapHttpResponse, ToRequestError};
use jmap_proto::error::request::RequestError;
use registry::schema::enums::Permission;
use std::time::Duration;
use utils::url_params::UrlParams;

pub trait ManagementApi: Sync + Send {
    fn handle_api_request(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn management_access_token(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<AccessToken>> + Send;
}

impl ManagementApi for Server {
    #[allow(unused_variables)]
    async fn handle_api_request(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let is_post = req.method() == Method::POST;
        let body = if is_post {
            fetch_body(req, 1024 * 1024, session.session_id).await
        } else {
            None
        };
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();

        match path.first().copied().unwrap_or_default() {
            "auth" if is_post => {
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;
                Box::pin(self.handle_login_request(
                    session,
                    body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                ))
                .await
            }
            "calendar"
                if is_post
                    && path.get(1).copied() == Some("rsvp")
                    && self.core.groupware.itip_http_rsvp_url.is_some() =>
            {
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                let request = serde_json::from_slice::<RsvpRequest>(
                    &body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                )
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;

                self.http_rsvp_handle(request, accept_language(req), session.remote_ip)
                    .await
                    .map(|response| JsonResponse::new(response).no_cache().into_http_response())
            }
            "discover" => {
                if let Some(email) = path.get(1).copied() {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;
                    self.handle_discover_request(session, decode_path_element(email).as_ref())
                        .await
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            "account" => {
                // Authenticate request
                let (_in_flight, access_token) = self.authenticate_headers(req, session).await?;
                self.handle_account_request(&access_token).await
            }
            "schema" => {
                // Authenticate request
                let (_in_flight, access_token) = self.authenticate_headers(req, session).await?;
                static SCHEMA_JSON: &[u8] =
                    include_bytes!("../../../../resources/schema/schema.json.gz");
                const SCHEMA_HASH: &str =
                    include_str!("../../../../resources/schema/schema.json.sha256");

                if path.get(1).is_some_and(|hash| hash == &SCHEMA_HASH) {
                    Ok(Resource::new("application/json", SCHEMA_JSON.to_vec())
                        .into_http_response()
                        .with_immutable_cache()
                        .with_header(CONTENT_ENCODING, "gzip"))
                } else {
                    Ok(HttpResponse::redirect(format!("/api/schema/{SCHEMA_HASH}")))
                }
            }
            "token" => {
                let access_token = self.management_access_token(req, session).await?;
                let account_id = access_token.account_id();
                match path.get(1).copied() {
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    Some("tracing") if self.core.is_enterprise_edition() => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveTracing)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_no_cache()
                            .with_text_body(
                                self.encode_access_token(
                                    GrantType::LiveTracing,
                                    account_id,
                                    self.account(account_id).await?.name(),
                                    60,
                                    None,
                                    None,
                                )
                                .await?,
                            ))
                    }
                    #[cfg(feature = "enterprise")]
                    Some("metrics") if self.core.is_enterprise_edition() => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveMetrics)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_no_cache()
                            .with_text_body(
                                self.encode_access_token(
                                    GrantType::LiveMetrics,
                                    account_id,
                                    self.account(account_id).await?.name(),
                                    60,
                                    None,
                                    None,
                                )
                                .await?,
                            ))
                    }
                    // SPDX-SnippetEnd
                    Some("delivery") => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveDeliveryTest)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_no_cache()
                            .with_text_body(
                                self.encode_access_token(
                                    GrantType::LiveDelivery,
                                    account_id,
                                    self.account(account_id).await?.name(),
                                    60,
                                    None,
                                    None,
                                )
                                .await?,
                            ))
                    }
                    Some("tracing") | Some("metrics") => {
                        Err(trc::ResourceEvent::NotFound
                            .ctx(trc::Key::Details, "Enterprise feature"))
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }
            "live" => {
                let access_token = self.management_access_token(req, session).await?;
                let params = UrlParams::new(req.uri().query());
                let account_id = access_token.account_id();

                match (
                    path.get(1).copied().unwrap_or_default(),
                    path.get(2).copied(),
                    req.method(),
                ) {
                    ("delivery", Some(target), &Method::GET) => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveDeliveryTest)?;

                        let timeout = Duration::from_secs(
                            params
                                .parse::<u64>("timeout")
                                .filter(|interval| *interval >= 1)
                                .unwrap_or(30),
                        );

                        let mut rx = spawn_delivery_diagnose(
                            self.clone(),
                            decode_path_element(target).to_lowercase(),
                            timeout,
                        );

                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_content_type("text/event-stream")
                            .with_cache_control("no-store")
                            .with_stream_body(BoxBody::new(StreamBody::new(
                                async_stream::stream! {
                                    while let Some(stage) = rx.recv().await {
                                        yield Ok(stage.to_frame());
                                    }
                                    yield Ok(DeliveryStage::Completed.to_frame());
                                },
                            ))))
                    }
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    ("tracing", _, &Method::GET) if self.core.is_enterprise_edition() => {
                        use crate::api::telemetry::TelemetryApi;

                        self.handle_telemetry_api_request(req, true, &access_token)
                            .await
                    }
                    #[cfg(feature = "enterprise")]
                    ("metrics", _, &Method::GET) if self.core.is_enterprise_edition() => {
                        use crate::api::telemetry::TelemetryApi;

                        self.handle_telemetry_api_request(req, false, &access_token)
                            .await
                    }
                    // SPDX-SnippetEnd
                    ("tracing" | "metrics", _, &Method::GET) => {
                        Err(trc::ResourceEvent::NotFound
                            .ctx(trc::Key::Details, "Enterprise feature"))
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn management_access_token(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<AccessToken> {
        let params = UrlParams::new(req.uri().query());
        if let Some(token) = params.get("token") {
            let path = req.uri().path();
            let grant = if path.starts_with("/api/live/delivery") {
                Some((GrantType::LiveDelivery, Permission::LiveDeliveryTest))
            } else {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                {
                    if self.core.is_enterprise_edition() {
                        if path.starts_with("/api/live/tracing") {
                            Some((GrantType::LiveTracing, Permission::LiveTracing))
                        } else if path.starts_with("/api/live/metrics") {
                            Some((GrantType::LiveMetrics, Permission::LiveMetrics))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                {
                    None
                }
            };

            if let Some((grant_type, permission)) = grant {
                self.validate_access_token(grant_type.into(), token)
                    .await
                    .map(|token_info| {
                        AccessToken::from_permissions(token_info.account_id, [permission])
                    })
            } else {
                self.authenticate_headers(req, session)
                    .await
                    .map(|(_, token)| token)
            }
        } else {
            self.authenticate_headers(req, session)
                .await
                .map(|(_, token)| token)
        }
    }
}

pub trait ToManageHttpResponse {
    fn into_http_response(self, challenge: AuthChallenge) -> HttpResponse;
}

impl ToManageHttpResponse for &trc::Error {
    fn into_http_response(self, challenge: AuthChallenge) -> HttpResponse {
        match self.as_ref() {
            trc::EventType::Auth(
                trc::AuthEvent::Failed | trc::AuthEvent::Error | trc::AuthEvent::TokenExpired,
            ) => HttpResponse::unauthorized(challenge),
            _ => self.to_request_error().into_http_response(),
        }
    }
}

pub fn accept_language(req: &HttpRequest) -> &str {
    req.headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .map(|language| {
            let language = language.split_once(',').map_or(language, |(l, _)| l);
            language.split_once(';').map_or(language, |(l, _)| l).trim()
        })
        .filter(|language| !language.is_empty())
        .unwrap_or("en")
}

const BEARER_CHALLENGE: &str = concat!(
    "Bearer realm=\"Stalwart Server\", ",
    "resource_metadata=\"/.well-known/oauth-protected-resource\""
);
const BASIC_CHALLENGE: &str = "Basic realm=\"Stalwart Server\"";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthChallenge {
    Bearer,
    BearerAndBasic,
}

pub trait UnauthorizedResponse {
    fn unauthorized(challenge: AuthChallenge) -> Self;
}

impl UnauthorizedResponse for HttpResponse {
    fn unauthorized(challenge: AuthChallenge) -> Self {
        let response = HttpResponse::new(StatusCode::UNAUTHORIZED)
            .with_header(header::WWW_AUTHENTICATE, BEARER_CHALLENGE);

        if challenge == AuthChallenge::BearerAndBasic {
            response.with_header(header::WWW_AUTHENTICATE, BASIC_CHALLENGE)
        } else {
            response
        }
        .with_content_type("application/problem+json")
        .with_text_body(serde_json::to_string(&RequestError::unauthorized()).unwrap_or_default())
    }
}
