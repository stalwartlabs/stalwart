/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    HttpSessionManager,
    api::{AuthChallenge, ManagementApi, ToManageHttpResponse},
    auth::{
        authenticate::{Authenticator, HttpAuthenticated, HttpHeaders},
        oauth::{
            FormData,
            auth::OAuthApiHandler,
            authorize::{PROTECTED_RESOURCE_PATH, resource_metadata_url},
            logout::EndSessionHandler,
            openid::{OidcMetadataRequest, OpenIdHandler},
            registration::ClientRegistrationHandler,
            request_origin,
            token::TokenHandler,
        },
    },
    form::FormHandler,
    stream::InFlightStream,
};
use common::{
    BuildServer, Inner, KV_ACME, Server,
    auth::oauth::{client::RequestOrigin, scope::OAuthScopes},
    config::telemetry::PrometheusAuth,
    ipc::PushEvent,
    manager::{
        app_client::APP_CLIENT_DOCUMENT,
        application::{AppClientDocument, Resource},
    },
    network::{
        SessionData, SessionManager, SessionStream, forwarded::ClientIp, memory::MemoryClass,
    },
};
use compact_str::{CompactString, ToCompactString};
use dav::{DavMethod, request::DavRequestHandler};
use groupware::DavResourceName;
use http_proto::{
    DownloadResponse, HttpContext, HttpRequest, HttpResponse, HttpResponseBody, HttpSessionData,
    JsonProblemResponse, ToHttpResponse, form_urlencoded, request::fetch_body,
};
use hyper::{
    Method, StatusCode, body,
    header::{
        self, CONTENT_ENCODING, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, X_FRAME_OPTIONS,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use jmap::{
    api::{
        ToJmapHttpResponse,
        event_source::EventSourceHandler,
        request::RequestHandler,
        session::{SessionHandler, allowed_capabilities},
    },
    blob::{download::BlobDownload, upload::BlobUpload},
    websocket::upgrade::WebSocketUpgrade,
};
use jmap_proto::request::{Request, capability::Session};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use scim::request::ScimRequestHandler;
// SPDX-SnippetEnd
use percent_encoding::percent_decode_str;
use registry::schema::enums::Permission;
use std::{str::FromStr, sync::Arc};
use store::dispatch::lookup::KeyValue;
use telemetry::prometheus::negotiate::negotiate;
use trc::SecurityEvent;
use types::{blob::BlobId, id::Id};

static RSVP_PAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/html-templates/calendar-rsvp.html.min.gz"
));

static LOGIN_PAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/html-templates/login.html.min.gz"
));

pub trait ParseHttp: Sync + Send {
    fn parse_http_request(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ParseHttp for Server {
    async fn parse_http_request(
        &self,
        mut req: HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let mut path = req.uri().path().split('/');
        path.next();

        // Validate endpoint access
        let ctx = HttpContext::new(&session, &req);
        match ctx.has_endpoint_access(self).await {
            StatusCode::OK => (),
            status => {
                // Allow loopback address to avoid lockouts
                if !session.remote_ip.is_loopback() {
                    return Ok(JsonProblemResponse(status).into_http_response());
                }
            }
        }

        match path.next().unwrap_or_default() {
            "jmap" => {
                match (path.next().unwrap_or_default(), req.method()) {
                    ("", &Method::POST) => {
                        // Authenticate request
                        let HttpAuthenticated {
                            in_flight: _in_flight,
                            access_token,
                            ..
                        } = self.authenticate_headers(&req, &session).await?;

                        if let Some(content_type) = req.headers().get(CONTENT_TYPE) {
                            let is_json = content_type
                                .to_str()
                                .ok()
                                .map(|ct| {
                                    ct.split_once(';')
                                        .map_or(ct, |(m, _)| m)
                                        .trim()
                                        .eq_ignore_ascii_case("application/json")
                                })
                                .unwrap_or(false);
                            if !is_json {
                                return Err(trc::JmapEvent::NotJson
                                    .into_err()
                                    .details("The Content-Type header must be application/json."));
                            }
                        }

                        let bytes = fetch_body(
                            &mut req,
                            if !access_token.has_permission(Permission::UnlimitedUploads) {
                                self.core.jmap.upload_max_size
                            } else {
                                0
                            },
                            session.session_id,
                        )
                        .await
                        .ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?;

                        let mut request = Request::parse(
                            &bytes,
                            self.core.jmap.request_max_calls,
                            self.core.jmap.request_max_size,
                        )?;
                        request.using = allowed_capabilities(&access_token, request.using);

                        let mut reservation = self.memory_reservation(MemoryClass::Read);
                        return Ok(self
                            .handle_jmap_request(request, &access_token, &session, &mut reservation)
                            .await
                            .into_http_response());
                    }
                    ("download", &Method::GET) => {
                        // Authenticate request
                        let HttpAuthenticated {
                            in_flight: _in_flight,
                            access_token,
                            ..
                        } = self.authenticate_headers(&req, &session).await?;
                        let access_token =
                            access_token.assert_allows_oauth_scopes(OAuthScopes::INTEROPERABLE)?;

                        if let (Some(_), Some(blob_id), Some(name)) = (
                            path.next().and_then(|p| Id::from_str(p).ok()),
                            path.next().and_then(BlobId::from_base32),
                            path.next(),
                        ) {
                            return match self.blob_contents(&blob_id, &access_token).await? {
                                Some(contents) => {
                                    let (prefix, blob) = contents.into_http_parts()?;
                                    Ok(DownloadResponse {
                                        filename: name.to_string(),
                                        content_type: req
                                            .uri()
                                            .query()
                                            .and_then(|q| {
                                                form_urlencoded::parse(q.as_bytes())
                                                    .find(|(k, _)| k == "accept")
                                                    .map(|(_, v)| v.into_owned())
                                            })
                                            .unwrap_or("application/octet-stream".to_string()),
                                        prefix,
                                        blob,
                                    }
                                    .into_http_response())
                                }
                                None => Err(trc::ResourceEvent::NotFound.into_err()),
                            };
                        }
                    }
                    ("upload", &Method::POST) => {
                        // Authenticate request
                        let HttpAuthenticated {
                            in_flight: _in_flight,
                            access_token,
                            ..
                        } = self.authenticate_headers(&req, &session).await?;
                        let access_token =
                            access_token.assert_allows_oauth_scopes(OAuthScopes::INTEROPERABLE)?;

                        if let Some(account_id) = path.next().and_then(|p| Id::from_str(p).ok()) {
                            return match fetch_body(
                                &mut req,
                                if !access_token.has_permission(Permission::UnlimitedUploads) {
                                    self.core.jmap.upload_max_size
                                } else {
                                    0
                                },
                                session.session_id,
                            )
                            .await
                            {
                                Some(bytes) => Ok(self
                                    .blob_upload(
                                        account_id,
                                        req.headers()
                                            .get(CONTENT_TYPE)
                                            .and_then(|h| h.to_str().ok())
                                            .unwrap_or("application/octet-stream"),
                                        &bytes,
                                        &access_token,
                                    )
                                    .await?
                                    .into_http_response()),
                                None => Err(trc::LimitEvent::SizeUpload.into_err()),
                            };
                        }
                    }
                    ("eventsource", &Method::GET) => {
                        // Authenticate request
                        let HttpAuthenticated {
                            in_flight: _in_flight,
                            access_token,
                            ..
                        } = self.authenticate_headers(&req, &session).await?;
                        let access_token =
                            access_token.assert_allows_oauth_scopes(OAuthScopes::INTEROPERABLE)?;

                        return self.handle_event_source(req, access_token).await;
                    }
                    ("ws", &Method::GET) => {
                        // Authenticate request
                        let HttpAuthenticated {
                            in_flight: _in_flight,
                            access_token,
                            epoch,
                        } = self.authenticate_headers(&req, &session).await?;
                        let access_token =
                            access_token.assert_allows_oauth_scopes(OAuthScopes::INTEROPERABLE)?;

                        return self
                            .upgrade_websocket_connection(req, access_token, epoch, session)
                            .await;
                    }
                    ("session", &Method::GET) => {
                        return if req.headers().contains_key(header::AUTHORIZATION) {
                            // Authenticate request
                            let HttpAuthenticated {
                                in_flight: _in_flight,
                                access_token,
                                ..
                            } = self.authenticate_headers(&req, &session).await?;

                            self.handle_session_resource(
                                self.core.network.http.url_https.to_string(),
                                &access_token,
                            )
                            .await
                            .map(|s| s.into_http_response())
                        } else {
                            Ok(Session::new(
                                &self.core.network.http.url_https,
                                &self.core.jmap.capabilities,
                            )
                            .into_http_response())
                        };
                    }
                    (_, &Method::OPTIONS) => {
                        return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
                    }
                    _ => (),
                }
            }
            "dav" => {
                let response = match (
                    path.next().and_then(DavResourceName::parse),
                    DavMethod::parse(req.method()),
                ) {
                    (Some(_), Some(DavMethod::OPTIONS)) => HttpResponse::new(StatusCode::OK)
                        .with_header(
                            "DAV",
                            concat!(
                                "1, 2, 3, access-control, extended-mkcol, calendar-access, ",
                                "calendar-auto-schedule, calendar-no-timezone, addressbook"
                            ),
                        )
                        .with_header(
                            "Allow",
                            concat!(
                                "OPTIONS, GET, HEAD, POST, PUT, DELETE, COPY, MOVE, MKCALENDAR, ",
                                "MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, REPORT, ACL"
                            ),
                        ),
                    (Some(resource), Some(method)) => {
                        // Authenticate request
                        let HttpAuthenticated {
                            in_flight: _in_flight,
                            access_token,
                            ..
                        } = self.authenticate_headers(&req, &session).await?;

                        self.handle_dav_request(req, access_token, &session, resource, method)
                            .await
                    }
                    (_, None) => HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED),
                    (None, _) => HttpResponse::new(StatusCode::NOT_FOUND),
                };

                return Ok(response);
            }
            ".well-known" => match (path.next().unwrap_or_default(), req.method()) {
                ("jmap", &Method::GET) => {
                    return Ok(HttpResponse::new(StatusCode::TEMPORARY_REDIRECT)
                        .with_no_cache()
                        .with_location("/jmap/session"));
                }
                ("caldav", _) => {
                    return Ok(HttpResponse::new(StatusCode::TEMPORARY_REDIRECT)
                        .with_no_cache()
                        .with_location(DavResourceName::Cal.base_path()));
                }
                ("carddav", _) => {
                    return Ok(HttpResponse::new(StatusCode::TEMPORARY_REDIRECT)
                        .with_no_cache()
                        .with_location(DavResourceName::Card.base_path()));
                }
                ("oauth-authorization-server", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self
                        .handle_oauth_metadata(request_origin(&req, &session))
                        .await;
                }
                ("oauth-protected-resource", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self
                        .handle_oauth_protected_resource(
                            request_origin(&req, &session),
                            req.uri()
                                .path()
                                .strip_prefix(PROTECTED_RESOURCE_PATH)
                                .unwrap_or_default(),
                        )
                        .await;
                }
                ("openid-configuration", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self
                        .handle_oidc_metadata(
                            OidcMetadataRequest::WellKnown,
                            request_origin(&req, &session),
                        )
                        .await;
                }
                ("acme-challenge", &Method::GET) if self.has_acme_http_providers() => {
                    if let Some(token) = path.next() {
                        return match self
                            .in_memory_store()
                            .key_get::<String>(KeyValue::<()>::build_key(KV_ACME, token))
                            .await?
                        {
                            Some(proof) => Ok(Resource::new("text/plain", proof.into_bytes())
                                .into_http_response()),
                            None => Err(trc::ResourceEvent::NotFound.into_err()),
                        };
                    }
                }
                ("mta-sts.txt", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return if let Some(policy) = &self.core.smtp.session.mta_sts_policy {
                        Ok(Resource::new("text/plain", policy.text.clone()).into_http_response())
                    } else {
                        Err(trc::ResourceEvent::NotFound.into_err())
                    };
                }
                ("user-agent-configuration.json", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;
                    return Ok(Resource::new(
                        "application/json",
                        self.get_pacc_for_domain(
                            req.headers()
                                .get(header::HOST)
                                .and_then(|h| h.to_str().ok())
                                .map(pacc_domain)
                                .unwrap_or_default(),
                        )
                        .await?
                        .into_bytes(),
                    )
                    .into_http_response()
                    .with_sandbox_policy()
                    .with_cors_unrestricted());
                }
                ("mail-v1.xml", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self
                        .handle_autoconfig_request(req.uri().query())
                        .await
                        .map(|resource| resource.into_http_response().with_sandbox_policy());
                }
                ("autoconfig", &Method::GET)
                    if path.next().unwrap_or_default() == "mail"
                        && path.next().unwrap_or_default() == "config-v1.1.xml" =>
                {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self.handle_autoconfig_request(req.uri().query()).await.map(
                        |resource| {
                            resource
                                .into_http_response()
                                .with_sandbox_policy()
                                .with_cors_unrestricted()
                        },
                    );
                }
                (_, &Method::OPTIONS) => {
                    return Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_cors_unrestricted());
                }
                _ => (),
            },
            "auth" => match (path.next().unwrap_or_default(), req.method()) {
                ("device", &Method::POST) => {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self.handle_device_auth(&mut req, &session).await;
                }
                ("token", &Method::POST) => {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self.handle_token_request(&mut req, session).await;
                }
                ("revoke", &Method::POST) => {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self.handle_token_revocation(&mut req, session).await;
                }
                ("introspect", &Method::POST) => {
                    // Authenticate request
                    let _auth = self.authenticate_headers(&req, &session).await?;

                    return self
                        .handle_token_introspect(&mut req, session.session_id)
                        .await;
                }
                ("userinfo", &Method::GET) => {
                    // Authenticate request
                    let HttpAuthenticated {
                        in_flight: _in_flight,
                        access_token,
                        ..
                    } = self.authenticate_headers(&req, &session).await?;

                    return self
                        .handle_userinfo_request(access_token.account_id())
                        .await;
                }
                ("register", &Method::POST) => {
                    return self
                        .handle_oauth_registration_request(&mut req, session)
                        .await;
                }
                ("logout", &Method::GET | &Method::POST) => {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self.handle_end_session(&mut req, &session).await;
                }
                ("jwks.json", &Method::GET) => {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return Ok(self.core.oauth.oidc_jwks.clone().into_http_response());
                }
                (_, &Method::OPTIONS) => {
                    return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
                }
                _ => (),
            },
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            "scim" => {
                let (_in_flight, access_token) = if req.authorization().is_some() {
                    match self.authenticate_headers(&req, &session).await {
                        Ok(auth) => (auth.in_flight, Some(auth.access_token)),
                        Err(err) => {
                            let response =
                                scim::error::Error::from(err).into_response(session.session_id);
                            return Ok(response);
                        }
                    }
                } else if let Err(err) = self
                    .is_http_anonymous_request_allowed(session.remote_ip)
                    .await
                {
                    return Ok(scim::error::Error::from(err).into_response(session.session_id));
                } else {
                    (None, None)
                };

                return Ok(Box::pin(self.handle_scim_request(req, session, access_token)).await);
            }
            // SPDX-SnippetEnd
            "api" => {
                // Allow CORS preflight requests
                if req.method() == Method::OPTIONS {
                    return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
                }

                return Ok(match self.handle_api_request(&mut req, &session).await {
                    Ok(response) => response,
                    Err(err) => {
                        let response = err.into_http_response(AuthChallenge::Bearer, || {
                            resource_metadata_url(
                                self,
                                request_origin(&req, &session),
                                req.uri().path(),
                            )
                        });
                        trc::error!(err.span_id(session.session_id));
                        response
                    }
                });
            }
            "mail" => {
                if req.method() == Method::GET
                    && path.next().unwrap_or_default() == "config-v1.1.xml"
                {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self
                        .handle_autoconfig_request(req.uri().query())
                        .await
                        .map(|resource| resource.into_http_response().with_sandbox_policy());
                }
            }
            "calendar" => {
                // Limit anonymous requests
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                if self.core.groupware.itip_http_rsvp_url.is_some()
                    && req.method() == Method::GET
                    && path.next().unwrap_or_default() == "rsvp"
                {
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    if let Some(page) = self
                        .core
                        .enterprise
                        .as_ref()
                        .and_then(|e| e.template_scheduling_web.as_ref())
                    {
                        return Ok(HttpResponse::new(StatusCode::OK)
                            .with_content_type("text/html; charset=utf-8")
                            .with_text_body(page.to_string())
                            .with_no_store());
                    }
                    // SPDX-SnippetEnd

                    return Ok(HttpResponse::new(StatusCode::OK)
                        .with_content_type("text/html; charset=utf-8")
                        .with_header(CONTENT_ENCODING, "gzip")
                        .with_binary_body(RSVP_PAGE)
                        .with_no_store());
                }
            }
            "autodiscover" | "Autodiscover" | "AutoDiscover" => {
                let document_name = path.next().unwrap_or_default();
                if req.method() == Method::POST
                    && document_name.eq_ignore_ascii_case("autodiscover.xml")
                {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    return self
                        .handle_autodiscover_request(
                            fetch_body(&mut req, 8192, session.session_id).await,
                        )
                        .await
                        .map(|resource| resource.into_http_response().with_sandbox_policy());
                } else if document_name.eq_ignore_ascii_case("autodiscover.json") {
                    // Limit anonymous requests
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;

                    let path_email = path
                        .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
                        .find(|segment| segment.contains('@'));

                    return self
                        .handle_autodiscover_v2_request(req.uri().query(), path_email.as_deref())
                        .await
                        .map(|result| {
                            match result {
                                Ok(resource) => resource.into_http_response(),
                                Err(err) => HttpResponse::new(StatusCode::BAD_REQUEST)
                                    .with_content_type("application/json; charset=utf-8")
                                    .with_text_body(err),
                            }
                            .with_sandbox_policy()
                        });
                }
            }
            "robots.txt" => {
                // Limit anonymous requests
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                return Ok(
                    Resource::new("text/plain", b"User-agent: *\nDisallow: /\n".to_vec())
                        .into_http_response(),
                );
            }
            "healthz" => {
                // Limit anonymous requests
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;

                match path.next().unwrap_or_default() {
                    "live" => {
                        return Ok(JsonProblemResponse(StatusCode::OK).into_http_response());
                    }
                    "ready" => {
                        return Ok(JsonProblemResponse({
                            if !self.core.storage.data.is_none() {
                                StatusCode::OK
                            } else {
                                StatusCode::SERVICE_UNAVAILABLE
                            }
                        })
                        .into_http_response());
                    }
                    _ => (),
                }
            }
            "metrics" => match path.next().unwrap_or_default() {
                "prometheus" => {
                    if let Some(prometheus) = &self.core.metrics.prometheus {
                        if req.method() != Method::GET {
                            return Ok(HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED)
                                .with_header(header::ALLOW, "GET"));
                        }
                        if matches!(prometheus.auth, PrometheusAuth::None) {
                            self.is_http_anonymous_request_allowed(session.remote_ip)
                                .await?;
                        } else if !prometheus.auth.is_authorized(req.authorization_basic()) {
                            return Err(trc::AuthEvent::Failed
                                .into_err()
                                .details("Invalid or missing credentials.")
                                .caused_by(trc::location!()));
                        }

                        let format = negotiate(
                            req.headers()
                                .get(header::ACCEPT)
                                .map(|value| value.as_bytes()),
                        );
                        return Ok(HttpResponse::new(StatusCode::OK)
                            .with_content_type(format.content_type())
                            .with_binary_body(self.export_prometheus_metrics(prometheus, format)));
                    }
                }
                "otel" => {
                    // Reserved for future use
                }
                _ => (),
            },
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            "logo" if self.is_enterprise_edition() => {
                let domain_hint = req
                    .uri()
                    .query()
                    .and_then(|q| {
                        form_urlencoded::parse(q.as_bytes())
                            .find(|(k, v)| k == "domain" && !v.is_empty())
                            .map(|(_, v)| v)
                    })
                    .or_else(|| {
                        req.headers()
                            .get(header::HOST)
                            .and_then(|h| h.to_str().ok())
                            .map(|h| h.rsplit_once(':').map_or(h, |(h, _)| h))
                            .map(std::borrow::Cow::Borrowed)
                    });
                match self
                    .logo_resource(domain_hint.as_deref().unwrap_or_default())
                    .await
                {
                    Ok(Some(resource)) => {
                        return Ok(resource
                            .into_http_response()
                            .with_image_sandbox_policy()
                            .with_content_disposition("inline; filename=\"logo\""));
                    }
                    Ok(None) => {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                    Err(err) => {
                        trc::error!(err.span_id(session.session_id));
                    }
                }
            }
            // SPDX-SnippetEnd
            "form" => {
                if let Some(form) = &self.core.network.contact_form {
                    match *req.method() {
                        Method::POST => {
                            self.is_http_anonymous_request_allowed(session.remote_ip)
                                .await?;

                            let form_data =
                                FormData::from_request(&mut req, form.max_size, session.session_id)
                                    .await?;

                            return self.handle_contact_form(&session, form, form_data).await;
                        }
                        Method::OPTIONS => {
                            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
                        }
                        _ => {}
                    }
                }
            }
            "login" | "device" => {
                return Ok(HttpResponse::new(StatusCode::OK)
                    .with_content_type("text/html; charset=utf-8")
                    .with_header(CONTENT_ENCODING, "gzip")
                    .with_header(X_FRAME_OPTIONS, "DENY")
                    .with_header(CONTENT_SECURITY_POLICY, "frame-ancestors 'none'")
                    .with_binary_body(LOGIN_PAGE));
            }
            external => {
                if path.next().is_none() {
                    if !external.is_empty() {
                        if !self.inner.data.applications.has_prefix(external)
                            && ban_scanned_path(self, req.uri().path(), &session).await?
                        {
                            return Err(trc::ResourceEvent::NotFound.into_err());
                        }
                        return Ok(HttpResponse::redirect(format!("/{external}/")));
                    } else if let Some(url) = &self.core.network.http.redirect_root {
                        return Ok(HttpResponse::redirect(url.clone()));
                    }
                } else if req.uri().path().get(external.len() + 2..) == Some(APP_CLIENT_DOCUMENT)
                    && let Some(response) = match self
                        .application_client_document(external, request_origin(&req, &session))
                    {
                        AppClientDocument::Document(document) => {
                            Some(Ok(Resource::new("application/json", document)
                                .into_http_response()
                                .with_no_cache()
                                .with_cors_unrestricted()))
                        }
                        AppClientDocument::Untrusted => {
                            Some(Err(trc::ResourceEvent::NotFound.into_err()))
                        }
                        AppClientDocument::NotShipped => None,
                    }
                {
                    return response;
                } else if let Some(resource) = self
                    .inner
                    .data
                    .applications
                    .serve(
                        external,
                        req.uri()
                            .path()
                            .get(external.len() + 2..)
                            .unwrap_or_default(),
                    )
                    .await?
                {
                    let response = resource.resource.into_http_response();
                    return Ok(if !resource.no_cache {
                        response.with_immutable_cache()
                    } else {
                        response.with_no_cache()
                    });
                }
            }
        }

        // Block dangerous URLs
        ban_scanned_path(self, req.uri().path(), &session).await?;

        Err(trc::ResourceEvent::NotFound.into_err())
    }
}

async fn ban_scanned_path(
    server: &Server,
    path: &str,
    session: &HttpSessionData,
) -> trc::Result<bool> {
    let banned = server.is_http_banned_path(path, session.remote_ip).await?;
    if banned {
        trc::event!(
            Security(SecurityEvent::ScanBan),
            SpanId = session.session_id,
            RemoteIp = session.remote_ip,
            Path = CompactString::from(path),
        );
    }
    Ok(banned)
}

async fn handle_session<T: SessionStream>(inner: Arc<Inner>, session: SessionData<T>) {
    let is_tls = session.stream.is_tls();

    if let Err(http_err) = http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(InFlightStream::new(session.stream, session.in_flight)),
            service_fn(|req: hyper::Request<body::Incoming>| {
                let instance = session.instance.clone();
                let inner = inner.clone();

                async move {
                    let server = inner.build_server();

                    // Obtain remote IP
                    let remote_ip = match server
                        .core
                        .network
                        .http
                        .remote_ip_source
                        .resolve(req.headers())
                    {
                        ClientIp::Peer => {
                            trc::event!(
                                Http(trc::HttpEvent::RequestUrl),
                                SpanId = session.session_id,
                                Url = req.uri().to_compact_string(),
                            );

                            session.remote_ip
                        }
                        ClientIp::Forwarded(forwarded_for) => {
                            trc::event!(
                                Http(trc::HttpEvent::RequestUrl),
                                SpanId = session.session_id,
                                RemoteIp = forwarded_for,
                                Url = req.uri().to_compact_string(),
                            );

                            forwarded_for
                        }
                        ClientIp::Missing if session.remote_ip.is_loopback() => {
                            trc::event!(
                                Http(trc::HttpEvent::RequestUrl),
                                SpanId = session.session_id,
                                Url = req.uri().to_compact_string(),
                            );

                            session.remote_ip
                        }
                        ClientIp::Missing => {
                            trc::event!(
                                Http(trc::HttpEvent::XForwardedMissing),
                                SpanId = session.session_id,
                            );
                            session.remote_ip
                        }
                        ClientIp::Invalid => {
                            trc::event!(
                                Http(trc::HttpEvent::XForwardedInvalid),
                                ListenerId = instance.id.clone(),
                                RemoteIp = session.remote_ip,
                                SpanId = session.session_id,
                            );

                            return Ok::<_, hyper::Error>(
                                JsonProblemResponse(StatusCode::BAD_REQUEST)
                                    .into_http_response()
                                    .build(),
                            );
                        }
                    };

                    // Check if the remote IP has been blocked
                    if server.is_ip_blocked(remote_ip) {
                        trc::event!(
                            Security(trc::SecurityEvent::IpBlocked),
                            ListenerId = instance.id.clone(),
                            RemoteIp = remote_ip,
                            SpanId = session.session_id,
                        );

                        return Ok::<_, hyper::Error>(
                            JsonProblemResponse(StatusCode::FORBIDDEN)
                                .into_http_response()
                                .build(),
                        );
                    }

                    // Parse HTTP request
                    let challenge_uri = req.uri().clone();
                    let challenge_host = req.headers().get(HOST).cloned();
                    let response = match server
                        .parse_http_request(
                            req,
                            HttpSessionData {
                                instance,
                                local_ip: session.local_ip,
                                local_port: session.local_port,
                                remote_ip,
                                remote_port: session.remote_port,
                                is_tls,
                                session_id: session.session_id,
                            },
                        )
                        .await
                    {
                        Ok(response) => response,
                        Err(err) => {
                            let response =
                                err.into_http_response(AuthChallenge::BearerAndBasic, || {
                                    resource_metadata_url(
                                        &server,
                                        RequestOrigin {
                                            is_tls,
                                            authority: challenge_host
                                                .as_ref()
                                                .and_then(|host| host.to_str().ok())
                                                .or_else(|| {
                                                    challenge_uri
                                                        .authority()
                                                        .map(|authority| authority.as_str())
                                                })
                                                .unwrap_or_default(),
                                        },
                                        challenge_uri.path(),
                                    )
                                });
                            trc::error!(err.span_id(session.session_id));
                            response
                        }
                    };

                    trc::event!(
                        Http(trc::HttpEvent::ResponseBody),
                        SpanId = session.session_id,
                        Contents = match response.body() {
                            HttpResponseBody::Text(value) =>
                                trc::Value::String(value.as_str().into()),
                            HttpResponseBody::Binary(_) | HttpResponseBody::Prefixed(_) =>
                                trc::Value::String("[binary data]".into()),
                            HttpResponseBody::Stream(_) => trc::Value::String("[stream]".into()),
                            _ => trc::Value::None,
                        },
                        Code = response.status().as_u16(),
                        Size = response.size(),
                    );

                    // Build response
                    let mut response = response.build();

                    // Add custom headers
                    if !server.core.network.http.response_headers.is_empty() {
                        let headers = response.headers_mut();

                        for (header, value) in &server.core.network.http.response_headers {
                            headers.insert(header.clone(), value.clone());
                        }
                    }

                    Ok::<_, hyper::Error>(response)
                }
            }),
        )
        .with_upgrades()
        .await
        && !http_err.is_timeout()
    {
        if http_err.is_parse() {
            let server = inner.build_server();
            if server.core.network.http.remote_ip_source.is_peer() {
                match server.is_scanner_fail2banned(session.remote_ip).await {
                    Ok(true) => {
                        trc::event!(
                            Security(SecurityEvent::ScanBan),
                            SpanId = session.session_id,
                            RemoteIp = session.remote_ip,
                            Reason = http_err.to_compact_string(),
                        );
                        return;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        trc::error!(
                            err.span_id(session.session_id)
                                .details("Failed to check for fail2ban")
                        );
                    }
                }
            }
        }

        trc::event!(
            Http(trc::HttpEvent::Error),
            SpanId = session.session_id,
            Reason = http_err.to_compact_string(),
        );
    }
}

impl SessionManager for HttpSessionManager {
    fn handle<T: SessionStream>(self, session: SessionData<T>) -> impl Future<Output = ()> + Send {
        handle_session(self.inner, session)
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {
            let _ = self.inner.ipc.push_tx.send(PushEvent::Stop).await;
        }
    }
}

const PACC_HOST_PREFIX: &str = "ua-auto-config.";

fn pacc_domain(host: &str) -> &str {
    let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
    host.get(..PACC_HOST_PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(PACC_HOST_PREFIX))
        .and_then(|_| host.get(PACC_HOST_PREFIX.len()..))
        .unwrap_or(host)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/http/src/request/tests.rs"]
mod tests;
