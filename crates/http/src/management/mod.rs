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

use crate::management::diagnose::TroubleshootApi;
use common::{Server, auth::AccessToken};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse, request::fetch_body,
};
use hyper::{StatusCode, header};
use jmap::api::{ToJmapHttpResponse, ToRequestError};
use jmap_proto::error::request::RequestError;
use registry::schema::enums::Permission;
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "error")]
#[serde(rename_all = "camelCase")]
pub enum ManagementApiError<'x> {
    FieldAlreadyExists {
        field: &'x str,
        value: &'x str,
    },
    FieldMissing {
        field: &'x str,
    },
    NotFound {
        item: &'x str,
    },
    Unsupported {
        details: &'x str,
    },
    AssertFailed,
    Other {
        details: &'x str,
        reason: Option<&'x str>,
    },
}

pub trait ManagementApi: Sync + Send {
    fn handle_api_manage_request(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManagementApi for Server {
    #[allow(unused_variables)]
    async fn handle_api_manage_request(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let body = fetch_body(req, 1024 * 1024, session.session_id).await;
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();

        match path.first().copied().unwrap_or_default() {
            "diagnose" => {
                // Validate the access token
                access_token.enforce_permission(Permission::Troubleshoot)?;

                self.handle_diagnose_api_request(req, path, access_token, body)
                    .await
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            "telemetry" => {
                // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
                // Any attempt to modify, bypass, or disable this license validation mechanism
                // constitutes a severe violation of the Stalwart Enterprise License Agreement.
                // Such actions may result in immediate termination of your license, legal action,
                // and substantial financial penalties. Stalwart Labs LLC actively monitors for
                // unauthorized modifications and will pursue all available legal remedies against
                // violators to the fullest extent of the law, including but not limited to claims
                // for copyright infringement, breach of contract, and fraud.

                if self.core.is_enterprise_edition() {
                    use crate::management::telemetry::TelemetryApi;

                    self.handle_telemetry_api_request(req, path, access_token)
                        .await
                } else {
                    Err(trc::ManageEvent::NotSupported.ctx(trc::Key::Details, "Enterprise feature"))
                }
            }
            // SPDX-SnippetEnd
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

pub trait ToManageHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl ToManageHttpResponse for &trc::Error {
    fn into_http_response(self) -> HttpResponse {
        match self.as_ref() {
            trc::EventType::Manage(cause) => {
                match cause {
                    trc::ManageEvent::MissingParameter => ManagementApiError::FieldMissing {
                        field: self.value_as_str(trc::Key::Key).unwrap_or_default(),
                    },
                    trc::ManageEvent::AlreadyExists => ManagementApiError::FieldAlreadyExists {
                        field: self.value_as_str(trc::Key::Key).unwrap_or_default(),
                        value: self.value_as_str(trc::Key::Value).unwrap_or_default(),
                    },
                    trc::ManageEvent::NotFound => ManagementApiError::NotFound {
                        item: self.value_as_str(trc::Key::Key).unwrap_or_default(),
                    },
                    trc::ManageEvent::NotSupported => ManagementApiError::Unsupported {
                        details: self
                            .value(trc::Key::Details)
                            .or_else(|| self.value(trc::Key::Reason))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Requested action is unsupported"),
                    },
                    trc::ManageEvent::AssertFailed => ManagementApiError::AssertFailed,
                    trc::ManageEvent::Error => ManagementApiError::Other {
                        reason: self.value_as_str(trc::Key::Reason),
                        details: self
                            .value_as_str(trc::Key::Details)
                            .unwrap_or("Unknown error"),
                    },
                }
            }
            .into_http_response(),
            trc::EventType::Auth(
                trc::AuthEvent::Failed | trc::AuthEvent::Error | trc::AuthEvent::TokenExpired,
            ) => HttpResponse::unauthorized(true),
            _ => self.to_request_error().into_http_response(),
        }
    }
}

pub trait UnauthorizedResponse {
    fn unauthorized(include_realms: bool) -> Self;
}

impl UnauthorizedResponse for HttpResponse {
    fn unauthorized(include_realms: bool) -> Self {
        (if include_realms {
            HttpResponse::new(StatusCode::UNAUTHORIZED)
                .with_header(header::WWW_AUTHENTICATE, "Bearer realm=\"Stalwart Server\"")
                .with_header(header::WWW_AUTHENTICATE, "Basic realm=\"Stalwart Server\"")
        } else {
            HttpResponse::new(StatusCode::UNAUTHORIZED)
        })
        .with_content_type("application/problem+json")
        .with_text_body(serde_json::to_string(&RequestError::unauthorized()).unwrap_or_default())
    }
}

impl ManagementApiError<'_> {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}
