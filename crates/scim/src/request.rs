/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::{ScimAuthorization, ScimEnabled},
    context::{ScimContext, parse_id},
    discovery::ScimDiscovery,
    error::{Error as ScimResponseError, Result, scim_response},
};
use common::{Server, auth::AccessToken};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData,
    request::{decode_path_element, fetch_body},
};
use hyper::{Method, StatusCode, header};
use scim_proto::{
    CONTENT_TYPE, ResourceType,
    message::{error::Error, search::SearchRequest},
    schema::spc::ServiceProviderConfig,
};
use serde::Serialize;

pub const MAX_BODY_SIZE: usize = 1024 * 1024;
pub const SEARCH_ENDPOINT: &str = ".search";

pub trait ScimRequestHandler: Sync + Send {
    fn handle_scim_request(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
        access_token: Option<AccessToken>,
    ) -> impl Future<Output = HttpResponse> + Send;
}

impl ScimRequestHandler for Server {
    async fn handle_scim_request(
        &self,
        mut req: HttpRequest,
        session: HttpSessionData,
        access_token: Option<AccessToken>,
    ) -> HttpResponse {
        match self
            .dispatch_scim_request(&mut req, &session, access_token.as_ref())
            .await
        {
            Ok(response) => response,
            Err(error) => error.into_response(session.session_id),
        }
    }
}

trait ScimDispatch {
    fn dispatch_scim_request(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
        access_token: Option<&AccessToken>,
    ) -> impl Future<Output = Result<HttpResponse>> + Send;
}

impl ScimDispatch for Server {
    async fn dispatch_scim_request(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
        access_token: Option<&AccessToken>,
    ) -> Result<HttpResponse> {
        if req.method() == Method::OPTIONS {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        self.assert_scim_enabled()?;

        let mut segments = req.uri().path().split('/').skip(2);

        if segments.next() != Some("v2") {
            return Err(Error::not_found().into());
        }

        let endpoint = segments.next().unwrap_or_default();
        let element = segments
            .next()
            .filter(|element| !element.is_empty())
            .map(decode_path_element);

        if segments.next().is_some_and(|segment| !segment.is_empty()) {
            return Err(Error::not_found().into());
        }

        match endpoint {
            "Users" | "Groups" => {
                let resource_type = if endpoint == "Users" {
                    ResourceType::User
                } else {
                    ResourceType::Group
                };
                let ctx = self.scim_context(req, session, access_token)?;

                match (element.as_deref(), req.method()) {
                    (None, &Method::GET) => {
                        let request = search_request(req.uri().query())?;
                        ctx.query(resource_type, &request).await
                    }
                    (None, &Method::POST) => {
                        let body = fetch(req, session, MAX_BODY_SIZE).await?;
                        let request = search_request(req.uri().query())?;

                        match resource_type {
                            ResourceType::User => ctx.user_create(&body, &request).await,
                            ResourceType::Group => ctx.group_create(&body, &request).await,
                        }
                    }
                    (Some(SEARCH_ENDPOINT), method) => {
                        if method != Method::POST {
                            return Err(method_not_allowed("POST"));
                        }

                        let body = fetch(req, session, MAX_BODY_SIZE).await?;
                        let request = SearchRequest::parse(&body)?;

                        ctx.query(resource_type, &request).await
                    }
                    (Some(element), method) => {
                        let id = parse_id(element)?;
                        let body = match *method {
                            Method::PUT | Method::PATCH => {
                                Some(fetch(req, session, MAX_BODY_SIZE).await?)
                            }
                            _ => None,
                        };
                        let request = search_request(req.uri().query())?;

                        match (resource_type, req.method()) {
                            (ResourceType::User, &Method::GET) => {
                                ctx.user_get(req, id, &request).await
                            }
                            (ResourceType::User, &Method::PUT) => {
                                ctx.user_replace(req, id, &body.unwrap_or_default(), &request)
                                    .await
                            }
                            (ResourceType::User, &Method::PATCH) => {
                                ctx.user_patch(req, id, &body.unwrap_or_default(), &request)
                                    .await
                            }
                            (ResourceType::User, &Method::DELETE) => {
                                ctx.user_destroy(req, id).await
                            }
                            (ResourceType::Group, &Method::GET) => {
                                ctx.group_get(req, id, &request).await
                            }
                            (ResourceType::Group, &Method::PUT) => {
                                ctx.group_replace(req, id, &body.unwrap_or_default(), &request)
                                    .await
                            }
                            (ResourceType::Group, &Method::PATCH) => {
                                ctx.group_patch(req, id, &body.unwrap_or_default(), &request)
                                    .await
                            }
                            (ResourceType::Group, &Method::DELETE) => {
                                ctx.group_destroy(req, id).await
                            }
                            _ => Err(method_not_allowed("GET, PUT, PATCH, DELETE")),
                        }
                    }
                    _ => Err(method_not_allowed("GET, POST")),
                }
            }
            "Bulk" if element.is_none() => {
                let ctx = self.scim_context(req, session, access_token)?;

                if req.method() == Method::POST {
                    let body = fetch(
                        req,
                        session,
                        ServiceProviderConfig::DEFAULT.bulk.max_payload_size,
                    )
                    .await?;

                    ctx.bulk(&body).await
                } else {
                    Err(method_not_allowed("POST"))
                }
            }
            SEARCH_ENDPOINT if element.is_none() => {
                let ctx = self.scim_context(req, session, access_token)?;

                if req.method() == Method::POST {
                    let body = fetch(req, session, MAX_BODY_SIZE).await?;
                    let request = SearchRequest::parse(&body)?;

                    ctx.search_all(&request).await
                } else {
                    Err(method_not_allowed("POST"))
                }
            }
            "ServiceProviderConfig" if element.is_none() => {
                assert_unfiltered(req)?;

                if req.method() == Method::GET {
                    self.scim_service_provider_config()
                } else {
                    Err(method_not_allowed("GET"))
                }
            }
            "ResourceTypes" => {
                assert_unfiltered(req)?;

                if req.method() == Method::GET {
                    self.scim_resource_types(element.as_deref())
                } else {
                    Err(method_not_allowed("GET"))
                }
            }
            "Schemas" => {
                assert_unfiltered(req)?;

                if req.method() == Method::GET {
                    self.scim_schemas(element.as_deref())
                } else {
                    Err(method_not_allowed("GET"))
                }
            }
            "Me" => Err(Error::not_implemented()
                .with_detail("The '/Me' endpoint is not supported by this service provider.")
                .into()),
            _ => Err(Error::not_found().into()),
        }
    }
}

trait ScimContextBuilder {
    fn scim_context<'x>(
        &'x self,
        req: &HttpRequest,
        session: &HttpSessionData,
        access_token: Option<&'x AccessToken>,
    ) -> Result<ScimContext<'x>>;
}

impl ScimContextBuilder for Server {
    fn scim_context<'x>(
        &'x self,
        req: &HttpRequest,
        session: &HttpSessionData,
        access_token: Option<&'x AccessToken>,
    ) -> Result<ScimContext<'x>> {
        Ok(ScimContext {
            server: self,
            access_token: req.scim_access_token(access_token)?,
            session_id: session.session_id,
        })
    }
}

async fn fetch(
    req: &mut HttpRequest,
    session: &HttpSessionData,
    max_size: usize,
) -> Result<Vec<u8>> {
    fetch_body(req, max_size, session.session_id)
        .await
        .ok_or_else(|| {
            ScimResponseError::Scim(Error::new(413).with_detail(format!(
                "The size of the request payload exceeds the maximum of {max_size} bytes."
            )))
        })
}

pub fn search_request(query: Option<&str>) -> Result<SearchRequest<'_>> {
    match query {
        Some(query) => SearchRequest::from_query(query).map_err(Into::into),
        None => Ok(SearchRequest::default()),
    }
}

pub fn method_not_allowed(allow: &'static str) -> ScimResponseError {
    ScimResponseError::Allow(
        Error::new(405).with_detail(format!(
            "The HTTP method is not supported by this endpoint, allowed methods are {allow}."
        )),
        allow,
    )
}

fn assert_unfiltered(req: &HttpRequest) -> Result<()> {
    if SearchRequest::from_query(req.uri().query().unwrap_or_default())
        .is_ok_and(|request| request.filter.is_some())
    {
        Err(Error::forbidden(
            "The discovery endpoints do not support filtering, remove the 'filter' parameter.",
        )
        .into())
    } else {
        Ok(())
    }
}

pub fn respond_with_etag<T: Serialize>(
    status: StatusCode,
    body: &T,
    version: String,
) -> Result<HttpResponse> {
    scim_response(status, body).map(|response| response.with_header(header::ETAG, version))
}

pub fn not_modified(version: &str) -> HttpResponse {
    HttpResponse::new(StatusCode::NOT_MODIFIED)
        .with_content_type(CONTENT_TYPE)
        .with_header(header::ETAG, version.to_string())
}
