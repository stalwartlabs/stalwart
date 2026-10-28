/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::context::bounded;
use http_proto::HttpResponse;
use hyper::{StatusCode, header};
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{schema::prelude::Property, types::EnumImpl};
use scim_proto::{CONTENT_TYPE, ResourceType, message::error::Error as ScimError};
use std::fmt::Write;
use store::registry::write::RegistryWriteResult;

pub const REALM: &str = "Bearer realm=\"Stalwart SCIM\"";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Scim(ScimError),
    Allow(ScimError, &'static str),
    Internal(trc::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Scim(error) | Error::Allow(error, _) => error.fmt(f),
            Error::Internal(error) => error.fmt(f),
        }
    }
}

impl From<ScimError> for Error {
    fn from(error: ScimError) -> Self {
        Error::Scim(error)
    }
}

impl From<trc::Error> for Error {
    fn from(error: trc::Error) -> Self {
        Error::Internal(error)
    }
}

impl Error {
    pub fn into_response(self, session_id: u64) -> HttpResponse {
        if let Error::Scim(error) | Error::Allow(error, _) = &self {
            match failure_event(error.status, Origin::Scim) {
                Some(trc::ScimEvent::Forbidden) => trc::event!(
                    Scim(trc::ScimEvent::Forbidden),
                    SpanId = session_id,
                    Code = error.status,
                    Reason = error.scim_type.map(|scim_type| scim_type.as_str()),
                    Details = error.detail.as_deref().map(bounded),
                ),
                Some(trc::ScimEvent::Conflict) => trc::event!(
                    Scim(trc::ScimEvent::Conflict),
                    SpanId = session_id,
                    Code = error.status,
                    Reason = error.scim_type.map(|scim_type| scim_type.as_str()),
                    Details = error.detail.as_deref().map(bounded),
                ),
                Some(trc::ScimEvent::Error) => trc::event!(
                    Scim(trc::ScimEvent::Error),
                    SpanId = session_id,
                    Code = error.status,
                    Reason = error.scim_type.map(|scim_type| scim_type.as_str()),
                    Details = error.detail.as_deref().map(bounded),
                ),
                _ => {}
            }
        }

        match self {
            Error::Scim(error) => error.into_scim_response(),
            Error::Allow(error, allow) => {
                error.into_scim_response().with_header(header::ALLOW, allow)
            }
            Error::Internal(error) => {
                let scim_error = error.into_scim_error();

                match failure_event(scim_error.status, Origin::Internal) {
                    Some(trc::ScimEvent::Forbidden) => trc::event!(
                        Scim(trc::ScimEvent::Forbidden),
                        SpanId = session_id,
                        Code = scim_error.status,
                        Reason = scim_error.scim_type.map(|scim_type| scim_type.as_str()),
                        Details = scim_error.detail.as_deref().map(bounded),
                        AccountId = error
                            .value(trc::Key::AccountId)
                            .and_then(|value| value.to_uint()),
                    ),
                    Some(trc::ScimEvent::Conflict) => trc::event!(
                        Scim(trc::ScimEvent::Conflict),
                        SpanId = session_id,
                        Code = scim_error.status,
                        Reason = scim_error.scim_type.map(|scim_type| scim_type.as_str()),
                        Details = scim_error.detail.as_deref().map(bounded),
                    ),
                    _ => {}
                }

                let mut response = scim_error.into_scim_response();

                if response.status() == StatusCode::TOO_MANY_REQUESTS
                    && let Some(seconds) = error
                        .value(trc::Key::Expires)
                        .and_then(|value| value.to_uint())
                {
                    response = response.with_header(header::RETRY_AFTER, seconds.to_string());
                }

                trc::error!(error.span_id(session_id));

                response
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Scim,
    Internal,
}

pub fn failure_event(status: u16, origin: Origin) -> Option<trc::ScimEvent> {
    match (status, origin) {
        (403, _) => Some(trc::ScimEvent::Forbidden),
        (409 | 412, _) => Some(trc::ScimEvent::Conflict),
        (_, Origin::Scim) => Some(trc::ScimEvent::Error),
        (_, Origin::Internal) => None,
    }
}

pub trait IntoScimError {
    fn into_scim_error(self) -> ScimError;
}

pub trait IntoScimResourceError {
    fn into_scim_error_for(self, resource_type: ResourceType) -> ScimError;
}

impl IntoScimResourceError for RegistryWriteResult {
    fn into_scim_error_for(self, resource_type: ResourceType) -> ScimError {
        match (&self, resource_type) {
            (RegistryWriteResult::PrimaryKeyConflict { .. }, ResourceType::Group) => {
                ScimError::uniqueness(
                    "A Group with the same derived mailbox address already exists.",
                )
            }
            _ => self.into_scim_error(),
        }
    }
}

pub trait IntoScimResponse {
    fn into_scim_response(self) -> HttpResponse;
}

impl IntoScimResponse for ScimError {
    fn into_scim_response(self) -> HttpResponse {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = HttpResponse::new(status).with_content_type(CONTENT_TYPE);

        if status == StatusCode::UNAUTHORIZED {
            response = response.with_header(header::WWW_AUTHENTICATE, REALM);
        }

        response.with_text_body(serde_json::to_string(&self).unwrap_or_default())
    }
}

impl IntoScimError for &trc::Error {
    fn into_scim_error(self) -> ScimError {
        let detail = || {
            self.value(trc::Key::Details)
                .or_else(|| self.value(trc::Key::Reason))
                .and_then(|value| value.as_str())
                .map(|detail| detail.to_string())
        };

        match self.as_ref() {
            trc::EventType::Auth(
                trc::AuthEvent::Failed | trc::AuthEvent::Error | trc::AuthEvent::TokenExpired,
            ) => ScimError::unauthorized(),
            trc::EventType::Security(_) | trc::EventType::Jmap(trc::JmapEvent::Forbidden) => {
                ScimError::forbidden(detail().unwrap_or_else(|| {
                    "The authenticated principal is not authorized to perform this operation."
                        .to_string()
                }))
            }
            trc::EventType::Resource(trc::ResourceEvent::NotFound) => ScimError::not_found(),
            trc::EventType::Store(trc::StoreEvent::AssertValueFailed) => {
                ScimError::conflict("The resource was modified concurrently, retry the request.")
            }
            trc::EventType::Limit(trc::LimitEvent::SizeRequest | trc::LimitEvent::SizeUpload) => {
                ScimError::new(413)
                    .with_detail("The request payload exceeds the maximum allowed size.")
            }
            trc::EventType::Limit(
                trc::LimitEvent::TooManyRequests | trc::LimitEvent::ConcurrentRequest,
            ) => ScimError::new(429)
                .with_detail("The request rate limit has been exceeded, retry the request later."),
            _ => ScimError::internal_error()
                .with_detail("An unexpected error occurred while processing the request."),
        }
    }
}

impl IntoScimError for RegistryWriteResult {
    fn into_scim_error(self) -> ScimError {
        match self {
            RegistryWriteResult::Success(_) => ScimError::internal_error(),
            RegistryWriteResult::PrimaryKeyConflict { property, .. } => {
                ScimError::uniqueness(format!(
                    "A resource with the same '{}' already exists.",
                    scim_name(property)
                ))
            }
            RegistryWriteResult::InvalidForeignKey { object_id } => {
                ScimError::invalid_value(format!(
                    "The referenced {} does not exist.",
                    object_id.object().as_str()
                ))
            }
            RegistryWriteResult::ForeignKeyOutOfScope { object_id, scope } => {
                ScimError::invalid_value(format!(
                    "The referenced {} is not assigned to the same {scope}.",
                    object_id.object().as_str()
                ))
            }
            RegistryWriteResult::ValidationError { errors } => {
                let mut detail = String::with_capacity(64);
                for error in &errors {
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    let _ = write!(&mut detail, "{error}");
                }
                ScimError::invalid_value(if detail.is_empty() {
                    "The request contains invalid values.".to_string()
                } else {
                    detail
                })
            }
            RegistryWriteResult::NotFound { .. } => ScimError::not_found(),
            RegistryWriteResult::CannotDeleteLinked { linked_objects, .. } => {
                ScimError::conflict(format!(
                    "The resource cannot be deleted because {} other resource(s) depend on it.",
                    linked_objects.len()
                ))
            }
            RegistryWriteResult::CannotDeleteSingleton => {
                ScimError::forbidden("The resource cannot be deleted.")
            }
            RegistryWriteResult::InvalidSingletonId => {
                ScimError::invalid_value("Invalid resource identifier.")
            }
            RegistryWriteResult::NotSupported => ScimError::not_implemented(),
        }
    }
}

impl IntoScimError for &SetError<Property> {
    fn into_scim_error(self) -> ScimError {
        let detail = || match self.description() {
            Some(description) => description.to_string(),
            None if !self.validation_errors().is_empty() => {
                let mut detail = String::with_capacity(64);
                for error in self.validation_errors() {
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    let _ = write!(&mut detail, "{error}");
                }
                detail
            }
            None => "The request could not be completed.".to_string(),
        };

        match self.error_type() {
            SetErrorType::Forbidden
            | SetErrorType::ForbiddenFrom
            | SetErrorType::ForbiddenToSend
            | SetErrorType::OverQuota
            | SetErrorType::TooLarge => ScimError::forbidden(detail()),
            SetErrorType::NotFound => ScimError::not_found(),
            SetErrorType::AlreadyExists | SetErrorType::PrimaryKeyViolation => {
                ScimError::uniqueness(detail())
            }
            SetErrorType::ObjectIsLinked => ScimError::conflict(detail()),
            _ => ScimError::invalid_value(detail()),
        }
    }
}

pub fn scim_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Result<HttpResponse> {
    serde_json::to_string(body)
        .map(|body| {
            HttpResponse::new(status)
                .with_content_type(CONTENT_TYPE)
                .with_text_body(body)
        })
        .map_err(|err| {
            Error::Internal(
                trc::EventType::Resource(trc::ResourceEvent::Error)
                    .into_err()
                    .caused_by(trc::location!())
                    .reason(err),
            )
        })
}

pub fn no_content() -> HttpResponse {
    HttpResponse::new(StatusCode::NO_CONTENT).with_content_type(CONTENT_TYPE)
}

fn scim_name(property: Property) -> &'static str {
    match property {
        Property::Name | Property::Email | Property::EmailAddress => "userName",
        Property::Description => "displayName",
        Property::ExternalId => "externalId",
        Property::Aliases => "emails",
        Property::MemberGroupIds => "members",
        other => other.as_str(),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/scim/src/error/tests.rs"]
mod tests;
