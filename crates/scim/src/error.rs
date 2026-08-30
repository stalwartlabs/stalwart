/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

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
        match self {
            Error::Scim(error) => error.into_scim_response(),
            Error::Allow(error, allow) => {
                error.into_scim_response().with_header(header::ALLOW, allow)
            }
            Error::Internal(error) => {
                let mut response = error.into_scim_error().into_scim_response();

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

#[cfg(test)]
mod tests {
    use super::*;
    use registry::types::{error::ValidationError, id::ObjectId};
    use scim_proto::message::error::ScimType;
    use types::id::Id;

    #[test]
    fn write_failures_map_to_the_scim_errors_clients_expect() {
        let object_id = ObjectId::new(registry::schema::prelude::ObjectType::Account, Id::new(1));

        for (result, status, scim_type) in [
            (
                RegistryWriteResult::PrimaryKeyConflict {
                    property: Property::Email,
                    existing_id: object_id,
                },
                409,
                Some(ScimType::Uniqueness),
            ),
            (
                RegistryWriteResult::InvalidForeignKey { object_id },
                400,
                Some(ScimType::InvalidValue),
            ),
            (
                RegistryWriteResult::ValidationError {
                    errors: vec![ValidationError::required(Property::Name)],
                },
                400,
                Some(ScimType::InvalidValue),
            ),
            (RegistryWriteResult::NotFound { object_id }, 404, None),
            (
                RegistryWriteResult::CannotDeleteLinked {
                    object_id,
                    linked_objects: vec![object_id],
                },
                409,
                None,
            ),
            (RegistryWriteResult::CannotDeleteSingleton, 403, None),
            (
                RegistryWriteResult::InvalidSingletonId,
                400,
                Some(ScimType::InvalidValue),
            ),
            (RegistryWriteResult::NotSupported, 501, None),
        ] {
            let error = result.into_scim_error();

            assert_eq!(error.status, status, "{error:?}");
            assert_eq!(error.scim_type, scim_type, "{error:?}");
        }
    }

    #[test]
    fn a_duplicate_address_names_user_name_in_the_detail() {
        let error = RegistryWriteResult::PrimaryKeyConflict {
            property: Property::Email,
            existing_id: ObjectId::new(registry::schema::prelude::ObjectType::Account, Id::new(1)),
        }
        .into_scim_error();

        assert!(
            error.detail.as_deref().unwrap().contains("userName"),
            "{error}"
        );
    }

    #[test]
    fn validation_errors_are_summarised_in_the_detail() {
        let error = RegistryWriteResult::ValidationError {
            errors: vec![
                ValidationError::required(Property::Name),
                ValidationError::required(Property::DomainId),
            ],
        }
        .into_scim_error();

        let detail = error.detail.as_deref().unwrap();

        assert!(detail.contains("name"), "{detail}");
        assert!(detail.contains("domainId"), "{detail}");
        assert!(detail.contains("; "), "{detail}");
    }

    #[test]
    fn trc_errors_map_to_the_documented_statuses() {
        for (error, status) in [
            (trc::AuthEvent::Failed.into_err(), 401),
            (trc::SecurityEvent::Unauthorized.into_err(), 403),
            (trc::JmapEvent::Forbidden.into_err(), 403),
            (trc::ResourceEvent::NotFound.into_err(), 404),
            (trc::LimitEvent::SizeRequest.into_err(), 413),
            (trc::LimitEvent::TooManyRequests.into_err(), 429),
            (trc::StoreEvent::AssertValueFailed.into_err(), 409),
            (trc::StoreEvent::UnexpectedError.into_err(), 500),
        ] {
            assert_eq!((&error).into_scim_error().status, status, "{error}");
        }
    }

    #[test]
    fn errors_are_serialised_as_scim_json() {
        let response = ScimError::uniqueness("Duplicate userName").into_scim_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = match response.body() {
            http_proto::HttpResponseBody::Text(body) => body.clone(),
            _ => panic!("The error body is not text."),
        };
        let body = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(body["schemas"][0], scim_proto::MESSAGE_ERROR);
        assert_eq!(body["status"], "409");
        assert_eq!(body["scimType"], "uniqueness");
    }

    #[test]
    fn unauthorized_responses_carry_the_bearer_challenge() {
        let response = ScimError::unauthorized().into_scim_response();
        let headers = response.headers().unwrap();

        assert_eq!(
            headers
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap(),
            REALM
        );
        assert!(!REALM.to_lowercase().contains("basic"));
    }

    #[test]
    fn every_response_declares_the_scim_content_type() {
        for response in [
            ScimError::not_found().into_scim_response(),
            no_content(),
            scim_response(StatusCode::OK, &serde_json::json!({})).unwrap(),
        ] {
            assert_eq!(
                response
                    .headers()
                    .and_then(|headers| headers.get(header::CONTENT_TYPE))
                    .map(|value| value.to_str().unwrap()),
                Some(CONTENT_TYPE)
            );
        }
    }
}
