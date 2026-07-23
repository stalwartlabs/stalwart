/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::UploadResponse;
use calcard::jscalendar::JSCalendarDateTime;
use common::ipc::{CalendarAlert, PushNotification};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use hyper::StatusCode;
use jmap_proto::{
    error::request::{RateLimitPolicy, RateLimitUnit, RequestError, RequestLimitError},
    request::capability::Session,
    response::{Response, status::PushObject},
    types::state::State,
};
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

pub mod acl;
pub mod auth;
pub mod event_source;
pub mod query;
pub mod request;
pub mod session;

impl ToHttpResponse for UploadResponse {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

pub trait ToJmapHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl ToJmapHttpResponse for Response<'_> {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

impl ToJmapHttpResponse for Session {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

impl ToJmapHttpResponse for RequestError<'_> {
    fn into_http_response(self) -> HttpResponse {
        let mut response =
            HttpResponse::new(StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_REQUEST));
        if let Some(retry_after) = self.retry_after {
            response = response.with_header("Retry-After", retry_after.to_string());
        }
        if let Some(policy) = self.rate_limit_policy_header() {
            response = response.with_header("RateLimit-Policy", policy);
        }
        if let Some(state) = self.rate_limit_state_header() {
            response = response.with_header("RateLimit", state);
        }
        response
            .with_content_type("application/problem+json")
            .with_text_body(serde_json::to_string(&self).unwrap_or_default())
    }
}

pub trait ToRequestError {
    fn to_request_error(&self) -> RequestError<'_>;
}

impl ToRequestError for trc::Error {
    fn to_request_error(&self) -> RequestError<'_> {
        let details_or_reason = self
            .value(trc::Key::Details)
            .or_else(|| self.value(trc::Key::Reason))
            .and_then(|v| v.as_str());
        let details = details_or_reason.unwrap_or_else(|| self.as_ref().message());

        match self.as_ref() {
            trc::EventType::Jmap(cause) => match cause {
                trc::JmapEvent::UnknownCapability => RequestError::unknown_capability(details),
                trc::JmapEvent::NotJson => RequestError::not_json(details),
                trc::JmapEvent::NotRequest => RequestError::not_request(details),
                _ => RequestError::invalid_parameters(),
            },
            trc::EventType::Limit(cause) => {
                let reset = self.value(trc::Key::Expires).and_then(|v| v.to_uint());
                let limit = self.value(trc::Key::Limit).and_then(|v| v.to_uint());
                let total = self.value(trc::Key::Total).and_then(|v| v.to_uint());
                let size = self.value(trc::Key::Size).and_then(|v| v.to_uint());

                match cause {
                    trc::LimitEvent::SizeRequest => {
                        RequestError::limit(RequestLimitError::SizeRequest)
                    }
                    trc::LimitEvent::SizeUpload => {
                        RequestError::limit(RequestLimitError::SizeUpload)
                    }
                    trc::LimitEvent::CallsIn => RequestError::limit(RequestLimitError::CallsIn),
                    trc::LimitEvent::ConcurrentRequest | trc::LimitEvent::ConcurrentConnection => {
                        let mut policy =
                            RateLimitPolicy::new("concurrent-requests", limit.unwrap_or(0))
                                .with_unit(RateLimitUnit::ConcurrentRequests);
                        if let Some(reset) = reset {
                            policy = policy.with_reset(reset);
                        }
                        RequestError::limit(RequestLimitError::ConcurrentRequest)
                            .with_rate_limit(policy)
                    }
                    trc::LimitEvent::ConcurrentUpload => {
                        let mut policy =
                            RateLimitPolicy::new("concurrent-uploads", limit.unwrap_or(0))
                                .with_unit(RateLimitUnit::ConcurrentRequests);
                        if let Some(reset) = reset {
                            policy = policy.with_reset(reset);
                        }
                        RequestError::limit(RequestLimitError::ConcurrentUpload)
                            .with_rate_limit(policy)
                    }
                    trc::LimitEvent::Quota => RequestError::over_quota(),
                    trc::LimitEvent::TenantQuota => RequestError::tenant_over_quota(),
                    trc::LimitEvent::BlobQuota => {
                        let mut err = RequestError::over_blob_quota(
                            total.unwrap_or(0) as usize,
                            size.unwrap_or(0) as usize,
                        );
                        if let Some(total) = total {
                            let mut policy = RateLimitPolicy::new("blob-upload-files", total);
                            if let Some(reset) = reset {
                                policy = policy.with_reset(reset);
                            }
                            err = err.with_rate_limit(policy);
                        }
                        if let Some(size) = size {
                            let mut policy = RateLimitPolicy::new("blob-upload-bytes", size)
                                .with_unit(RateLimitUnit::ContentBytes);
                            if let Some(reset) = reset {
                                policy = policy.with_reset(reset);
                            }
                            err = err.with_rate_limit(policy);
                        }
                        err
                    }
                    trc::LimitEvent::TooManyRequests => {
                        let mut err = RequestError::too_many_requests();
                        if let Some(limit) = limit {
                            let mut policy = RateLimitPolicy::new("requests", limit);
                            if let Some(reset) = reset {
                                policy = policy.with_reset(reset);
                            }
                            err = err.with_rate_limit(policy);
                        } else if let Some(reset) = reset {
                            err = err.with_retry_after(reset);
                        }
                        err
                    }
                }
            }
            trc::EventType::Auth(cause) => match cause {
                trc::AuthEvent::MfaRequired => {
                    RequestError::blank(402, "MFA code required", self.as_ref().message())
                }
                trc::AuthEvent::TooManyAttempts => {
                    let mut err = RequestError::too_many_auth_attempts();
                    if let Some(reset) = self.value(trc::Key::Expires).and_then(|v| v.to_uint()) {
                        err = err.with_retry_after(reset);
                    }
                    err
                }
                _ => RequestError::unauthorized(),
            },
            trc::EventType::Security(cause) => match cause {
                trc::SecurityEvent::AuthenticationBan
                | trc::SecurityEvent::ScanBan
                | trc::SecurityEvent::AbuseBan
                | trc::SecurityEvent::LoiterBan
                | trc::SecurityEvent::IpBlocked => {
                    let mut err = RequestError::too_many_auth_attempts();
                    if let Some(reset) = self.value(trc::Key::Expires).and_then(|v| v.to_uint()) {
                        err = err.with_retry_after(reset);
                    }
                    err
                }
                trc::SecurityEvent::Unauthorized | trc::SecurityEvent::IpUnauthorized => {
                    RequestError::forbidden()
                }
                trc::SecurityEvent::IpBlockExpired | trc::SecurityEvent::IpAllowExpired => {
                    RequestError::internal_server_error()
                }
            },
            trc::EventType::Resource(cause) => match cause {
                trc::ResourceEvent::NotFound => RequestError::not_found(),
                trc::ResourceEvent::BadParameters => RequestError::blank(
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Invalid parameters",
                    details_or_reason.unwrap_or("One or multiple parameters could not be parsed."),
                ),
                trc::ResourceEvent::Error => RequestError::internal_server_error(),
                _ => RequestError::internal_server_error(),
            },
            _ => RequestError::internal_server_error(),
        }
    }
}

pub(crate) trait IntoPushObject {
    fn into_push_object(self) -> PushObject;
}

impl IntoPushObject for Vec<PushNotification> {
    fn into_push_object(self) -> PushObject {
        let mut changed: VecMap<Id, VecMap<DataType, State>> = VecMap::new();
        let mut objects = Vec::with_capacity(self.len());
        for notification in self {
            match notification {
                PushNotification::StateChange(state_change) => {
                    for type_state in state_change.types {
                        changed
                            .get_mut_or_insert(state_change.account_id.into())
                            .set(type_state, (state_change.change_id).into());
                    }
                }
                PushNotification::CalendarAlert(calendar_alert) => {
                    objects.push(calendar_alert.into_push_object());
                }
                PushNotification::EmailPush(email_push) => {
                    let state_change = email_push.to_state_change();
                    for type_state in state_change.types {
                        changed
                            .get_mut_or_insert(state_change.account_id.into())
                            .set(type_state, state_change.change_id.into());
                    }
                }
            }
        }

        if !objects.is_empty() {
            if changed.is_empty() {
                objects.push(PushObject::StateChange { changed });
            }
            if objects.len() > 1 {
                PushObject::Group { entries: objects }
            } else {
                objects.into_iter().next().unwrap()
            }
        } else {
            PushObject::StateChange { changed }
        }
    }
}

impl IntoPushObject for CalendarAlert {
    fn into_push_object(self) -> PushObject {
        PushObject::CalendarAlert {
            account_id: self.account_id.into(),
            calendar_event_id: self.event_id.into(),
            uid: self.uid,
            recurrence_id: self
                .recurrence_id
                .map(|timestamp| JSCalendarDateTime::new(timestamp, true).to_rfc3339()),
            alert_id: self.alert_id,
        }
    }
}
