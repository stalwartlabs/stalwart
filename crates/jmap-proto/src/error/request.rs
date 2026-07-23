/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RequestLimitError {
    #[serde(rename = "maxSizeRequest")]
    SizeRequest,
    #[serde(rename = "maxSizeUpload")]
    SizeUpload,
    #[serde(rename = "maxCallsInRequest")]
    CallsIn,
    #[serde(rename = "maxConcurrentRequests")]
    ConcurrentRequest,
    #[serde(rename = "maxConcurrentUpload")]
    ConcurrentUpload,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum RequestErrorType {
    #[serde(rename = "urn:ietf:params:jmap:error:unknownCapability")]
    UnknownCapability,
    #[serde(rename = "urn:ietf:params:jmap:error:notJSON")]
    NotJSON,
    #[serde(rename = "urn:ietf:params:jmap:error:notRequest")]
    NotRequest,
    #[serde(rename = "urn:ietf:params:jmap:error:limit")]
    Limit,
    #[serde(rename = "about:blank")]
    Other,
}

#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    pub name: &'static str,
    pub limit: u64,
    pub remaining: u64,
    pub window: Option<u64>,
    pub reset: Option<u64>,
    pub unit: RateLimitUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitUnit {
    Requests,
    ContentBytes,
    ConcurrentRequests,
}

impl RateLimitUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            RateLimitUnit::Requests => "requests",
            RateLimitUnit::ContentBytes => "content-bytes",
            RateLimitUnit::ConcurrentRequests => "concurrent-requests",
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RequestError<'x> {
    #[serde(rename = "type")]
    pub p_type: RequestErrorType,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Cow<'x, str>>,
    pub detail: Cow<'x, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<RequestLimitError>,
    #[serde(skip)]
    pub rate_limit: Vec<RateLimitPolicy>,
    #[serde(skip)]
    pub retry_after: Option<u64>,
}

impl<'x> RequestError<'x> {
    pub fn blank(
        status: u16,
        title: impl Into<Cow<'x, str>>,
        detail: impl Into<Cow<'x, str>>,
    ) -> Self {
        RequestError {
            p_type: RequestErrorType::Other,
            status,
            title: Some(title.into()),
            detail: detail.into(),
            limit: None,
            rate_limit: Vec::new(),
            retry_after: None,
        }
    }

    pub fn with_rate_limit(mut self, policy: RateLimitPolicy) -> Self {
        if let Some(reset) = policy.reset
            && self.retry_after.is_none_or(|r| reset > r)
        {
            self.retry_after = Some(reset);
        }
        self.rate_limit.push(policy);
        self
    }

    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        if self.retry_after.is_none_or(|r| seconds > r) {
            self.retry_after = Some(seconds);
        }
        self
    }

    pub fn internal_server_error() -> Self {
        RequestError::blank(
            500,
            "Internal Server Error",
            concat!(
                "There was a problem while processing your request. ",
                "Please contact the system administrator if this problem persists."
            ),
        )
    }

    pub fn unavailable() -> Self {
        RequestError::blank(
            503,
            "Temporarily Unavailable",
            concat!(
                "There was a temporary problem while processing your request. ",
                "Please try again in a few moments."
            ),
        )
    }

    pub fn invalid_parameters() -> Self {
        RequestError::blank(
            400,
            "Invalid Parameters",
            "One or multiple parameters could not be parsed.",
        )
    }

    pub fn forbidden() -> Self {
        RequestError::blank(
            403,
            "Forbidden",
            "You do not have enough permissions to access this resource.",
        )
    }

    pub fn over_blob_quota(max_files: usize, max_bytes: usize) -> Self {
        RequestError::blank(
            429,
            "Quota exceeded",
            format!(
                "You have exceeded the blob upload quota of {} files or {} bytes.",
                max_files, max_bytes
            ),
        )
    }

    pub fn over_quota() -> Self {
        RequestError::blank(
            403,
            "Quota exceeded",
            "You have exceeded your account quota.",
        )
    }

    pub fn tenant_over_quota() -> Self {
        RequestError::blank(
            403,
            "Tenant quota exceeded",
            "Your organization has exceeded its quota.",
        )
    }

    pub fn too_many_requests() -> Self {
        RequestError::blank(
            429,
            "Too Many Requests",
            "Your request has been rate limited. Please try again in a few seconds.",
        )
    }

    pub fn too_many_auth_attempts() -> Self {
        RequestError::blank(
            429,
            "Too Many Authentication Attempts",
            "Your request has been rate limited. Please try again in a few minutes.",
        )
    }

    pub fn limit(limit_type: RequestLimitError) -> Self {
        RequestError {
            p_type: RequestErrorType::Limit,
            status: 400,
            title: None,
            detail: match limit_type {
                RequestLimitError::SizeRequest => concat!(
                    "The request is larger than the server ",
                    "is willing to process."
                ),
                RequestLimitError::SizeUpload => concat!(
                    "The uploaded file is larger than the server ",
                    "is willing to process."
                ),
                RequestLimitError::CallsIn => concat!(
                    "The request exceeds the maximum number ",
                    "of calls in a single request."
                ),
                RequestLimitError::ConcurrentRequest => concat!(
                    "The request exceeds the maximum number ",
                    "of concurrent requests."
                ),
                RequestLimitError::ConcurrentUpload => concat!(
                    "The request exceeds the maximum number ",
                    "of concurrent uploads."
                ),
            }
            .into(),
            limit: Some(limit_type),
            rate_limit: Vec::new(),
            retry_after: None,
        }
    }

    pub fn not_found() -> Self {
        RequestError::blank(
            404,
            "Not Found",
            "The requested resource does not exist on this server.",
        )
    }

    pub fn unauthorized() -> Self {
        RequestError::blank(401, "Unauthorized", "You have to authenticate first.")
    }

    pub fn unknown_capability(capability: &'_ str) -> RequestError<'_> {
        RequestError {
            p_type: RequestErrorType::UnknownCapability,
            limit: None,
            title: None,
            status: 400,
            detail: format!(
                concat!(
                    "The Request object used capability ",
                    "'{}', which is not supported",
                    "by this server."
                ),
                capability
            )
            .into(),
            rate_limit: Vec::new(),
            retry_after: None,
        }
    }

    pub fn not_json(detail: &'_ str) -> RequestError<'_> {
        RequestError {
            p_type: RequestErrorType::NotJSON,
            limit: None,
            title: None,
            status: 400,
            detail: format!("Failed to parse JSON: {detail}").into(),
            rate_limit: Vec::new(),
            retry_after: None,
        }
    }

    pub fn not_request(detail: impl Into<Cow<'x, str>>) -> RequestError<'x> {
        RequestError {
            p_type: RequestErrorType::NotRequest,
            limit: None,
            title: None,
            status: 400,
            detail: detail.into(),
            rate_limit: Vec::new(),
            retry_after: None,
        }
    }
}

impl RateLimitPolicy {
    pub fn new(name: &'static str, limit: u64) -> Self {
        RateLimitPolicy {
            name,
            limit,
            remaining: 0,
            window: None,
            reset: None,
            unit: RateLimitUnit::Requests,
        }
    }

    pub fn with_window(mut self, window: u64) -> Self {
        self.window = Some(window);
        self
    }

    pub fn with_reset(mut self, reset: u64) -> Self {
        self.reset = Some(reset);
        self
    }

    pub fn with_remaining(mut self, remaining: u64) -> Self {
        self.remaining = remaining;
        self
    }

    pub fn with_unit(mut self, unit: RateLimitUnit) -> Self {
        self.unit = unit;
        self
    }

    pub fn fmt_policy(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = write!(out, "\"{}\";q={}", self.name, self.limit);
        if let Some(window) = self.window {
            let _ = write!(out, ";w={window}");
        }
        if !matches!(self.unit, RateLimitUnit::Requests) {
            let _ = write!(out, ";qu=\"{}\"", self.unit.as_str());
        }
    }

    pub fn fmt_state(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = write!(out, "\"{}\";r={}", self.name, self.remaining);
        if let Some(reset) = self.reset {
            let _ = write!(out, ";t={reset}");
        }
    }
}

impl<'x> RequestError<'x> {
    pub fn rate_limit_policy_header(&self) -> Option<String> {
        if self.rate_limit.is_empty() {
            return None;
        }
        let mut out = String::new();
        for (i, policy) in self.rate_limit.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            policy.fmt_policy(&mut out);
        }
        Some(out)
    }

    pub fn rate_limit_state_header(&self) -> Option<String> {
        if self.rate_limit.is_empty() {
            return None;
        }
        let mut out = String::new();
        for (i, policy) in self.rate_limit.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            policy.fmt_state(&mut out);
        }
        Some(out)
    }
}

impl Display for RequestError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_headers_match_spec() {
        // Spec example: RateLimit-Policy: "burst";q=100;w=60,"daily";q=1000;w=86400
        let mut p1 = String::new();
        RateLimitPolicy::new("burst", 100)
            .with_window(60)
            .fmt_policy(&mut p1);
        assert_eq!(p1, r#""burst";q=100;w=60"#);

        // Spec example: RateLimit-Policy: "peruser";q=65535;qu="content-bytes";w=10
        let mut p2 = String::new();
        RateLimitPolicy::new("peruser", 65535)
            .with_window(10)
            .with_unit(RateLimitUnit::ContentBytes)
            .fmt_policy(&mut p2);
        assert_eq!(p2, r#""peruser";q=65535;w=10;qu="content-bytes""#);

        // Spec example: RateLimit: "default";r=50;t=30
        let mut s = String::new();
        RateLimitPolicy::new("default", 100)
            .with_remaining(50)
            .with_reset(30)
            .fmt_state(&mut s);
        assert_eq!(s, r#""default";r=50;t=30"#);

        // Two policies in one header
        let err = RequestError::too_many_requests()
            .with_rate_limit(
                RateLimitPolicy::new("burst", 100)
                    .with_window(60)
                    .with_reset(30),
            )
            .with_rate_limit(
                RateLimitPolicy::new("daily", 1000)
                    .with_window(86400)
                    .with_reset(3600),
            );
        assert_eq!(
            err.rate_limit_policy_header().as_deref(),
            Some(r#""burst";q=100;w=60, "daily";q=1000;w=86400"#),
        );
        assert_eq!(
            err.rate_limit_state_header().as_deref(),
            Some(r#""burst";r=0;t=30, "daily";r=0;t=3600"#),
        );
        assert_eq!(err.retry_after, Some(3600));
    }
}
