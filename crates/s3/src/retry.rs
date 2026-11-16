/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use reqwest::StatusCode;
use std::time::Duration;

const BASE_DELAY_MS: u64 = 1_000;
const MAX_DELAY_MS: u64 = 20_000;
const MAX_SHIFT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_retries: u32,
}

impl RetryPolicy {
    pub fn new(max_retries: u32) -> Self {
        RetryPolicy { max_retries }
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    pub fn can_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }

    pub fn delay(&self, attempt: u32) -> Duration {
        let cap = (BASE_DELAY_MS << attempt.min(MAX_SHIFT)).min(MAX_DELAY_MS);
        Duration::from_millis(rand::random_range(0..=cap))
    }

    pub fn is_retryable_status(status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        )
    }

    pub fn is_retryable_error(err: &reqwest::Error) -> bool {
        !err.is_builder() && !err.is_redirect()
    }

    pub fn is_retryable_code(code: &str) -> bool {
        hashify::set!(
            code.as_bytes(),
            "InternalError",
            "ServiceUnavailable",
            "SlowDown",
            "RequestTimeout"
        )
    }
}

pub(crate) struct Attempts {
    policy: RetryPolicy,
    retries: u32,
}

impl Attempts {
    pub(crate) fn new(policy: RetryPolicy) -> Self {
        Attempts { policy, retries: 0 }
    }

    pub(crate) fn can_retry(&self) -> bool {
        self.policy.can_retry(self.retries)
    }

    pub(crate) fn retries_status(&self, status: StatusCode) -> bool {
        RetryPolicy::is_retryable_status(status) && self.can_retry()
    }

    pub(crate) fn retries_transport(&self, err: &reqwest::Error) -> bool {
        RetryPolicy::is_retryable_error(err) && self.can_retry()
    }

    pub(crate) async fn backoff(&mut self) {
        tokio::time::sleep(self.policy.delay(self.retries)).await;
        self.retries += 1;
    }
}
