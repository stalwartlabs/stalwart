/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::{
    config::TransactionDefaults,
    error::{Backoff, Error},
};
use std::time::Duration;

const DEFAULT_BACKOFF: Duration = Duration::from_millis(10);
const BACKOFF_GROWTH_RATE: u32 = 2;
const RESOURCE_CONSTRAINED_MAX_BACKOFF: Duration = Duration::from_secs(30);
const FUTURE_VERSION_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Retry {
    retries: u32,
    backoff: Duration,
}

impl Retry {
    pub(crate) const fn new() -> Self {
        Retry {
            retries: 0,
            backoff: DEFAULT_BACKOFF,
        }
    }

    pub(crate) fn next_delay(
        &mut self,
        error: Error,
        defaults: &TransactionDefaults,
    ) -> Result<Duration, Error> {
        let backoff = error.error_code().backoff();
        if backoff == Some(Backoff::Immediate) {
            return Ok(Duration::ZERO);
        }
        let limit_hit = defaults
            .retry_limit
            .is_some_and(|limit| self.retries >= limit);
        self.retries = self.retries.saturating_add(1);
        if limit_hit {
            return Err(error);
        }
        match backoff {
            Some(Backoff::Growing) => Ok(self.grow(defaults.max_retry_delay)),
            Some(Backoff::ResourceConstrained) => Ok(self.grow(RESOURCE_CONSTRAINED_MAX_BACKOFF)),
            Some(Backoff::FutureVersion) => {
                Ok(FUTURE_VERSION_RETRY_DELAY.min(defaults.max_retry_delay))
            }
            Some(Backoff::Immediate) | None => Err(error),
        }
    }

    fn grow(&mut self, max: Duration) -> Duration {
        let delay = self.backoff.mul_f64(fastrand::f64());
        self.backoff = self.backoff.saturating_mul(BACKOFF_GROWTH_RATE).min(max);
        delay
    }
}

impl Default for Retry {
    fn default() -> Self {
        Retry::new()
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/retry/tests.rs"]
mod tests;
