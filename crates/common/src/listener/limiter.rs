/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct ConcurrencyLimiter(Arc<ConcurrencyLimiterInner>);

#[derive(Debug)]
pub struct ConcurrencyLimiterInner {
    max_concurrent: u64,
    concurrent: AtomicU64,
}

#[derive(Default)]
pub struct InFlight(Arc<ConcurrencyLimiterInner>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u64) -> Self {
        ConcurrencyLimiter(Arc::new(ConcurrencyLimiterInner {
            max_concurrent,
            concurrent: AtomicU64::new(0),
        }))
    }

    pub fn is_allowed(&self) -> LimiterResult {
        if self.0.concurrent.load(Ordering::Relaxed) < self.0.max_concurrent {
            // Return in-flight request
            self.0.concurrent.fetch_add(1, Ordering::Relaxed);
            LimiterResult::Allowed(InFlight(self.0.clone()))
        } else {
            LimiterResult::Forbidden
        }
    }

    pub fn check_is_allowed(&self) -> bool {
        self.0.concurrent.load(Ordering::Relaxed) < self.0.max_concurrent
    }

    pub fn is_active(&self) -> bool {
        self.0.concurrent.load(Ordering::Relaxed) > 0
    }
}

impl InFlight {
    pub fn num_concurrent(&self) -> u64 {
        self.0.concurrent.load(Ordering::Relaxed)
    }
}

pub enum LimiterResult {
    Allowed(InFlight),
    Forbidden,
    Disabled,
}

impl From<LimiterResult> for Option<InFlight> {
    fn from(result: LimiterResult) -> Self {
        match result {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => None,
            LimiterResult::Disabled => Some(InFlight::default()),
        }
    }
}
