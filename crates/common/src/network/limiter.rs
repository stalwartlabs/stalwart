/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ThrottleKey, ThrottleKeyHasher, ThrottleKeyHasherBuilder};
use std::{
    hash::{BuildHasher, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct ConcurrencyLimiter(Arc<ConcurrencyLimiterInner>);

#[derive(Debug, Default)]
pub struct ConcurrencyLimiterInner {
    max_concurrent: u64,
    concurrent: AtomicU64,
}

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

    pub fn max_concurrent(&self) -> u64 {
        self.0.max_concurrent
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
            LimiterResult::Disabled => Some(InFlight(Arc::new(ConcurrencyLimiterInner::default()))),
        }
    }
}

impl PartialEq for ThrottleKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl std::hash::Hash for ThrottleKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl AsRef<[u8]> for ThrottleKey {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

impl Hasher for ThrottleKeyHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        debug_assert!(
            bytes.len() >= std::mem::size_of::<u64>(),
            "ThrottleKeyHasher: input too short {bytes:?}"
        );
        self.hash = bytes
            .get(0..std::mem::size_of::<u64>())
            .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()));
    }
}

impl BuildHasher for ThrottleKeyHasherBuilder {
    type Hasher = ThrottleKeyHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ThrottleKeyHasher::default()
    }
}
