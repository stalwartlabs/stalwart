/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::{
    error::{Error, ErrorCode, Result},
    version::{ReadVersionCache, Version},
};
use parking_lot::Mutex;
use std::{
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::Notify};

const STALE_REFRESH_HOLD_OFF: u64 = 10_000_000;

pub(crate) struct VersionCache {
    base: Instant,
    version: AtomicI64,
    obtained: AtomicU64,
    invalidated: AtomicU64,
    committed: AtomicI64,
    refreshing: AtomicBool,
    outcome: Mutex<Outcome>,
    failed_at: AtomicU64,
    refreshed: Notify,
    refresh_after: u64,
    max_age: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    Fresh(Version),
    Stale(Version),
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    Expired,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refresh {
    Started,
    Running,
    NotNeeded,
}

#[derive(Clone, Copy)]
struct Outcome {
    generation: u64,
    started: u64,
    result: Option<Result<Version>>,
}

struct Flight {
    cache: Arc<VersionCache>,
    started: u64,
    finished: bool,
}

impl VersionCache {
    pub(crate) fn new(config: ReadVersionCache) -> Self {
        let max_age = config.max_age.min(ReadVersionCache::MAX_AGE_LIMIT);
        VersionCache {
            base: Instant::now(),
            version: AtomicI64::new(0),
            obtained: AtomicU64::new(0),
            invalidated: AtomicU64::new(0),
            committed: AtomicI64::new(0),
            refreshing: AtomicBool::new(false),
            outcome: Mutex::new(Outcome {
                generation: 0,
                started: 0,
                result: None,
            }),
            failed_at: AtomicU64::new(0),
            refreshed: Notify::new(),
            refresh_after: saturating_nanos(config.refresh_after.min(max_age)),
            max_age: saturating_nanos(max_age),
        }
    }

    fn now(&self) -> u64 {
        saturating_nanos(self.base.elapsed()).saturating_add(1)
    }

    pub(crate) fn lookup(&self) -> Lookup {
        let obtained = self.obtained.load(Ordering::Acquire);
        let invalidated = self.invalidated.load(Ordering::Acquire);
        let Some(version) = Version::new(self.version.load(Ordering::Acquire)) else {
            return Lookup::Expired;
        };
        let age = self.now().saturating_sub(obtained);
        if obtained <= invalidated || age >= self.max_age {
            Lookup::Expired
        } else if age >= self.refresh_after {
            Lookup::Stale(version)
        } else {
            Lookup::Fresh(version)
        }
    }

    fn begin_refresh<Fut>(
        self: &Arc<Self>,
        runtime: &Handle,
        trigger: Trigger,
        fetch: impl FnOnce() -> Fut,
    ) -> Refresh
    where
        Fut: Future<Output = Result<Version>> + Send + 'static,
    {
        if self.refreshing.load(Ordering::Relaxed)
            || self
                .refreshing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return Refresh::Running;
        }
        if match self.lookup() {
            Lookup::Fresh(_) => true,
            Lookup::Stale(_) => trigger == Trigger::Expired,
            Lookup::Expired => false,
        } {
            self.refreshing.store(false, Ordering::Release);
            self.refreshed.notify_waiters();
            return Refresh::NotNeeded;
        }
        let flight = Flight {
            cache: self.clone(),
            started: self.now(),
            finished: false,
        };
        let fetch = fetch();
        runtime.spawn(async move {
            let result = fetch.await;
            flight.finish(result);
        });
        Refresh::Started
    }

    pub(crate) fn refresh_in_background<Fut>(
        self: &Arc<Self>,
        runtime: &Handle,
        fetch: impl FnOnce() -> Fut,
    ) where
        Fut: Future<Output = Result<Version>> + Send + 'static,
    {
        let failed_at = self.failed_at.load(Ordering::Relaxed);
        if failed_at == 0 || self.now().saturating_sub(failed_at) >= STALE_REFRESH_HOLD_OFF {
            self.begin_refresh(runtime, Trigger::Stale, fetch);
        }
    }

    pub(crate) async fn get_or_refresh<Fut>(
        self: &Arc<Self>,
        runtime: &Handle,
        fetch: impl Fn() -> Fut,
    ) -> Result<Version>
    where
        Fut: Future<Output = Result<Version>> + Send + 'static,
    {
        loop {
            match self.lookup() {
                Lookup::Fresh(version) | Lookup::Stale(version) => return Ok(version),
                Lookup::Expired => {}
            }
            let mut refreshed = pin!(self.refreshed.notified());
            refreshed.as_mut().enable();
            let generation = self.outcome.lock().generation;
            let invalidated = self.invalidated.load(Ordering::Acquire);
            if self.begin_refresh(runtime, Trigger::Expired, &fetch) == Refresh::NotNeeded {
                continue;
            }
            refreshed.await;
            let outcome = *self.outcome.lock();
            if outcome.generation != generation
                && outcome.started > invalidated
                && let Some(result) = outcome.result
            {
                return result;
            }
        }
    }

    pub(crate) fn store(&self, version: Version, started: u64) {
        self.store_max(version.get());
        self.obtained.fetch_max(started, Ordering::AcqRel);
    }

    pub(crate) fn request_started(&self) -> u64 {
        self.now()
    }

    pub(crate) fn secs_since(&self, started: u64) -> f64 {
        Duration::from_nanos(self.now().saturating_sub(started)).as_secs_f64()
    }

    pub(crate) fn raise_floor(&self, committed: Version) {
        if self.committed.load(Ordering::Acquire) < committed.get() {
            self.committed.fetch_max(committed.get(), Ordering::AcqRel);
        }
        self.store_max(committed.get());
    }

    pub(crate) fn advance(&self, version: Version) {
        self.store_max(version.get());
    }

    pub(crate) fn invalidate(&self) {
        self.invalidated.fetch_max(self.now(), Ordering::AcqRel);
    }

    pub(crate) fn invalidate_if(&self, version: Version) {
        if self.version.load(Ordering::Acquire) == version.get() {
            self.invalidate();
        }
    }

    pub(crate) fn last_committed(&self) -> Option<Version> {
        Version::new(self.committed.load(Ordering::Acquire))
    }

    fn store_max(&self, version: i64) -> bool {
        self.version.load(Ordering::Acquire) < version
            && self.version.fetch_max(version, Ordering::AcqRel) < version
    }

    fn publish(&self, started: u64, result: Result<Version>) {
        self.failed_at.store(
            if result.is_ok() { 0 } else { self.now() },
            Ordering::Relaxed,
        );
        let mut outcome = self.outcome.lock();
        outcome.generation += 1;
        outcome.started = started;
        outcome.result = Some(result);
        self.refreshing.store(false, Ordering::Release);
        drop(outcome);
        self.refreshed.notify_waiters();
    }
}

impl Flight {
    fn finish(mut self, result: Result<Version>) {
        if let Ok(version) = result {
            self.cache.store(version, self.started);
        }
        self.cache.publish(self.started, result);
        self.finished = true;
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        if !self.finished {
            self.cache.publish(
                self.started,
                Err(Error::new(ErrorCode::OPERATION_CANCELLED)),
            );
        }
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/read_version/tests.rs"]
mod tests;
