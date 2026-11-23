/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use foundationdb::{Database, FdbError};
use std::{
    sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    time::{Duration, Instant},
};

mod assembly;
pub mod blob;
pub mod main;
mod preread;
#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb_c/probe.rs"]
pub mod probe;
pub mod read;
mod window;
pub mod write;

pub(crate) const MAX_VALUE_SIZE: usize = 100000;
pub(crate) const FDB_VALUE_TOO_LARGE: i32 = 2103;
const FDB_BATCH_THROTTLED: i32 = 1051;
const MAX_THROTTLED_TIME: Duration = Duration::from_secs(15 * 60);

const MAX_EXACT_MODE_ROWS: u64 = 256;

const REFRESH_READ_VERSION_AFTER: Duration = Duration::from_secs(1);
const MAX_READ_VERSION_AGE: Duration = Duration::from_secs(4);

pub struct FdbStore {
    db: Database,
    version: ReadVersion,
    windows: window::WindowLoad,
    cluster_file: Option<Box<str>>,
    connection: Option<Box<str>>,
}

pub(crate) struct ReadVersion {
    base: Instant,
    version: AtomicI64,
    committed: AtomicI64,
    obtained: AtomicU64,
    refreshing: AtomicBool,
}

impl ReadVersion {
    fn now(&self) -> u64 {
        self.base.elapsed().as_nanos() as u64
    }

    fn current(&self) -> i64 {
        self.version.load(Ordering::Acquire)
    }

    fn age(&self) -> u64 {
        self.now()
            .saturating_sub(self.obtained.load(Ordering::Acquire))
    }

    fn store_max(&self, version: i64) -> bool {
        let mut current = self.version.load(Ordering::Relaxed);
        while version > current {
            match self.version.compare_exchange_weak(
                current,
                version,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
        false
    }

    fn refreshed(&self, version: i64) {
        self.store_max(version);
        self.obtained.store(self.now(), Ordering::Release);
    }

    fn raise_floor(&self, version: i64) {
        self.committed.fetch_max(version, Ordering::AcqRel);
        self.store_max(version);
    }

    fn advance(&self, version: i64) {
        if self.store_max(version) {
            self.obtained.store(self.now(), Ordering::Release);
        }
    }

    fn last_committed(&self) -> Option<i64> {
        Some(self.committed.load(Ordering::Acquire)).filter(|version| *version > 0)
    }

    fn expire(&self) {
        self.version.store(0, Ordering::Release);
    }

    fn try_begin_refresh(&self) -> Option<RefreshGuard<'_>> {
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            Some(RefreshGuard(&self.refreshing))
        } else {
            None
        }
    }
}

impl Default for ReadVersion {
    fn default() -> Self {
        Self {
            base: Instant::now(),
            version: AtomicI64::new(0),
            committed: AtomicI64::new(0),
            obtained: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
        }
    }
}

pub(crate) struct RefreshGuard<'a>(&'a AtomicBool);

impl Drop for RefreshGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[inline(always)]
fn into_error(error: FdbError) -> trc::Error {
    trc::StoreEvent::FoundationdbError
        .reason(error.message())
        .ctx(trc::Key::Code, error.code())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb_c/tests.rs"]
mod tests;
