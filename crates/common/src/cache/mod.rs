/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    GroupwareResources, HttpAuthCache, MailboxCache, MessageStoreCache, MessageUpdateLock,
    UpdateLock, Verification,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit, futures::Notified};
use utils::cache::CacheItemWeight;

pub mod directory;
pub mod email;
#[cfg(feature = "exchange")]
pub mod exchange;
#[cfg(feature = "exchange")]
pub mod exchange_sessions;
pub mod http_auth;
pub mod invalidate;
pub mod large;
pub mod principals;
pub mod refresh;
pub mod reload;
pub mod swap;

impl MailboxCache {
    pub fn parent_id(&self) -> Option<u32> {
        if self.parent_id != u32::MAX {
            Some(self.parent_id)
        } else {
            None
        }
    }

    pub fn sort_order(&self) -> Option<u32> {
        if self.sort_order != u32::MAX {
            Some(self.sort_order)
        } else {
            None
        }
    }

    pub fn is_root(&self) -> bool {
        self.parent_id == u32::MAX
    }
}

pub enum LockResult<'x> {
    Acquired(SemaphorePermit<'x>),
    Stale(SemaphorePermit<'x>),
}

#[must_use]
pub struct UpdatePermit<'x> {
    lock: &'x MessageUpdateLock,
}

pub trait CacheEpoch {
    fn epoch(&self) -> u64;
}

#[derive(Debug)]
pub struct RevalidateInterval {
    started_at: Instant,
    interval: AtomicU64,
}

impl RevalidateInterval {
    pub const DEFAULT: Duration = Duration::from_secs(5);

    pub fn new(interval: Duration) -> Self {
        RevalidateInterval {
            started_at: Instant::now(),
            interval: AtomicU64::new(interval.as_millis() as u64),
        }
    }

    pub fn set(&self, interval: Duration) {
        self.interval
            .store(interval.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn get(&self) -> Duration {
        Duration::from_millis(self.interval.load(Ordering::Relaxed))
    }

    pub fn now(&self) -> u64 {
        (self.started_at.elapsed().as_millis() as u64).max(1)
    }

    pub fn is_within(&self, verified_at: u64) -> bool {
        verified_at != 0
            && self.now().saturating_sub(verified_at) < self.interval.load(Ordering::Relaxed)
    }
}

impl Default for RevalidateInterval {
    fn default() -> Self {
        RevalidateInterval::new(RevalidateInterval::DEFAULT)
    }
}

impl Verification {
    pub fn capture(revalidate: &RevalidateInterval, update_lock: &impl CacheEpoch) -> Self {
        Verification {
            verified_at: revalidate.now(),
            epoch: update_lock.epoch(),
        }
    }

    pub fn is_current(&self, update_lock: &impl CacheEpoch) -> bool {
        self.epoch == update_lock.epoch()
    }

    pub fn is_fresh(&self, update_lock: &impl CacheEpoch, revalidate: &RevalidateInterval) -> bool {
        self.is_current(update_lock) && revalidate.is_within(self.verified_at)
    }

    pub fn is_verified_since(&self, epoch: u64, revalidate: &RevalidateInterval) -> bool {
        self.epoch >= epoch && revalidate.is_within(self.verified_at)
    }

    pub fn is_verified_after(&self, verified_at: u64) -> bool {
        self.verified_at > verified_at
    }
}

impl MessageStoreCache {
    pub fn is_fresh(&self, revalidate: &RevalidateInterval) -> bool {
        self.verification.is_fresh(&self.update_lock, revalidate)
    }
}

impl GroupwareResources {
    pub fn is_fresh(&self, revalidate: &RevalidateInterval) -> bool {
        self.verification.is_fresh(&self.update_lock, revalidate)
    }
}

impl UpdateLock {
    pub fn new() -> Self {
        Self {
            semaphore: Semaphore::new(1),
            revision: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn mark_stale(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    pub async fn acquire(&self, current_revision: u64) -> trc::Result<LockResult<'_>> {
        let permit = self.semaphore.acquire().await.map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
                .details("Failed to acquire semaphore permit")
        })?;

        if self.revision.load(Ordering::Acquire) == current_revision {
            Ok(LockResult::Acquired(permit))
        } else {
            Ok(LockResult::Stale(permit))
        }
    }

    pub fn set_revision(&self, revision: u64) {
        self.revision.store(revision, Ordering::Release);
    }
}

impl Default for UpdateLock {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageUpdateLock {
    pub fn try_update(&self) -> Option<UpdatePermit<'_>> {
        if self.is_updating.load(Ordering::Relaxed)
            || self
                .is_updating
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            None
        } else {
            Some(UpdatePermit { lock: self })
        }
    }

    pub fn released(&self) -> Notified<'_> {
        self.released.notified()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn mark_stale(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }
}

impl Drop for UpdatePermit<'_> {
    fn drop(&mut self) {
        self.lock.is_updating.store(false, Ordering::Release);
        self.lock.released.notify_waiters();
    }
}

const _: () = assert!(size_of::<MessageUpdateLock>() <= size_of::<UpdateLock>());

impl CacheEpoch for UpdateLock {
    fn epoch(&self) -> u64 {
        UpdateLock::epoch(self)
    }
}

impl CacheEpoch for MessageUpdateLock {
    fn epoch(&self) -> u64 {
        MessageUpdateLock::epoch(self)
    }
}

impl<L: CacheEpoch> CacheEpoch for Arc<L> {
    fn epoch(&self) -> u64 {
        L::epoch(self)
    }
}

impl CacheItemWeight for MessageStoreCache {
    fn weight(&self) -> u64 {
        self.size
    }
}

impl CacheItemWeight for HttpAuthCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<HttpAuthCache>() as u64
    }
}

impl CacheItemWeight for GroupwareResources {
    fn weight(&self) -> u64 {
        self.size
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/cache/tests.rs"]
mod tests;
