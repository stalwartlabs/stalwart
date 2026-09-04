/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    GroupwareResources, HttpAuthCache, MailboxCache, MessageStoreCache, UpdateLock, Verification,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};
use utils::cache::CacheItemWeight;

pub mod directory;
pub mod email;
pub mod invalidate;
pub mod principals;
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
    pub fn capture(revalidate: &RevalidateInterval, update_lock: &UpdateLock) -> Self {
        Verification {
            verified_at: revalidate.now(),
            epoch: update_lock.epoch(),
        }
    }

    pub fn is_current(&self, update_lock: &UpdateLock) -> bool {
        self.epoch == update_lock.epoch()
    }

    pub fn is_fresh(&self, update_lock: &UpdateLock, revalidate: &RevalidateInterval) -> bool {
        self.is_current(update_lock) && revalidate.is_within(self.verified_at)
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
