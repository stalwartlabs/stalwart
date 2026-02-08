/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavResources, HttpAuthCache, MailboxCache, MessageStoreCache, UpdateLock};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Semaphore, SemaphorePermit};
use utils::cache::CacheItemWeight;

pub mod directory;
pub mod invalidate;
pub mod reload;

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

impl UpdateLock {
    pub fn new() -> Self {
        Self {
            semaphore: Semaphore::new(1),
            revision: AtomicU64::new(0),
        }
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

impl CacheItemWeight for DavResources {
    fn weight(&self) -> u64 {
        self.size
    }
}
