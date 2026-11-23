/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::range::Direction;
use crossbeam_utils::sync::{ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard};
use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::BTreeSet,
    ops::Bound::{Excluded, Included, Unbounded},
    sync::{Arc, PoisonError},
};

pub(crate) const LOCATION_CACHE_EVICTION_SIZE: usize = 600_000;
const EVICTED_PER_256: u8 = 32;

pub(crate) struct LocationCache<T> {
    shards: ShardedLock<BTreeSet<ByBegin<T>>>,
    capacity: usize,
}

pub(crate) struct Shard<T> {
    begin: Box<[u8]>,
    end: Box<[u8]>,
    location: T,
}

struct ByBegin<T>(Arc<Shard<T>>);

impl<T> LocationCache<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        LocationCache {
            shards: ShardedLock::new(BTreeSet::new()),
            capacity,
        }
    }

    pub(crate) fn locate(&self, key: &[u8], direction: Direction) -> Option<Arc<Shard<T>>> {
        find(&self.read(), key, direction).map(|shard| Arc::clone(&shard.0))
    }

    pub(crate) fn insert(&self, shard: Shard<T>) -> Arc<Shard<T>> {
        let shard = Arc::new(shard);
        let mut victims = Vec::new();
        {
            let mut shards = self.write();
            remove_overlapping(&mut shards, &shard.begin, &shard.end, &mut victims);
            while !shards.is_empty() && shards.len() >= self.capacity {
                victims.extend(shards.extract_if(.., |_| fastrand::u8(..) < EVICTED_PER_256));
            }
            shards.insert(ByBegin(Arc::clone(&shard)));
        }
        drop(victims);
        shard
    }

    pub(crate) fn invalidate_key(&self, key: &[u8], direction: Direction) {
        if find(&self.read(), key, direction).is_none() {
            return;
        }
        let victim = {
            let mut shards = self.write();
            find(&shards, key, direction)
                .map(|shard| Arc::clone(&shard.0))
                .and_then(|shard| shards.take(shard.begin()))
        };
        drop(victim);
    }

    pub(crate) fn invalidate_range(&self, begin: &[u8], end: &[u8]) {
        if begin > end {
            return;
        }
        let mut victims = Vec::new();
        remove_overlapping(&mut self.write(), begin, end, &mut victims);
        drop(victims);
    }

    fn read(&self) -> ShardedLockReadGuard<'_, BTreeSet<ByBegin<T>>> {
        self.shards.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> ShardedLockWriteGuard<'_, BTreeSet<ByBegin<T>>> {
        self.shards.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<T> Shard<T> {
    pub(crate) fn new(begin: &[u8], end: &[u8], location: T) -> Option<Self> {
        (begin < end).then(|| Shard {
            begin: begin.into(),
            end: end.into(),
            location,
        })
    }

    pub(crate) fn begin(&self) -> &[u8] {
        &self.begin
    }

    pub(crate) fn end(&self) -> &[u8] {
        &self.end
    }

    pub(crate) fn location(&self) -> &T {
        &self.location
    }
}

fn find<'a, T>(
    shards: &'a BTreeSet<ByBegin<T>>,
    key: &[u8],
    direction: Direction,
) -> Option<&'a ByBegin<T>> {
    match direction {
        Direction::Forward => shards
            .range::<[u8], _>((Unbounded, Included(key)))
            .next_back()
            .filter(|shard| key < shard.0.end()),
        Direction::Reverse if key.is_empty() => {
            shards.first().filter(|shard| shard.0.begin().is_empty())
        }
        Direction::Reverse => shards
            .range::<[u8], _>((Unbounded, Excluded(key)))
            .next_back()
            .filter(|shard| key <= shard.0.end()),
    }
}

fn remove_overlapping<T>(
    shards: &mut BTreeSet<ByBegin<T>>,
    begin: &[u8],
    end: &[u8],
    victims: &mut Vec<ByBegin<T>>,
) {
    if let Some(previous) = shards
        .range::<[u8], _>((Unbounded, Excluded(begin)))
        .next_back()
        .filter(|shard| shard.0.end() > begin)
        .map(|shard| Arc::clone(&shard.0))
    {
        victims.extend(shards.take(previous.begin()));
    }
    while let Some(next) = shards
        .range::<[u8], _>((Included(begin), Excluded(end)))
        .next()
        .map(|shard| Arc::clone(&shard.0))
    {
        victims.extend(shards.take(next.begin()));
    }
}

impl<T> Borrow<[u8]> for ByBegin<T> {
    fn borrow(&self) -> &[u8] {
        &self.0.begin
    }
}

impl<T> Ord for ByBegin<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.begin.cmp(&other.0.begin)
    }
}

impl<T> PartialOrd for ByBegin<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> PartialEq for ByBegin<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.begin == other.0.begin
    }
}

impl<T> Eq for ByBegin<T> {}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/location/tests.rs"]
mod tests;
