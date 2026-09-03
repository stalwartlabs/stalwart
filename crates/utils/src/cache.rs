/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use arcstr::ArcStr;
use mail_auth::{DnssecStatus, MX, RecordSet, ResolverCache, Txt};
use quick_cache::{
    Equivalent, Options, OptionsBuilder, Weighter,
    sync::{DefaultLifecycle, PlaceholderGuard},
};
use std::{
    borrow::Borrow,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

const HOT_ALLOCATION: f64 = 0.97;

pub struct Cache<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> {
    inner: quick_cache::sync::Cache<K, V, CacheItemWeighter, ahash::RandomState>,
    admission_limit: u64,
    name: &'static str,
}

pub struct CacheWithTtl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight>(
    quick_cache::sync::Cache<K, TtlEntry<V>, CacheItemWeighter, ahash::RandomState>,
);

#[derive(Clone)]
pub struct TtlEntry<V: Clone + CacheItemWeight> {
    value: V,
    expires: Instant,
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> Cache<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        Self::new_estimated(weight as usize / estimated_weight as usize, weight)
    }

    pub fn new_estimated(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self::build(
            cache_options(estimated_items_capacity, weight_capacity, None),
            "",
        )
    }

    pub fn new_single_shard(weight: u64, estimated_weight: u64) -> Self {
        Self::build(
            cache_options(weight as usize / estimated_weight as usize, weight, Some(1)),
            "",
        )
    }

    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    fn build(options: Options, name: &'static str) -> Self {
        let inner = quick_cache::sync::Cache::with_options(
            options,
            CacheItemWeighter,
            ahash::RandomState::default(),
            DefaultLifecycle::default(),
        );
        let shard_capacity = inner.shard_capacity();
        let admission_limit = ((shard_capacity as f64 * HOT_ALLOCATION) as u64)
            .clamp(shard_capacity.min(1), shard_capacity);

        Self {
            inner,
            admission_limit,
            name,
        }
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.get(key)
    }

    #[inline(always)]
    pub fn peek<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.peek(key)
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<
        V,
        PlaceholderGuard<'a, K, V, CacheItemWeighter, ahash::RandomState, DefaultLifecycle<K, V>>,
    >
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        self.inner.get_value_or_guard_async(key).await
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V) {
        if self.reject_oversized(&key, &value) {
            return;
        }
        self.inner.insert(key, value);
    }

    #[inline(always)]
    pub fn update(&self, key: K, value: V) {
        if self.reject_oversized(&key, &value) {
            return;
        }
        if let Err((key, value)) = self.inner.replace(key, value, true) {
            self.inner.insert(key, value);
        }
    }

    #[inline(always)]
    fn reject_oversized(&self, key: &K, value: &V) -> bool {
        let weight = key.weight() + value.weight();
        if weight <= self.admission_limit {
            return false;
        }

        trc::event!(
            Cache(trc::CacheEvent::EntryTooLarge),
            Type = self.name,
            Size = weight,
            Limit = self.admission_limit,
        );
        true
    }

    #[inline(always)]
    pub fn is_oversized(&self, key: &K, value: &V) -> bool {
        key.weight() + value.weight() > self.admission_limit
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.remove(key).map(|(_, v)| v)
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.inner.clear();
    }

    #[inline(always)]
    pub fn inner(&self) -> &quick_cache::sync::Cache<K, V, CacheItemWeighter, ahash::RandomState> {
        &self.inner
    }

    #[inline(always)]
    pub fn weight_capacity(&self) -> u64 {
        self.inner.capacity()
    }

    #[inline(always)]
    pub fn admission_limit(&self) -> u64 {
        self.admission_limit
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> CacheWithTtl<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        Self::new_estimated(weight as usize / estimated_weight as usize, weight)
    }

    pub fn new_estimated(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self(quick_cache::sync::Cache::with_options(
            cache_options(estimated_items_capacity, weight_capacity, None),
            CacheItemWeighter,
            ahash::RandomState::default(),
            DefaultLifecycle::default(),
        ))
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.get(key).and_then(|v| {
            if v.expires > Instant::now() {
                Some(v.value)
            } else {
                self.0.remove(key);
                None
            }
        })
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<
        V,
        PlaceholderGuard<
            'a,
            K,
            TtlEntry<V>,
            CacheItemWeighter,
            ahash::RandomState,
            DefaultLifecycle<K, TtlEntry<V>>,
        >,
    >
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        match self.0.get_value_or_guard_async(key).await {
            Ok(value) => {
                if value.expires > Instant::now() {
                    Ok(value.value)
                } else {
                    self.0.remove(key);
                    self.0.get_value_or_guard_async(key).await.map(|v| v.value)
                }
            }
            Err(err) => Err(err),
        }
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V, expires: Duration) {
        self.0.insert(key, TtlEntry::new(value, expires));
    }

    #[inline(always)]
    pub fn insert_with_expiry(&self, key: K, value: V, expires: Instant) {
        self.0.insert(key, TtlEntry::with_expiry(value, expires));
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.remove(key).map(|(_, v)| v.value)
    }

    #[inline(always)]
    pub fn retain(&self, f: impl Fn(&K) -> bool) {
        self.0.retain(|key, _| f(key));
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.0.clear();
    }
}

const MIN_ENTRIES_PER_SHARD: usize = 256;

fn cache_options(
    estimated_items_capacity: usize,
    weight_capacity: u64,
    shards: Option<usize>,
) -> Options {
    let estimated_items_capacity = estimated_items_capacity.max(1);
    let mut builder = OptionsBuilder::new();
    builder
        .estimated_items_capacity(estimated_items_capacity)
        .weight_capacity(weight_capacity);
    builder.shards(match shards {
        Some(shards) => shards.max(1),
        None => {
            let capped = default_shards().min(estimated_items_capacity / MIN_ENTRIES_PER_SHARD);
            if capped <= 1 {
                1
            } else {
                1 << (usize::BITS - 1 - capped.leading_zeros())
            }
        }
    });
    builder.build().unwrap()
}

fn default_shards() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        * 4
}

#[derive(Clone)]
pub struct CacheItemWeighter;

impl<K: CacheItemWeight, V: CacheItemWeight> Weighter<K, V> for CacheItemWeighter {
    fn weight(&self, key: &K, val: &V) -> u64 {
        key.weight() + val.weight()
    }
}

pub trait CacheItemWeight {
    fn weight(&self) -> u64;
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for TtlEntry<T> {
    fn weight(&self) -> u64 {
        self.value.weight() + std::mem::size_of::<Instant>() as u64
    }
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for Option<T> {
    fn weight(&self) -> u64 {
        match self {
            Some(v) => v.weight(),
            None => std::mem::size_of::<usize>() as u64,
        }
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Arc<T> {
    fn weight(&self) -> u64 {
        self.as_ref().weight()
    }
}

impl CacheItemWeight for u64 {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u64>() as u64
    }
}

impl CacheItemWeight for String {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<String>() as u64
    }
}

impl CacheItemWeight for Box<str> {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<Box<str>>() as u64
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Box<[T]> {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Box<[T]>>() as u64 + self.iter().map(|item| item.weight()).sum::<u64>()
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Arc<[T]> {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Arc<[T]>>() as u64 + self.iter().map(|item| item.weight()).sum::<u64>()
    }
}

impl<T: CacheItemWeight> CacheItemWeight for RecordSet<T> {
    fn weight(&self) -> u64 {
        self.rrset.weight() + std::mem::size_of::<DnssecStatus>() as u64
    }
}

impl CacheItemWeight for u32 {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u32>() as u64
    }
}

impl CacheItemWeight for IpAddr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<IpAddr>() as u64
    }
}

impl CacheItemWeight for Ipv4Addr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Ipv4Addr>() as u64
    }
}

impl CacheItemWeight for Ipv6Addr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Ipv6Addr>() as u64
    }
}

impl CacheItemWeight for MX {
    fn weight(&self) -> u64 {
        self.exchanges
            .iter()
            .map(|e| e.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
            .sum::<u64>()
            + std::mem::size_of::<MX>() as u64
    }
}

impl CacheItemWeight for Txt {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Txt>() as u64
    }
}

impl CacheItemWeight for bool {
    fn weight(&self) -> u64 {
        std::mem::size_of::<bool>() as u64
    }
}

impl CacheItemWeight for ArcStr {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<ArcStr>() as u64
    }
}

impl CacheItemWeight for () {
    fn weight(&self) -> u64 {
        0
    }
}

impl<T: Clone + CacheItemWeight> TtlEntry<T> {
    pub fn new(value: T, expires: Duration) -> Self {
        Self {
            value,
            expires: Instant::now() + expires,
        }
    }

    pub fn with_expiry(value: T, expires: Instant) -> Self {
        Self { value, expires }
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> ResolverCache<K, V>
    for CacheWithTtl<K, V>
{
    fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        CacheWithTtl::get(self, key)
    }

    fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        CacheWithTtl::remove(self, key)
    }

    fn insert(&self, key: K, value: V, expires: Instant) {
        self.0.insert(key, TtlEntry::with_expiry(value, expires));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc as StdArc, Barrier};

    const CAPACITY: u64 = 10_000_000;

    #[derive(Clone)]
    struct Sized(Box<str>);

    impl Sized {
        fn of(len: usize) -> Self {
            Self("x".repeat(len).into())
        }
    }

    impl CacheItemWeight for Sized {
        fn weight(&self) -> u64 {
            self.0.len() as u64
        }
    }

    fn cache() -> Cache<u32, Sized> {
        let cache = Cache::<u32, Sized>::new_single_shard(CAPACITY, 1000);
        assert_eq!(cache.inner().num_shards(), 1);
        cache
    }

    #[test]
    fn admission_limit_is_the_hot_target_not_the_capacity() {
        let cache = cache();
        assert_eq!(cache.weight_capacity(), CAPACITY);
        assert_eq!(cache.admission_limit(), 9_700_000);

        let key_weight = 0u32.weight() as usize;
        cache.insert(0, Sized::of(9_700_000 - key_weight));
        assert!(cache.get(&0).is_some(), "an entry at the limit is admitted");

        cache.insert(1, Sized::of(9_700_001 - key_weight));
        assert!(cache.get(&1).is_none(), "one byte over is rejected");
    }

    #[test]
    fn oversized_insert_leaves_the_resident_entry_intact() {
        let cache = cache();

        cache.insert(0, Sized::of(1_000));
        cache.update(0, Sized::of(CAPACITY as usize));
        assert_eq!(
            cache.get(&0).map(|v| v.weight()),
            Some(1_000),
            "an oversized update must not destroy the resident entry"
        );

        cache.insert(0, Sized::of(CAPACITY as usize));
        assert_eq!(
            cache.get(&0).map(|v| v.weight()),
            Some(1_000),
            "an oversized insert must not destroy the resident entry either"
        );
    }

    #[test]
    fn oversized_writes_never_expose_a_missing_entry_to_readers() {
        let cache = StdArc::new(cache());
        cache.insert(0, Sized::of(1_000));

        let threads = 8;
        let barrier = StdArc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);

        for thread in 0..threads {
            let cache = cache.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut misses = 0u32;
                for _ in 0..2_000 {
                    if thread % 2 == 0 {
                        cache.update(0, Sized::of(CAPACITY as usize));
                    } else if cache.get(&0).is_none() {
                        misses += 1;
                    }
                }
                misses
            }));
        }

        let misses = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum::<u32>();
        assert_eq!(
            misses, 0,
            "concurrent oversized writes must never evict the resident entry"
        );
    }

    #[test]
    fn sharded_admission_limit_is_a_usable_fraction_of_capacity() {
        let cache = Cache::<u32, Sized>::new(CAPACITY, 1_000);
        assert!(
            cache.admission_limit() * 40 >= CAPACITY,
            "a sharded cache must admit entries well above a naive per-shard slice, \
             limit {} against capacity {CAPACITY}",
            cache.admission_limit()
        );

        let entry = Sized::of((CAPACITY / 64) as usize);
        cache.insert(0, entry);
        assert!(
            cache.get(&0).is_some(),
            "an entry at 1/64 of capacity must be admitted"
        );
    }

    #[test]
    fn sharded_cache_rejects_entry_larger_than_a_shard() {
        let cache = Cache::<u32, Sized>::new_estimated(10_000, CAPACITY);
        let resident = Sized::of(1_000);
        cache.insert(0, resident);

        cache.update(0, Sized::of((CAPACITY / 2) as usize));

        if cache.inner().num_shards() > 1 {
            assert_eq!(
                cache.get(&0).map(|v| v.weight()),
                Some(1_000),
                "the per-shard limit must not destroy the resident entry"
            );
        }
    }
}
