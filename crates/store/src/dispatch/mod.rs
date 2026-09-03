/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Store;
use roaring::RoaringBitmap;

pub mod blob;
pub mod lookup;
pub mod search;
pub mod store;

#[cfg(feature = "test_mode")]
pub use ops::StoreOps;

pub const MAX_SCAN_RANGES: usize = 1024;
pub const MAX_SCAN_GAP: u32 = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum ScanShape {
    Range(u32, u32),
    Ranges(Vec<(u32, u32)>),
}

impl Store {
    pub fn id(&self) -> &'static str {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(_) => "sqlite",
            #[cfg(feature = "foundation")]
            Self::FoundationDb(_) => "foundationdb",
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => "postgresql",
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => "mysql",
            #[cfg(feature = "rocks")]
            Self::RocksDb(_) => "rocksdb",
            Self::Ephemeral(_) => "ephemeral",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(_) => "read_replica",
            // SPDX-SnippetEnd
            Self::None => "none",
        }
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait DocumentSet: Sync + Send {
    fn min(&self) -> u32;
    fn max(&self) -> u32;
    fn contains(&self, id: u32) -> bool;
    fn len(&self) -> usize;
    fn iterate(&self) -> impl Iterator<Item = u32>;

    fn is_dense(&self) -> bool {
        self.len() as u64 * MAX_SCAN_GAP as u64 >= (self.max() - self.min()) as u64
    }

    fn scan_shape(&self) -> ScanShape {
        let len = self.len();
        let min = self.min();
        let max = self.max();
        if len == 0 {
            return ScanShape::Range(min, max);
        }
        if self.is_dense() {
            return ScanShape::Range(min, max);
        }

        let ranges = self.scan_ranges();
        match ranges.as_slice() {
            [] => ScanShape::Range(min, max),
            &[(from, to)] => ScanShape::Range(from, to),
            _ => ScanShape::Ranges(ranges),
        }
    }

    fn scan_ranges(&self) -> Vec<(u32, u32)> {
        if self.len() == 0 {
            return Vec::new();
        }
        if self.is_dense() {
            let min = self.min();
            return vec![(min, self.max().saturating_sub(1).max(min))];
        }

        let mut gap = MAX_SCAN_GAP;
        loop {
            if let Some(ranges) = self.cluster_ranges(gap) {
                return ranges;
            }
            gap = gap.saturating_mul(2);
        }
    }

    fn cluster_ranges(&self, gap: u32) -> Option<Vec<(u32, u32)>> {
        let mut ids = self.iterate();
        let Some(first) = ids.next() else {
            return Some(Vec::new());
        };

        let mut ranges = Vec::new();
        let mut range = (first, first);
        for document_id in ids {
            if document_id - range.1 <= gap {
                range.1 = document_id;
            } else {
                if ranges.len() + 1 >= MAX_SCAN_RANGES {
                    return None;
                }
                ranges.push(range);
                range = (document_id, document_id);
            }
        }
        ranges.push(range);

        Some(ranges)
    }
}

impl DocumentSet for RoaringBitmap {
    fn min(&self) -> u32 {
        self.min().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.max().map(|m| m + 1).unwrap_or(0)
    }

    fn contains(&self, id: u32) -> bool {
        self.contains(id)
    }

    fn len(&self) -> usize {
        self.len() as usize
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.iter()
    }
}

impl DocumentSet for Vec<u32> {
    fn contains(&self, id: u32) -> bool {
        self.binary_search(&id).is_ok()
    }

    fn min(&self) -> u32 {
        self.first().copied().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.last().copied().map(|m| m + 1).unwrap_or(0)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.iter().copied()
    }
}

impl DocumentSet for () {
    fn min(&self) -> u32 {
        0
    }

    fn max(&self) -> u32 {
        u32::MAX
    }

    fn contains(&self, _: u32) -> bool {
        true
    }

    fn len(&self) -> usize {
        0
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        std::iter::empty()
    }

    fn scan_ranges(&self) -> Vec<(u32, u32)> {
        vec![(0, u32::MAX)]
    }
}

#[cfg(feature = "test_mode")]
mod ops {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GET_VALUE: AtomicUsize = AtomicUsize::new(0);
    static ITERATE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct StoreOps {
        pub get_value: usize,
        pub iterate: usize,
    }

    impl StoreOps {
        pub(crate) fn count_get_value() {
            GET_VALUE.fetch_add(1, Ordering::Relaxed);
        }

        pub(crate) fn count_iterate(ranges: usize) {
            ITERATE.fetch_add(ranges, Ordering::Relaxed);
        }

        pub fn take() -> Self {
            StoreOps {
                get_value: GET_VALUE.swap(0, Ordering::Relaxed),
                iterate: ITERATE.swap(0, Ordering::Relaxed),
            }
        }

        pub fn total(&self) -> usize {
            self.get_value + self.iterate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_set_scan_ranges() {
        assert_eq!(RoaringBitmap::new().scan_ranges(), vec![]);
        assert_eq!(
            RoaringBitmap::from_iter(0..100u32).scan_ranges(),
            vec![(0, 99)]
        );
        assert_eq!(
            RoaringBitmap::from_iter([5u32, 60]).scan_ranges(),
            vec![(5, 60)]
        );
        assert_eq!(
            RoaringBitmap::from_iter([5u32, 900_000]).scan_ranges(),
            vec![(5, 5), (900_000, 900_000)]
        );
        assert_eq!(
            RoaringBitmap::from_iter([5u32, 6, 7, 5_000, 5_001, 90_000]).scan_ranges(),
            vec![(5, 7), (5_000, 5_001), (90_000, 90_000)]
        );
        assert_eq!(
            RoaringBitmap::from_iter((0..MAX_SCAN_RANGES as u32).map(|id| id * 1_000))
                .scan_ranges()
                .len(),
            MAX_SCAN_RANGES
        );
        assert_eq!(
            RoaringBitmap::from_iter((0..=MAX_SCAN_RANGES as u32).map(|id| id * 1_000))
                .scan_ranges(),
            vec![(0, MAX_SCAN_RANGES as u32 * 1_000)]
        );
        assert_eq!(
            RoaringBitmap::from_iter(
                (0..=MAX_SCAN_RANGES as u32)
                    .map(|id| id * 1_000 + if id >= 512 { 1_000_000 } else { 0 })
            )
            .scan_ranges(),
            vec![
                (0, 511_000),
                (1_512_000, MAX_SCAN_RANGES as u32 * 1_000 + 1_000_000)
            ]
        );
    }

    #[test]
    fn document_set_scan_ranges_coalesce() {
        let ids = (0..1_000u32)
            .flat_map(|pair| [pair * 200, pair * 200 + 67])
            .collect::<Vec<_>>();
        let set = RoaringBitmap::from_iter(ids.iter().copied());
        assert!(!set.is_dense());
        assert_eq!(set.cluster_ranges(MAX_SCAN_GAP), None);

        let ranges = set.scan_ranges();
        assert_eq!(ranges.len(), 1_000);
        assert!(ranges.len() <= MAX_SCAN_RANGES);
        assert!(ranges.windows(2).all(|pair| pair[0].1 < pair[1].0));
        assert!(
            ids.iter()
                .all(|id| ranges.iter().any(|(from, to)| (from..=to).contains(&id)))
        );

        let span = (ids[ids.len() - 1] - ids[0] + 1) as u64;
        let covered = ranges
            .iter()
            .map(|(from, to)| (to - from + 1) as u64)
            .sum::<u64>();
        assert!(covered * 2 < span, "{covered} of {span}");

        assert_eq!(ids.scan_ranges(), ranges);
        assert!(matches!(set.scan_shape(), ScanShape::Ranges(shape) if shape == ranges));
    }

    #[test]
    fn document_set_scan_shape() {
        assert_eq!(RoaringBitmap::new().scan_shape(), ScanShape::Range(0, 0));
        assert_eq!(().scan_shape(), ScanShape::Range(0, u32::MAX));
        assert_eq!(
            RoaringBitmap::from_iter(0..100u32).scan_shape(),
            ScanShape::Range(0, 100)
        );
        assert_eq!(
            RoaringBitmap::from_iter([5u32, 60]).scan_shape(),
            ScanShape::Range(5, 61)
        );
        assert_eq!(
            RoaringBitmap::from_iter([7u32]).scan_shape(),
            ScanShape::Range(7, 8)
        );
        assert_eq!(
            RoaringBitmap::from_iter([12u32, 150_000, 199_998]).scan_shape(),
            ScanShape::Ranges(vec![(12, 12), (150_000, 150_000), (199_998, 199_998)])
        );
        assert!(matches!(
            RoaringBitmap::from_iter((0..64u32).map(|id| id * 100_000)).scan_shape(),
            ScanShape::Ranges(ranges)
                if ranges.len() == 64 && ranges.iter().all(|(from, to)| from == to)
        ));
    }

    #[test]
    fn document_set_scan_ranges_agree_across_impls() {
        for ids in [
            vec![],
            vec![7u32],
            (0..100u32).collect(),
            vec![5, 60],
            vec![5, 900_000],
            vec![5, 6, 7, 5_000, 5_001, 90_000],
        ] {
            assert_eq!(
                ids.scan_ranges(),
                RoaringBitmap::from_iter(ids.iter().copied()).scan_ranges(),
                "{ids:?}"
            );
        }
    }

    #[test]
    fn document_set_scan_ranges_unbounded() {
        assert_eq!(().scan_ranges(), vec![(0, u32::MAX)]);
    }
}
