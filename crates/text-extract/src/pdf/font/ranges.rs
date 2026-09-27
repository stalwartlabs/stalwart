/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Reverse, collections::BTreeMap};

#[derive(Debug, Clone, Copy)]
struct Entry<T> {
    lo: u64,
    hi: u64,
    base: u64,
    value: T,
}

#[derive(Debug, Clone)]
pub(crate) struct RangeMap<T> {
    entries: Vec<Entry<T>>,
}

impl<T> Default for RangeMap<T> {
    fn default() -> Self {
        RangeMap {
            entries: Vec::new(),
        }
    }
}

impl<T: Copy> RangeMap<T> {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.entries.capacity() * std::mem::size_of::<Entry<T>>()
    }

    pub(crate) fn push(&mut self, lo: u64, hi: u64, value: T) {
        if lo <= hi {
            self.entries.push(Entry {
                lo,
                hi,
                base: lo,
                value,
            });
        }
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (u64, u64, T)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.lo, entry.hi, entry.value))
    }

    pub(crate) fn finish(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let mut ordered: Vec<(usize, Entry<T>)> = self.entries.drain(..).enumerate().collect();
        ordered.sort_by_key(|(sequence, entry)| (entry.lo, *sequence));
        let overlapping = ordered
            .windows(2)
            .any(|pair| matches!(pair, [(_, left), (_, right)] if right.lo <= left.hi));
        if !overlapping {
            self.entries
                .extend(ordered.into_iter().map(|(_, entry)| entry));
            self.entries.shrink_to_fit();
            return;
        }
        ordered.sort_by_key(|(sequence, _)| Reverse(*sequence));
        let mut covered: BTreeMap<u64, u64> = BTreeMap::new();
        let mut overlapped: Vec<(u64, u64)> = Vec::new();
        for (_, entry) in ordered {
            let start = match covered.range(..=entry.lo).next_back() {
                Some((&low, &high)) if high >= entry.lo => low,
                _ => entry.lo,
            };
            overlapped.clear();
            overlapped.extend(
                covered
                    .range(start..=entry.hi)
                    .map(|(&low, &high)| (low, high)),
            );
            let mut cursor = Some(entry.lo);
            let (mut merged_lo, mut merged_hi) = (entry.lo, entry.hi);
            for &(low, high) in &overlapped {
                if let Some(next) = cursor
                    && low > next
                {
                    self.entries.push(Entry {
                        lo: next,
                        hi: low - 1,
                        ..entry
                    });
                }
                cursor = cursor.and_then(|next| next.max(high).checked_add(1));
                merged_lo = merged_lo.min(low);
                merged_hi = merged_hi.max(high);
                covered.remove(&low);
            }
            if let Some(next) = cursor
                && next <= entry.hi
            {
                self.entries.push(Entry { lo: next, ..entry });
            }
            covered.insert(merged_lo, merged_hi);
        }
        self.entries.sort_unstable_by_key(|entry| entry.lo);
        self.entries.shrink_to_fit();
    }

    pub(crate) fn find(&self, key: u64) -> Option<(T, u64)> {
        let index = self.entries.partition_point(|entry| entry.lo <= key);
        let entry = self.entries.get(index.checked_sub(1)?)?;
        (key <= entry.hi).then(|| (entry.value, key - entry.base))
    }

    #[cfg(test)]
    pub(crate) fn is_disjoint(&self) -> bool {
        self.entries
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.hi < right.lo))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_ranges_win_and_pieces_keep_their_base() {
        let mut map = RangeMap::default();
        map.push(0, 100, 'a');
        map.push(10, 20, 'b');
        map.push(15, 200, 'c');
        map.push(u64::MAX - 1, u64::MAX, 'd');
        map.push(5, 1, 'x');
        map.finish();
        assert!(map.is_disjoint());
        assert_eq!(map.find(3), Some(('a', 3)));
        assert_eq!(map.find(12), Some(('b', 2)));
        assert_eq!(map.find(16), Some(('c', 1)));
        assert_eq!(map.find(150), Some(('c', 135)));
        assert_eq!(map.find(201), None);
        assert_eq!(map.find(u64::MAX), Some(('d', 1)));
    }

    #[test]
    fn disjoint_input_keeps_order() {
        let mut map = RangeMap::default();
        for index in (0..1000u64).rev() {
            map.push(index * 2, index * 2, index);
        }
        map.finish();
        assert_eq!(map.len(), 1000);
        assert_eq!(map.find(20), Some((10, 0)));
        assert_eq!(map.find(21), None);
    }
}
