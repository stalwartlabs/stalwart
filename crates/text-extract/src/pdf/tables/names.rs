/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::Ordering;

pub(super) struct NameTable {
    text: &'static str,
    offsets: &'static [u16],
}

impl NameTable {
    pub(super) const fn new(text: &'static str, offsets: &'static [u16]) -> Self {
        Self { text, offsets }
    }

    pub(super) fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    pub(super) fn get(&self, index: usize) -> Option<&'static str> {
        let &[start, end] = self.offsets.get(index..index + 2)? else {
            return None;
        };
        self.text.get(usize::from(start)..usize::from(end))
    }

    pub(super) fn find(&self, name: &[u8]) -> Option<usize> {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let mid = low + (high - low) / 2;
            match self.get(mid)?.as_bytes().cmp(name) {
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid,
                Ordering::Equal => return Some(mid),
            }
        }
        None
    }
}
