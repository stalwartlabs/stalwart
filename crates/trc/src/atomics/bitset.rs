/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::ipc::{USIZE_BITS, USIZE_BITS_MASK, bitset::Bitset};

pub struct AtomicBitset<const N: usize>([AtomicUsize; N]);

impl<const N: usize> AtomicBitset<N> {
    #[allow(clippy::new_without_default)]
    #[allow(clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        Self({
            const INIT: AtomicUsize = AtomicUsize::new(0);
            let mut array = [INIT; N];
            let mut i = 0;
            while i < N {
                array[i] = AtomicUsize::new(0);
                i += 1;
            }
            array
        })
    }

    #[inline(always)]
    pub fn set(&self, index: impl Into<usize>) {
        let index = index.into();
        self.0[index / USIZE_BITS].fetch_or(1 << (index & USIZE_BITS_MASK), Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn clear(&self, index: impl Into<usize>) {
        let index = index.into();
        self.0[index / USIZE_BITS].fetch_and(!(1 << (index & USIZE_BITS_MASK)), Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn get(&self, index: impl Into<usize>) -> bool {
        let index = index.into();
        self.0[index / USIZE_BITS].load(Ordering::Relaxed) & (1 << (index & USIZE_BITS_MASK)) != 0
    }

    pub fn update(&self, bitset: impl AsRef<Bitset<N>>) {
        let bitset = bitset.as_ref();
        for i in 0..N {
            self.0[i].store(bitset.0[i], Ordering::Relaxed);
        }
    }

    pub fn union(&self, bitset: impl AsRef<Bitset<N>>) {
        let bitset = bitset.as_ref();
        for i in 0..N {
            self.0[i].fetch_or(bitset.0[i], Ordering::Relaxed);
        }
    }

    pub fn clear_all(&self) {
        for word in &self.0 {
            word.store(0, Ordering::Relaxed);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|word| word.load(Ordering::Relaxed) == 0)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/trc/src/atomics/bitset/tests.rs"]
mod tests;
