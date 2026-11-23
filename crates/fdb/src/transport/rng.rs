/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    hash::{BuildHasher, Hasher, RandomState},
    time::Duration,
};

const JITTER_OFFSET: f64 = 0.9;
const JITTER_RANGE: f64 = 0.2;
const UNIT_SCALE: f64 = 1.0 / (1u64 << 53) as f64;

pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new() -> Self {
        Self(RandomState::new().build_hasher().finish())
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn jitter(&mut self, delay: Duration) -> Duration {
        let unit = (self.next_u64() >> 11) as f64 * UNIT_SCALE;
        delay.mul_f64(JITTER_OFFSET + JITTER_RANGE * unit)
    }
}
