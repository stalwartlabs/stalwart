/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use super::PrimitiveError;

pub(crate) trait Rng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), PrimitiveError>;
}

pub(crate) struct SystemRng(SystemRandom);

impl SystemRng {
    pub(crate) fn new() -> Self {
        SystemRng(SystemRandom::new())
    }
}

impl Rng for SystemRng {
    #[inline]
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), PrimitiveError> {
        self.0.fill(dest).map_err(|_| PrimitiveError::Random)
    }
}
