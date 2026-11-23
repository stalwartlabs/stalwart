/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Uid {
    pub first: u64,
    pub second: u64,
}

impl Uid {
    pub const ZERO: Uid = Uid::new(0, 0);
    pub const LEN: usize = 16;

    pub const fn new(first: u64, second: u64) -> Self {
        Uid { first, second }
    }

    pub const fn well_known(id: u64) -> Self {
        Uid::new(u64::MAX, id)
    }

    pub const fn is_well_known(self) -> bool {
        self.first == u64::MAX
    }

    pub const fn to_le_bytes(self) -> [u8; Self::LEN] {
        (((self.second as u128) << 64) | self.first as u128).to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; Self::LEN]) -> Self {
        let value = u128::from_le_bytes(bytes);
        Uid::new(value as u64, (value >> 64) as u64)
    }
}
