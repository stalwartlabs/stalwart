/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Debug, num::ParseIntError, str::FromStr};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Hash128([u8; Hash128::LEN]);

impl Hash128 {
    pub const LEN: usize = std::mem::size_of::<u128>();

    #[inline(always)]
    pub fn from_be_bytes(bytes: [u8; Hash128::LEN]) -> Self {
        Hash128(bytes)
    }

    #[inline(always)]
    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        bytes
            .get(..Hash128::LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .map(Hash128)
    }

    #[inline(always)]
    pub fn as_be_bytes(&self) -> &[u8; Hash128::LEN] {
        &self.0
    }

    #[inline(always)]
    pub fn to_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }
}

impl From<u128> for Hash128 {
    #[inline(always)]
    fn from(value: u128) -> Self {
        Hash128(value.to_be_bytes())
    }
}

impl From<Hash128> for u128 {
    #[inline(always)]
    fn from(value: Hash128) -> Self {
        value.to_u128()
    }
}

impl AsRef<[u8]> for Hash128 {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Hash128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_u128())
    }
}

impl Debug for Hash128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Hash128")
            .field(&format_args!("{:032x}", self.to_u128()))
            .finish()
    }
}

impl FromStr for Hash128 {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u128::from_str(s).map(Hash128::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash128_round_trips() {
        let value = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        let hash = Hash128::from(value);

        assert_eq!(hash.to_u128(), value);
        assert_eq!(hash.as_be_bytes(), &value.to_be_bytes());
        assert_eq!(Hash128::from_be_bytes(value.to_be_bytes()), hash);
        assert_eq!(Hash128::from_be_slice(&value.to_be_bytes()[..]), Some(hash));
        assert_eq!(Hash128::from_be_slice(&value.to_be_bytes()[..15]), None);

        assert_eq!(hash.to_string(), value.to_string());
        assert_eq!(Hash128::from_str(&hash.to_string()).unwrap(), hash);
    }

    #[test]
    fn hash128_sorts_like_a_big_endian_integer() {
        let mut values = [3u128, 1 << 120, 0, u128::MAX, 7]
            .map(Hash128::from)
            .to_vec();
        values.sort_unstable();

        let sorted = values.iter().map(|v| v.to_u128()).collect::<Vec<_>>();
        assert_eq!(sorted, [0, 3, 7, 1 << 120, u128::MAX]);

        for pair in values.windows(2) {
            assert!(pair[0].as_be_bytes() < pair[1].as_be_bytes());
        }
    }

    #[test]
    fn hash128_layout() {
        assert_eq!(std::mem::size_of::<Hash128>(), Hash128::LEN);
        assert_eq!(std::mem::align_of::<Hash128>(), 1);
    }
}
