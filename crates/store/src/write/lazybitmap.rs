/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::{RoaringBitmap, RoaringTreemap};
use utils::codec::leb128::{Leb128Iterator, Leb128Writer};

const IS_ROARING: u8 = 1;

pub(crate) struct LazyBitmap(pub RoaringBitmap);
pub(crate) struct LazyTreemap(pub RoaringTreemap);

impl LazyBitmap {
    pub fn serialize_optimized(&mut self, block_base: u32) -> Vec<u8> {
        self.0.optimize();
        let roaring_size = self.0.serialized_size();

        if roaring_size <= self.0.len() as usize {
            return self.serialize_roaring(roaring_size);
        }

        let delta = self.serialize_delta(block_base);
        if roaring_size + 1 < delta.len() {
            self.serialize_roaring(roaring_size)
        } else {
            delta
        }
    }

    fn serialize_roaring(&self, roaring_size: usize) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(roaring_size + 1);
        serialized.push(IS_ROARING);
        let _ = self.0.serialize_into(&mut serialized);
        serialized
    }

    fn serialize_delta(&self, mut delta: u32) -> Vec<u8> {
        let mut serialized = Vec::with_capacity((self.0.len() as usize * 2) + 1);
        serialized.push(0);
        for id in self.0.iter() {
            let _ = serialized.write_leb128(id - delta);
            delta = id;
        }
        serialized
    }

    pub fn deserialize_delta(bytes: &[u8], mut delta: u32) -> trc::Result<Self> {
        let Some((is_roaring, bytes)) = bytes
            .split_at_checked(1)
            .map(|(byte, bytes)| (byte == [IS_ROARING], bytes))
        else {
            return Err(trc::Error::corrupted_key(bytes, None, trc::location!()));
        };

        if is_roaring {
            RoaringBitmap::deserialize_from(bytes)
                .ok()
                .map(Self)
                .ok_or_else(|| trc::Error::corrupted_key(bytes, None, trc::location!()))
        } else {
            let mut bitmap = RoaringBitmap::new();
            let mut iter = bytes.iter();

            while let Some(delta_id) = iter.next_leb128::<u32>() {
                delta = delta
                    .checked_add(delta_id)
                    .filter(|delta| bitmap.try_push(*delta).is_ok())
                    .ok_or_else(|| trc::Error::corrupted_key(bytes, None, trc::location!()))?;
            }

            if iter.next().is_none() {
                Ok(Self(bitmap))
            } else {
                Err(trc::Error::corrupted_key(bytes, None, trc::location!()))
            }
        }
    }
}

impl LazyTreemap {
    pub fn serialize_delta(&self, mut delta: u64) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(self.0.len() as usize * 8);
        for id in self.0.iter() {
            let _ = serialized.write_leb128(id - delta);
            delta = id;
        }
        serialized
    }

    pub fn deserialize_delta(bytes: &[u8], mut delta: u64) -> trc::Result<Self> {
        let mut treemap = RoaringTreemap::new();
        let mut iter = bytes.iter();

        while let Some(delta_id) = iter.next_leb128::<u64>() {
            delta = delta
                .checked_add(delta_id)
                .filter(|delta| treemap.try_push(*delta).is_ok())
                .ok_or_else(|| trc::Error::corrupted_key(bytes, None, trc::location!()))?;
        }

        if iter.next().is_none() {
            Ok(Self(treemap))
        } else {
            Err(trc::Error::corrupted_key(bytes, None, trc::location!()))
        }
    }
}

impl AsRef<RoaringBitmap> for LazyBitmap {
    fn as_ref(&self) -> &RoaringBitmap {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT_BLOCK_SHIFT: u32 = 16;

    fn roundtrip(block_id: u16, ids: Vec<u32>) -> usize {
        let base = (block_id as u32) << ACCOUNT_BLOCK_SHIFT;
        for id in &ids {
            assert!(
                *id >= base && *id - base <= u16::MAX as u32,
                "id {id} outside block {block_id}"
            );
        }

        let mut bitmap = LazyBitmap(RoaringBitmap::from_iter(ids.iter().copied()));
        let serialized = bitmap.serialize_optimized(base);
        let deserialized = LazyBitmap::deserialize_delta(&serialized, base).unwrap();
        assert_eq!(bitmap.0, deserialized.0, "roundtrip failed for {ids:?}");
        serialized.len()
    }

    #[test]
    fn test_lazy_bitmap_roundtrip() {
        for block_id in [0u16, 1, 200, u16::MAX] {
            let base = (block_id as u32) << ACCOUNT_BLOCK_SHIFT;
            roundtrip(block_id, vec![]);
            roundtrip(block_id, vec![base]);
            roundtrip(block_id, vec![base, base + 1, base + u16::MAX as u32]);
            roundtrip(block_id, (base..base + 10000).collect());
            roundtrip(block_id, (base..=base + u16::MAX as u32).collect());
            roundtrip(block_id, (0..30000).map(|id| base + (id * 2)).collect());
        }
    }

    #[test]
    fn test_lazy_bitmap_is_block_relative() {
        let sparse = |block_id: u16| {
            let base = (block_id as u32) << ACCOUNT_BLOCK_SHIFT;
            roundtrip(block_id, vec![base + 3, base + 90, base + 40000])
        };

        assert_eq!(sparse(0), sparse(200));
        assert_eq!(sparse(0), sparse(u16::MAX));
    }

    #[test]
    fn test_lazy_bitmap_rejects_non_ascending() {
        let mut serialized = vec![0u8];
        let _ = serialized.write_leb128(10u32);
        let _ = serialized.write_leb128(0u32);
        assert!(LazyBitmap::deserialize_delta(&serialized, 0).is_err());

        let mut serialized = vec![0u8];
        let _ = serialized.write_leb128(u32::MAX);
        let _ = serialized.write_leb128(u32::MAX);
        assert!(LazyBitmap::deserialize_delta(&serialized, 0).is_err());
    }

    #[test]
    fn test_lazy_treemap_roundtrip() {
        let base = 5u64 << 48;
        for ids in [
            vec![],
            vec![base],
            vec![base + 1, base + 100, base + (1 << 30)],
        ] {
            let treemap = LazyTreemap(RoaringTreemap::from_iter(ids.iter().copied()));
            let serialized = treemap.serialize_delta(base);
            let deserialized = LazyTreemap::deserialize_delta(&serialized, base).unwrap();
            assert_eq!(treemap.0, deserialized.0, "roundtrip failed for {ids:?}");
        }
    }

    #[test]
    fn test_lazy_treemap_rejects_non_ascending() {
        let mut serialized = Vec::new();
        let _ = serialized.write_leb128(10u64);
        let _ = serialized.write_leb128(0u64);
        assert!(LazyTreemap::deserialize_delta(&serialized, 0).is_err());
    }
}
