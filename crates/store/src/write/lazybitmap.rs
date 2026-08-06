/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Deserialize;
use roaring::{RoaringBitmap, RoaringTreemap};
use utils::codec::leb128::{Leb128Iterator, Leb128Writer};

const IS_ROARING: u8 = 1;

pub(crate) struct LazyBitmap(pub RoaringBitmap);
pub(crate) struct LazyTreemap(pub RoaringTreemap);

impl LazyBitmap {
    pub fn serialize_optimized(&mut self) -> Vec<u8> {
        self.0.optimize();
        let roaring_size = self.0.serialized_size();

        if roaring_size <= self.0.len() as usize {
            self.serialize_roaring(roaring_size)
        } else {
            let delta = self.serialize_delta();
            if roaring_size + 1 < delta.len() {
                self.serialize_roaring(roaring_size)
            } else {
                delta
            }
        }
    }

    fn serialize_roaring(&self, roaring_size: usize) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(roaring_size + 1);
        serialized.push(IS_ROARING);
        let _ = self.0.serialize_into(&mut serialized);
        serialized
    }

    fn serialize_delta(&self) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(self.0.len() as usize * 4);
        serialized.push(0);
        let mut last_id = 0;
        for id in self.0.iter() {
            let _ = serialized.write_leb128(id - last_id);
            last_id = id;
        }
        serialized
    }
}

impl Deserialize for LazyBitmap {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
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
            let mut last_id = 0;
            let mut iter = bytes.iter();

            while let Some(delta) = iter.next_leb128::<u32>() {
                last_id += delta;
                bitmap.insert(last_id);
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
            delta += delta_id;
            treemap.insert(delta);
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

    #[test]
    fn test_lazy_bitmap_roundtrip() {
        for ids in [
            vec![],
            vec![0u32],
            vec![1, 100, 65536, u32::MAX],
            (0..10000).collect::<Vec<_>>(),
        ] {
            let mut bitmap = LazyBitmap(RoaringBitmap::from_iter(ids.iter().copied()));
            let serialized = bitmap.serialize_optimized();
            let deserialized = LazyBitmap::deserialize(&serialized).unwrap();
            assert_eq!(bitmap.0, deserialized.0, "roundtrip failed for {ids:?}");
        }
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
}
