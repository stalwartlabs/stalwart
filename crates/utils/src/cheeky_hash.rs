/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use nohash_hasher::IsEnabled;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

// A hash that can cheekily store small inputs directly without hashing them.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive,
)]
#[repr(transparent)]
pub struct CheekyHash([u8; HASH_SIZE + 1]);

const HASH_SIZE: usize = std::mem::size_of::<u128>();

pub type CheekyHashSet = HashSet<CheekyHash, nohash_hasher::BuildNoHashHasher<CheekyHash>>;
pub type CheekyHashMap<V> = HashMap<CheekyHash, V, nohash_hasher::BuildNoHashHasher<CheekyHash>>;
pub type CheekyBTreeMap<V> = BTreeMap<CheekyHash, V>;

impl CheekyHash {
    pub const HASH_SIZE: usize = HASH_SIZE;

    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let mut hash = [0u8; HASH_SIZE + 1];

        hash[HASH_SIZE] = bytes.len().min(u8::MAX as usize) as u8;

        if bytes.len() <= HASH_SIZE {
            hash[..bytes.len()].copy_from_slice(bytes);
        } else {
            let h1 = xxhash_rust::xxh3::xxh3_128(bytes).to_be_bytes();
            hash[..HASH_SIZE].copy_from_slice(&h1);
        }

        CheekyHash(hash)
    }

    #[inline(always)]
    pub fn as_key(&self) -> &[u8] {
        &self.0[..(self.0[HASH_SIZE] as usize).min(HASH_SIZE)]
    }

    #[inline(always)]
    pub fn key_len(&self) -> usize {
        (self.0[HASH_SIZE] as usize).min(HASH_SIZE)
    }

    #[inline(always)]
    pub fn as_payload(&self) -> &[u8] {
        &self.0[..HASH_SIZE]
    }

    #[inline(always)]
    fn as_u128(&self) -> u128 {
        u128::from_be_bytes(self.as_payload().try_into().unwrap())
    }
}

impl std::fmt::Display for CheekyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032x}", self.as_u128())
    }
}

impl Hash for CheekyHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let len = self.0[HASH_SIZE] as usize;
        if len <= HASH_SIZE {
            state.write_u64(xxhash_rust::xxh3::xxh3_64(&self.0[..len]));
        } else {
            state.write_u64(u64::from_be_bytes(
                self.0[..std::mem::size_of::<u64>()].try_into().unwrap(),
            ));
        }
    }
}

impl IsEnabled for CheekyHash {}

impl Debug for CheekyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0[HASH_SIZE] as usize;
        let payload = self.as_payload();
        let payload_str = if len <= HASH_SIZE {
            std::str::from_utf8(&payload[..len]).unwrap_or("<non-utf8>")
        } else {
            "<hashed data>"
        };

        f.debug_struct("CheekyHash")
            .field("length", &len)
            .field("bytes", &payload_str)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_cheeky_hash_all() {
        // Test 1: Empty input is stored directly with an empty key
        let hash_empty = CheekyHash::new([]);
        assert!(
            hash_empty.as_key().is_empty(),
            "Empty input should have an empty key"
        );
        assert_eq!(
            hash_empty.as_payload().len(),
            HASH_SIZE,
            "Payload is always HASH_SIZE bytes"
        );

        // Test 2: Single byte input is stored directly
        let hash_single = CheekyHash::new([42]);
        assert_eq!(
            hash_single.as_key(),
            &[42u8][..],
            "Single byte value should be preserved verbatim"
        );

        // Test 3: Small input (< HASH_SIZE) is stored directly
        let small_data = b"hello";
        let hash_small = CheekyHash::new(small_data);
        assert_eq!(
            hash_small.as_key(),
            &small_data[..],
            "Small data should be stored directly"
        );

        // Test 4: Input exactly at the HASH_SIZE boundary is still stored directly
        let boundary_data = vec![1u8; HASH_SIZE];
        let hash_boundary = CheekyHash::new(&boundary_data);
        assert_eq!(
            hash_boundary.as_key(),
            &boundary_data[..],
            "Data of exactly HASH_SIZE bytes should be stored directly"
        );

        // Test 5: Large input (> HASH_SIZE) is hashed
        let large_data = vec![7u8; HASH_SIZE + 1];
        let hash_large = CheekyHash::new(&large_data);
        assert_eq!(
            hash_large.as_key().len(),
            HASH_SIZE,
            "Hashed key is the 16-byte payload with no length byte"
        );
        assert_eq!(
            hash_large.as_key(),
            hash_large.as_payload(),
            "Hashed key is exactly the payload"
        );
        assert_ne!(
            hash_large.as_payload(),
            &large_data[..HASH_SIZE],
            "Large data should be hashed, not stored directly"
        );

        // Test 6: as_key vs as_payload for a short input
        let hash = CheekyHash::new(b"test");
        assert_eq!(hash.as_key(), &b"test"[..], "Short key is the raw input");
        assert_eq!(
            hash.as_payload().len(),
            HASH_SIZE,
            "Payload is always HASH_SIZE bytes"
        );

        // Test 7: Copy, Clone, PartialEq traits
        let hash1 = CheekyHash::new(b"identical");
        let hash2 = hash1; // Copy
        assert_eq!(hash1, hash2, "Copied hashes should be equal");

        // Test 8: Different inputs produce different hashes
        let hash_a = CheekyHash::new(b"abc");
        let hash_b = CheekyHash::new(b"def");
        assert_ne!(
            hash_a, hash_b,
            "Different inputs should produce different hashes"
        );

        // Test 9: Same input produces same hash (deterministic)
        let hash_x1 = CheekyHash::new(b"deterministic");
        let hash_x2 = CheekyHash::new(b"deterministic");
        assert_eq!(
            hash_x1, hash_x2,
            "Same input should produce identical hashes"
        );

        // Test 10: Large inputs with different content produce different hashes
        let large1 = vec![1u8; 100];
        let large2 = vec![2u8; 100];
        let hash_large1 = CheekyHash::new(&large1);
        let hash_large2 = CheekyHash::new(&large2);
        assert_ne!(
            hash_large1, hash_large2,
            "Different large inputs should produce different hashes"
        );

        // Test 11: Hash trait (can be used in HashMap/HashSet)
        let mut map = HashMap::new();
        let key = CheekyHash::new(b"key");
        map.insert(key, "value");
        assert_eq!(
            map.get(&key),
            Some(&"value"),
            "CheekyHash should work as HashMap key"
        );

        // Test 12: Debug trait renders the short payload without padding
        let hash = CheekyHash::new(b"debug");
        let debug_str = format!("{:?}", hash);
        assert!(
            debug_str.contains("CheekyHash"),
            "Debug output should contain type name"
        );
        assert!(
            debug_str.contains("debug"),
            "Debug output should contain the short payload"
        );
        assert!(
            !debug_str.contains('\0'),
            "Debug output should not leak padding null bytes"
        );

        // Test 13: CheekyHashSet and CheekyHashMap
        let mut cheeky_set: CheekyHashSet = CheekyHashSet::default();
        cheeky_set.insert(CheekyHash::new(b"set_item"));
        assert!(cheeky_set.contains(&CheekyHash::new(b"set_item")));
        let mut cheeky_map: CheekyHashMap<&str> = CheekyHashMap::default();
        cheeky_map.insert(CheekyHash::new(b"map_key"), "map_value");
        assert_eq!(
            cheeky_map.get(&CheekyHash::new(b"map_key")),
            Some(&"map_value")
        );

        // Test 14: Short and long keys never collide in key space
        let short = CheekyHash::new(vec![9u8; HASH_SIZE]);
        let long = CheekyHash::new(vec![9u8; HASH_SIZE + 1]);
        assert_ne!(short.as_key(), long.as_key());
        assert_ne!(short, long);
    }
}
