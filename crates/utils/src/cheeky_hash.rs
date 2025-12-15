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
pub struct CheekyHash([u8; HASH_SIZE]);

const HASH_SIZE: usize = std::mem::size_of::<u64>() * 2;
const HASH_PAYLOAD: usize = HASH_SIZE - 1;

pub type CheekyHashSet = HashSet<CheekyHash, nohash_hasher::BuildNoHashHasher<CheekyHash>>;
pub type CheekyHashMap<V> = HashMap<CheekyHash, V, nohash_hasher::BuildNoHashHasher<CheekyHash>>;
pub type CheekyBTreeMap<V> = BTreeMap<CheekyHash, V>;

impl CheekyHash {
    pub const HASH_SIZE: usize = HASH_SIZE;
    pub const NULL: CheekyHash = CheekyHash([0u8; HASH_SIZE]);
    pub const FULL: CheekyHash = CheekyHash([u8::MAX; HASH_SIZE]);

    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        let bytes = bytes.as_ref();

        if bytes.len() <= HASH_PAYLOAD {
            hash[0] = bytes.len() as u8;
            hash[1..1 + bytes.len()].copy_from_slice(bytes);
        } else {
            let h1 = xxhash_rust::xxh3::xxh3_64(bytes).to_be_bytes();
            let h2 = farmhash::fingerprint64(bytes).to_be_bytes();
            hash[0] = bytes.len().min(u8::MAX as usize) as u8;
            hash[1..1 + std::mem::size_of::<u64>()].copy_from_slice(&h1);
            hash[1 + std::mem::size_of::<u64>()..]
                .copy_from_slice(&h2[..std::mem::size_of::<u64>() - 1]);
        }

        CheekyHash(hash)
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let len = *bytes.first()?;
        let mut hash = [0u8; HASH_SIZE];
        let hash_len = 1 + (len as usize).min(HASH_PAYLOAD);

        hash[0] = len;
        hash[1..hash_len].copy_from_slice(bytes.get(1..hash_len)?);
        Some(CheekyHash(hash))
    }

    #[allow(clippy::len_without_is_empty)]
    #[inline(always)]
    pub fn len(&self) -> usize {
        (self.0[0] as usize).min(HASH_PAYLOAD) + 1
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..self.len()]
    }

    #[inline(always)]
    pub fn as_raw_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.0[0] as usize;
        if len <= HASH_PAYLOAD {
            &self.0[1..1 + len]
        } else {
            &self.0[1..]
        }
    }

    pub fn payload_len(&self) -> u8 {
        self.0[0]
    }
}

impl AsRef<[u8]> for CheekyHash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Hash for CheekyHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let len = self.0[0] as usize;
        if len <= HASH_PAYLOAD {
            state.write_u64(xxhash_rust::xxh3::xxh3_64(&self.0[1..1 + len]));
        } else {
            state.write_u64(u64::from_be_bytes(
                self.0[1..1 + std::mem::size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            ));
        }
    }
}

impl IsEnabled for CheekyHash {}

impl ArchivedCheekyHash {
    #[inline(always)]
    pub fn as_raw_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.0[0] as usize;
        &self.0[..1 + len.min(HASH_PAYLOAD)]
    }

    #[inline(always)]
    pub fn to_native(&self) -> CheekyHash {
        CheekyHash(self.0)
    }
}

impl Debug for CheekyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.payload_len();
        let payload = self.payload();
        let payload_str = if len <= HASH_PAYLOAD as u8 {
            std::str::from_utf8(payload).unwrap_or("<non-utf8>")
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

    #[test]
    fn test_cheeky_hash_all() {
        // Test 1: Empty input
        let hash_empty = CheekyHash::new([]);
        assert_eq!(
            hash_empty.as_bytes()[0],
            0,
            "Empty input should have length 0"
        );
        assert_eq!(
            hash_empty.as_bytes().len(),
            1,
            "Empty input should only have length byte"
        );

        // Test 2: Single byte input
        let hash_single = CheekyHash::new([42]);
        assert_eq!(
            hash_single.as_bytes()[0],
            1,
            "Single byte should have length 1"
        );
        assert_eq!(
            hash_single.as_bytes()[1],
            42,
            "Single byte value should be preserved"
        );
        assert_eq!(hash_single.as_bytes().len(), 2);

        // Test 3: Small input (less than HASH_LEN)
        let small_data = b"hello";
        let hash_small = CheekyHash::new(small_data);
        assert_eq!(hash_small.as_bytes()[0], 5, "Length should be 5");
        assert_eq!(
            &hash_small.as_bytes()[1..6],
            small_data,
            "Small data should be stored directly"
        );
        assert_eq!(hash_small.as_bytes().len(), 6);

        // Test 4: Input exactly at HASH_PAYLOAD boundary
        let boundary_data = vec![1u8; HASH_PAYLOAD - 1];
        let hash_boundary = CheekyHash::new(&boundary_data);
        assert_eq!(
            hash_boundary.as_bytes()[0],
            (HASH_PAYLOAD - 1) as u8,
            "Length should be HASH_LEN"
        );
        assert_eq!(
            &hash_boundary.as_bytes()[1..],
            &boundary_data[..],
            "Boundary data should be stored directly"
        );

        // Test 5: Large input (greater than HASH_LEN) - uses hashing
        let large_data = vec![7u8; HASH_SIZE];
        let hash_large = CheekyHash::new(&large_data);
        assert_eq!(
            hash_large.as_bytes()[0],
            HASH_SIZE as u8,
            "Large data should have length byte set to HASH_LEN"
        );
        assert_eq!(
            hash_large.as_bytes().len(),
            HASH_SIZE,
            "Large data hash should be full length"
        );
        // Verify it's actually hashed (not raw data)
        assert_ne!(
            &hash_large.as_bytes()[1..],
            &large_data[..HASH_PAYLOAD],
            "Large data should be hashed, not stored directly"
        );

        // Test 6: AsRef<[u8]> trait
        let hash = CheekyHash::new(b"test");
        let bytes_ref: &[u8] = hash.as_ref();
        assert_eq!(bytes_ref, hash.as_bytes(), "AsRef should match as_bytes");

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
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let key = CheekyHash::new(b"key");
        map.insert(key, "value");
        assert_eq!(
            map.get(&key),
            Some(&"value"),
            "CheekyHash should work as HashMap key"
        );

        // Test 12: Debug trait
        let hash = CheekyHash::new(b"debug");
        let debug_str = format!("{:?}", hash);
        assert!(
            debug_str.contains("CheekyHash"),
            "Debug output should contain type name"
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

        println!("All CheekyHash tests passed!");
    }
}
