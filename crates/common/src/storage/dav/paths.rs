/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ArenaRef, DAV_CHUNK, DavPath, PathChunk, PathIndex};
use ahash::AHashSet;
use std::sync::Arc;

impl PathChunk {
    #[inline(always)]
    pub fn path_at(&self, idx: usize) -> &str {
        std::str::from_utf8(&self.bytes[self.paths[idx].path.range()]).unwrap_or_default()
    }

    #[inline(always)]
    pub fn first_path(&self) -> &str {
        self.path_at(0)
    }

    #[inline(always)]
    pub fn last_path(&self) -> &str {
        self.path_at(self.paths.len() - 1)
    }

    pub fn heap_size(&self) -> u64 {
        (self.paths.len() * std::mem::size_of::<DavPath>()
            + self.bytes.len()
            + std::mem::size_of::<PathChunk>()) as u64
    }
}

impl PathIndex {
    pub fn pack(mut entries: Vec<(String, DavPath)>) -> Self {
        entries.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        entries.dedup_by(|a, b| a.0 == b.0);

        let total = entries.len();
        let mut chunks = Vec::with_capacity(total.div_ceil(DAV_CHUNK).max(1));
        for group in entries.chunks(DAV_CHUNK) {
            let mut bytes: Vec<u8> = Vec::with_capacity(group.len() * 48);
            let mut paths = Vec::with_capacity(group.len());
            for (name, path) in group {
                let off = bytes.len() as u32;
                bytes.extend_from_slice(name.as_bytes());
                paths.push(DavPath {
                    path: ArenaRef {
                        off,
                        len: name.len() as u32,
                    },
                    ..*path
                });
            }
            chunks.push(Arc::new(PathChunk {
                paths: paths.into_boxed_slice(),
                bytes: bytes.into_boxed_slice(),
            }));
        }

        Self { chunks, total }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.total
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PathChunk, &DavPath)> + '_ {
        self.chunks
            .iter()
            .flat_map(|chunk| chunk.paths.iter().map(move |path| (chunk.as_ref(), path)))
    }

    fn chunk_for(&self, key: &str) -> usize {
        let mut lo = 0usize;
        let mut hi = self.chunks.len();
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if self.chunks[mid].first_path() <= key {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    pub fn get(&self, name: &str) -> Option<(&PathChunk, &DavPath)> {
        if self.chunks.is_empty() {
            return None;
        }
        let chunk = &self.chunks[self.chunk_for(name)];
        let key = name.as_bytes();
        chunk
            .paths
            .binary_search_by(|probe| {
                std::str::from_utf8(&chunk.bytes[probe.path.range()])
                    .unwrap_or_default()
                    .as_bytes()
                    .cmp(key)
            })
            .ok()
            .map(|idx| (chunk.as_ref(), &chunk.paths[idx]))
    }

    pub fn range(&self, from: String) -> impl Iterator<Item = (&PathChunk, &DavPath)> + '_ {
        let start = if self.chunks.is_empty() {
            0
        } else {
            self.chunk_for(&from)
        };
        self.chunks[start.min(self.chunks.len())..]
            .iter()
            .flat_map(|chunk| chunk.paths.iter().map(move |path| (chunk.as_ref(), path)))
    }

    pub fn heap_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.heap_size()).sum()
    }

    pub fn patch(&self, removes: &AHashSet<String>, adds: Vec<(String, DavPath)>) -> Self {
        if removes.is_empty() && adds.is_empty() {
            return self.clone();
        }

        let mut touched: AHashSet<usize> = AHashSet::with_capacity(8);
        let mut per_chunk_adds: Vec<(usize, Vec<(String, DavPath)>)> = Vec::with_capacity(8);

        for key in removes {
            for (idx, chunk) in self.chunks.iter().enumerate() {
                if chunk.paths.is_empty() {
                    continue;
                }
                if chunk.first_path() <= key.as_str() && key.as_str() <= chunk.last_path() {
                    touched.insert(idx);
                    break;
                }
            }
        }

        for (key, path) in adds {
            let mut target = 0usize;
            for (idx, chunk) in self.chunks.iter().enumerate() {
                if chunk.paths.is_empty() {
                    continue;
                }
                target = idx;
                if key.as_str() <= chunk.last_path() {
                    break;
                }
            }
            touched.insert(target);
            match per_chunk_adds.iter_mut().find(|(idx, _)| *idx == target) {
                Some((_, entries)) => entries.push((key, path)),
                None => per_chunk_adds.push((target, vec![(key, path)])),
            }
        }

        let mut chunks = Vec::with_capacity(self.chunks.len() + 1);
        let mut total = 0usize;
        for (idx, chunk) in self.chunks.iter().enumerate() {
            if !touched.contains(&idx) {
                total += chunk.paths.len();
                chunks.push(Arc::clone(chunk));
                continue;
            }

            let mut entries: Vec<(String, DavPath)> = Vec::with_capacity(chunk.paths.len() + 4);
            for slot in 0..chunk.paths.len() {
                let name = chunk.path_at(slot);
                if !removes.contains(name) {
                    entries.push((name.to_string(), chunk.paths[slot]));
                }
            }
            if let Some(pos) = per_chunk_adds.iter().position(|(target, _)| *target == idx) {
                entries.extend(per_chunk_adds.swap_remove(pos).1);
            }
            let packed = PathIndex::pack(entries);
            total += packed.total;
            chunks.extend(packed.chunks);
        }

        Self { chunks, total }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::dav::CONTAINER_FLAG;

    fn entry(name: &str, document_id: u32, is_container: bool) -> (String, DavPath) {
        (
            name.to_string(),
            DavPath {
                path: ArenaRef::default(),
                parent_id: crate::NO_ID,
                hierarchy_seq: if is_container { CONTAINER_FLAG } else { 0 },
                document_id,
            },
        )
    }

    #[test]
    fn path_index_spans_many_chunks() {
        let mut entries = Vec::new();
        for i in 0..(DAV_CHUNK * 3 + 7) {
            entries.push(entry(&format!("p{i:08}"), i as u32, i % 2 == 0));
        }
        let index = PathIndex::pack(entries);
        assert!(index.chunks.len() >= 4, "fixture must span several chunks");

        for i in [
            0usize,
            1,
            DAV_CHUNK - 1,
            DAV_CHUNK,
            DAV_CHUNK * 2 + 3,
            DAV_CHUNK * 3 + 6,
        ] {
            let name = format!("p{i:08}");
            let found = index.get(&name).unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(found.1.document_id, i as u32, "{name}");
        }
        assert!(index.get("p99999999").is_none());
        assert!(index.get("a").is_none());
    }

    #[test]
    fn path_index_roundtrip() {
        let index = PathIndex::pack(vec![
            entry("default", 1, true),
            entry("work", 2, true),
            entry("default/a.ics", 10, false),
            entry("default/b.ics", 11, false),
        ]);

        assert_eq!(index.len(), 4);
        for (name, expected) in [
            ("default", 1u32),
            ("work", 2),
            ("default/a.ics", 10),
            ("default/b.ics", 11),
        ] {
            let found = index.get(name).unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(found.1.document_id, expected, "{name}");
        }
        assert!(index.get("missing").is_none());
        assert!(index.get("").is_none());
    }

    #[test]
    fn path_index_range_includes_the_collection_itself() {
        let index = PathIndex::pack(vec![
            entry("a", 1, true),
            entry("default", 2, true),
            entry("default/x.ics", 3, false),
            entry("zz", 4, true),
        ]);
        let seen = index
            .range("default".to_string())
            .map(|(chunk, path)| {
                std::str::from_utf8(&chunk.bytes[path.path.range()])
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert!(
            seen.iter().any(|p| p == "default"),
            "the collection's own path must be reachable from its range, got {seen:?}"
        );
        assert!(
            seen.iter().any(|p| p == "default/x.ics"),
            "children must be reachable too, got {seen:?}"
        );
    }

    #[test]
    fn path_index_range_covers_prefix() {
        let index = PathIndex::pack(vec![
            entry("a", 1, true),
            entry("default", 2, true),
            entry("default/x.ics", 3, false),
            entry("zz", 4, true),
        ]);
        let found = index
            .range("default/".to_string())
            .filter(|(chunk, path)| {
                std::str::from_utf8(&chunk.bytes[path.path.range()])
                    .unwrap()
                    .starts_with("default/")
            })
            .count();
        assert_eq!(found, 1);
    }
}
