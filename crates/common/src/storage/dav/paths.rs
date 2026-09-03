/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ArenaRef, DAV_CHUNK, DavPath, PathChunk, PathIndex};
use ahash::AHashSet;
use std::{cmp::Ordering, sync::Arc};

struct ArenaRun {
    old_start: usize,
    old_end: usize,
    new_base: usize,
}

struct ChunkWriter<'a> {
    source: &'a PathChunk,
    paths: Vec<DavPath>,
    bytes: Vec<u8>,
    run: Option<ArenaRun>,
}

impl<'a> ChunkWriter<'a> {
    fn new(source: &'a PathChunk, adds: &[(String, DavPath)]) -> Self {
        Self {
            source,
            paths: Vec::with_capacity(source.paths.len() + adds.len()),
            bytes: Vec::with_capacity(
                source.bytes.len() + adds.iter().map(|(name, _)| name.len()).sum::<usize>(),
            ),
            run: None,
        }
    }

    fn keep(&mut self, path: &DavPath) {
        let range = path.path.range();
        let (old_start, new_base) = match &mut self.run {
            Some(run) if run.old_end == range.start => {
                run.old_end = range.end;
                (run.old_start, run.new_base)
            }
            _ => {
                self.flush();
                let new_base = self.bytes.len();
                self.run = Some(ArenaRun {
                    old_start: range.start,
                    old_end: range.end,
                    new_base,
                });
                (range.start, new_base)
            }
        };
        self.paths.push(DavPath {
            path: ArenaRef {
                off: (new_base + (range.start - old_start)) as u32,
                len: path.path.len,
            },
            ..*path
        });
    }

    fn insert(&mut self, name: &str, path: &DavPath) {
        self.flush();
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(name.as_bytes());
        self.paths.push(DavPath {
            path: ArenaRef {
                off,
                len: name.len() as u32,
            },
            ..*path
        });
    }

    fn flush(&mut self) {
        if let Some(run) = self.run.take() {
            self.bytes
                .extend_from_slice(&self.source.bytes[run.old_start..run.old_end]);
        }
    }

    fn finish(mut self) -> Vec<Arc<PathChunk>> {
        self.flush();
        PathChunk::from_contiguous(self.paths, self.bytes)
    }
}

impl PathChunk {
    fn from_contiguous(paths: Vec<DavPath>, bytes: Vec<u8>) -> Vec<Arc<PathChunk>> {
        if paths.is_empty() {
            Vec::new()
        } else if paths.len() <= 2 * DAV_CHUNK {
            vec![Arc::new(PathChunk {
                paths: paths.into_boxed_slice(),
                bytes: bytes.into_boxed_slice(),
            })]
        } else {
            paths
                .chunks(DAV_CHUNK)
                .map(|group| {
                    let start = group[0].path.off as usize;
                    let end = group[group.len() - 1].path.range().end;
                    let paths = group
                        .iter()
                        .map(|path| DavPath {
                            path: ArenaRef {
                                off: path.path.off - start as u32,
                                len: path.path.len,
                            },
                            ..*path
                        })
                        .collect::<Vec<_>>();
                    Arc::new(PathChunk {
                        paths: paths.into_boxed_slice(),
                        bytes: bytes[start..end].to_vec().into_boxed_slice(),
                    })
                })
                .collect()
        }
    }

    fn splice(&self, removed_slots: &[usize], adds: &[(String, DavPath)]) -> Vec<Arc<PathChunk>> {
        let mut writer = ChunkWriter::new(self, adds);
        let mut next_removed = 0usize;
        let mut next_add = 0usize;

        'paths: for (slot, path) in self.paths.iter().enumerate() {
            if removed_slots.get(next_removed) == Some(&slot) {
                next_removed += 1;
                continue;
            }
            let name = &self.bytes[path.path.range()];
            while let Some((add_name, add_path)) = adds.get(next_add) {
                match add_name.as_bytes().cmp(name) {
                    Ordering::Less => {
                        writer.insert(add_name, add_path);
                        next_add += 1;
                    }
                    Ordering::Equal => {
                        next_add += 1;
                        if add_path.document_id < path.document_id {
                            writer.insert(add_name, add_path);
                            continue 'paths;
                        }
                        break;
                    }
                    Ordering::Greater => break,
                }
            }
            writer.keep(path);
        }

        for (add_name, add_path) in &adds[next_add..] {
            writer.insert(add_name, add_path);
        }

        writer.finish()
    }

    #[inline(always)]
    pub fn path_at(&self, idx: usize) -> &str {
        self.path_str(&self.paths[idx])
    }

    #[inline(always)]
    pub fn path_str(&self, path: &DavPath) -> &str {
        std::str::from_utf8(&self.bytes[path.path.range()]).unwrap_or_default()
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
    fn entry_order(a: &(String, DavPath), b: &(String, DavPath)) -> Ordering {
        a.0.as_bytes()
            .cmp(b.0.as_bytes())
            .then_with(|| a.1.document_id.cmp(&b.1.document_id))
    }

    fn sort_entries(entries: &mut Vec<(String, DavPath)>) {
        entries.sort_unstable_by(Self::entry_order);
        entries.dedup_by(|a, b| a.0 == b.0);
    }

    pub fn pack(mut entries: Vec<(String, DavPath)>) -> Self {
        Self::sort_entries(&mut entries);

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

    fn locate(&self, name: &str) -> Option<(usize, usize)> {
        if self.chunks.is_empty() {
            return None;
        }
        let idx = self.chunk_for(name);
        let chunk = &self.chunks[idx];
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
            .map(|slot| (idx, slot))
    }

    pub fn get(&self, name: &str) -> Option<(&PathChunk, &DavPath)> {
        self.locate(name).map(|(idx, slot)| {
            let chunk = &self.chunks[idx];
            (chunk.as_ref(), &chunk.paths[slot])
        })
    }

    fn lower_bound(&self, key: &str) -> (usize, usize) {
        if self.chunks.is_empty() {
            return (0, 0);
        }
        let idx = self.chunk_for(key);
        let chunk = &self.chunks[idx];
        let slot = chunk
            .paths
            .partition_point(|probe| chunk.path_str(probe) < key);
        if slot < chunk.paths.len() {
            (idx, slot)
        } else {
            (idx + 1, 0)
        }
    }

    pub fn range(&self, prefix: String) -> impl Iterator<Item = (&PathChunk, &DavPath)> + '_ {
        let (start_chunk, start_slot) = self.lower_bound(&prefix);
        self.chunks
            .iter()
            .skip(start_chunk)
            .enumerate()
            .flat_map(move |(offset, chunk)| {
                chunk
                    .paths
                    .iter()
                    .skip(if offset == 0 { start_slot } else { 0 })
                    .map(move |path| (chunk.as_ref(), path))
            })
            .take_while(move |(chunk, path)| chunk.path_str(path).starts_with(&prefix))
    }

    pub fn heap_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.heap_size()).sum()
    }

    pub fn patch(&self, removes: &AHashSet<String>, mut adds: Vec<(String, DavPath)>) -> Self {
        if removes.is_empty() && adds.is_empty() {
            return self.clone();
        }

        if self.chunks.is_empty() {
            return PathIndex::pack(adds);
        }

        Self::sort_entries(&mut adds);

        let mut removed: Vec<(usize, usize)> =
            removes.iter().filter_map(|key| self.locate(key)).collect();
        removed.sort_unstable();

        let mut chunks = Vec::with_capacity(self.chunks.len() + 2);
        let mut total = 0usize;
        let mut add_start = 0usize;
        let mut removed_start = 0usize;

        for (idx, chunk) in self.chunks.iter().enumerate() {
            let add_end = match self.chunks.get(idx + 1) {
                Some(next) => {
                    let bound = next.first_path().as_bytes();
                    add_start
                        + adds[add_start..].partition_point(|(name, _)| name.as_bytes() < bound)
                }
                None => adds.len(),
            };
            let removed_end = removed_start
                + removed[removed_start..].partition_point(|(target, _)| *target <= idx);

            if add_start == add_end && removed_start == removed_end {
                total += chunk.paths.len();
                chunks.push(Arc::clone(chunk));
                continue;
            }

            let removed_slots = removed[removed_start..removed_end]
                .iter()
                .map(|(_, slot)| *slot)
                .collect::<Vec<_>>();
            for piece in chunk.splice(&removed_slots, &adds[add_start..add_end]) {
                total += piece.paths.len();
                chunks.push(piece);
            }

            add_start = add_end;
            removed_start = removed_end;
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

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    type Row = (String, u32, u32, u32);

    fn row_entry(name: &str, i: u32) -> (String, DavPath) {
        (
            name.to_string(),
            DavPath {
                path: ArenaRef::default(),
                parent_id: i % 7,
                hierarchy_seq: if i.is_multiple_of(2) {
                    CONTAINER_FLAG | i
                } else {
                    i
                },
                document_id: i,
            },
        )
    }

    fn base_entries(count: usize) -> Vec<(String, DavPath)> {
        (0..count)
            .map(|i| row_entry(&format!("p{:08}", i * 4), i as u32))
            .collect()
    }

    fn rows(index: &PathIndex) -> Vec<Row> {
        index
            .iter()
            .map(|(chunk, path)| {
                (
                    chunk.path_str(path).to_string(),
                    path.document_id,
                    path.parent_id,
                    path.hierarchy_seq,
                )
            })
            .collect()
    }

    fn entries_of(index: &PathIndex) -> Vec<(String, DavPath)> {
        index
            .iter()
            .map(|(chunk, path)| (chunk.path_str(path).to_string(), *path))
            .collect()
    }

    fn check_invariants(index: &PathIndex) {
        let mut total = 0;
        let mut previous: Option<String> = None;
        for chunk in &index.chunks {
            assert!(!chunk.paths.is_empty(), "empty chunk");
            assert!(
                chunk.paths.len() <= 2 * DAV_CHUNK,
                "oversized chunk: {}",
                chunk.paths.len()
            );
            for path in chunk.paths.iter() {
                assert!(
                    path.path.range().end <= chunk.bytes.len(),
                    "arena ref out of bounds"
                );
                let name = chunk.path_str(path).to_string();
                if let Some(previous) = &previous {
                    assert!(*previous < name, "unsorted: {previous:?} >= {name:?}");
                }
                previous = Some(name);
            }
            total += chunk.paths.len();
        }
        assert_eq!(index.len(), total);
    }

    fn assert_matches_pack(
        spliced: &PathIndex,
        entries: Vec<(String, DavPath)>,
        probes: &[String],
    ) {
        let expected = PathIndex::pack(entries);
        check_invariants(spliced);
        check_invariants(&expected);
        assert_eq!(rows(spliced), rows(&expected));
        assert_eq!(spliced.len(), expected.len());

        let mut keys = probes.to_vec();
        keys.extend(
            expected
                .iter()
                .map(|(chunk, path)| chunk.path_str(path).to_string()),
        );
        for key in &keys {
            let got = spliced
                .get(key)
                .map(|(_, path)| (path.document_id, path.parent_id, path.hierarchy_seq));
            let want = expected
                .get(key)
                .map(|(_, path)| (path.document_id, path.parent_id, path.hierarchy_seq));
            assert_eq!(got, want, "get({key:?})");
        }

        let mut prefixes = probes.to_vec();
        prefixes
            .extend(["", "a", "p", "p0000", "p0001", "p00016", "p00032", "z"].map(String::from));
        for prefix in prefixes {
            let got = spliced
                .range(prefix.clone())
                .map(|(chunk, path)| (chunk.path_str(path).to_string(), path.document_id))
                .collect::<Vec<_>>();
            let want = expected
                .range(prefix.clone())
                .map(|(chunk, path)| (chunk.path_str(path).to_string(), path.document_id))
                .collect::<Vec<_>>();
            assert_eq!(got, want, "range({prefix:?})");
        }
    }

    fn apply(
        index: &PathIndex,
        removes: &[String],
        adds: Vec<(String, DavPath)>,
    ) -> (PathIndex, Vec<(String, DavPath)>) {
        let remove_set = removes.iter().cloned().collect::<AHashSet<_>>();
        let mut model = entries_of(index)
            .into_iter()
            .filter(|(name, _)| !remove_set.contains(name))
            .collect::<Vec<_>>();
        model.extend(adds.iter().cloned());
        (index.patch(&remove_set, adds), model)
    }

    #[test]
    fn path_index_patch_edge_cases() {
        let base = PathIndex::pack(base_entries(DAV_CHUNK * 3 + 7));
        assert_eq!(base.chunks.len(), 4);

        let chunk1_first = base.chunks[1].first_path().to_string();
        let chunk2_first = base.chunks[2].first_path().to_string();
        let removes = vec![
            base.chunks[0].first_path().to_string(),
            base.chunks[1].last_path().to_string(),
            base.chunks[2].first_path().to_string(),
            base.chunks[3].last_path().to_string(),
            "p99999999".to_string(),
        ];
        let adds = vec![
            row_entry("a0", 100_000),
            row_entry("a1", 100_001),
            row_entry("z0", 100_002),
            row_entry(&chunk1_first, 100_003),
            row_entry(&chunk2_first, 1),
            row_entry("p00016383", 100_004),
            row_entry("p00000002", 100_005),
            row_entry("p00000002", 100_006),
            row_entry("p00000002", 99_999),
        ];
        let (step1, model) = apply(&base, &removes, adds);
        assert_matches_pack(&step1, model, &removes);
        assert_eq!(step1.get("a0").unwrap().1.document_id, 100_000);
        assert!(
            step1
                .get(&chunk2_first)
                .is_some_and(|(_, p)| p.document_id == 1)
        );
        assert_eq!(step1.get("p00000002").unwrap().1.document_id, 99_999);

        let last = step1.chunks.len() - 1;
        let removes = step1.chunks[last]
            .paths
            .iter()
            .map(|path| step1.chunks[last].path_str(path).to_string())
            .collect::<Vec<_>>();
        let (step2, model) = apply(&step1, &removes, Vec::new());
        assert_eq!(step2.chunks.len(), step1.chunks.len() - 1);
        for idx in 0..step2.chunks.len() {
            assert!(Arc::ptr_eq(&step2.chunks[idx], &step1.chunks[idx]));
        }
        assert_matches_pack(&step2, model, &removes);

        let removes = step2.chunks[1]
            .paths
            .iter()
            .map(|path| step2.chunks[1].path_str(path).to_string())
            .collect::<Vec<_>>();
        let inside = format!("{}x", step2.chunks[1].first_path());
        let (step3, model) = apply(&step2, &removes, vec![row_entry(&inside, 200_000)]);
        assert_eq!(step3.chunks.len(), step2.chunks.len());
        assert_eq!(step3.chunks[1].paths.len(), 1);
        assert_matches_pack(&step3, model, &removes);

        let adds = (0..2 * DAV_CHUNK)
            .map(|i| row_entry(&format!("p{:08}", i * 2 + 1), 300_000 + i as u32))
            .collect::<Vec<_>>();
        let (step4, model) = apply(&step3, &[], adds);
        assert!(step4.chunks.len() > step3.chunks.len());
        assert_matches_pack(&step4, model, &[]);

        let empty = PathIndex::default();
        let (from_empty, model) = apply(&empty, &["x".to_string()], vec![row_entry("b", 1)]);
        assert_eq!(from_empty.chunks.len(), 1);
        assert_matches_pack(&from_empty, model, &[]);
        let (drained, model) = apply(&from_empty, &["b".to_string()], Vec::new());
        assert!(drained.chunks.is_empty());
        assert_matches_pack(&drained, model, &[]);

        let (untouched, _) = apply(&base, &["missing".to_string()], Vec::new());
        for idx in 0..base.chunks.len() {
            assert!(Arc::ptr_eq(&untouched.chunks[idx], &base.chunks[idx]));
        }
    }

    #[test]
    fn path_index_patch_matches_pack_randomised() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut index = PathIndex::pack(base_entries(DAV_CHUNK * 3 + 100));
        let mut next_id = 1_000_000u32;

        for round in 0..60 {
            let current = entries_of(&index);
            let mut removes = Vec::new();
            let mut adds = Vec::new();

            match round % 12 {
                5 => {
                    let idx = rng.below(index.chunks.len());
                    let chunk = &index.chunks[idx];
                    removes.extend(chunk.paths.iter().map(|p| chunk.path_str(p).to_string()));
                    if rng.below(2) == 0 {
                        adds.push(row_entry(&format!("{}q", chunk.first_path()), next_id));
                        next_id += 1;
                    }
                }
                9 => {
                    let idx = rng.below(index.chunks.len());
                    let first = index.chunks[idx].first_path().to_string();
                    for i in 0..DAV_CHUNK + 300 {
                        adds.push(row_entry(&format!("{first}-{i:06}"), next_id));
                        next_id += 1;
                    }
                }
                _ => {
                    for _ in 0..rng.below(9) {
                        removes.push(current[rng.below(current.len())].0.clone());
                    }
                    for _ in 0..rng.below(9) {
                        let name = match rng.below(10) {
                            0 => format!("a{}", rng.below(1000)),
                            1 => format!("z{}", rng.below(1000)),
                            2 => current[rng.below(current.len())].0.clone(),
                            3 => index.chunks[rng.below(index.chunks.len())]
                                .first_path()
                                .to_string(),
                            4 => index.chunks[rng.below(index.chunks.len())]
                                .last_path()
                                .to_string(),
                            _ => format!("p{:08}", rng.below((DAV_CHUNK * 3 + 100) * 4 + 8)),
                        };
                        let id = if rng.below(4) == 0 {
                            rng.below(5000) as u32
                        } else {
                            next_id += 1;
                            next_id
                        };
                        adds.push(row_entry(&name, id));
                    }
                }
            }

            let (spliced, model) = apply(&index, &removes, adds);
            let mut probes = removes.clone();
            probes.push(format!("p{:08}", rng.below(60_000)));
            assert_matches_pack(&spliced, model, &probes);
            index = spliced;
        }
    }

    #[test]
    fn path_index_patch_timing() {
        let index = PathIndex::pack(base_entries(DAV_CHUNK * 32));
        let key = index.chunks[index.chunks.len() / 2]
            .first_path()
            .to_string();
        let started = std::time::Instant::now();
        let iterations = 50;
        for i in 0..iterations {
            let add = vec![row_entry(&format!("{key}-{i}"), 5_000_000 + i)];
            let patched = index.patch(&AHashSet::default(), add);
            let removes = [format!("{key}-{i}")].into_iter().collect::<AHashSet<_>>();
            let restored = patched.patch(&removes, Vec::new());
            assert_eq!(restored.len(), index.len());
        }
        let per_op = started.elapsed() / (iterations * 2);
        println!(
            "patch of a {} entry index: {per_op:?} per structural change",
            index.len()
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
