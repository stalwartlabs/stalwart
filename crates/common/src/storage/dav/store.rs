/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ArenaRef, CachedName, DAV_CHUNK, DavName, GroupwareResource, GroupwareResourceMetadata, GroupwareResourceRef,
    NO_ID, ResourceChunk, ResourceStore, TinyCalendarPreferences,
};
use std::{ops::Range, sync::Arc};
use types::acl::AclGrant;

impl ResourceChunk {
    #[inline(always)]
    pub fn str_at(&self, r: ArenaRef) -> &str {
        std::str::from_utf8(&self.bytes[r.range()]).unwrap_or_default()
    }

    #[inline(always)]
    pub fn names_at(&self, r: ArenaRef) -> &[CachedName] {
        &self.names[r.range()]
    }

    #[inline(always)]
    pub fn acls_at(&self, r: ArenaRef) -> &[AclGrant] {
        &self.acls[r.range()]
    }

    #[inline(always)]
    pub fn prefs_at(&self, r: ArenaRef) -> &[TinyCalendarPreferences] {
        &self.prefs[r.range()]
    }

    pub fn heap_size(&self) -> u64 {
        (self.records.len() * std::mem::size_of::<GroupwareResource>()
            + self.bytes.len()
            + self.names.len() * std::mem::size_of::<CachedName>()
            + self.acls.len() * std::mem::size_of::<AclGrant>()
            + self.prefs.len() * std::mem::size_of::<TinyCalendarPreferences>()
            + std::mem::size_of::<ResourceChunk>()) as u64
    }
}

#[derive(Default)]
pub struct ResourceChunkBuilder {
    pub records: Vec<GroupwareResource>,
    pub bytes: Vec<u8>,
    pub names: Vec<CachedName>,
    pub acls: Vec<AclGrant>,
    pub prefs: Vec<TinyCalendarPreferences>,
}

impl ResourceChunkBuilder {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            records: Vec::with_capacity(n),
            bytes: Vec::with_capacity(n * 48),
            names: Vec::with_capacity(n),
            acls: Vec::with_capacity(8),
            prefs: Vec::with_capacity(8),
        }
    }

    pub fn push_str(&mut self, s: &str) -> ArenaRef {
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        ArenaRef {
            off,
            len: s.len() as u32,
        }
    }

    pub fn push_acls(&mut self, acls: &[AclGrant]) -> ArenaRef {
        let off = self.acls.len() as u32;
        self.acls.extend_from_slice(acls);
        ArenaRef {
            off,
            len: acls.len() as u32,
        }
    }

    pub fn push_prefs(&mut self, prefs: &[TinyCalendarPreferences]) -> ArenaRef {
        let off = self.prefs.len() as u32;
        self.prefs.extend_from_slice(prefs);
        ArenaRef {
            off,
            len: prefs.len() as u32,
        }
    }

    pub fn push_names(&mut self, names: &[DavName]) -> ArenaRef {
        let off = self.names.len() as u32;
        for name in names {
            let name_ref = self.push_str(&name.name);
            self.names.push(CachedName {
                name: name_ref,
                parent_id: name.parent_id,
            });
        }
        ArenaRef {
            off,
            len: names.len() as u32,
        }
    }

    pub fn push_from(&mut self, src: &GroupwareResourceRef<'_>) {
        let data = match &src.resource.data {
            GroupwareResourceMetadata::File {
                name,
                size,
                parent_id,
                acls,
                etag,
            } => GroupwareResourceMetadata::File {
                name: self.push_str(src.chunk.str_at(*name)),
                size: *size,
                parent_id: *parent_id,
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                etag: *etag,
            },
            GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag,
            } => GroupwareResourceMetadata::Calendar {
                name: self.push_str(src.chunk.str_at(*name)),
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                preferences: self.push_prefs(src.chunk.prefs_at(*preferences)),
                etag: *etag,
            },
            GroupwareResourceMetadata::AddressBook { name, acls, etag } => {
                GroupwareResourceMetadata::AddressBook {
                    name: self.push_str(src.chunk.str_at(*name)),
                    acls: self.push_acls(src.chunk.acls_at(*acls)),
                    etag: *etag,
                }
            }
            GroupwareResourceMetadata::CalendarEvent {
                names,
                start,
                duration,
                created_at,
                modified_at,
                uid,
                etag,
            } => GroupwareResourceMetadata::CalendarEvent {
                names: self.push_cached_names(src.chunk, *names),
                start: *start,
                duration: *duration,
                created_at: *created_at,
                modified_at: *modified_at,
                uid: self.push_str(src.chunk.str_at(*uid)),
                etag: *etag,
            },
            GroupwareResourceMetadata::ContactCard {
                names,
                created_at,
                modified_at,
                uid,
                etag,
            } => GroupwareResourceMetadata::ContactCard {
                names: self.push_cached_names(src.chunk, *names),
                created_at: *created_at,
                modified_at: *modified_at,
                uid: self.push_str(src.chunk.str_at(*uid)),
                etag: *etag,
            },
            GroupwareResourceMetadata::CalendarEventNotification {
                names,
                created_at,
                event_id,
                etag,
            } => GroupwareResourceMetadata::CalendarEventNotification {
                names: self.push_cached_names(src.chunk, *names),
                created_at: *created_at,
                event_id: *event_id,
                etag: *etag,
            },
        };
        self.records.push(GroupwareResource {
            document_id: src.resource.document_id,
            data,
        });
    }

    fn push_cached_names(&mut self, chunk: &ResourceChunk, names: ArenaRef) -> ArenaRef {
        let off = self.names.len() as u32;
        let len = names.len;
        for idx in names.range() {
            let name = chunk.names[idx];
            let name_ref = self.push_str(chunk.str_at(name.name));
            self.names.push(CachedName {
                name: name_ref,
                parent_id: name.parent_id,
            });
        }
        ArenaRef { off, len }
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn finish(self) -> ResourceChunk {
        let min_id = self.records.first().map(|r| r.document_id).unwrap_or(NO_ID);
        let max_id = self.records.last().map(|r| r.document_id).unwrap_or(0);
        ResourceChunk {
            records: self.records.into_boxed_slice(),
            bytes: self.bytes.into_boxed_slice(),
            names: self.names.into_boxed_slice(),
            acls: self.acls.into_boxed_slice(),
            prefs: self.prefs.into_boxed_slice(),
            min_id,
            max_id,
        }
    }
}

struct SplitChunks<'x> {
    target: &'x mut Vec<Arc<ResourceChunk>>,
    current: ResourceChunkBuilder,
}

impl<'x> SplitChunks<'x> {
    fn new(target: &'x mut Vec<Arc<ResourceChunk>>, capacity: usize) -> Self {
        Self {
            target,
            current: ResourceChunkBuilder::with_capacity(capacity.min(DAV_CHUNK)),
        }
    }

    fn push(&mut self, resource: &GroupwareResourceRef<'_>) {
        if self.current.len() == DAV_CHUNK {
            let full =
                std::mem::replace(&mut self.current, ResourceChunkBuilder::with_capacity(64));
            self.target.push(Arc::new(full.finish()));
        }
        self.current.push_from(resource);
    }

    fn finish(self) {
        if !self.current.is_empty() {
            self.target.push(Arc::new(self.current.finish()));
        }
    }
}

impl ResourceStore {
    pub fn from_sorted(
        containers: Vec<ResourceChunkBuilder>,
        items: Vec<ResourceChunkBuilder>,
        unified_id_space: bool,
    ) -> Self {
        let mut chunks = Vec::with_capacity(containers.len() + items.len());
        let mut total = 0;
        for builder in containers.into_iter().filter(|builder| !builder.is_empty()) {
            debug_assert!(
                builder.records.is_sorted_by_key(|r| r.document_id),
                "chunk records must be ordered by document_id for binary search"
            );
            total += builder.len();
            chunks.push(Arc::new(builder.finish()));
        }
        let containers_end = chunks.len();
        for builder in items.into_iter().filter(|builder| !builder.is_empty()) {
            debug_assert!(
                builder.records.is_sorted_by_key(|r| r.document_id),
                "chunk records must be ordered by document_id for binary search"
            );
            total += builder.len();
            chunks.push(Arc::new(builder.finish()));
        }
        Self {
            chunks,
            containers_end,
            total,
            unified_id_space,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.total
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = GroupwareResourceRef<'_>> + '_ {
        self.chunks.iter().flat_map(|chunk| {
            chunk.records.iter().map(move |resource| GroupwareResourceRef {
                chunk: chunk.as_ref(),
                resource,
            })
        })
    }

    pub fn iter_with_acls(&self) -> impl Iterator<Item = GroupwareResourceRef<'_>> + '_ {
        self.chunks
            .iter()
            .filter(|chunk| !chunk.acls.is_empty())
            .flat_map(|chunk| {
                chunk.records.iter().map(move |resource| GroupwareResourceRef {
                    chunk: chunk.as_ref(),
                    resource,
                })
            })
            .filter(|resource| resource.has_acls())
    }

    pub fn heap_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.heap_size()).sum()
    }

    fn run(&self, is_container: bool) -> Range<usize> {
        if self.unified_id_space {
            0..self.chunks.len()
        } else if is_container {
            0..self.containers_end
        } else {
            self.containers_end..self.chunks.len()
        }
    }

    fn chunk_for(&self, run: &Range<usize>, document_id: u32) -> Option<usize> {
        let chunks = &self.chunks[run.clone()];
        let slot = chunks
            .partition_point(|chunk| chunk.min_id <= document_id)
            .checked_sub(1)?;
        Some(run.start + slot)
    }

    fn locate(&self, run: Range<usize>, document_id: u32) -> Option<GroupwareResourceRef<'_>> {
        let chunk = &self.chunks[self.chunk_for(&run, document_id)?];
        if document_id > chunk.max_id {
            return None;
        }
        chunk
            .records
            .binary_search_by_key(&document_id, |r| r.document_id)
            .ok()
            .map(|slot| GroupwareResourceRef {
                chunk: chunk.as_ref(),
                resource: &chunk.records[slot],
            })
    }

    pub fn find(&self, document_id: u32, want_container: bool) -> Option<GroupwareResourceRef<'_>> {
        self.locate(self.run(want_container), document_id)
            .filter(|resource| resource.is_container() == want_container)
    }

    #[inline(always)]
    pub fn find_any(&self, document_id: u32) -> Option<GroupwareResourceRef<'_>> {
        if self.unified_id_space {
            self.locate(self.run(true), document_id)
        } else {
            self.locate(self.run(true), document_id)
                .or_else(|| self.locate(self.run(false), document_id))
        }
    }

    pub fn rebuild(
        &self,
        staging: &ResourceChunk,
        changes: &ahash::AHashMap<(bool, u32), Option<u32>>,
    ) -> Self {
        let unified = self.unified_id_space;
        let mut container_chunks: Vec<Arc<ResourceChunk>> = Vec::new();
        let mut item_chunks: Vec<Arc<ResourceChunk>> = Vec::new();

        for is_container in [true, false] {
            if unified && !is_container {
                continue;
            }
            let key_flag = if unified { true } else { is_container };

            let mut pending: Vec<(u32, Option<u32>)> = changes
                .iter()
                .filter(|((flag, _), _)| *flag == key_flag)
                .map(|((_, document_id), slot)| (*document_id, *slot))
                .collect();
            pending.sort_unstable_by_key(|(document_id, _)| *document_id);
            let mut pending = pending.into_iter().peekable();

            let staged = |slot: u32| GroupwareResourceRef {
                chunk: staging,
                resource: &staging.records[slot as usize],
            };

            let target = if is_container {
                &mut container_chunks
            } else {
                &mut item_chunks
            };

            let run = &self.chunks[self.run(is_container)];
            for (position, chunk) in run.iter().enumerate() {
                let is_last = position + 1 == run.len();
                let owned = |(document_id, slot): &(u32, Option<u32>)| {
                    (is_last && slot.is_some()) || *document_id <= chunk.max_id
                };

                if !pending.peek().is_some_and(owned) {
                    target.push(Arc::clone(chunk));
                    continue;
                }

                let mut builder = SplitChunks::new(target, chunk.records.len() + 4);
                for record in chunk.records.iter() {
                    while let Some((_, slot)) =
                        pending.next_if(|(document_id, _)| *document_id < record.document_id)
                    {
                        if let Some(slot) = slot {
                            builder.push(&staged(slot));
                        }
                    }
                    match pending.next_if(|(document_id, _)| *document_id == record.document_id) {
                        Some((_, Some(slot))) => builder.push(&staged(slot)),
                        Some((_, None)) => {}
                        None => builder.push(&GroupwareResourceRef {
                            chunk,
                            resource: record,
                        }),
                    }
                }
                while let Some((_, slot)) = pending.next_if(owned) {
                    if let Some(slot) = slot {
                        builder.push(&staged(slot));
                    }
                }
                builder.finish();
            }

            let mut builder = SplitChunks::new(target, 4);
            for (_, slot) in pending {
                if let Some(slot) = slot {
                    builder.push(&staged(slot));
                }
            }
            builder.finish();
        }

        let containers_end = container_chunks.len();
        let mut chunks = container_chunks;
        chunks.extend(item_chunks);
        let total = chunks.iter().map(|chunk| chunk.records.len()).sum();

        Self {
            chunks,
            containers_end,
            total,
            unified_id_space: unified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GroupwareResourceMetadata;

    fn calendar(builder: &mut ResourceChunkBuilder, document_id: u32, name: &str) {
        let name = builder.push_str(name);
        let acls = builder.push_acls(&[]);
        let preferences = builder.push_prefs(&[]);
        builder.records.push(GroupwareResource {
            document_id,
            data: GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag: document_id,
            },
        });
    }

    fn event(builder: &mut ResourceChunkBuilder, document_id: u32, parent_id: u32, name: &str) {
        let names = builder.push_names(&[DavName {
            name: name.to_string(),
            parent_id,
        }]);
        let uid = builder.push_str("uid");
        builder.records.push(GroupwareResource {
            document_id,
            data: GroupwareResourceMetadata::CalendarEvent {
                names,
                start: 0,
                duration: 0,
                created_at: 0,
                modified_at: 0,
                uid,
                etag: document_id,
            },
        });
    }

    #[test]
    fn store_finds_across_two_id_spaces() {
        let mut containers = ResourceChunkBuilder::with_capacity(2);
        calendar(&mut containers, 0, "default");
        calendar(&mut containers, 5, "work");

        let mut items = ResourceChunkBuilder::with_capacity(2);
        event(&mut items, 0, 0, "a.ics");
        event(&mut items, 5, 5, "b.ics");

        let store = ResourceStore::from_sorted(vec![containers], vec![items], false);
        assert_eq!(store.len(), 4);

        let default = store.find(0, true).expect("container 0");
        assert_eq!(default.container_name(), Some("default"));
        assert!(default.is_container());

        let colliding = store.find(0, false).expect("item 0");
        assert!(!colliding.is_container());
        assert_eq!(colliding.child_names().len(), 1);
        assert_eq!(
            colliding.child_name_at(&colliding.child_names()[0]),
            "a.ics"
        );

        let work = store.find(5, true).expect("container 5");
        assert_eq!(work.container_name(), Some("work"));
    }

    fn staged_event(document_id: u32, parent_id: u32, name: &str) -> ResourceChunk {
        let mut builder = ResourceChunkBuilder::with_capacity(1);
        event(&mut builder, document_id, parent_id, name);
        builder.finish()
    }

    #[test]
    fn rebuild_inserts_the_first_item_of_an_empty_run() {
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut containers, 0, "default");
        let store = ResourceStore::from_sorted(vec![containers], Vec::new(), false);
        assert_eq!(store.len(), 1);

        let staging = staged_event(7, 0, "a.ics");
        let mut changes = ahash::AHashMap::new();
        changes.insert((false, 7u32), Some(0u32));

        let rebuilt = store.rebuild(&staging, &changes);
        assert_eq!(rebuilt.len(), 2, "the new item must be admitted");
        assert!(
            rebuilt.find(0, true).is_some(),
            "the container must survive"
        );
        let item = rebuilt.find(7, false).expect("new item");
        assert_eq!(item.child_name_at(&item.child_names()[0]), "a.ics");
    }

    #[test]
    fn rebuild_shares_untouched_chunks_and_applies_updates() {
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut containers, 0, "default");
        let mut items = ResourceChunkBuilder::with_capacity(1);
        event(&mut items, 1, 0, "a.ics");
        let store = ResourceStore::from_sorted(vec![containers], vec![items], false);

        let staging = staged_event(1, 0, "renamed.ics");
        let mut changes = ahash::AHashMap::new();
        changes.insert((false, 1u32), Some(0u32));

        let rebuilt = store.rebuild(&staging, &changes);
        assert_eq!(rebuilt.len(), 2);
        let item = rebuilt.find(1, false).expect("updated item");
        assert_eq!(item.child_name_at(&item.child_names()[0]), "renamed.ics");
        assert!(
            Arc::ptr_eq(&store.chunks[0], &rebuilt.chunks[0]),
            "the untouched container chunk must be shared, not rebuilt"
        );
    }

    #[test]
    fn rebuild_drops_deleted_records() {
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut containers, 0, "default");
        let mut items = ResourceChunkBuilder::with_capacity(2);
        event(&mut items, 1, 0, "a.ics");
        event(&mut items, 2, 0, "b.ics");
        let store = ResourceStore::from_sorted(vec![containers], vec![items], false);

        let staging = ResourceChunkBuilder::with_capacity(0).finish();
        let mut changes = ahash::AHashMap::new();
        changes.insert((false, 1u32), None);

        let rebuilt = store.rebuild(&staging, &changes);
        assert_eq!(rebuilt.len(), 2);
        assert!(rebuilt.find(1, false).is_none(), "deleted item is gone");
        assert!(rebuilt.find(2, false).is_some(), "sibling survives");
    }

    #[test]
    fn rebuild_shares_the_tail_chunk_on_a_deleted_new_id() {
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut containers, 0, "default");
        let mut items = ResourceChunkBuilder::with_capacity(1);
        event(&mut items, 1, 0, "a.ics");
        let store = ResourceStore::from_sorted(vec![containers], vec![items], false);

        let staging = ResourceChunkBuilder::with_capacity(0).finish();
        let mut changes = ahash::AHashMap::new();
        changes.insert((false, 9u32), None);

        let rebuilt = store.rebuild(&staging, &changes);
        assert_eq!(rebuilt.len(), 2);
        assert_eq!(rebuilt.chunks.len(), 2);
        assert!(
            Arc::ptr_eq(&store.chunks[1], &rebuilt.chunks[1]),
            "a delete of an id the tail chunk never held must not rebuild it"
        );
    }

    #[test]
    fn rebuild_handles_a_unified_id_space() {
        let mut nodes = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut nodes, 0, "docs");
        let store = ResourceStore::from_sorted(vec![nodes], Vec::new(), true);

        let staging = staged_event(3, 0, "c.ics");
        let mut changes = ahash::AHashMap::new();
        changes.insert((true, 3u32), Some(0u32));

        let rebuilt = store.rebuild(&staging, &changes);
        assert_eq!(rebuilt.len(), 2);
        assert!(rebuilt.find_any(3).is_some(), "new node must be findable");
        assert!(rebuilt.find_any(0).is_some(), "existing node survives");
    }

    #[test]
    fn store_finds_when_only_containers_exist() {
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut containers, 0, "default");
        let store = ResourceStore::from_sorted(vec![containers], Vec::new(), false);

        assert!(store.find(0, true).is_some(), "container must be findable");
        assert!(store.find(0, false).is_none(), "not an item");
    }
}
