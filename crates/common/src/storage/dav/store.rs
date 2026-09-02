/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ArenaRef, CachedName, DavName, DavResource, DavResourceMetadata, DavResourceRef, NO_ID,
    ResourceChunk, ResourceStore, TinyCalendarPreferences,
};
use std::sync::Arc;
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
        (self.records.len() * std::mem::size_of::<DavResource>()
            + self.bytes.len()
            + self.names.len() * std::mem::size_of::<CachedName>()
            + self.acls.len() * std::mem::size_of::<AclGrant>()
            + self.prefs.len() * std::mem::size_of::<TinyCalendarPreferences>()
            + std::mem::size_of::<ResourceChunk>()) as u64
    }
}

#[derive(Default)]
pub struct ResourceChunkBuilder {
    pub records: Vec<DavResource>,
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

    pub fn push_from(&mut self, src: &DavResourceRef<'_>) {
        let data = match &src.resource.data {
            DavResourceMetadata::File {
                name,
                size,
                parent_id,
                acls,
                etag,
            } => DavResourceMetadata::File {
                name: self.push_str(src.chunk.str_at(*name)),
                size: *size,
                parent_id: *parent_id,
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                etag: *etag,
            },
            DavResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag,
            } => DavResourceMetadata::Calendar {
                name: self.push_str(src.chunk.str_at(*name)),
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                preferences: self.push_prefs(src.chunk.prefs_at(*preferences)),
                etag: *etag,
            },
            DavResourceMetadata::AddressBook { name, acls, etag } => {
                DavResourceMetadata::AddressBook {
                    name: self.push_str(src.chunk.str_at(*name)),
                    acls: self.push_acls(src.chunk.acls_at(*acls)),
                    etag: *etag,
                }
            }
            DavResourceMetadata::CalendarEvent {
                names,
                start,
                duration,
                created_at,
                modified_at,
                uid,
                etag,
            } => DavResourceMetadata::CalendarEvent {
                names: self.push_cached_names(src.chunk, *names),
                start: *start,
                duration: *duration,
                created_at: *created_at,
                modified_at: *modified_at,
                uid: self.push_str(src.chunk.str_at(*uid)),
                etag: *etag,
            },
            DavResourceMetadata::ContactCard {
                names,
                created_at,
                modified_at,
                uid,
                etag,
            } => DavResourceMetadata::ContactCard {
                names: self.push_cached_names(src.chunk, *names),
                created_at: *created_at,
                modified_at: *modified_at,
                uid: self.push_str(src.chunk.str_at(*uid)),
                etag: *etag,
            },
            DavResourceMetadata::CalendarEventNotification {
                names,
                created_at,
                event_id,
                etag,
            } => DavResourceMetadata::CalendarEventNotification {
                names: self.push_cached_names(src.chunk, *names),
                created_at: *created_at,
                event_id: *event_id,
                etag: *etag,
            },
        };
        self.records.push(DavResource {
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

impl ResourceStore {
    pub fn from_sorted(
        containers: Vec<ResourceChunkBuilder>,
        items: Vec<ResourceChunkBuilder>,
        unified_id_space: bool,
    ) -> Self {
        let mut chunks = Vec::with_capacity(containers.len() + items.len());
        let mut total = 0;
        for builder in containers {
            debug_assert!(
                builder.records.is_sorted_by_key(|r| r.document_id),
                "chunk records must be ordered by document_id for binary search"
            );
            total += builder.len();
            chunks.push(Arc::new(builder.finish()));
        }
        let containers_end = chunks.len();
        for builder in items {
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

    pub fn iter(&self) -> impl Iterator<Item = DavResourceRef<'_>> + '_ {
        self.chunks.iter().flat_map(|chunk| {
            chunk.records.iter().map(move |resource| DavResourceRef {
                chunk: chunk.as_ref(),
                resource,
            })
        })
    }

    pub fn heap_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.heap_size()).sum()
    }

    pub fn find(&self, document_id: u32, want_container: bool) -> Option<DavResourceRef<'_>> {
        let run = if self.unified_id_space {
            0..self.chunks.len()
        } else if want_container {
            0..self.containers_end
        } else {
            self.containers_end..self.chunks.len()
        };

        for chunk in &self.chunks[run] {
            if document_id < chunk.min_id || document_id > chunk.max_id {
                continue;
            }
            if let Ok(idx) = chunk
                .records
                .binary_search_by_key(&document_id, |r| r.document_id)
            {
                let resource = &chunk.records[idx];
                return (resource.is_container() == want_container).then_some(DavResourceRef {
                    chunk: chunk.as_ref(),
                    resource,
                });
            }
        }
        None
    }

    #[inline(always)]
    pub fn find_any(&self, document_id: u32) -> Option<DavResourceRef<'_>> {
        self.find(document_id, true)
            .or_else(|| self.find(document_id, false))
    }

    pub fn rebuild(
        &self,
        staging: &ResourceChunk,
        changes: &ahash::AHashMap<(bool, u32), Option<u32>>,
    ) -> Self {
        let unified = self.unified_id_space;
        let runs: [(bool, std::ops::Range<usize>); 2] = if unified {
            [(true, 0..self.chunks.len()), (false, 0..0)]
        } else {
            [
                (true, 0..self.containers_end),
                (false, self.containers_end..self.chunks.len()),
            ]
        };

        let mut container_chunks: Vec<Arc<ResourceChunk>> = Vec::new();
        let mut item_chunks: Vec<Arc<ResourceChunk>> = Vec::new();

        for (is_container, range) in runs {
            if unified && !is_container {
                continue;
            }
            let key_flag = if unified { true } else { is_container };

            let mut pending: Vec<(u32, u32)> = changes
                .iter()
                .filter_map(|((flag, id), slot)| slot.map(|slot| (*flag, *id, slot)))
                .filter(|(flag, id, _)| {
                    *flag == key_flag
                        && if unified {
                            self.find_any(*id).is_none()
                        } else {
                            self.find(*id, is_container).is_none()
                        }
                })
                .map(|(_, id, slot)| (id, slot))
                .collect();
            pending.sort_unstable_by_key(|(id, _)| *id);
            pending.reverse();

            let staged = |slot: u32| DavResourceRef {
                chunk: staging,
                resource: &staging.records[slot as usize],
            };

            let target = if is_container {
                &mut container_chunks
            } else {
                &mut item_chunks
            };

            for chunk_idx in range.clone() {
                let chunk = &self.chunks[chunk_idx];
                let is_last = chunk_idx + 1 == range.end;
                let touched = chunk
                    .records
                    .iter()
                    .any(|record| changes.contains_key(&(key_flag, record.document_id)))
                    || pending.iter().any(|(id, _)| {
                        (*id >= chunk.min_id && *id <= chunk.max_id)
                            || (is_last && *id > chunk.max_id)
                    });

                if !touched {
                    target.push(Arc::clone(chunk));
                    continue;
                }

                let mut builder = ResourceChunkBuilder::with_capacity(chunk.records.len() + 4);
                for record in chunk.records.iter() {
                    while pending
                        .last()
                        .is_some_and(|(id, _)| *id < record.document_id)
                    {
                        let (_, slot) = pending.pop().unwrap();
                        builder.push_from(&staged(slot));
                    }
                    match changes.get(&(key_flag, record.document_id)) {
                        Some(Some(slot)) => builder.push_from(&staged(*slot)),
                        Some(None) => {}
                        None => builder.push_from(&DavResourceRef {
                            chunk,
                            resource: record,
                        }),
                    }
                }
                if is_last {
                    while let Some((_, slot)) = pending.pop() {
                        builder.push_from(&staged(slot));
                    }
                }

                if !builder.is_empty() {
                    target.push(Arc::new(builder.finish()));
                }
            }

            if !pending.is_empty() {
                let mut builder = ResourceChunkBuilder::with_capacity(pending.len());
                while let Some((_, slot)) = pending.pop() {
                    builder.push_from(&staged(slot));
                }
                if !builder.is_empty() {
                    target.push(Arc::new(builder.finish()));
                }
            }
        }

        let containers_end = container_chunks.len();
        let total = container_chunks
            .iter()
            .chain(item_chunks.iter())
            .map(|chunk| chunk.records.len())
            .sum();
        let mut chunks = container_chunks;
        chunks.extend(item_chunks);

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
    use crate::DavResourceMetadata;

    fn calendar(builder: &mut ResourceChunkBuilder, document_id: u32, name: &str) {
        let name = builder.push_str(name);
        let acls = builder.push_acls(&[]);
        let preferences = builder.push_prefs(&[]);
        builder.records.push(DavResource {
            document_id,
            data: DavResourceMetadata::Calendar {
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
        builder.records.push(DavResource {
            document_id,
            data: DavResourceMetadata::CalendarEvent {
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
