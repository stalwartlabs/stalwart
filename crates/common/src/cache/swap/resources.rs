/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapPart, frame::SwapFrame};
use crate::{
    ArenaRef, CachedName, DavPath, GroupwareResource, GroupwareResourceMetadata, GroupwareResources, PathChunk,
    PathIndex, ResourceChunk, ResourceStore, TinyCalendarPreferences, UpdateLock,
};
use calcard::common::timezone::Tz;
use rkyv::with::InlineAsBox;
use std::sync::Arc;
use types::acl::AclGrant;
use utils::map::bitmap::Bitmap;

const KIND_FILE: u32 = 1;
const KIND_CALENDAR: u32 = 2;
const KIND_CALENDAR_EVENT: u32 = 3;
const KIND_CALENDAR_EVENT_NOTIFICATION: u32 = 4;
const KIND_ADDRESS_BOOK: u32 = 5;
const KIND_CONTACT_CARD: u32 = 6;

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct FlatResource {
    pub start: i64,
    pub created_at: i64,
    pub ref_a_off: u32,
    pub ref_a_len: u32,
    pub ref_b_off: u32,
    pub ref_b_len: u32,
    pub num_a: u32,
    pub num_b: u32,
    pub document_id: u32,
    pub kind: u32,
    pub etag: u32,
}

impl FlatResource {
    fn pack(resource: &GroupwareResource) -> Self {
        let mut flat = FlatResource {
            start: 0,
            created_at: 0,
            ref_a_off: 0,
            ref_a_len: 0,
            ref_b_off: 0,
            ref_b_len: 0,
            num_a: 0,
            num_b: 0,
            document_id: resource.document_id,
            kind: 0,
            etag: resource.etag(),
        };

        match &resource.data {
            GroupwareResourceMetadata::File {
                name,
                size,
                parent_id,
                acls,
                ..
            } => {
                flat.kind = KIND_FILE;
                flat.set_ref_a(name);
                flat.set_ref_b(acls);
                flat.num_a = *size;
                flat.num_b = *parent_id;
            }
            GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                ..
            } => {
                flat.kind = KIND_CALENDAR;
                flat.set_ref_a(name);
                flat.set_ref_b(acls);
                flat.num_a = preferences.off;
                flat.num_b = preferences.len;
            }
            GroupwareResourceMetadata::CalendarEvent {
                names,
                start,
                duration,
                created_at,
                modified_at,
                uid,
                ..
            } => {
                flat.kind = KIND_CALENDAR_EVENT;
                flat.set_ref_a(names);
                flat.set_ref_b(uid);
                flat.start = *start;
                flat.created_at = *created_at;
                flat.num_a = *duration;
                flat.num_b = *modified_at as u32;
            }
            GroupwareResourceMetadata::CalendarEventNotification {
                names,
                created_at,
                event_id,
                ..
            } => {
                flat.kind = KIND_CALENDAR_EVENT_NOTIFICATION;
                flat.set_ref_a(names);
                flat.created_at = *created_at;
                flat.num_a = *event_id;
            }
            GroupwareResourceMetadata::AddressBook { name, acls, .. } => {
                flat.kind = KIND_ADDRESS_BOOK;
                flat.set_ref_a(name);
                flat.set_ref_b(acls);
            }
            GroupwareResourceMetadata::ContactCard {
                names,
                created_at,
                modified_at,
                uid,
                ..
            } => {
                flat.kind = KIND_CONTACT_CARD;
                flat.set_ref_a(names);
                flat.set_ref_b(uid);
                flat.created_at = *created_at;
                flat.num_b = *modified_at as u32;
            }
        }

        flat
    }

    fn set_ref_a(&mut self, arena: &ArenaRef) {
        self.ref_a_off = arena.off;
        self.ref_a_len = arena.len;
    }

    fn set_ref_b(&mut self, arena: &ArenaRef) {
        self.ref_b_off = arena.off;
        self.ref_b_len = arena.len;
    }
}

impl ArchivedFlatResource {
    fn ref_a(&self) -> ArenaRef {
        ArenaRef {
            off: self.ref_a_off.to_native(),
            len: self.ref_a_len.to_native(),
        }
    }

    fn ref_b(&self) -> ArenaRef {
        ArenaRef {
            off: self.ref_b_off.to_native(),
            len: self.ref_b_len.to_native(),
        }
    }

    fn unpack(&self) -> Option<GroupwareResource> {
        let data = match self.kind.to_native() {
            KIND_FILE => GroupwareResourceMetadata::File {
                name: self.ref_a(),
                size: self.num_a.to_native(),
                parent_id: self.num_b.to_native(),
                acls: self.ref_b(),
                etag: self.etag.to_native(),
            },
            KIND_CALENDAR => GroupwareResourceMetadata::Calendar {
                name: self.ref_a(),
                acls: self.ref_b(),
                preferences: ArenaRef {
                    off: self.num_a.to_native(),
                    len: self.num_b.to_native(),
                },
                etag: self.etag.to_native(),
            },
            KIND_CALENDAR_EVENT => GroupwareResourceMetadata::CalendarEvent {
                names: self.ref_a(),
                start: self.start.to_native(),
                duration: self.num_a.to_native(),
                created_at: self.created_at.to_native(),
                modified_at: self.num_b.to_native() as i32,
                uid: self.ref_b(),
                etag: self.etag.to_native(),
            },
            KIND_CALENDAR_EVENT_NOTIFICATION => GroupwareResourceMetadata::CalendarEventNotification {
                names: self.ref_a(),
                created_at: self.created_at.to_native(),
                event_id: self.num_a.to_native(),
                etag: self.etag.to_native(),
            },
            KIND_ADDRESS_BOOK => GroupwareResourceMetadata::AddressBook {
                name: self.ref_a(),
                acls: self.ref_b(),
                etag: self.etag.to_native(),
            },
            KIND_CONTACT_CARD => GroupwareResourceMetadata::ContactCard {
                names: self.ref_a(),
                created_at: self.created_at.to_native(),
                modified_at: self.num_b.to_native() as i32,
                uid: self.ref_b(),
                etag: self.etag.to_native(),
            },
            _ => return None,
        };

        Some(GroupwareResource {
            document_id: self.document_id.to_native(),
            data,
        })
    }
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedResources<'x> {
    pub base_path: String,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub containers_end: u32,
    pub total: u32,
    pub path_total: u32,
    pub unified_id_space: bool,
    pub chunks: Vec<ArchivedResourceChunk<'x>>,
    pub path_chunks: Vec<ArchivedPathChunk<'x>>,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedResourceChunk<'x> {
    pub records: Vec<FlatResource>,
    #[rkyv(with = InlineAsBox)]
    pub bytes: &'x [u8],
    pub name_offsets: Vec<u32>,
    pub name_lengths: Vec<u32>,
    pub name_parents: Vec<u32>,
    pub acl_accounts: Vec<u32>,
    pub acl_grants: Vec<u64>,
    pub pref_accounts: Vec<u32>,
    pub pref_timezones: Vec<u16>,
    pub pref_flags: Vec<u16>,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedPathChunk<'x> {
    #[rkyv(with = InlineAsBox)]
    pub bytes: &'x [u8],
    pub path_offsets: Vec<u32>,
    pub path_lengths: Vec<u32>,
    pub parent_ids: Vec<u32>,
    pub hierarchy_seqs: Vec<u32>,
    pub document_ids: Vec<u32>,
}

fn fits_within(arena: ArenaRef, limit: usize) -> bool {
    (arena.off as usize)
        .checked_add(arena.len as usize)
        .is_some_and(|end| end <= limit)
}

impl GroupwareResource {
    fn fits_within(&self, bytes: usize, names: usize, acls: usize, prefs: usize) -> bool {
        match &self.data {
            GroupwareResourceMetadata::File {
                name,
                acls: acl_ref,
                ..
            }
            | GroupwareResourceMetadata::AddressBook {
                name,
                acls: acl_ref,
                ..
            } => fits_within(*name, bytes) && fits_within(*acl_ref, acls),
            GroupwareResourceMetadata::Calendar {
                name,
                acls: acl_ref,
                preferences,
                ..
            } => {
                fits_within(*name, bytes)
                    && fits_within(*acl_ref, acls)
                    && fits_within(*preferences, prefs)
            }
            GroupwareResourceMetadata::CalendarEvent {
                names: name_refs,
                uid,
                ..
            }
            | GroupwareResourceMetadata::ContactCard {
                names: name_refs,
                uid,
                ..
            } => fits_within(*name_refs, names) && fits_within(*uid, bytes),
            GroupwareResourceMetadata::CalendarEventNotification {
                names: name_refs, ..
            } => fits_within(*name_refs, names),
        }
    }
}

impl GroupwareResources {
    pub fn to_snapshot(&self) -> Option<Vec<u8>> {
        let (chunks, path_chunks) = self.pack();
        self.seal_snapshot(chunks, path_chunks)
    }

    #[allow(clippy::type_complexity)]
    fn pack(&self) -> (Vec<ArchivedResourceChunk<'_>>, Vec<ArchivedPathChunk<'_>>) {
        let mut chunks = Vec::with_capacity(self.resources.chunks.len());
        for chunk in &self.resources.chunks {
            let mut name_offsets = Vec::with_capacity(chunk.names.len());
            let mut name_lengths = Vec::with_capacity(chunk.names.len());
            let mut name_parents = Vec::with_capacity(chunk.names.len());
            for name in chunk.names.iter() {
                name_offsets.push(name.name.off);
                name_lengths.push(name.name.len);
                name_parents.push(name.parent_id);
            }

            let mut acl_accounts = Vec::with_capacity(chunk.acls.len());
            let mut acl_grants = Vec::with_capacity(chunk.acls.len());
            for acl in chunk.acls.iter() {
                acl_accounts.push(acl.account_id);
                acl_grants.push(acl.grants.bitmap);
            }

            let mut pref_accounts = Vec::with_capacity(chunk.prefs.len());
            let mut pref_timezones = Vec::with_capacity(chunk.prefs.len());
            let mut pref_flags = Vec::with_capacity(chunk.prefs.len());
            for pref in chunk.prefs.iter() {
                pref_accounts.push(pref.account_id);
                pref_timezones.push(pref.tz.as_id());
                pref_flags.push(pref.flags);
            }

            chunks.push(ArchivedResourceChunk {
                records: chunk.records.iter().map(FlatResource::pack).collect(),
                bytes: &chunk.bytes,
                name_offsets,
                name_lengths,
                name_parents,
                acl_accounts,
                acl_grants,
                pref_accounts,
                pref_timezones,
                pref_flags,
            });
        }

        let mut path_chunks = Vec::with_capacity(self.paths.chunks.len());
        for chunk in &self.paths.chunks {
            let mut path_offsets = Vec::with_capacity(chunk.paths.len());
            let mut path_lengths = Vec::with_capacity(chunk.paths.len());
            let mut parent_ids = Vec::with_capacity(chunk.paths.len());
            let mut hierarchy_seqs = Vec::with_capacity(chunk.paths.len());
            let mut document_ids = Vec::with_capacity(chunk.paths.len());
            for path in chunk.paths.iter() {
                path_offsets.push(path.path.off);
                path_lengths.push(path.path.len);
                parent_ids.push(path.parent_id);
                hierarchy_seqs.push(path.hierarchy_seq);
                document_ids.push(path.document_id);
            }

            path_chunks.push(ArchivedPathChunk {
                bytes: &chunk.bytes,
                path_offsets,
                path_lengths,
                parent_ids,
                hierarchy_seqs,
                document_ids,
            });
        }

        (chunks, path_chunks)
    }

    fn seal_snapshot(
        &self,
        chunks: Vec<ArchivedResourceChunk<'_>>,
        path_chunks: Vec<ArchivedPathChunk<'_>>,
    ) -> Option<Vec<u8>> {
        let mut out = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            &ArchivedResources {
                base_path: self.base_path.clone(),
                item_change_id: self.item_change_id,
                container_change_id: self.container_change_id,
                containers_end: self.resources.containers_end as u32,
                total: self.resources.total as u32,
                path_total: self.paths.total as u32,
                unified_id_space: self.resources.unified_id_space,
                chunks,
                path_chunks,
            },
            SwapFrame::reserve_header(),
        )
        .ok()?;

        SwapFrame::seal(
            &mut out,
            SwapPart::Resources,
            self.highest_change_id,
            self.resources.total as u32,
        )
        .then_some(out)
    }

    pub fn from_snapshot(buf: &[u8]) -> Option<Self> {
        let frame = SwapFrame::parse(buf)?;
        if frame.part() != SwapPart::Resources {
            return None;
        }

        let archived =
            rkyv::access::<ArchivedArchivedResources, rkyv::rancor::Error>(frame.payload()).ok()?;

        let containers_end = archived.containers_end.to_native() as usize;
        let unified_id_space = archived.unified_id_space;
        if containers_end > archived.chunks.len()
            || (unified_id_space && containers_end != archived.chunks.len())
        {
            return None;
        }

        let mut chunks = Vec::with_capacity(archived.chunks.len());
        let mut total = 0usize;
        for chunk in archived.chunks.iter() {
            let names_len = chunk.name_offsets.len();
            if chunk.name_lengths.len() != names_len || chunk.name_parents.len() != names_len {
                return None;
            }
            let acls_len = chunk.acl_accounts.len();
            if chunk.acl_grants.len() != acls_len {
                return None;
            }
            let prefs_len = chunk.pref_accounts.len();
            if chunk.pref_timezones.len() != prefs_len || chunk.pref_flags.len() != prefs_len {
                return None;
            }

            let bytes: Box<[u8]> = (&*chunk.bytes).into();

            let names: Box<[CachedName]> = chunk
                .name_offsets
                .iter()
                .zip(chunk.name_lengths.iter())
                .zip(chunk.name_parents.iter())
                .map(|((off, len), parent_id)| CachedName {
                    name: ArenaRef {
                        off: off.to_native(),
                        len: len.to_native(),
                    },
                    parent_id: parent_id.to_native(),
                })
                .collect();
            if names
                .iter()
                .any(|name| !fits_within(name.name, bytes.len()))
            {
                return None;
            }

            let acls: Box<[AclGrant]> = chunk
                .acl_accounts
                .iter()
                .zip(chunk.acl_grants.iter())
                .map(|(account_id, grants)| AclGrant {
                    account_id: account_id.to_native(),
                    grants: Bitmap::from(grants.to_native()),
                })
                .collect();

            let prefs: Box<[TinyCalendarPreferences]> = chunk
                .pref_accounts
                .iter()
                .zip(chunk.pref_timezones.iter())
                .zip(chunk.pref_flags.iter())
                .map(|((account_id, tz), flags)| TinyCalendarPreferences {
                    account_id: account_id.to_native(),
                    tz: Tz::from_id(tz.to_native()).unwrap_or_default(),
                    flags: flags.to_native(),
                })
                .collect();

            let mut records = Vec::with_capacity(chunk.records.len());
            for record in chunk.records.iter() {
                let record = record.unpack()?;
                if !record.fits_within(bytes.len(), names_len, acls_len, prefs_len) {
                    return None;
                }
                records.push(record);
            }

            let (Some(min_id), Some(max_id)) = (
                records.first().map(|r| r.document_id),
                records.last().map(|r| r.document_id),
            ) else {
                return None;
            };

            total += records.len();
            chunks.push(Arc::new(ResourceChunk {
                records: records.into_boxed_slice(),
                bytes,
                names,
                acls,
                prefs,
                min_id,
                max_id,
            }));
        }

        if total != archived.total.to_native() as usize {
            return None;
        }

        let mut path_chunks = Vec::with_capacity(archived.path_chunks.len());
        let mut path_total = 0usize;
        for chunk in archived.path_chunks.iter() {
            let paths_len = chunk.path_offsets.len();
            if chunk.path_lengths.len() != paths_len
                || chunk.parent_ids.len() != paths_len
                || chunk.hierarchy_seqs.len() != paths_len
                || chunk.document_ids.len() != paths_len
            {
                return None;
            }

            let bytes: Box<[u8]> = (&*chunk.bytes).into();
            let paths: Box<[DavPath]> = chunk
                .path_offsets
                .iter()
                .zip(chunk.path_lengths.iter())
                .zip(chunk.parent_ids.iter())
                .zip(chunk.hierarchy_seqs.iter())
                .zip(chunk.document_ids.iter())
                .map(
                    |((((off, len), parent_id), hierarchy_seq), document_id)| DavPath {
                        path: ArenaRef {
                            off: off.to_native(),
                            len: len.to_native(),
                        },
                        parent_id: parent_id.to_native(),
                        hierarchy_seq: hierarchy_seq.to_native(),
                        document_id: document_id.to_native(),
                    },
                )
                .collect();
            if paths.is_empty()
                || paths
                    .iter()
                    .any(|path| !fits_within(path.path, bytes.len()))
            {
                return None;
            }

            path_total += paths_len;
            path_chunks.push(Arc::new(PathChunk { paths, bytes }));
        }

        if path_total != archived.path_total.to_native() as usize {
            return None;
        }

        let mut resources = GroupwareResources {
            base_path: archived.base_path.to_string(),
            paths: Arc::new(PathIndex {
                chunks: path_chunks,
                total: path_total,
            }),
            resources: ResourceStore {
                chunks,
                containers_end,
                total,
                unified_id_space,
            },
            item_change_id: archived.item_change_id.to_native(),
            container_change_id: archived.container_change_id.to_native(),
            highest_change_id: frame.change_id(),
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        resources.recompute_size();
        resources
            .update_lock
            .set_revision(resources.highest_change_id);

        Some(resources)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DAV_CHUNK, DavName, storage::dav::ResourceChunkBuilder};
    use types::acl::Acl;

    fn grants(account_id: u32) -> AclGrant {
        AclGrant {
            account_id,
            grants: Bitmap::from_iter([Acl::Read, Acl::Modify]),
        }
    }

    fn calcard(items: usize) -> GroupwareResources {
        let mut containers = Vec::new();
        let mut chunk = ResourceChunkBuilder::with_capacity(4);
        let mut entries = Vec::new();

        for document_id in 0..3u32 {
            let name = chunk.push_str(&format!("calendar-{document_id}"));
            let acls = chunk.push_acls(&[grants(document_id + 100), grants(document_id + 200)]);
            let preferences = chunk.push_prefs(&[TinyCalendarPreferences {
                account_id: document_id + 300,
                tz: Tz::UTC,
                flags: 0b101,
            }]);
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::Calendar {
                    name,
                    acls,
                    preferences,
                    etag: document_id + 700,
                },
            });
            entries.push((
                format!("calendar-{document_id}"),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: crate::NO_ID,
                    hierarchy_seq: crate::storage::dav::CONTAINER_FLAG,
                    document_id,
                },
            ));
        }
        containers.push(chunk);

        let mut items_chunks = Vec::new();
        let mut chunk = ResourceChunkBuilder::with_capacity(items);
        for document_id in 0..items as u32 {
            if chunk.len() == DAV_CHUNK {
                items_chunks.push(std::mem::replace(
                    &mut chunk,
                    ResourceChunkBuilder::with_capacity(DAV_CHUNK),
                ));
            }
            let parent_id = document_id % 3;
            let names = chunk.push_names(&[DavName {
                name: format!("event-{document_id}.ics"),
                parent_id,
            }]);
            let uid = chunk.push_str(&format!("uid-{document_id}@example.org"));
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::CalendarEvent {
                    names,
                    start: 1_700_000_000 + document_id as i64,
                    duration: 3600 + document_id,
                    created_at: 1_600_000_000 + document_id as i64,
                    modified_at: -(document_id as i32) - 1,
                    etag: document_id + 800,
                    uid,
                },
            });
            entries.push((
                format!("calendar-{parent_id}/event-{document_id}.ics"),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id,
                    hierarchy_seq: 0,
                    document_id,
                },
            ));
        }
        items_chunks.push(chunk);

        let mut resources = GroupwareResources {
            base_path: "/dav/cal/jane".to_string(),
            paths: Arc::new(PathIndex::pack(entries)),
            resources: ResourceStore::from_sorted(containers, items_chunks, false),
            item_change_id: 42,
            container_change_id: 17,
            highest_change_id: 42,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        resources.recompute_size();
        resources
    }

    fn files(count: usize) -> GroupwareResources {
        let mut chunk = ResourceChunkBuilder::with_capacity(count);
        let mut entries = Vec::new();

        for document_id in 0..count as u32 {
            let name = chunk.push_str(&format!("file-{document_id}.txt"));
            let acls = if document_id % 4 == 0 {
                chunk.push_acls(&[grants(document_id + 900)])
            } else {
                chunk.push_acls(&[])
            };
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::File {
                    etag: document_id + 900,
                    name,
                    size: 1024 + document_id,
                    parent_id: if document_id == 0 {
                        crate::NO_ID
                    } else {
                        document_id - 1
                    },
                    acls,
                },
            });
            entries.push((
                format!("folder/file-{document_id}.txt"),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: crate::NO_ID,
                    hierarchy_seq: 1,
                    document_id,
                },
            ));
        }

        let mut resources = GroupwareResources {
            base_path: "/dav/file/jane".to_string(),
            paths: Arc::new(PathIndex::pack(entries)),
            resources: ResourceStore::from_sorted(vec![chunk], Vec::new(), true),
            item_change_id: 7,
            container_change_id: 7,
            highest_change_id: 7,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        resources.recompute_size();
        resources
    }

    fn assert_same(left: &GroupwareResources, right: &GroupwareResources) {
        assert_eq!(left.base_path, right.base_path);
        assert_eq!(left.item_change_id, right.item_change_id);
        assert_eq!(left.container_change_id, right.container_change_id);
        assert_eq!(left.highest_change_id, right.highest_change_id);
        assert_eq!(left.size, right.size);
        assert_eq!(left.resources.total, right.resources.total);
        assert_eq!(
            left.resources.containers_end,
            right.resources.containers_end
        );
        assert_eq!(
            left.resources.unified_id_space,
            right.resources.unified_id_space
        );
        assert_eq!(left.resources.chunks.len(), right.resources.chunks.len());
        assert_eq!(left.paths.total, right.paths.total);
        assert_eq!(left.paths.chunks.len(), right.paths.chunks.len());

        for (a, b) in left.resources.iter().zip(right.resources.iter()) {
            assert_eq!(a.document_id(), b.document_id());
            assert_eq!(a.is_container(), b.is_container());
            assert_eq!(a.acls(), b.acls());
            assert_eq!(a.size(), b.size());
            assert_eq!(a.parent_id(), b.parent_id());
            assert_eq!(a.event_time_range(), b.event_time_range());
            assert_eq!(a.created_at(), b.created_at());
            assert_eq!(a.modified_at(), b.modified_at());
            assert_eq!(a.uid(), b.uid());
            assert_eq!(a.event_id(), b.event_id());
            assert_eq!(a.container_name(), b.container_name());
            assert_eq!(a.has_acls(), b.has_acls());
            for account_id in [100u32, 101, 102, 300, 301, 302] {
                let left_pref = a.calendar_preferences(account_id);
                let right_pref = b.calendar_preferences(account_id);
                assert_eq!(left_pref.is_some(), right_pref.is_some());
                if let (Some(left_pref), Some(right_pref)) = (left_pref, right_pref) {
                    assert_eq!(left_pref.account_id, right_pref.account_id);
                    assert_eq!(left_pref.tz.as_id(), right_pref.tz.as_id());
                    assert_eq!(left_pref.flags, right_pref.flags);
                }
            }
            assert_eq!(a.child_names().len(), b.child_names().len());
            for (left_name, right_name) in a.child_names().iter().zip(b.child_names().iter()) {
                assert_eq!(left_name.parent_id, right_name.parent_id);
                assert_eq!(a.child_name_at(left_name), b.child_name_at(right_name));
            }
        }

        for (chunk, path) in left.paths.iter() {
            let name = std::str::from_utf8(&chunk.bytes[path.path.range()]).expect("valid path");
            let found = right.paths.get(name);
            assert!(found.is_some(), "path {name} missing after round trip");
            let (_, other) = found.unwrap();
            assert_eq!(path.document_id, other.document_id);
            assert_eq!(path.parent_id, other.parent_id);
            assert_eq!(path.hierarchy_seq, other.hierarchy_seq);
        }

        for chunk in &left.resources.chunks {
            for record in chunk.records.iter() {
                let container = record.is_container();
                assert_eq!(
                    right
                        .resources
                        .find(record.document_id, container)
                        .map(|r| r.document_id()),
                    Some(record.document_id)
                );
            }
        }
    }

    #[test]
    fn perf_probe() {
        if std::env::var("SWAP_PERF").is_err() {
            return;
        }
        use std::time::Instant;

        fn p50(mut v: Vec<f64>) -> f64 {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        }

        for n in [50_000usize, 500_000] {
            let resources = calcard(n);
            let encoded = resources.to_snapshot().expect("encode");
            println!("--- calcard {n} ---");
            println!("chunks         = {}", resources.resources.chunks.len());
            println!("snapshot bytes = {}", encoded.len());
            println!(
                "bytes/resource = {:.2}",
                encoded.len() as f64 / resources.resources.len() as f64
            );

            for _ in 0..2 {
                std::hint::black_box(GroupwareResources::from_snapshot(&encoded));
            }

            let mut decode = Vec::new();
            for _ in 0..15 {
                let t = Instant::now();
                let out = GroupwareResources::from_snapshot(&encoded).expect("decode");
                decode.push(t.elapsed().as_secs_f64() * 1000.0);
                std::hint::black_box(out.resources.len());
            }
            println!("decode p50 ms  = {:.4}", p50(decode));

            let mut encode = Vec::new();
            for _ in 0..10 {
                let t = Instant::now();
                let out = resources.to_snapshot().expect("encode");
                encode.push(t.elapsed().as_secs_f64() * 1000.0);
                std::hint::black_box(out.len());
            }
            println!("encode p50 ms  = {:.4}", p50(encode));
        }
    }

    #[test]
    fn calcard_snapshot_round_trips() {
        let resources = calcard(500);
        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
    }

    #[test]
    fn calcard_snapshot_round_trips_many_chunks() {
        let resources = calcard(DAV_CHUNK + 100);
        assert!(resources.resources.chunks.len() > 2);
        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
    }

    #[test]
    fn files_snapshot_round_trips() {
        let resources = files(300);
        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
    }

    #[test]
    fn empty_snapshot_round_trips() {
        let resources = files(0);
        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
    }

    #[test]
    fn an_inconsistent_payload_with_a_valid_checksum_is_rejected() {
        let resources = calcard(200);

        let (mut chunks, path_chunks) = resources.pack();
        chunks[0].records[0].ref_a_off = u32::MAX - 1;
        assert!(
            GroupwareResources::from_snapshot(&resources.seal_snapshot(chunks, path_chunks).unwrap())
                .is_none(),
            "an arena offset past the end of the chunk was accepted"
        );

        let (mut chunks, path_chunks) = resources.pack();
        chunks[0].records[0].ref_b_len = u32::MAX;
        assert!(
            GroupwareResources::from_snapshot(&resources.seal_snapshot(chunks, path_chunks).unwrap())
                .is_none(),
            "an arena length past the end of the chunk was accepted"
        );

        let (chunks, mut path_chunks) = resources.pack();
        path_chunks[0].path_lengths[0] = u32::MAX;
        assert!(
            GroupwareResources::from_snapshot(&resources.seal_snapshot(chunks, path_chunks).unwrap())
                .is_none(),
            "a path reaching past the end of its byte arena was accepted"
        );
    }

    #[test]
    fn corrupt_snapshot_is_rejected() {
        let resources = calcard(200);
        let encoded = resources.to_snapshot().expect("encode");

        assert!(GroupwareResources::from_snapshot(&[]).is_none());
        assert!(GroupwareResources::from_snapshot(&encoded[..encoded.len() - 1]).is_none());

        let mut bad_part = encoded.clone();
        bad_part[6] = SwapPart::Messages.code();
        assert!(GroupwareResources::from_snapshot(&bad_part).is_none());

        for offset in [40usize, 600, 2048] {
            let mut flipped = encoded.clone();
            if offset < flipped.len() {
                flipped[offset] ^= 0x01;
                assert!(
                    GroupwareResources::from_snapshot(&flipped).is_none(),
                    "a payload byte flip at {offset} was not rejected"
                );
            }
        }
    }
}
