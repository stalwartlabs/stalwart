/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapPart, frame::SwapFrame};
use crate::{
    ArenaRef, CachedName, DavPath, FileFlags, GroupwareResource, GroupwareResourceMetadata,
    GroupwareResources, PathChunk, PathIndex, ResourceChunk, ResourceStore,
    TinyCalendarPreferences, UpdateLock, storage::dav::CONTAINER_FLAG,
};
use calcard::common::timezone::Tz;
use rkyv::with::InlineAsBox;
use std::sync::Arc;
use types::acl::AclGrant;
use utils::map::bitmap::Bitmap;

const KIND_FILE: u16 = 1;
const KIND_CALENDAR: u16 = 2;
const KIND_CALENDAR_EVENT: u16 = 3;
const KIND_CALENDAR_EVENT_NOTIFICATION: u16 = 4;
const KIND_ADDRESS_BOOK: u16 = 5;
const KIND_CONTACT_CARD: u16 = 6;

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct FlatResource {
    pub ref_a_off: u32,
    pub ref_b_off: u32,
    pub v0: u32,
    pub v1: u32,
    pub v2: u32,
    pub v3: u32,
    pub v4: u32,
    pub etag: u32,
    pub document_id: u32,
    pub ref_a_len: u16,
    pub ref_b_len: u16,
    pub flags: u16,
}

struct ChunkTimes {
    epoch: i64,
    wide: Vec<i64>,
}

impl ChunkTimes {
    fn for_records(records: &[GroupwareResource]) -> Self {
        Self {
            epoch: records
                .iter()
                .flat_map(|record| record.data.absolute_times())
                .min()
                .unwrap_or_default(),
            wide: Vec::new(),
        }
    }

    fn encode(&mut self, time: i64) -> u32 {
        match time.checked_sub(self.epoch) {
            Some(delta) if (0..=i32::MAX as i64).contains(&delta) => delta as u32,
            _ => {
                self.wide.push(time);
                -(self.wide.len() as i32) as u32
            }
        }
    }

    fn decode(&self, raw: u32) -> Option<i64> {
        let delta = raw as i32;
        if delta >= 0 {
            self.epoch.checked_add(delta as i64)
        } else {
            self.wide.get((-(delta as i64) - 1) as usize).copied()
        }
    }
}

impl GroupwareResourceMetadata {
    fn absolute_times(&self) -> impl Iterator<Item = i64> {
        let (start, created_at) = match self {
            GroupwareResourceMetadata::File { modified, .. } => (Some(*modified), None),
            GroupwareResourceMetadata::CalendarEvent {
                start, created_at, ..
            } => (Some(*start), Some(*created_at)),
            GroupwareResourceMetadata::CalendarEventNotification { created_at, .. }
            | GroupwareResourceMetadata::ContactCard { created_at, .. } => {
                (Some(*created_at), None)
            }
            GroupwareResourceMetadata::Calendar { .. }
            | GroupwareResourceMetadata::AddressBook { .. } => (None, None),
        };
        start.into_iter().chain(created_at)
    }

    fn kind(&self) -> u16 {
        match self {
            GroupwareResourceMetadata::File { .. } => KIND_FILE,
            GroupwareResourceMetadata::Calendar { .. } => KIND_CALENDAR,
            GroupwareResourceMetadata::CalendarEvent { .. } => KIND_CALENDAR_EVENT,
            GroupwareResourceMetadata::CalendarEventNotification { .. } => {
                KIND_CALENDAR_EVENT_NOTIFICATION
            }
            GroupwareResourceMetadata::AddressBook { .. } => KIND_ADDRESS_BOOK,
            GroupwareResourceMetadata::ContactCard { .. } => KIND_CONTACT_CARD,
        }
    }
}

impl FlatResource {
    fn pack(resource: &GroupwareResource, times: &mut ChunkTimes) -> Option<Self> {
        let mut flat = FlatResource {
            ref_a_off: 0,
            ref_b_off: 0,
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            v4: 0,
            etag: resource.etag(),
            document_id: resource.document_id,
            ref_a_len: 0,
            ref_b_len: 0,
            flags: 0,
        };

        match &resource.data {
            GroupwareResourceMetadata::File {
                name,
                size,
                parent_id,
                acls,
                modified,
                created_delta,
                flags,
                ..
            } => {
                flat.set_ref_a(name)?;
                flat.set_ref_b(acls)?;
                flat.v0 = *size;
                flat.v1 = *parent_id;
                flat.v2 = times.encode(*modified);
                flat.v3 = *created_delta as u32;
                flat.v4 = flags.0;
            }
            GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                ..
            } => {
                flat.set_ref_a(name)?;
                flat.set_ref_b(acls)?;
                flat.v0 = preferences.off;
                flat.v1 = preferences.len;
            }
            GroupwareResourceMetadata::CalendarEvent {
                names,
                start,
                duration,
                created_at,
                modified_at,
                uid,
                flags,
                ..
            } => {
                flat.flags = *flags;
                flat.set_ref_a(names)?;
                flat.set_ref_b(uid)?;
                flat.v0 = times.encode(*start);
                flat.v1 = times.encode(*created_at);
                flat.v2 = *duration;
                flat.v3 = *modified_at as u32;
            }
            GroupwareResourceMetadata::CalendarEventNotification {
                names,
                created_at,
                event_id,
                changed_by,
                principals,
                calendar_ids_len,
                flags,
                ..
            } => {
                flat.flags = *flags;
                flat.set_ref_a(names)?;
                flat.set_ref_b(principals)?;
                flat.v0 = times.encode(*created_at);
                flat.v1 = *event_id;
                flat.v2 = *changed_by;
                flat.v3 = *calendar_ids_len as u32;
            }
            GroupwareResourceMetadata::AddressBook { name, acls, .. } => {
                flat.set_ref_a(name)?;
                flat.set_ref_b(acls)?;
            }
            GroupwareResourceMetadata::ContactCard {
                names,
                created_at,
                modified_at,
                uid,
                ..
            } => {
                flat.set_ref_a(names)?;
                flat.set_ref_b(uid)?;
                flat.v0 = times.encode(*created_at);
                flat.v1 = *modified_at as u32;
            }
        }

        Some(flat)
    }

    fn set_ref_a(&mut self, arena: &ArenaRef) -> Option<()> {
        self.ref_a_off = arena.off;
        self.ref_a_len = u16::try_from(arena.len).ok()?;
        Some(())
    }

    fn set_ref_b(&mut self, arena: &ArenaRef) -> Option<()> {
        self.ref_b_off = arena.off;
        self.ref_b_len = u16::try_from(arena.len).ok()?;
        Some(())
    }
}

impl ArchivedFlatResource {
    fn ref_a(&self) -> ArenaRef {
        ArenaRef {
            off: self.ref_a_off.to_native(),
            len: self.ref_a_len.to_native() as u32,
        }
    }

    fn ref_b(&self) -> ArenaRef {
        ArenaRef {
            off: self.ref_b_off.to_native(),
            len: self.ref_b_len.to_native() as u32,
        }
    }

    fn unpack(&self, kind: u16, times: &ChunkTimes) -> Option<GroupwareResource> {
        let data = match kind {
            KIND_FILE => GroupwareResourceMetadata::File {
                name: self.ref_a(),
                size: self.v0.to_native(),
                parent_id: self.v1.to_native(),
                acls: self.ref_b(),
                etag: self.etag.to_native(),
                modified: times.decode(self.v2.to_native())?,
                created_delta: self.v3.to_native() as i32,
                flags: FileFlags(self.v4.to_native()),
            },
            KIND_CALENDAR => GroupwareResourceMetadata::Calendar {
                name: self.ref_a(),
                acls: self.ref_b(),
                preferences: ArenaRef {
                    off: self.v0.to_native(),
                    len: self.v1.to_native(),
                },
                etag: self.etag.to_native(),
            },
            KIND_CALENDAR_EVENT => GroupwareResourceMetadata::CalendarEvent {
                names: self.ref_a(),
                start: times.decode(self.v0.to_native())?,
                duration: self.v2.to_native(),
                created_at: times.decode(self.v1.to_native())?,
                modified_at: self.v3.to_native() as i32,
                uid: self.ref_b(),
                etag: self.etag.to_native(),
                flags: self.flags.to_native(),
            },
            KIND_CALENDAR_EVENT_NOTIFICATION => {
                GroupwareResourceMetadata::CalendarEventNotification {
                    names: self.ref_a(),
                    created_at: times.decode(self.v0.to_native())?,
                    event_id: self.v1.to_native(),
                    etag: self.etag.to_native(),
                    changed_by: self.v2.to_native(),
                    principals: self.ref_b(),
                    calendar_ids_len: u16::try_from(self.v3.to_native()).ok()?,
                    flags: self.flags.to_native(),
                }
            }
            KIND_ADDRESS_BOOK => GroupwareResourceMetadata::AddressBook {
                name: self.ref_a(),
                acls: self.ref_b(),
                etag: self.etag.to_native(),
            },
            KIND_CONTACT_CARD => GroupwareResourceMetadata::ContactCard {
                names: self.ref_a(),
                created_at: times.decode(self.v0.to_native())?,
                modified_at: self.v1.to_native() as i32,
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
    pub name_lengths: Vec<u16>,
    pub name_parents: Vec<u32>,
    pub acl_accounts: Vec<u32>,
    pub acl_grants: Vec<u64>,
    pub pref_accounts: Vec<u32>,
    pub pref_timezones: Vec<u16>,
    pub pref_flags: Vec<u16>,
    #[rkyv(with = InlineAsBox)]
    pub principals: &'x [u32],
    pub kind: u16,
    pub epoch: i64,
    pub wide_times: Vec<i64>,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedPathChunk<'x> {
    #[rkyv(with = InlineAsBox)]
    pub bytes: &'x [u8],
    pub path_lengths: Vec<u16>,
    pub hierarchy_seqs: Vec<u16>,
    pub parent_ids: Vec<u32>,
    pub document_ids: Vec<u32>,
}

const WIRE_CONTAINER_FLAG: u16 = 1 << 15;

fn fits_within(arena: ArenaRef, limit: usize) -> bool {
    (arena.off as usize)
        .checked_add(arena.len as usize)
        .is_some_and(|end| end <= limit)
}

impl GroupwareResource {
    fn fits_within(
        &self,
        bytes: usize,
        names: usize,
        acls: usize,
        prefs: usize,
        principals_len: usize,
    ) -> bool {
        match &self.data {
            GroupwareResourceMetadata::File {
                name,
                acls: acl_ref,
                flags,
                ..
            } => {
                flags.is_valid()
                    && fits_within(
                        ArenaRef {
                            off: name.off,
                            len: name.len.saturating_add(flags.extra_len() as u32),
                        },
                        bytes,
                    )
                    && fits_within(*acl_ref, acls)
            }
            GroupwareResourceMetadata::AddressBook {
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
                names: name_refs,
                principals,
                calendar_ids_len,
                ..
            } => {
                fits_within(*name_refs, names)
                    && fits_within(*principals, principals_len)
                    && *calendar_ids_len as u32 <= principals.len
            }
        }
    }
}

impl GroupwareResources {
    pub fn to_snapshot(&self) -> Option<Vec<u8>> {
        let (chunks, path_chunks) = self.pack()?;
        self.seal_snapshot(chunks, path_chunks)
    }

    #[allow(clippy::type_complexity)]
    fn pack(&self) -> Option<(Vec<ArchivedResourceChunk<'_>>, Vec<ArchivedPathChunk<'_>>)> {
        let mut chunks = Vec::with_capacity(self.resources.chunks.len());
        for chunk in &self.resources.chunks {
            let mut name_offsets = Vec::with_capacity(chunk.names.len());
            let mut name_lengths = Vec::with_capacity(chunk.names.len());
            let mut name_parents = Vec::with_capacity(chunk.names.len());
            for name in chunk.names.iter() {
                name_offsets.push(name.name.off);
                name_lengths.push(u16::try_from(name.name.len).ok()?);
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

            let kind = chunk.records.first().map_or(0, |record| record.data.kind());
            if chunk
                .records
                .iter()
                .any(|record| record.data.kind() != kind)
            {
                return None;
            }

            let mut times = ChunkTimes::for_records(&chunk.records);
            let mut records = Vec::with_capacity(chunk.records.len());
            for record in chunk.records.iter() {
                records.push(FlatResource::pack(record, &mut times)?);
            }

            chunks.push(ArchivedResourceChunk {
                records,
                bytes: &chunk.bytes,
                name_offsets,
                name_lengths,
                name_parents,
                acl_accounts,
                acl_grants,
                pref_accounts,
                pref_timezones,
                pref_flags,
                principals: &chunk.principals,
                kind,
                epoch: times.epoch,
                wide_times: times.wide,
            });
        }

        let mut path_chunks = Vec::with_capacity(self.paths.chunks.len());
        for chunk in &self.paths.chunks {
            let mut path_lengths = Vec::with_capacity(chunk.paths.len());
            let mut parent_ids = Vec::with_capacity(chunk.paths.len());
            let mut hierarchy_seqs = Vec::with_capacity(chunk.paths.len());
            let mut document_ids = Vec::with_capacity(chunk.paths.len());
            let mut next_off = 0u32;
            for path in chunk.paths.iter() {
                if path.path.off != next_off {
                    return None;
                }
                next_off += path.path.len;
                path_lengths.push(u16::try_from(path.path.len).ok()?);
                parent_ids.push(path.parent_id);
                let depth = u16::try_from(path.hierarchy_seq & !CONTAINER_FLAG).ok()?;
                if depth >= WIRE_CONTAINER_FLAG {
                    return None;
                }
                hierarchy_seqs.push(if path.hierarchy_seq & CONTAINER_FLAG != 0 {
                    depth | WIRE_CONTAINER_FLAG
                } else {
                    depth
                });
                document_ids.push(path.document_id);
            }
            if next_off as usize != chunk.bytes.len() {
                return None;
            }

            path_chunks.push(ArchivedPathChunk {
                bytes: &chunk.bytes,
                path_lengths,
                hierarchy_seqs,
                parent_ids,
                document_ids,
            });
        }

        Some((chunks, path_chunks))
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
                        len: len.to_native() as u32,
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

            let principals: Box<[u32]> = chunk
                .principals
                .iter()
                .map(|principal| principal.to_native())
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

            let times = ChunkTimes {
                epoch: chunk.epoch.to_native(),
                wide: chunk
                    .wide_times
                    .iter()
                    .map(|time| time.to_native())
                    .collect(),
            };
            let kind = chunk.kind.to_native();

            let mut records = Vec::with_capacity(chunk.records.len());
            for record in chunk.records.iter() {
                let record = record.unpack(kind, &times)?;
                if !record.fits_within(
                    bytes.len(),
                    names_len,
                    acls_len,
                    prefs_len,
                    principals.len(),
                ) {
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
                principals,
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
            let paths_len = chunk.path_lengths.len();
            if chunk.parent_ids.len() != paths_len
                || chunk.hierarchy_seqs.len() != paths_len
                || chunk.document_ids.len() != paths_len
            {
                return None;
            }

            let bytes: Box<[u8]> = (&*chunk.bytes).into();
            let mut off = 0u32;
            let paths: Box<[DavPath]> = chunk
                .path_lengths
                .iter()
                .zip(chunk.parent_ids.iter())
                .zip(chunk.hierarchy_seqs.iter())
                .zip(chunk.document_ids.iter())
                .map(|(((len, parent_id), hierarchy_seq), document_id)| {
                    let len = len.to_native() as u32;
                    let path = ArenaRef { off, len };
                    off += len;
                    let hierarchy_seq = hierarchy_seq.to_native();
                    DavPath {
                        path,
                        parent_id: parent_id.to_native(),
                        hierarchy_seq: (hierarchy_seq & !WIRE_CONTAINER_FLAG) as u32
                            | if hierarchy_seq & WIRE_CONTAINER_FLAG != 0 {
                                CONTAINER_FLAG
                            } else {
                                0
                            },
                        document_id: document_id.to_native(),
                    }
                })
                .collect();
            if paths.is_empty() || off as usize != bytes.len() {
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
    use crate::{
        DAV_CHUNK, DavName,
        storage::dav::{FILE_KIND_DIRECTORY, FILE_KIND_SYMLINK, ResourceChunkBuilder},
    };
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
                    flags: (document_id % 4) as u16 * 0x40,
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

    fn notifications(count: usize) -> GroupwareResources {
        let mut container = ResourceChunkBuilder::with_capacity(1);
        container.records.push(GroupwareResource {
            document_id: 0,
            data: GroupwareResourceMetadata::CalendarEventNotification {
                names: ArenaRef::default(),
                created_at: 0,
                event_id: crate::NO_ID,
                etag: 0,
                changed_by: crate::NO_ID,
                principals: ArenaRef::default(),
                calendar_ids_len: 0,
                flags: 0,
            },
        });

        let mut chunk = ResourceChunkBuilder::with_capacity(count);
        let mut entries = Vec::new();
        for document_id in 0..count as u32 {
            let names = chunk.push_names(&[DavName {
                name: format!("{document_id}.ics"),
                parent_id: 0,
            }]);
            let calendar_ids = [100 + document_id % 3];
            let dismissed_by: &[u32] = match document_id % 4 {
                0 => &[],
                1 => &[500],
                2 => &[500, 501],
                _ => &[501],
            };
            let principals =
                chunk.push_principals(calendar_ids.iter().chain(dismissed_by.iter()).copied());
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::CalendarEventNotification {
                    names,
                    created_at: 1_600_000_000 + document_id as i64,
                    event_id: document_id + 400,
                    etag: document_id + 800,
                    changed_by: 600 + document_id % 5,
                    principals,
                    calendar_ids_len: calendar_ids.len() as u16,
                    flags: (document_id % 4) as u16 * 0x40,
                },
            });
            entries.push((
                format!("inbox/{document_id}.ics"),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: 0,
                    hierarchy_seq: 0,
                    document_id,
                },
            ));
        }

        let mut resources = GroupwareResources {
            base_path: "/dav/cal/jane".to_string(),
            paths: Arc::new(PathIndex::pack(entries)),
            resources: ResourceStore::from_sorted(vec![container], vec![chunk], false),
            item_change_id: 11,
            container_change_id: 3,
            highest_change_id: 11,
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
            let (name, media_id, extra_len) = chunk.push_file_name(
                &format!("file {document_id}.txt"),
                match document_id % 3 {
                    0 => Some("text/plain"),
                    1 => Some("application/x-stalwart-test"),
                    _ => None,
                },
            );
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
                    modified: 1_700_000_000 + document_id as i64,
                    created_delta: -(document_id as i32),
                    flags: FileFlags::new(
                        if document_id % 5 == 0 {
                            FILE_KIND_DIRECTORY
                        } else {
                            FILE_KIND_SYMLINK
                        },
                        document_id % 7 == 0,
                        (document_id % 10) as u8,
                        media_id,
                        extra_len,
                    ),
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
            assert_eq!(a.event_flags(), b.event_flags());
            assert_eq!(a.event_id(), b.event_id());
            assert_eq!(a.container_name(), b.container_name());
            assert_eq!(a.file_flags(), b.file_flags());
            assert_eq!(a.media_type(), b.media_type());
            assert_eq!(a.has_acls(), b.has_acls());
            assert_eq!(a.notification(), b.notification());
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

    fn uuid(seed: u32) -> String {
        let mut h = 0xcbf29ce484222325u64;
        for byte in seed.to_le_bytes() {
            h = (h ^ byte as u64).wrapping_mul(0x100000001b3);
        }
        let lo = h.wrapping_mul(0x9e3779b97f4a7c15);
        format!(
            "{:08X}-{:04X}-4{:03X}-8{:03X}-{:012X}",
            h as u32,
            (h >> 32) as u16,
            (h >> 48) & 0xfff,
            lo & 0xfff,
            lo >> 16
        )
    }

    fn calcard_uuid(items: usize) -> GroupwareResources {
        const CALENDARS: [&str; 3] = ["Personal", "Work", "Family"];
        let mut containers = Vec::new();
        let mut chunk = ResourceChunkBuilder::with_capacity(4);
        let mut entries = Vec::new();

        for (document_id, calendar) in CALENDARS.iter().enumerate() {
            let document_id = document_id as u32;
            let name = chunk.push_str(calendar);
            let acls = chunk.push_acls(&[grants(document_id + 100)]);
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
                calendar.to_string(),
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
            let id = uuid(document_id);
            let names = chunk.push_names(&[DavName {
                name: format!("{id}.ics"),
                parent_id,
            }]);
            let uid = chunk.push_uid(&id, names);
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::CalendarEvent {
                    names,
                    start: 1_700_000_000 + document_id as i64 * 900,
                    duration: 3600,
                    created_at: 1_600_000_000 + document_id as i64,
                    modified_at: -(document_id as i32) - 1,
                    etag: document_id + 800,
                    uid,
                    flags: (document_id % 4) as u16 * 0x40,
                },
            });
            entries.push((
                format!("{}/{id}.ics", CALENDARS[parent_id as usize]),
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

    fn contacts(items: usize) -> GroupwareResources {
        let mut containers = Vec::new();
        let mut chunk = ResourceChunkBuilder::with_capacity(4);
        let mut entries = Vec::new();

        for document_id in 0..3u32 {
            let name = chunk.push_str(&format!("addressbook-{document_id}"));
            let acls = chunk.push_acls(&[grants(document_id + 100), grants(document_id + 200)]);
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::AddressBook {
                    name,
                    acls,
                    etag: document_id + 700,
                },
            });
            entries.push((
                format!("addressbook-{document_id}"),
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
                name: format!("card-{document_id}.vcf"),
                parent_id,
            }]);
            let uid = chunk.push_str(&format!("uid-{document_id}@example.org"));
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::ContactCard {
                    names,
                    created_at: 1_600_000_000 + document_id as i64,
                    modified_at: -(document_id as i32) - 1,
                    uid,
                    etag: document_id + 800,
                },
            });
            entries.push((
                format!("addressbook-{parent_id}/card-{document_id}.vcf"),
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
            base_path: "/dav/card/jane".to_string(),
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

    #[test]
    fn perf_probe() {
        if std::env::var("SWAP_PERF").is_err() {
            return;
        }
        use std::time::Instant;

        fn p50(mut v: Vec<f64>) -> f64 {
            v.sort_by(f64::total_cmp);
            v[v.len() / 2]
        }

        fn min(v: &[f64]) -> f64 {
            v.iter().copied().fold(f64::INFINITY, f64::min)
        }

        type Fixture = (&'static str, fn(usize) -> GroupwareResources);

        let fixtures: [Fixture; 5] = [
            ("calcard", calcard),
            ("calcard_uuid", calcard_uuid),
            ("contacts", contacts),
            ("files", files),
            ("notifications", notifications),
        ];

        println!(
            "{:<14} {:>8} {:>7} {:>12} {:>9} {:>12} {:>9} {:>10} {:>10} {:>10} {:>10}",
            "fixture",
            "n",
            "chunks",
            "snap_bytes",
            "snap/res",
            "mem_bytes",
            "mem/res",
            "dec_p50",
            "dec_min",
            "enc_p50",
            "enc_min"
        );

        for (name, build) in fixtures {
            for n in [50_000usize, 500_000] {
                let resources = build(n);
                let encoded = resources.to_snapshot().expect("encode");
                let len = resources.resources.len() as f64;

                for _ in 0..3 {
                    std::hint::black_box(GroupwareResources::from_snapshot(&encoded));
                }

                let mut decode = Vec::new();
                let mut frame = Vec::new();
                let mut access = Vec::new();
                for _ in 0..15 {
                    let t = Instant::now();
                    let out = GroupwareResources::from_snapshot(&encoded).expect("decode");
                    decode.push(t.elapsed().as_secs_f64() * 1000.0);
                    std::hint::black_box(out.resources.len());

                    let t = Instant::now();
                    let f = SwapFrame::parse(&encoded).expect("frame");
                    frame.push(t.elapsed().as_secs_f64() * 1000.0);
                    std::hint::black_box(f.payload().len());

                    let t = Instant::now();
                    let a = rkyv::access::<ArchivedArchivedResources, rkyv::rancor::Error>(
                        SwapFrame::parse(&encoded).unwrap().payload(),
                    )
                    .unwrap();
                    access.push(t.elapsed().as_secs_f64() * 1000.0);
                    std::hint::black_box(a.chunks.len());
                }
                if std::env::var("SWAP_PERF_BREAKDOWN").is_ok() {
                    println!(
                        "    [{name} {n}] frame(xxh3) p50 = {:.3} ms, rkyv access p50 = {:.3} ms, total decode p50 = {:.3} ms",
                        p50(frame.clone()),
                        p50(access.clone()),
                        p50(decode.clone())
                    );
                }

                let mut encode = Vec::new();
                for _ in 0..15 {
                    let t = Instant::now();
                    let out = resources.to_snapshot().expect("encode");
                    encode.push(t.elapsed().as_secs_f64() * 1000.0);
                    std::hint::black_box(out.len());
                }

                println!(
                    "{:<14} {:>8} {:>7} {:>12} {:>9.2} {:>12} {:>9.2} {:>10.3} {:>10.3} {:>10.3} {:>10.3}",
                    name,
                    n,
                    resources.resources.chunks.len(),
                    encoded.len(),
                    encoded.len() as f64 / len,
                    resources.size,
                    resources.size as f64 / len,
                    p50(decode.clone()),
                    min(&decode),
                    p50(encode.clone()),
                    min(&encode),
                );
            }
        }
    }

    #[test]
    fn calcard_uuid_snapshot_round_trips() {
        let resources = calcard_uuid(DAV_CHUNK + 100);
        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
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
    fn notification_snapshot_round_trips() {
        let resources = notifications(300);
        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
    }

    #[test]
    fn a_uid_that_prefixes_its_name_is_not_stored_twice() {
        const EVENTS: usize = 1000;
        let shared = calcard_uuid(EVENTS);
        let arena = shared.resources.chunks[shared.resources.containers_end..]
            .iter()
            .map(|chunk| chunk.bytes.len())
            .sum::<usize>();
        let names = shared.resources.chunks[shared.resources.containers_end..]
            .iter()
            .flat_map(|chunk| chunk.names.iter())
            .map(|name| name.name.len as usize)
            .sum::<usize>();
        assert_eq!(
            arena, names,
            "a `<uid>.ics` name must share its bytes with the uid"
        );
        assert_eq!(
            names,
            EVENTS * "00000000-0000-4000-8000-000000000000.ics".len()
        );
        let encoded = shared.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&shared, &decoded);
        assert_eq!(decoded.size, shared.size);
    }

    #[test]
    fn timestamps_far_from_the_chunk_epoch_round_trip() {
        let mut chunk = ResourceChunkBuilder::with_capacity(4);
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        let name = containers.push_str("work");
        let acls = containers.push_acls(&[]);
        let preferences = containers.push_prefs(&[]);
        containers.records.push(GroupwareResource {
            document_id: 0,
            data: GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag: 0,
            },
        });

        let starts = [i64::MIN, -1, 0, 1_700_000_000, i64::MAX];
        for (document_id, start) in starts.iter().enumerate() {
            let document_id = document_id as u32;
            let names = chunk.push_names(&[DavName {
                name: format!("{document_id}.ics"),
                parent_id: 0,
            }]);
            let uid = chunk.push_uid(&format!("{document_id}"), names);
            chunk.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::CalendarEvent {
                    names,
                    start: *start,
                    duration: 3600,
                    created_at: 1_600_000_000,
                    modified_at: 0,
                    etag: document_id,
                    uid,
                    flags: 0,
                },
            });
        }

        let mut resources = GroupwareResources {
            base_path: "/dav/cal/jane".to_string(),
            paths: Arc::new(PathIndex::pack(
                starts
                    .iter()
                    .enumerate()
                    .map(|(document_id, _)| {
                        (
                            format!("work/{document_id}.ics"),
                            DavPath {
                                path: ArenaRef::default(),
                                parent_id: 0,
                                hierarchy_seq: 0,
                                document_id: document_id as u32,
                            },
                        )
                    })
                    .collect(),
            )),
            resources: ResourceStore::from_sorted(vec![containers], vec![chunk], false),
            item_change_id: 1,
            container_change_id: 1,
            highest_change_id: 1,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        resources.recompute_size();

        let encoded = resources.to_snapshot().expect("encode");
        let decoded = GroupwareResources::from_snapshot(&encoded).expect("decode");
        assert_same(&resources, &decoded);
        for (resource, start) in decoded.resources.iter().skip(1).zip(starts.iter()) {
            assert_eq!(
                resource.event_time_range().map(|range| range.0),
                Some(*start)
            );
        }
    }

    #[test]
    fn identical_principal_runs_are_interned() {
        const DISTINCT_RUNS: usize = 24;
        let resources = notifications(300);
        let principals = resources
            .resources
            .chunks
            .iter()
            .map(|chunk| chunk.principals.len())
            .sum::<usize>();
        assert_eq!(
            principals, DISTINCT_RUNS,
            "the principal arena must hold one entry per distinct run, not per record"
        );
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

        let (mut chunks, path_chunks) = resources.pack().unwrap();
        chunks[0].records[0].ref_a_off = u32::MAX - 1;
        assert!(
            GroupwareResources::from_snapshot(
                &resources.seal_snapshot(chunks, path_chunks).unwrap()
            )
            .is_none(),
            "an arena offset past the end of the chunk was accepted"
        );

        let (mut chunks, path_chunks) = resources.pack().unwrap();
        chunks[0].records[0].ref_b_len = u16::MAX;
        assert!(
            GroupwareResources::from_snapshot(
                &resources.seal_snapshot(chunks, path_chunks).unwrap()
            )
            .is_none(),
            "an arena length past the end of the chunk was accepted"
        );

        let (chunks, mut path_chunks) = resources.pack().unwrap();
        path_chunks[0].path_lengths[0] = u16::MAX;
        assert!(
            GroupwareResources::from_snapshot(
                &resources.seal_snapshot(chunks, path_chunks).unwrap()
            )
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
