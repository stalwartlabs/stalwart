/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ArenaRef, CachedName, DavName, DavPath, DavResource, DavResourceMetadata, DavResourcePath,
    DavResourceRef, DavResources, NO_ID, PathChunk, TinyCalendarPreferences,
};
use store::rand::{RngExt, distr::Alphanumeric};
use types::acl::AclGrant;

use super::{CONTAINER_FLAG, SCHEDULE_INBOX_ID};

impl DavResourceRef<'_> {
    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.resource.document_id
    }

    #[inline(always)]
    pub fn is_container(&self) -> bool {
        self.resource.is_container()
    }

    #[inline(always)]
    pub fn size(&self) -> Option<u32> {
        self.resource.size()
    }

    #[inline(always)]
    pub fn is_child_of(&self, parent_id: u32) -> bool {
        self.resource.is_child_of(parent_id)
    }

    #[inline(always)]
    pub fn parent_id(&self) -> Option<u32> {
        self.resource.parent_id()
    }

    #[inline(always)]
    pub fn event_time_range(&self) -> Option<(i64, i64)> {
        self.resource.event_time_range()
    }

    #[inline(always)]
    pub fn created_at(&self) -> Option<i64> {
        self.resource.created_at()
    }

    #[inline(always)]
    pub fn modified_at(&self) -> Option<i64> {
        self.resource.modified_at()
    }

    #[inline(always)]
    pub fn event_id(&self) -> Option<u32> {
        self.resource.event_id()
    }

    #[inline(always)]
    pub fn etag(&self) -> u32 {
        self.resource.etag()
    }

    #[inline(always)]
    pub fn uid(&self) -> Option<&str> {
        match &self.resource.data {
            DavResourceMetadata::CalendarEvent { uid, .. }
            | DavResourceMetadata::ContactCard { uid, .. } => Some(self.chunk.str_at(*uid)),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn container_name(&self) -> Option<&str> {
        match &self.resource.data {
            DavResourceMetadata::File { name, .. }
            | DavResourceMetadata::Calendar { name, .. }
            | DavResourceMetadata::AddressBook { name, .. } => Some(self.chunk.str_at(*name)),
            DavResourceMetadata::CalendarEventNotification { names, .. } if names.is_empty() => {
                Some(if self.resource.document_id == SCHEDULE_INBOX_ID {
                    "inbox"
                } else {
                    "outbox"
                })
            }
            _ => None,
        }
    }

    #[inline(always)]
    pub fn child_names(&self) -> &[CachedName] {
        match self.resource.names_ref() {
            Some(names) => self.chunk.names_at(names),
            None => &[],
        }
    }

    #[inline(always)]
    pub fn child_name_at(&self, name: &CachedName) -> &str {
        self.chunk.str_at(name.name)
    }

    #[inline(always)]
    pub fn acls(&self) -> &[AclGrant] {
        match self.resource.acls_ref() {
            Some(acls) => self.chunk.acls_at(acls),
            None => &[],
        }
    }

    #[inline(always)]
    pub fn has_acls(&self) -> bool {
        self.resource
            .acls_ref()
            .is_some_and(|acls| !acls.is_empty())
    }

    pub fn calendar_preferences(&self, account_id: u32) -> Option<&TinyCalendarPreferences> {
        match &self.resource.data {
            DavResourceMetadata::Calendar { preferences, .. } => {
                let prefs = self.chunk.prefs_at(*preferences);
                prefs
                    .iter()
                    .find(|pref| pref.account_id == account_id)
                    .or_else(|| prefs.first())
            }
            _ => None,
        }
    }

    pub fn has_hierarchy_changes(&self, other: &DavResourceRef<'_>) -> bool {
        match (&self.resource.data, &other.resource.data) {
            (
                DavResourceMetadata::File {
                    name: a,
                    parent_id: c,
                    ..
                },
                DavResourceMetadata::File {
                    name: b,
                    parent_id: d,
                    ..
                },
            ) => c != d || self.chunk.str_at(*a) != other.chunk.str_at(*b),
            (
                DavResourceMetadata::Calendar { name: a, .. },
                DavResourceMetadata::Calendar { name: b, .. },
            )
            | (
                DavResourceMetadata::AddressBook { name: a, .. },
                DavResourceMetadata::AddressBook { name: b, .. },
            ) => self.chunk.str_at(*a) != other.chunk.str_at(*b),
            _ => {
                let a = self.child_names();
                let b = other.child_names();
                a.len() != b.len()
                    || a.iter().zip(b.iter()).any(|(x, y)| {
                        x.parent_id != y.parent_id
                            || self.chunk.str_at(x.name) != other.chunk.str_at(y.name)
                    })
            }
        }
    }
}

impl DavResource {
    #[inline(always)]
    pub fn names_ref(&self) -> Option<ArenaRef> {
        match &self.data {
            DavResourceMetadata::CalendarEvent { names, .. }
            | DavResourceMetadata::ContactCard { names, .. }
            | DavResourceMetadata::CalendarEventNotification { names, .. } => Some(*names),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn acls_ref(&self) -> Option<ArenaRef> {
        match &self.data {
            DavResourceMetadata::File { acls, .. }
            | DavResourceMetadata::Calendar { acls, .. }
            | DavResourceMetadata::AddressBook { acls, .. } => Some(*acls),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn is_container(&self) -> bool {
        match &self.data {
            DavResourceMetadata::File { size, .. } => *size == NO_ID,
            DavResourceMetadata::Calendar { .. } | DavResourceMetadata::AddressBook { .. } => true,
            DavResourceMetadata::CalendarEventNotification { names, .. } => names.is_empty(),
            _ => false,
        }
    }

    #[inline(always)]
    pub fn size(&self) -> Option<u32> {
        match &self.data {
            DavResourceMetadata::File { size, .. } if *size != NO_ID => Some(*size),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn parent_id(&self) -> Option<u32> {
        match &self.data {
            DavResourceMetadata::File { parent_id, .. } if *parent_id != NO_ID => Some(*parent_id),
            DavResourceMetadata::CalendarEventNotification { names, .. } if names.is_empty() => {
                Some(SCHEDULE_INBOX_ID)
            }
            _ => None,
        }
    }

    #[inline(always)]
    pub fn event_time_range(&self) -> Option<(i64, i64)> {
        match &self.data {
            DavResourceMetadata::CalendarEvent {
                start, duration, ..
            } => Some((*start, *start + *duration as i64)),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn created_at(&self) -> Option<i64> {
        match &self.data {
            DavResourceMetadata::CalendarEvent { created_at, .. }
            | DavResourceMetadata::ContactCard { created_at, .. }
            | DavResourceMetadata::CalendarEventNotification { created_at, .. } => {
                Some(*created_at)
            }
            _ => None,
        }
    }

    #[inline(always)]
    pub fn modified_at(&self) -> Option<i64> {
        match &self.data {
            DavResourceMetadata::CalendarEvent {
                created_at,
                modified_at,
                ..
            }
            | DavResourceMetadata::ContactCard {
                created_at,
                modified_at,
                ..
            } => Some(*created_at + *modified_at as i64),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn event_id(&self) -> Option<u32> {
        match &self.data {
            DavResourceMetadata::CalendarEventNotification { event_id, .. } => Some(*event_id),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn etag(&self) -> u32 {
        match &self.data {
            DavResourceMetadata::File { etag, .. }
            | DavResourceMetadata::Calendar { etag, .. }
            | DavResourceMetadata::CalendarEvent { etag, .. }
            | DavResourceMetadata::CalendarEventNotification { etag, .. }
            | DavResourceMetadata::AddressBook { etag, .. }
            | DavResourceMetadata::ContactCard { etag, .. } => *etag,
        }
    }

    pub fn is_child_of(&self, parent_id: u32) -> bool {
        match &self.data {
            DavResourceMetadata::File { parent_id: id, .. } => *id == parent_id,
            DavResourceMetadata::CalendarEventNotification { names, .. } => {
                names.is_empty() && parent_id == SCHEDULE_INBOX_ID
            }
            _ => false,
        }
    }
}

impl DavResourcePath<'_> {
    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.path.document_id
    }

    #[inline(always)]
    pub fn parent_id(&self) -> Option<u32> {
        (self.path.parent_id != NO_ID).then_some(self.path.parent_id)
    }

    #[inline(always)]
    pub fn path(&self) -> &str {
        std::str::from_utf8(&self.path_chunk.bytes[self.path.path.range()]).unwrap_or_default()
    }

    #[inline(always)]
    pub fn is_container(&self) -> bool {
        self.resource.is_container()
    }

    #[inline(always)]
    pub fn hierarchy_seq(&self) -> u32 {
        self.path.hierarchy_seq & !CONTAINER_FLAG
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.resource.size().unwrap_or_default()
    }
}

impl DavName {
    pub fn new(name: String, parent_id: u32) -> Self {
        Self { name, parent_id }
    }

    pub fn new_with_rand_name(parent_id: u32) -> Self {
        Self {
            name: store::rand::rng()
                .sample_iter(Alphanumeric)
                .take(10)
                .map(char::from)
                .collect::<String>(),
            parent_id,
        }
    }
}

impl DavResources {
    fn pair<'x>(&'x self, entry: (&'x PathChunk, &'x DavPath)) -> Option<DavResourcePath<'x>> {
        let (path_chunk, path) = entry;
        let want_container = path.hierarchy_seq & CONTAINER_FLAG != 0;
        self.resources
            .find(path.document_id, want_container)
            .map(|resource| DavResourcePath {
                path,
                path_chunk,
                resource,
            })
    }

    pub fn by_path(&self, name: &str) -> Option<DavResourcePath<'_>> {
        self.paths.get(name).and_then(|entry| self.pair(entry))
    }

    pub fn container_resource_by_id(&self, id: u32) -> Option<DavResourceRef<'_>> {
        self.resources.find(id, true)
    }

    pub fn item_by_id(&self, id: u32) -> Option<DavResourceRef<'_>> {
        self.resources.find(id, false)
    }

    fn path_entries_by_id(&self, document_id: u32) -> Option<Vec<(&PathChunk, &DavPath)>> {
        let mut entries = Vec::with_capacity(2);

        let found = if self.resources.unified_id_space {
            [self.resources.find_any(document_id), None]
        } else {
            [
                self.resources.find(document_id, true),
                self.resources.find(document_id, false),
            ]
        };

        for resource in found.into_iter().flatten() {
            for (path, _) in self.materialized_paths(&resource)? {
                let entry = self.paths.get(&path)?;
                if entry.1.document_id != document_id {
                    return None;
                }
                entries.push(entry);
            }
        }

        Some(entries)
    }

    pub fn container_resource_path_by_id(&self, id: u32) -> Option<DavResourcePath<'_>> {
        self.resources.find(id, true)?;
        match self.container_path_entry(id) {
            Some(entry) => self.pair(entry),
            None => self
                .paths
                .iter()
                .find(|(_, path)| {
                    path.document_id == id && path.hierarchy_seq & CONTAINER_FLAG != 0
                })
                .and_then(|entry| self.pair(entry)),
        }
    }

    pub fn any_resource_path_by_id(&self, id: u32) -> Option<DavResourcePath<'_>> {
        match self.path_entries_by_id(id) {
            Some(entries) => entries
                .into_iter()
                .next()
                .and_then(|entry| self.pair(entry)),
            None => self
                .paths
                .iter()
                .find(|(_, path)| path.document_id == id)
                .and_then(|entry| self.pair(entry)),
        }
    }

    pub fn subtree(&self, search_path: &str) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.by_path(search_path).into_iter().chain(
            self.paths
                .range(format!("{search_path}/"))
                .filter_map(move |entry| self.pair(entry)),
        )
    }

    pub fn subtree_with_depth(
        &self,
        search_path: &str,
        depth: usize,
    ) -> impl Iterator<Item = DavResourcePath<'_>> {
        let prefix = format!("{search_path}/");
        let cut = prefix.len();
        self.by_path(search_path)
            .into_iter()
            .chain(self.paths.range(prefix).filter_map(move |entry| {
                (entry.0.path_str(entry.1).as_bytes()[cut..]
                    .iter()
                    .filter(|&&c| c == b'/')
                    .count()
                    < depth)
                    .then(|| self.pair(entry))
                    .flatten()
            }))
    }

    pub fn tree_with_depth(&self, depth: usize) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.paths.iter().filter_map(move |entry| {
            let path =
                std::str::from_utf8(&entry.0.bytes[entry.1.path.range()]).unwrap_or_default();
            (path.as_bytes().iter().filter(|&&c| c == b'/').count() <= depth)
                .then(|| self.pair(entry))
                .flatten()
        })
    }

    fn child_entries(&self, parent_id: u32) -> impl Iterator<Item = (&PathChunk, &DavPath)> {
        let prefix = match self.container_path_entry(parent_id) {
            Some((chunk, path)) => format!("{}/", chunk.path_str(path)),
            None => String::new(),
        };
        self.paths
            .range(prefix)
            .filter(move |(_, path)| path.parent_id == parent_id)
    }

    pub fn children(&self, parent_id: u32) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.child_entries(parent_id)
            .filter_map(move |entry| self.pair(entry))
    }

    pub fn children_ids(&self, parent_id: u32) -> impl Iterator<Item = u32> {
        self.child_entries(parent_id)
            .map(|(_, path)| path.document_id)
    }

    pub fn format_resource(&self, resource: DavResourcePath<'_>) -> String {
        if resource.is_container() {
            format!("{}{}/", self.base_path, resource.path())
        } else {
            format!("{}{}", self.base_path, resource.path())
        }
    }

    pub fn format_resource_paths_by_id(&self, document_id: u32) -> std::vec::IntoIter<String> {
        match self.path_entries_by_id(document_id) {
            Some(entries) => entries
                .into_iter()
                .filter_map(|entry| self.pair(entry))
                .map(|resource| self.format_resource(resource))
                .collect::<Vec<_>>(),
            None => self
                .paths
                .iter()
                .filter(|(_, path)| path.document_id == document_id)
                .filter_map(|entry| self.pair(entry))
                .map(|resource| self.format_resource(resource))
                .collect::<Vec<_>>(),
        }
        .into_iter()
    }

    pub fn format_resource_path_by_parent(
        &self,
        document_id: u32,
        parent_id: u32,
    ) -> Option<String> {
        match self.path_entries_by_id(document_id) {
            Some(entries) => entries
                .into_iter()
                .find(|(_, path)| path.parent_id == parent_id),
            None => self
                .paths
                .iter()
                .find(|(_, path)| path.document_id == document_id && path.parent_id == parent_id),
        }
        .and_then(|entry| self.pair(entry))
        .map(|resource| self.format_resource(resource))
    }

    pub fn format_collection(&self, name: &str) -> String {
        format!("{}{name}/", self.base_path)
    }

    pub fn format_item(&self, name: &str) -> String {
        format!("{}{}", self.base_path, name)
    }

    #[inline(always)]
    pub fn containers(&self) -> impl Iterator<Item = DavResourceRef<'_>> + '_ {
        self.resources.iter().filter(|r| r.is_container())
    }

    #[inline(always)]
    pub fn resources_with_acls(&self) -> impl Iterator<Item = DavResourceRef<'_>> + '_ {
        self.resources.iter_with_acls()
    }

    pub fn recompute_size(&mut self) {
        self.size = std::mem::size_of::<DavResources>() as u64
            + self.base_path.len() as u64
            + self.resources.heap_size()
            + self.paths.heap_size();
    }
}
