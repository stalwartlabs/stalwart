/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavName, DavPath, DavResource, DavResourceMetadata, DavResourcePath, DavResources,
    TinyCalendarPreferences,
};
use std::hash::{Hash, Hasher};
use store::rand::{Rng, distr::Alphanumeric};
use types::acl::AclGrant;

const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;

impl DavResourcePath<'_> {
    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.resource.document_id
    }

    #[inline(always)]
    pub fn parent_id(&self) -> Option<u32> {
        self.path.parent_id
    }

    #[inline(always)]
    pub fn path(&self) -> &str {
        self.path.path.as_str()
    }

    #[inline(always)]
    pub fn is_container(&self) -> bool {
        self.resource.is_container()
    }

    #[inline(always)]
    pub fn hierarchy_seq(&self) -> u32 {
        self.path.hierarchy_seq
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.resource.size().unwrap_or_default()
    }
}

impl DavResources {
    pub fn by_path(&self, name: &str) -> Option<DavResourcePath<'_>> {
        self.paths.get(name).map(|path| DavResourcePath {
            path,
            resource: &self.resources[path.resource_idx],
        })
    }

    pub fn container_resource_by_id(&self, id: u32) -> Option<&DavResource> {
        self.resources
            .iter()
            .find(|res| res.document_id == id && res.is_container())
    }

    pub fn container_resource_path_by_id(&self, id: u32) -> Option<DavResourcePath<'_>> {
        self.resources
            .iter()
            .enumerate()
            .find(|(_, resource)| resource.document_id == id && resource.is_container())
            .and_then(|(idx, resource)| {
                self.paths
                    .iter()
                    .find(|path| path.resource_idx == idx)
                    .map(|path| DavResourcePath { path, resource })
            })
    }

    pub fn any_resource_path_by_id(&self, id: u32) -> Option<DavResourcePath<'_>> {
        self.resources
            .iter()
            .enumerate()
            .find(|(_, resource)| resource.document_id == id)
            .and_then(|(idx, resource)| {
                self.paths
                    .iter()
                    .find(|path| path.resource_idx == idx)
                    .map(|path| DavResourcePath { path, resource })
            })
    }

    pub fn subtree(&self, search_path: &str) -> impl Iterator<Item = DavResourcePath<'_>> {
        let prefix = format!("{search_path}/");
        self.paths.iter().filter_map(move |path| {
            if path.path.starts_with(&prefix) || path.path == search_path {
                Some(DavResourcePath {
                    path,
                    resource: &self.resources[path.resource_idx],
                })
            } else {
                None
            }
        })
    }

    pub fn subtree_with_depth(
        &self,
        search_path: &str,
        depth: usize,
    ) -> impl Iterator<Item = DavResourcePath<'_>> {
        let prefix = format!("{search_path}/");
        self.paths.iter().filter_map(move |path| {
            if path
                .path
                .strip_prefix(&prefix)
                .is_some_and(|name| name.as_bytes().iter().filter(|&&c| c == b'/').count() < depth)
                || path.path.as_str() == search_path
            {
                Some(DavResourcePath {
                    path,
                    resource: &self.resources[path.resource_idx],
                })
            } else {
                None
            }
        })
    }

    pub fn tree_with_depth(&self, depth: usize) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.paths.iter().filter_map(move |path| {
            if path.path.as_bytes().iter().filter(|&&c| c == b'/').count() <= depth {
                Some(DavResourcePath {
                    path,
                    resource: &self.resources[path.resource_idx],
                })
            } else {
                None
            }
        })
    }

    pub fn children(&self, parent_id: u32) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.paths
            .iter()
            .filter(move |item| item.parent_id.is_some_and(|id| id == parent_id))
            .map(|path| DavResourcePath {
                path,
                resource: &self.resources[path.resource_idx],
            })
    }

    pub fn children_ids(&self, parent_id: u32) -> impl Iterator<Item = u32> {
        self.paths
            .iter()
            .filter(move |item| item.parent_id.is_some_and(|id| id == parent_id))
            .map(|path| self.resources[path.resource_idx].document_id)
    }

    pub fn format_resource(&self, resource: DavResourcePath<'_>) -> String {
        if resource.resource.is_container() {
            format!("{}{}/", self.base_path, resource.path.path)
        } else {
            format!("{}{}", self.base_path, resource.path.path)
        }
    }

    pub fn format_collection(&self, name: &str) -> String {
        format!("{}{name}/", self.base_path)
    }

    pub fn format_item(&self, name: &str) -> String {
        format!("{}{}", self.base_path, name)
    }
}

impl DavResource {
    pub fn is_child_of(&self, parent_id: u32) -> bool {
        match &self.data {
            DavResourceMetadata::File { parent_id: id, .. } => id.is_some_and(|id| id == parent_id),
            DavResourceMetadata::CalendarEvent { names, .. } => {
                names.iter().any(|name| name.parent_id == parent_id)
            }
            DavResourceMetadata::ContactCard { names } => {
                names.iter().any(|name| name.parent_id == parent_id)
            }
            DavResourceMetadata::CalendarEventNotification { names } => {
                names.is_empty() && parent_id == SCHEDULE_INBOX_ID
            }
            _ => false,
        }
    }

    pub fn parent_id(&self) -> Option<u32> {
        match &self.data {
            DavResourceMetadata::File { parent_id, .. } => *parent_id,
            DavResourceMetadata::CalendarEvent { names, .. } => {
                names.first().map(|name| name.parent_id)
            }
            DavResourceMetadata::ContactCard { names } => names.first().map(|name| name.parent_id),
            DavResourceMetadata::CalendarEventNotification { names } if names.is_empty() => {
                Some(SCHEDULE_INBOX_ID)
            }
            _ => None,
        }
    }

    pub fn child_names(&self) -> Option<&[DavName]> {
        match &self.data {
            DavResourceMetadata::CalendarEvent { names, .. } => Some(names.as_slice()),
            DavResourceMetadata::ContactCard { names } => Some(names.as_slice()),
            DavResourceMetadata::CalendarEventNotification { names } if !names.is_empty() => {
                Some(names.as_slice())
            }
            _ => None,
        }
    }

    pub fn container_name(&self) -> Option<&str> {
        match &self.data {
            DavResourceMetadata::File { name, .. } => Some(name.as_str()),
            DavResourceMetadata::Calendar { name, .. } => Some(name.as_str()),
            DavResourceMetadata::AddressBook { name, .. } => Some(name.as_str()),
            DavResourceMetadata::CalendarEventNotification { names } if names.is_empty() => {
                Some(if self.document_id == SCHEDULE_INBOX_ID {
                    "inbox"
                } else {
                    "outbox"
                })
            }
            _ => None,
        }
    }

    pub fn has_hierarchy_changes(&self, other: &DavResource) -> bool {
        match (&self.data, &other.data) {
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
            ) => a != b || c != d,
            (
                DavResourceMetadata::Calendar { name: a, .. },
                DavResourceMetadata::Calendar { name: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::AddressBook { name: a, .. },
                DavResourceMetadata::AddressBook { name: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::CalendarEvent { names: a, .. },
                DavResourceMetadata::CalendarEvent { names: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::ContactCard { names: a, .. },
                DavResourceMetadata::ContactCard { names: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::CalendarEventNotification { names: a, .. },
                DavResourceMetadata::CalendarEventNotification { names: b, .. },
            ) => a != b,
            _ => unreachable!(),
        }
    }

    pub fn event_time_range(&self) -> Option<(i64, i64)> {
        match &self.data {
            DavResourceMetadata::CalendarEvent {
                start, duration, ..
            } => Some((*start, *start + *duration as i64)),
            _ => None,
        }
    }

    pub fn calendar_preferences(&self, account_id: u32) -> Option<&TinyCalendarPreferences> {
        match &self.data {
            DavResourceMetadata::Calendar { preferences, .. } => preferences
                .iter()
                .find(|pref| pref.account_id == account_id)
                .or_else(|| preferences.first()),
            _ => None,
        }
    }

    pub fn is_container(&self) -> bool {
        match &self.data {
            DavResourceMetadata::File { size, .. } => size.is_none(),
            DavResourceMetadata::Calendar { .. } | DavResourceMetadata::AddressBook { .. } => true,
            DavResourceMetadata::CalendarEventNotification { names } => names.is_empty(),
            _ => false,
        }
    }

    pub fn size(&self) -> Option<u32> {
        match &self.data {
            DavResourceMetadata::File { size, .. } => *size,
            _ => None,
        }
    }

    pub fn acls(&self) -> Option<&[AclGrant]> {
        match &self.data {
            DavResourceMetadata::File { acls, .. } => Some(acls.as_slice()),
            DavResourceMetadata::Calendar { acls, .. } => Some(acls.as_slice()),
            DavResourceMetadata::AddressBook { acls, .. } => Some(acls.as_slice()),
            _ => None,
        }
    }
}

impl Hash for DavPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl PartialEq for DavPath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for DavPath {}

impl std::borrow::Borrow<str> for DavPath {
    fn borrow(&self) -> &str {
        &self.path
    }
}

impl std::hash::Hash for DavResource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.document_id.hash(state);
    }
}

impl PartialEq for DavResource {
    fn eq(&self, other: &Self) -> bool {
        self.document_id == other.document_id
    }
}

impl Eq for DavResource {}

impl std::borrow::Borrow<u32> for DavResource {
    fn borrow(&self) -> &u32 {
        &self.document_id
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
