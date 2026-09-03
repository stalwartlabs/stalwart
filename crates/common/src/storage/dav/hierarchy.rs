/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CONTAINER_FLAG, encode_path_segment};
use crate::{
    ArenaRef, DavPath, DavResourceMetadata, DavResourceRef, DavResources, NO_ID, PathChunk,
    PathIndex, ResourceChunk, ResourceStore,
};
use ahash::{AHashMap, AHashSet};

const MAX_HIERARCHY_DEPTH: usize = 128;

pub enum PathUpdate {
    Shared,
    Patched(PathIndex),
    Rebuild,
}

impl DavResources {
    pub fn patch_paths(
        &self,
        previous: &ResourceStore,
        staging: &ResourceChunk,
        changes: &AHashMap<(bool, u32), Option<u32>>,
    ) -> PathUpdate {
        let mut removes: AHashSet<String> = AHashSet::with_capacity(changes.len());
        let mut adds: Vec<(String, DavPath)> = Vec::with_capacity(changes.len());

        for ((is_container, document_id), slot) in changes {
            let old = if previous.unified_id_space {
                previous.find_any(*document_id)
            } else {
                previous.find(*document_id, *is_container)
            };
            let new = slot.map(|slot| DavResourceRef {
                chunk: staging,
                resource: &staging.records[slot as usize],
            });

            match (old, new) {
                (Some(old), Some(new)) => {
                    if old.is_container() != new.is_container() {
                        return PathUpdate::Rebuild;
                    }
                    if !new.has_hierarchy_changes(&old) {
                        continue;
                    }
                    if old.is_container() {
                        return PathUpdate::Rebuild;
                    }
                    let (Some(before), Some(after)) =
                        (self.materialized_paths(&old), self.materialized_paths(&new))
                    else {
                        return PathUpdate::Rebuild;
                    };
                    removes.extend(before.into_iter().map(|(path, _)| path));
                    adds.extend(after);
                }
                (Some(old), None) => {
                    if old.is_container() && self.has_child_paths(&old) {
                        return PathUpdate::Rebuild;
                    }
                    let Some(before) = self.materialized_paths(&old) else {
                        return PathUpdate::Rebuild;
                    };
                    removes.extend(before.into_iter().map(|(path, _)| path));
                }
                (None, Some(new)) => {
                    let Some(after) = self.materialized_paths(&new) else {
                        return PathUpdate::Rebuild;
                    };
                    adds.extend(after);
                }
                (None, None) => {}
            }
        }

        if removes.is_empty() && adds.is_empty() {
            PathUpdate::Shared
        } else {
            PathUpdate::Patched(self.paths.patch(&removes, adds))
        }
    }

    fn has_child_paths(&self, container: &DavResourceRef<'_>) -> bool {
        match self.container_path_of(container) {
            Some(path) => self.paths.range(format!("{path}/")).next().is_some(),
            None => true,
        }
    }
}

impl DavResources {
    pub fn container_path_entry(&self, container_id: u32) -> Option<(&PathChunk, &DavPath)> {
        let container = self.resources.find(container_id, true)?;
        let candidate = self.container_path_of(&container)?;
        let entry = self.paths.get(&candidate)?;
        (entry.1.document_id == container_id && entry.1.hierarchy_seq & CONTAINER_FLAG != 0)
            .then_some(entry)
    }

    pub fn materialized_paths(
        &self,
        resource: &DavResourceRef<'_>,
    ) -> Option<Vec<(String, DavPath)>> {
        match &resource.resource.data {
            DavResourceMetadata::File { .. } => {
                let path = self.nested_path_of(resource)?;
                let (parent_id, parent_seq) = match Self::nesting_parent(resource) {
                    Some(parent_id) => match self.container_path_entry(parent_id) {
                        Some((_, parent)) => {
                            (parent_id, Some(parent.hierarchy_seq & !CONTAINER_FLAG))
                        }
                        None if self.resources.find(parent_id, true).is_some() => return None,
                        None => (parent_id, None),
                    },
                    None => (NO_ID, None),
                };
                Some(vec![(
                    path,
                    DavPath {
                        path: ArenaRef::default(),
                        parent_id,
                        hierarchy_seq: parent_seq.map_or(0, |seq| seq + 1)
                            | if resource.is_container() {
                                CONTAINER_FLAG
                            } else {
                                0
                            },
                        document_id: resource.document_id(),
                    },
                )])
            }
            _ if resource.is_container() => Some(vec![(
                self.container_path_of(resource)?,
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: NO_ID,
                    hierarchy_seq: 1 | CONTAINER_FLAG,
                    document_id: resource.document_id(),
                },
            )]),
            _ => {
                let mut entries = Vec::with_capacity(resource.child_names().len());
                for name in resource.child_names() {
                    let Some(container) = self.resources.find(name.parent_id, true) else {
                        continue;
                    };
                    let parent = self.container_path_of(&container)?;
                    if self
                        .paths
                        .get(&parent)
                        .is_none_or(|(_, entry)| entry.document_id != name.parent_id)
                    {
                        return None;
                    }
                    entries.push((
                        format!(
                            "{parent}/{}",
                            encode_path_segment(resource.child_name_at(name))
                        ),
                        DavPath {
                            path: ArenaRef::default(),
                            parent_id: name.parent_id,
                            hierarchy_seq: 0,
                            document_id: resource.document_id(),
                        },
                    ));
                }
                Some(entries)
            }
        }
    }

    fn container_path_of(&self, container: &DavResourceRef<'_>) -> Option<String> {
        match &container.resource.data {
            DavResourceMetadata::File { .. } => self.nested_path_of(container),
            _ => container
                .container_name()
                .map(|name| encode_path_segment(name).into_owned()),
        }
    }

    fn nested_path_of(&self, resource: &DavResourceRef<'_>) -> Option<String> {
        let mut segments = vec![encode_path_segment(resource.container_name()?).into_owned()];
        let mut parent = Self::nesting_parent(resource);

        while let Some(parent_id) = parent {
            if segments.len() > MAX_HIERARCHY_DEPTH {
                return None;
            }
            let Some(ancestor) = self.resources.find_any(parent_id) else {
                break;
            };
            segments.push(encode_path_segment(ancestor.container_name()?).into_owned());
            parent = Self::nesting_parent(&ancestor);
        }

        segments.reverse();
        Some(segments.join("/"))
    }

    fn nesting_parent(resource: &DavResourceRef<'_>) -> Option<u32> {
        match &resource.resource.data {
            DavResourceMetadata::File { parent_id, .. } if *parent_id != NO_ID => Some(*parent_id),
            _ => None,
        }
    }
}
