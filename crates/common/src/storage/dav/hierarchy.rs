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
use std::borrow::Cow;

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
                    self.collect_owned_removes(&old, before, &mut removes);
                    adds.extend(after);
                }
                (Some(old), None) => {
                    if old.is_container() && self.has_child_paths(&old) {
                        return PathUpdate::Rebuild;
                    }
                    let Some(before) = self.materialized_paths(&old) else {
                        return PathUpdate::Rebuild;
                    };
                    self.collect_owned_removes(&old, before, &mut removes);
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

    fn collect_owned_removes(
        &self,
        owner: &DavResourceRef<'_>,
        before: Vec<(String, DavPath)>,
        removes: &mut AHashSet<String>,
    ) {
        let document_id = owner.document_id();
        removes.extend(before.into_iter().map(|(path, _)| path).filter(|path| {
            !self
                .paths
                .get(path)
                .is_some_and(|(_, entry)| entry.document_id != document_id)
        }));
    }

    fn has_child_paths(&self, container: &DavResourceRef<'_>) -> bool {
        match self.container_path_of(container) {
            Some(path) => self.paths.range(format!("{path}/")).next().is_some(),
            None => true,
        }
    }

    pub(crate) fn container_path_entry(&self, container_id: u32) -> Option<(&PathChunk, &DavPath)> {
        let container = self.resources.find(container_id, true)?;
        self.container_path_entry_of(&container)
    }

    pub(super) fn container_path_entry_of(
        &self,
        container: &DavResourceRef<'_>,
    ) -> Option<(&PathChunk, &DavPath)> {
        let candidate = self.container_path_of(container)?;
        let entry = self.paths.get(&candidate)?;
        (entry.1.document_id == container.document_id()
            && entry.1.hierarchy_seq & CONTAINER_FLAG != 0)
            .then_some(entry)
    }

    pub(crate) fn materialized_paths(
        &self,
        resource: &DavResourceRef<'_>,
    ) -> Option<Vec<(String, DavPath)>> {
        match &resource.resource.data {
            DavResourceMetadata::File { .. } => {
                let (path, parent_id, parent_seq) = match Self::nesting_parent(resource) {
                    Some(parent_id) => match self.container_path_entry(parent_id) {
                        Some((parent_chunk, parent)) => (
                            format!(
                                "{}/{}",
                                parent_chunk.path_str(parent),
                                encode_path_segment(resource.container_name()?)
                            ),
                            parent_id,
                            Some(parent.hierarchy_seq & !CONTAINER_FLAG),
                        ),
                        None if self.resources.find(parent_id, true).is_some() => return None,
                        None => (self.nested_path_of(resource)?, parent_id, None),
                    },
                    None => (self.nested_path_of(resource)?, NO_ID, None),
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
                self.container_path_of(resource)?.into_owned(),
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

    fn container_path_of<'x>(&'x self, container: &'x DavResourceRef<'x>) -> Option<Cow<'x, str>> {
        match &container.resource.data {
            DavResourceMetadata::File { .. } => self.nested_path_of(container).map(Cow::Owned),
            _ => container.container_name().map(encode_path_segment),
        }
    }

    fn nested_path_of(&self, resource: &DavResourceRef<'_>) -> Option<String> {
        let mut chain = vec![DavResourceRef {
            chunk: resource.chunk,
            resource: resource.resource,
        }];
        let mut parent = Self::nesting_parent(resource);

        while let Some(parent_id) = parent {
            if chain.len() > MAX_HIERARCHY_DEPTH {
                return None;
            }
            let Some(ancestor) = self.resources.find_any(parent_id) else {
                break;
            };
            parent = Self::nesting_parent(&ancestor);
            chain.push(ancestor);
        }

        chain
            .iter()
            .rev()
            .map(|node| node.container_name().map(encode_path_segment))
            .collect::<Option<Vec<_>>>()
            .map(|segments| segments.join("/"))
    }

    fn nesting_parent(resource: &DavResourceRef<'_>) -> Option<u32> {
        match &resource.resource.data {
            DavResourceMetadata::File { parent_id, .. } if *parent_id != NO_ID => Some(*parent_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DavName, DavResource, UpdateLock, storage::dav::ResourceChunkBuilder};
    use std::sync::Arc;

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
                etag: 0,
            },
        });
    }

    fn event(builder: &mut ResourceChunkBuilder, document_id: u32, parent_id: u32, name: &str) {
        let names = builder.push_names(&[DavName::new(name.to_string(), parent_id)]);
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
                etag: 0,
            },
        });
    }

    fn resources(store: ResourceStore, paths: Arc<PathIndex>) -> DavResources {
        DavResources {
            base_path: String::new(),
            paths,
            resources: store,
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
        }
    }

    fn calcard_entry(path: &str, document_id: u32, parent_id: u32) -> (String, DavPath) {
        (
            path.to_string(),
            DavPath {
                path: ArenaRef::default(),
                parent_id,
                hierarchy_seq: if parent_id == NO_ID {
                    1 | CONTAINER_FLAG
                } else {
                    0
                },
                document_id,
            },
        )
    }

    #[test]
    fn deleting_a_path_loser_keeps_the_winner_entry() {
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        calendar(&mut containers, 0, "work");
        let mut items = ResourceChunkBuilder::with_capacity(2);
        event(&mut items, 1, 0, "a.ics");
        event(&mut items, 2, 0, "a.ics");
        let previous = ResourceStore::from_sorted(vec![containers], vec![items], false);
        let paths = Arc::new(PathIndex::pack(vec![
            calcard_entry("work", 0, NO_ID),
            calcard_entry("work/a.ics", 1, 0),
            calcard_entry("work/a.ics", 2, 0),
        ]));
        assert_eq!(paths.get("work/a.ics").unwrap().1.document_id, 1);

        let staging = ResourceChunkBuilder::with_capacity(0).finish();
        let mut changes = AHashMap::new();
        changes.insert((false, 2u32), None);
        let updated = resources(previous.rebuild(&staging, &changes), paths.clone());

        let index = match updated.patch_paths(&previous, &staging, &changes) {
            PathUpdate::Shared => paths,
            PathUpdate::Patched(index) => Arc::new(index),
            PathUpdate::Rebuild => panic!("an item delete must not force a rebuild"),
        };
        assert_eq!(
            index.get("work/a.ics").map(|(_, entry)| entry.document_id),
            Some(1),
            "deleting the losing resource must keep the winner's entry"
        );

        let mut changes = AHashMap::new();
        changes.insert((false, 1u32), None);
        let updated = resources(previous.rebuild(&staging, &changes), index);
        let PathUpdate::Patched(index) = updated.patch_paths(&previous, &staging, &changes) else {
            panic!("deleting the owner must patch the index");
        };
        assert!(index.get("work/a.ics").is_none());
    }
}
