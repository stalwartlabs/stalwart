/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavResourceName, RFC_3986,
    file::{ArchivedFileNode, FileNode},
};
use common::{DavPath, DavResource, DavResourceMetadata, DavResources, Server, UpdateLock};
use std::sync::Arc;
use store::ahash::{AHashMap, AHashSet};
use trc::AddContext;
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
};
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

pub(super) async fn build_file_resources(
    server: &Server,
    account_id: u32,
    update_lock: Arc<UpdateLock>,
) -> trc::Result<DavResources> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::FileNode.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let account_info = server.account(account_id).await?;

    let mut resources = Vec::with_capacity(16);
    server
        .archives(
            account_id,
            Collection::FileNode,
            &(),
            |document_id, archive| {
                resources.push(resource_from_file(
                    archive.unarchive::<FileNode>()?,
                    document_id,
                ));

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    update_lock.set_revision(last_change_id);
    let mut files = DavResources {
        base_path: format!(
            "{}/{}/",
            DavResourceName::File.base_path(),
            percent_encoding::utf8_percent_encode(account_info.name(), RFC_3986),
        ),
        size: std::mem::size_of::<DavResources>() as u64,
        paths: AHashSet::with_capacity(resources.len()),
        resources,
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        update_lock,
    };

    build_nested_hierarchy(&mut files);

    Ok(files)
}

pub(super) fn build_nested_hierarchy(resources: &mut DavResources) {
    let mut topological_sort = TopologicalSort::with_capacity(resources.resources.len());
    let mut names = AHashMap::with_capacity(resources.resources.len());

    for (resource_idx, resource) in resources.resources.iter().enumerate() {
        if let DavResourceMetadata::File { parent_id, .. } = resource.data {
            topological_sort.insert(
                parent_id.map(|id| id + 1).unwrap_or_default(),
                resource.document_id + 1,
            );
            names.insert(
                resource.document_id,
                DavPath {
                    path: resource.container_name().unwrap().to_string(),
                    parent_id,
                    hierarchy_seq: 0,
                    resource_idx,
                },
            );
        }
    }

    for (hierarchy_sequence, folder_id) in topological_sort.into_iterator().enumerate() {
        if folder_id != 0 {
            let folder_id = folder_id - 1;
            let path = names
                .get(&folder_id)
                .and_then(|folder| folder.parent_id.map(|parent_id| (&folder.path, parent_id)))
                .and_then(|(name, parent_id)| {
                    names
                        .get(&parent_id)
                        .map(|parent| format!("{}/{}", parent.path, name))
                });

            if let Some(folder) = names.get_mut(&folder_id) {
                if let Some(path) = path {
                    folder.path = path;
                }
                folder.hierarchy_seq = hierarchy_sequence as u32;
            }
        }
    }

    resources.paths = names
        .into_values()
        .inspect(|v| {
            resources.size += (std::mem::size_of::<DavPath>()
                + std::mem::size_of::<u32>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<DavResource>()
                + v.path.len()) as u64;
        })
        .collect();
}

pub(super) fn resource_from_file(node: &ArchivedFileNode, document_id: u32) -> DavResource {
    let parent_id = node.parent_id.to_native();
    DavResource {
        document_id,
        data: DavResourceMetadata::File {
            name: node.name.as_str().to_string(),
            size: node.file.as_ref().map(|f| f.size.to_native()),
            parent_id: if parent_id > 0 {
                Some(parent_id - 1)
            } else {
                None
            },
            acls: node
                .acls
                .iter()
                .map(|acl| AclGrant {
                    account_id: acl.account_id.to_native(),
                    grants: Bitmap::from(&acl.grants),
                })
                .collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MISSING_DOCUMENT_ID: u32 = 9;

    fn folder(document_id: u32, name: &str, parent_id: Option<u32>) -> DavResource {
        DavResource {
            document_id,
            data: DavResourceMetadata::File {
                name: name.to_string(),
                size: None,
                parent_id,
                acls: Default::default(),
            },
        }
    }

    fn file(document_id: u32, name: &str, parent_id: Option<u32>) -> DavResource {
        DavResource {
            document_id,
            data: DavResourceMetadata::File {
                name: name.to_string(),
                size: Some(1024),
                parent_id,
                acls: Default::default(),
            },
        }
    }

    fn build(resources: Vec<DavResource>) -> DavResources {
        let mut files = DavResources {
            base_path: "/dav/file/john/".to_string(),
            paths: AHashSet::with_capacity(resources.len()),
            resources,
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
        };
        build_nested_hierarchy(&mut files);
        files
    }

    fn sorted_paths(files: &DavResources) -> Vec<&str> {
        let mut paths = files
            .paths
            .iter()
            .map(|path| path.path.as_str())
            .collect::<Vec<_>>();
        paths.sort_unstable();
        paths
    }

    fn hierarchy_seq(files: &DavResources, path: &str) -> u32 {
        files.paths.get(path).expect(path).hierarchy_seq
    }

    #[test]
    fn nested_hierarchy() {
        let files = build(vec![
            folder(0, "docs", None),
            folder(1, "reports", Some(0)),
            file(2, "q1.txt", Some(1)),
            file(3, "readme.txt", None),
        ]);

        assert_eq!(
            sorted_paths(&files),
            ["docs", "docs/reports", "docs/reports/q1.txt", "readme.txt"]
        );
        assert!(hierarchy_seq(&files, "docs") < hierarchy_seq(&files, "docs/reports"));
        assert!(
            hierarchy_seq(&files, "docs/reports") < hierarchy_seq(&files, "docs/reports/q1.txt")
        );
    }

    #[test]
    fn nested_hierarchy_with_dangling_parent() {
        let files = build(vec![
            folder(0, "docs", None),
            folder(1, "reports", Some(MISSING_DOCUMENT_ID)),
            file(2, "q1.txt", Some(1)),
            file(3, "orphan.txt", Some(MISSING_DOCUMENT_ID)),
        ]);

        assert_eq!(
            sorted_paths(&files),
            ["docs", "orphan.txt", "reports", "reports/q1.txt"]
        );
        assert!(hierarchy_seq(&files, "reports") < hierarchy_seq(&files, "reports/q1.txt"));
    }
}
