/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ChunkAccumulator;
use crate::{
    DavResourceName, RFC_3986, encode_path_segment,
    file::{ArchivedFileNode, FileNode},
};
use common::{
    ArenaRef, DavPath, DavResource, DavResourceMetadata, DavResources, NO_ID, PathIndex,
    ResourceStore, Server, UpdateLock,
    storage::dav::{CONTAINER_FLAG, ResourceChunkBuilder},
};
use std::sync::Arc;
use store::ahash::AHashMap;
use trc::AddContext;
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
    field::Field,
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

    let mut nodes = ChunkAccumulator::default();
    server
        .archives(
            account_id,
            Collection::FileNode,
            Field::ARCHIVE,
            &(),
            |document_id, archive| {
                push_file(
                    nodes.current(),
                    archive.unarchive::<FileNode>()?,
                    document_id,
                    archive.version.hash().unwrap_or_default(),
                );
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    update_lock.set_revision(last_change_id);
    let resources = ResourceStore::from_sorted(nodes.finish(), Vec::new(), true);
    let paths = build_nested_hierarchy(&resources);
    let mut files = DavResources {
        base_path: format!(
            "{}/{}/",
            DavResourceName::File.base_path(),
            percent_encoding::utf8_percent_encode(account_info.name(), RFC_3986),
        ),
        size: 0,
        paths: Arc::new(paths),
        resources,
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        update_lock,
    };
    files.recompute_size();

    Ok(files)
}

pub(super) fn build_nested_hierarchy(resources: &ResourceStore) -> PathIndex {
    let mut topological_sort = TopologicalSort::with_capacity(resources.len());
    let mut names: AHashMap<u32, (String, u32, u32, bool)> =
        AHashMap::with_capacity(resources.len());

    for resource in resources.iter() {
        if let DavResourceMetadata::File { parent_id, .. } = resource.resource.data {
            topological_sort.insert(
                if parent_id != NO_ID { parent_id + 1 } else { 0 },
                resource.document_id() + 1,
            );
            names.insert(
                resource.document_id(),
                (
                    encode_path_segment(resource.container_name().unwrap_or_default()).into_owned(),
                    parent_id,
                    0,
                    resource.is_container(),
                ),
            );
        }
    }

    for (hierarchy_sequence, folder_id) in topological_sort.into_iterator().enumerate() {
        if folder_id != 0 {
            let folder_id = folder_id - 1;
            let path = names
                .get(&folder_id)
                .filter(|(_, parent_id, _, _)| *parent_id != NO_ID)
                .and_then(|(name, parent_id, _, _)| {
                    names
                        .get(parent_id)
                        .map(|(parent, _, _, _)| format!("{parent}/{name}"))
                });

            if let Some(folder) = names.get_mut(&folder_id) {
                if let Some(path) = path {
                    folder.0 = path;
                }
                folder.2 = hierarchy_sequence as u32;
            }
        }
    }

    let entries = names
        .into_iter()
        .map(
            |(document_id, (path, parent_id, hierarchy_seq, is_container))| {
                (
                    path,
                    DavPath {
                        path: ArenaRef::default(),
                        parent_id,
                        hierarchy_seq: hierarchy_seq
                            | if is_container { CONTAINER_FLAG } else { 0 },
                        document_id,
                    },
                )
            },
        )
        .collect::<Vec<_>>();

    PathIndex::pack(entries)
}

pub(super) fn push_file(
    builder: &mut ResourceChunkBuilder,
    node: &ArchivedFileNode,
    document_id: u32,
    etag: u32,
) {
    let parent_id = node.parent_id.to_native();
    let name = builder.push_str(node.name.as_str());
    let acls = builder.push_acls(
        &node
            .acls
            .iter()
            .map(|acl| AclGrant {
                account_id: acl.account_id.to_native(),
                grants: Bitmap::from(&acl.grants),
            })
            .collect::<Vec<_>>(),
    );
    builder.records.push(DavResource {
        document_id,
        data: DavResourceMetadata::File {
            name,
            size: node
                .file
                .as_ref()
                .map(|f| f.size.to_native())
                .unwrap_or(NO_ID),
            parent_id: if parent_id > 0 { parent_id - 1 } else { NO_ID },
            acls,
            etag,
        },
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const MISSING_DOCUMENT_ID: u32 = 9;

    struct Node {
        document_id: u32,
        name: &'static str,
        parent_id: Option<u32>,
        size: Option<u32>,
    }

    fn folder(document_id: u32, name: &'static str, parent_id: Option<u32>) -> Node {
        Node {
            document_id,
            name,
            parent_id,
            size: None,
        }
    }

    fn file(document_id: u32, name: &'static str, parent_id: Option<u32>) -> Node {
        Node {
            document_id,
            name,
            parent_id,
            size: Some(1024),
        }
    }

    fn build(nodes: Vec<Node>) -> DavResources {
        let mut builder = ResourceChunkBuilder::with_capacity(nodes.len());
        for node in &nodes {
            let name = builder.push_str(node.name);
            let acls = builder.push_acls(&[]);
            builder.records.push(DavResource {
                document_id: node.document_id,
                data: DavResourceMetadata::File {
                    name,
                    size: node.size.unwrap_or(NO_ID),
                    parent_id: node.parent_id.unwrap_or(NO_ID),
                    acls,
                    etag: 0,
                },
            });
        }
        let resources = ResourceStore::from_sorted(vec![builder], Vec::new(), true);
        let paths = build_nested_hierarchy(&resources);
        let mut files = DavResources {
            base_path: "/dav/file/john/".to_string(),
            paths: Arc::new(paths),
            resources,
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
        };
        files.recompute_size();
        files
    }

    fn sorted_paths(files: &DavResources) -> Vec<String> {
        let mut paths = files
            .paths
            .iter()
            .map(|(chunk, path)| {
                std::str::from_utf8(&chunk.bytes[path.path.range()])
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();
        paths.sort_unstable();
        paths
    }

    fn hierarchy_seq(files: &DavResources, path: &str) -> u32 {
        files.paths.get(path).expect(path).1.hierarchy_seq & !CONTAINER_FLAG
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
    fn nested_hierarchy_percent_encodes_paths() {
        let files = build(vec![
            folder(0, "My Documents", None),
            folder(1, "Berichte 2026", Some(0)),
            file(2, "Ünterlagen Q1.txt", Some(1)),
            folder(3, "My%20Folder", None),
            file(4, "file(1)+a:b.txt", Some(3)),
        ]);

        assert_eq!(
            sorted_paths(&files),
            [
                "My%20Documents",
                "My%20Documents/Berichte%202026",
                "My%20Documents/Berichte%202026/%C3%9Cnterlagen%20Q1.txt",
                "My%20Folder",
                "My%20Folder/file(1)+a:b.txt",
            ]
        );
        assert_eq!(
            files.format_resource(files.by_path("My%20Documents").unwrap()),
            "/dav/file/john/My%20Documents/"
        );
        assert_eq!(
            files.format_resource(
                files
                    .by_path("My%20Documents/Berichte%202026/%C3%9Cnterlagen%20Q1.txt")
                    .unwrap()
            ),
            "/dav/file/john/My%20Documents/Berichte%202026/%C3%9Cnterlagen%20Q1.txt"
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
