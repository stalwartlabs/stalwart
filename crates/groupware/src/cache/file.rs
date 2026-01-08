/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavResourceName, RFC_3986,
    file::{ArchivedFileNode, FileNode},
};
use common::{DavPath, DavResource, DavResourceMetadata, DavResources, Server};
use directory::backend::internal::manage::ManageDirectory;
use std::sync::Arc;
use store::ahash::{AHashMap, AHashSet};
use tokio::sync::Semaphore;
use trc::AddContext;
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
};
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

pub(super) async fn build_file_resources(
    server: &Server,
    account_id: u32,
    update_lock: Arc<Semaphore>,
) -> trc::Result<DavResources> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::FileNode.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));

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

    let mut files = DavResources {
        base_path: format!(
            "{}/{}/",
            DavResourceName::File.base_path(),
            percent_encoding::utf8_percent_encode(&name, RFC_3986),
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
            if let Some((name, parent_name)) = names
                .get(&folder_id)
                .and_then(|folder| folder.parent_id.map(|parent_id| (&folder.path, parent_id)))
                .and_then(|(name, parent_id)| {
                    names.get(&parent_id).map(|folder| (name, &folder.path))
                })
            {
                let name = format!("{parent_name}/{name}");
                let folder = names.get_mut(&folder_id).unwrap();
                folder.path = name;
                folder.hierarchy_seq = hierarchy_sequence as u32;
            } else {
                names.get_mut(&folder_id).unwrap().hierarchy_seq = hierarchy_sequence as u32;
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
