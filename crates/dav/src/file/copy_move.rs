/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::FromDavResource;
use crate::{
    DavError, DavMethod,
    common::{
        ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::{DavUriResource, UriResource},
    },
    file::{DavFileResource, FileItemId, file_name_from_uri, is_symlink},
};
use common::{
    DavResourcePath, GroupwareResources, Server,
    auth::AccessToken,
    storage::{dav::MAX_FILE_NODE_DEPTH, index::ObjectIndexBuilder},
};
use dav_proto::{Depth, RequestHeaders};
use groupware::{DestroyArchive, cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::StorageQuota;
use std::sync::Arc;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use store::{ahash::AHashMap, write::BatchBuilder};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection, VanishedCollection},
};

pub(crate) trait FileCopyMoveRequestHandler: Sync + Send {
    fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileCopyMoveRequestHandler for Server {
    async fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let from_account_id = from_resource_.account_id;
        let from_resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let from_access = (!access_token.is_member(from_account_id))
            .then(|| from_resources.file_access(access_token));
        if let Some(access) = &from_access
            && let Some(path) = from_resource_.resource
        {
            from_resources.hide_undiscoverable(
                &access.discoverable,
                path,
                StatusCode::NOT_FOUND,
                StatusCode::NOT_FOUND,
            )?;
        }
        let from_resource = from_resources.map_resource::<FileItemId>(&from_resource_)?;
        let from_resource_name = from_resource_
            .resource
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        // Validate destination
        let destination = self
            .validate_uri_with_status(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
                StatusCode::BAD_GATEWAY,
            )
            .await?;
        if destination.collection != Collection::FileNode {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let to_account_id = destination
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let is_same_account = to_account_id == from_account_id;
        let to_resources = if is_same_account {
            from_resources.clone()
        } else {
            self.fetch_groupware_resources(
                access_token.account_id(),
                to_account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?
        };

        // Map file item
        let destination_resource_name = destination
            .resource
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        if is_same_account {
            if is_same_or_descendant(from_resource_name, destination_resource_name) {
                return Ok(HttpResponse::new(StatusCode::BAD_GATEWAY));
            } else if is_same_or_descendant(destination_resource_name, from_resource_name) {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        let to_access_owned = (!is_same_account && !access_token.is_member(to_account_id))
            .then(|| to_resources.file_access(access_token));
        let to_access = if is_same_account {
            from_access.as_ref()
        } else {
            to_access_owned.as_ref()
        };
        if let Some(access) = to_access {
            to_resources.hide_undiscoverable(
                &access.discoverable,
                destination_resource_name,
                StatusCode::FORBIDDEN,
                StatusCode::CONFLICT,
            )?;
        }

        // Check if the resource exists
        let parent = to_resources.map_directory_parent(destination_resource_name)?;
        let mut delete_destination = None;
        if let Some(existing) = to_resources.by_path(destination_resource_name) {
            if is_symlink(&existing) {
                return Err(DavError::Code(StatusCode::CONFLICT));
            } else if headers.overwrite_fail {
                return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED));
            }
            delete_destination = Some(ExistingDestination {
                document_id: existing.document_id(),
                is_container: existing.is_container(),
            });
        }
        let name = file_name_from_uri(
            headers
                .destination
                .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
        )?;
        let copy_depth = match (is_move, headers.depth) {
            (false, Depth::Zero) => 0,
            (false, Depth::One) => 1,
            _ => usize::MAX,
        };
        if destination_resource_name.split('/').count()
            + subtree_height(&from_resources, from_resource_name, copy_depth)
            > MAX_FILE_NODE_DEPTH
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }
        let mut destination = parent
            .map(Destination::from_dav_resource)
            .unwrap_or_default();
        destination.new_name = Some(name);
        destination.account_id = to_account_id;
        let changes_parent =
            !is_same_account || from_resource.resource.parent_id != destination.document_id;

        // Validate source ACLs
        if let Some(access) = &from_access {
            let removes_source = is_move && !is_same_account;
            if from_resources
                .subtree(from_resource_name)
                .map(|resource| resource.document_id())
                .any(|document_id| {
                    !access.has_acl(document_id, Acl::Read)
                        || (removes_source && !access.has_acl(document_id, Acl::RemoveItems))
                })
                || (is_move
                    && (!access.has_acl(from_resource.resource.document_id, Acl::Modify)
                        || (changes_parent
                            && from_resource.resource.parent_id.is_none_or(|parent_id| {
                                !access.has_acl(parent_id, Acl::RemoveItems)
                            }))))
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Validate destination ACLs
        if let Some(to_access) = to_access {
            let adds_to_parent = changes_parent || !is_move;
            if (adds_to_parent
                && destination
                    .document_id
                    .is_none_or(|parent_id| !to_access.has_acl(parent_id, Acl::AddItems)))
                || (delete_destination.is_some()
                    && to_resources
                        .subtree(destination_resource_name)
                        .any(|resource| {
                            !to_access.has_acl(resource.document_id(), Acl::RemoveItems)
                        }))
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![
                ResourceState {
                    account_id: from_account_id,
                    collection: Collection::FileNode,
                    document_id: Some(from_resource.resource.document_id),
                    path: from_resource_name,
                    ..Default::default()
                },
                ResourceState {
                    account_id: to_account_id,
                    collection: Collection::FileNode,
                    document_id: Some(
                        delete_destination
                            .as_ref()
                            .map_or(u32::MAX, |existing| existing.document_id),
                    ),
                    path: destination_resource_name,
                    ..Default::default()
                },
            ],
            Default::default(),
            if is_move {
                DavMethod::MOVE
            } else {
                DavMethod::COPY
            },
        )
        .await?;

        let from_href = from_resources
            .by_path(from_resource_name)
            .map(|resource| from_resources.format_resource(resource))
            .unwrap_or_default();

        if delete_destination.is_none() && !changes_parent && is_move {
            // Rename
            return rename_item(
                self,
                access_token,
                &from_resources,
                from_resource,
                from_resource_name,
                from_href,
                destination,
            )
            .await;
        }

        // Validate quota
        if !is_move || !is_same_account {
            let space_needed = from_resources
                .subtree(from_resource_name)
                .map(|a| a.size() as u64)
                .sum::<u64>();
            let to_account = self.account(to_account_id).await?;
            self.has_available_quota(&to_account, space_needed).await?;

            let files_limit = self.object_quota_limit(&to_account, StorageQuota::MaxFiles);
            let folders_limit = self.object_quota_limit(&to_account, StorageQuota::MaxFolders);
            let is_item_overwrite = delete_destination
                .as_ref()
                .is_some_and(|d| !d.is_container && !from_resource.resource.is_container);
            if (files_limit.is_some() || folders_limit.is_some()) && !is_item_overwrite {
                let (created_files, created_folders) = if !from_resource.resource.is_container {
                    (1, 0)
                } else {
                    match (is_move, headers.depth) {
                        (false, Depth::Zero) => (0, 1),
                        (false, Depth::One) => {
                            count_nodes(from_resources.subtree_with_depth(from_resource_name, 1))
                        }
                        _ => count_nodes(from_resources.subtree(from_resource_name)),
                    }
                };
                let (deleted_files, deleted_folders) = if delete_destination.is_some() {
                    count_nodes(to_resources.subtree(destination_resource_name))
                } else {
                    (0, 0)
                };
                let new_files = created_files.saturating_sub(deleted_files);
                let new_folders = created_folders.saturating_sub(deleted_folders);

                if new_files > 0 || new_folders > 0 {
                    let used_folders = to_resources.resources.count(true);
                    let used_files = to_resources.resources.len().saturating_sub(used_folders);
                    if new_files > 0 {
                        self.assert_object_quota(
                            &to_account,
                            StorageQuota::MaxFiles,
                            new_files,
                            || used_files,
                        )?;
                    }
                    if new_folders > 0 {
                        self.assert_object_quota(
                            &to_account,
                            StorageQuota::MaxFolders,
                            new_folders,
                            || used_folders,
                        )?;
                    }
                }
            }
        }

        // Delete collection
        let is_overwrite = delete_destination
            .as_ref()
            .is_some_and(|d| d.is_container || from_resource.resource.is_container);
        if is_overwrite {
            delete_destination = None;
            // Find ids to delete
            let mut ids = to_resources
                .subtree(destination_resource_name)
                .collect::<Vec<_>>();
            if !ids.is_empty() {
                ids.sort_unstable_by_key(|b| std::cmp::Reverse(b.hierarchy_seq()));
                let mut sorted_ids = Vec::with_capacity(ids.len());
                sorted_ids.extend(ids.into_iter().map(|a| a.document_id()));
                DestroyArchive(sorted_ids)
                    .delete(self, access_token.account_tenant_ids(), to_account_id, None)
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        match (from_resource.resource.is_container, is_move) {
            (true, true) => {
                move_container(
                    self,
                    access_token,
                    from_resources,
                    from_resource,
                    from_resource_name,
                    from_href,
                    destination,
                    headers.depth,
                )
                .await
            }
            (true, false) => {
                copy_container(
                    self,
                    access_token,
                    from_resources,
                    from_resource,
                    from_resource_name,
                    from_href,
                    destination,
                    headers.depth,
                    false,
                )
                .await
            }
            (false, true) => {
                if let Some(existing) = delete_destination {
                    overwrite_and_delete_item(
                        self,
                        access_token,
                        from_resource,
                        from_href,
                        existing.document_id,
                        destination,
                    )
                    .await
                } else {
                    move_item(self, access_token, from_resource, from_href, destination).await
                }
            }
            (false, false) => {
                if let Some(existing) = delete_destination {
                    overwrite_item(
                        self,
                        access_token,
                        from_resource,
                        existing.document_id,
                        destination,
                    )
                    .await
                } else {
                    copy_item(self, access_token, from_resource, destination).await
                }
            }
        }
        .map(|r| {
            if is_overwrite && r.status() == StatusCode::CREATED {
                r.with_status_code(StatusCode::NO_CONTENT)
            } else {
                r
            }
        })
    }
}

fn is_same_or_descendant(path: &str, ancestor: &str) -> bool {
    path.strip_prefix(ancestor)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn subtree_height(resources: &GroupwareResources, path: &str, depth: usize) -> usize {
    if depth == 0 {
        return 0;
    }
    let base = path.split('/').count();
    resources
        .subtree(path)
        .map(|resource| resource.path().split('/').count().saturating_sub(base))
        .max()
        .unwrap_or_default()
        .min(depth)
}

fn count_nodes<'x>(nodes: impl Iterator<Item = DavResourcePath<'x>>) -> (usize, usize) {
    nodes.fold((0, 0), |(files, folders), node| {
        if node.is_container() {
            (files, folders + 1)
        } else {
            (files + 1, folders)
        }
    })
}

#[derive(Debug, Default)]
pub(crate) struct Destination {
    pub account_id: u32,
    pub new_name: Option<String>,
    pub document_id: Option<u32>,
}

#[derive(Debug)]
struct ExistingDestination {
    document_id: u32,
    is_container: bool,
}

// Moves a container under an existing container
#[allow(clippy::too_many_arguments)]
async fn move_container(
    server: &Server,
    access_token: &AccessToken,
    from_resources: Arc<GroupwareResources>,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_name: &str,
    from_href: String,
    destination: Destination,
    depth: Depth,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    if from_account_id == to_account_id {
        let node_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                from_account_id,
                Collection::FileNode,
                from_document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_
            .to_unarchived::<FileNode>()
            .caused_by(trc::location!())?;
        let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
        new_node.parent_id = parent_id;
        if let Some(new_name) = destination.new_name {
            new_node.name = new_name;
        }
        let mut batch = BatchBuilder::new();
        let etag = new_node
            .update(
                access_token.account_tenant_ids(),
                node,
                from_account_id,
                from_document_id,
                true,
                &mut batch,
            )
            .caused_by(trc::location!())?
            .etag();
        from_resources.log_descendant_updates(&mut batch, from_account_id, from_resource_name);
        batch
            .with_account_id(from_account_id)
            .log_vanished_item(VanishedCollection::FileNode, from_href);
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
    } else {
        copy_container(
            server,
            access_token,
            from_resources,
            from_resource,
            from_resource_name,
            from_href,
            destination,
            depth,
            true,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn copy_container(
    server: &Server,
    access_token: &AccessToken,
    from_resources: Arc<GroupwareResources>,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_name: &str,
    from_href: String,
    mut destination: Destination,
    depth: Depth,
    delete_source: bool,
) -> crate::Result<HttpResponse> {
    let infinity_copy = match depth {
        Depth::Zero if !delete_source => {
            return copy_item(server, access_token, from_resource, destination).await;
        }
        Depth::One if !delete_source => false,
        _ => true,
    };

    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    // Obtain files to copy
    let mut copy_files = if infinity_copy {
        from_resources
            .subtree(from_resource_name)
            .map(|r| (r.document_id(), r.hierarchy_seq()))
            .collect::<Vec<_>>()
    } else {
        from_resources
            .subtree_with_depth(from_resource_name, 1)
            .map(|r| (r.document_id(), r.hierarchy_seq()))
            .collect::<Vec<_>>()
    };

    // Top-down copy
    let mut batch = BatchBuilder::new();
    let mut id_map = AHashMap::with_capacity(copy_files.len());
    let mut delete_files = if delete_source {
        Vec::with_capacity(copy_files.len())
    } else {
        Vec::new()
    };
    copy_files.sort_unstable_by_key(|a| a.1);
    let new_slots =
        batch.reserve_document_ids(to_account_id, Collection::FileNode, copy_files.len() as u32);
    for (slot_offset, (document_id, _)) in copy_files.into_iter().enumerate() {
        let node_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                from_account_id,
                Collection::FileNode,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
            .into_deserialized::<FileNode>()
            .caused_by(trc::location!())?;

        // Build node
        let mut node = if !delete_source {
            node_.inner
        } else {
            let node = node_.inner.clone();
            delete_files.push((document_id, node_));
            node
        };
        let set_accessed = node.accessed == 0;
        node.stamp_insert(true, true, set_accessed);
        node.acls.clear();
        if let Some(new_name) = destination.new_name.take() {
            node.name = new_name;
        }
        let pending_parent = id_map.get(&node.parent_id).copied();
        if pending_parent.is_none() {
            node.parent_id = parent_id;
        }

        // Prepare write batch
        let new_slot = new_slots.get(slot_offset);
        let builder = ObjectIndexBuilder::<(), _>::new()
            .with_changes(node)
            .with_changed_by(access_token.account_tenant_ids());
        batch
            .with_account_id(to_account_id)
            .with_collection(Collection::FileNode)
            .create_document(new_slot)
            .custom(builder.with_pending_id_opt(pending_parent))
            .caused_by(trc::location!())?
            .commit_point();
        id_map.insert(document_id + 1, new_slot);
    }

    // Delete nodes
    if !delete_files.is_empty() {
        for (document_id, node) in delete_files.into_iter().rev() {
            // Delete record
            batch
                .with_account_id(from_account_id)
                .with_collection(Collection::FileNode)
                .with_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_changed_by(access_token.account_tenant_ids())
                        .with_current(node),
                )
                .caused_by(trc::location!())?
                .commit_point();
        }
        batch
            .with_account_id(from_account_id)
            .log_vanished_item(VanishedCollection::FileNode, from_href);
    }

    // Write changes
    if !batch.is_empty() {
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(HttpResponse::new(StatusCode::CREATED))
}

// Overwrites the contents of one file with another, then deletes the original
async fn overwrite_and_delete_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_path: String,
    to_document_id: u32,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;

    // dest_node is the current file at the destination
    let dest_node_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            to_account_id,
            Collection::FileNode,
            to_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

    let dest_node = dest_node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;

    // source_node is the file to be copied
    let source_node__ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::FileNode,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let source_node_ = source_node__
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut source_node = source_node_
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    if let Some(new_name) = destination.new_name {
        source_node.name = new_name;
    }
    if from_account_id != to_account_id {
        source_node.acls.clear();
    }
    source_node.parent_id = dest_node.inner.parent_id.into();

    let mut batch = BatchBuilder::new();
    let etag = source_node
        .update(
            access_token.account_tenant_ids(),
            dest_node,
            to_account_id,
            to_document_id,
            true,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    DestroyArchive(source_node_)
        .delete(
            access_token.account_tenant_ids(),
            from_account_id,
            from_document_id,
            &mut batch,
            from_resource_path,
        )
        .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
}

// Overwrites the contents of one file with another
async fn overwrite_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    to_document_id: u32,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;

    // dest_node is the current file at the destination
    let dest_node_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            to_account_id,
            Collection::FileNode,
            to_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

    let dest_node = dest_node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;

    // source_node is the file to be copied
    let mut source_node = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::FileNode,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    if let Some(new_name) = destination.new_name {
        source_node.name = new_name;
    }
    source_node.acls.clear();
    source_node.parent_id = dest_node.inner.parent_id.into();
    let mut batch = BatchBuilder::new();
    let etag = source_node
        .update(
            access_token.account_tenant_ids(),
            dest_node,
            to_account_id,
            to_document_id,
            true,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
}

// Moves an item under an existing container
async fn move_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_path: String,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    let node_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::FileNode,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let node = node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
    new_node.parent_id = parent_id;
    if let Some(new_name) = destination.new_name {
        new_node.name = new_name;
    }

    let mut batch = BatchBuilder::new();
    let etag = if from_account_id == to_account_id {
        // Destination is in the same account: just update the parent id
        let etag = new_node
            .update(
                access_token.account_tenant_ids(),
                node,
                from_account_id,
                from_document_id,
                true,
                &mut batch,
            )
            .caused_by(trc::location!())?
            .etag();
        batch.log_vanished_item(VanishedCollection::FileNode, from_resource_path);
        etag
    } else {
        // Destination is in a different account: insert a new node, then delete the old one
        new_node.acls.clear();
        let to_document_id = batch.reserve_document_id(to_account_id, Collection::FileNode);
        let etag = new_node
            .insert(
                access_token.account_tenant_ids(),
                to_account_id,
                to_document_id,
                true,
                true,
                &mut batch,
            )
            .caused_by(trc::location!())?
            .etag();
        DestroyArchive(node)
            .delete(
                access_token.account_tenant_ids(),
                from_account_id,
                from_document_id,
                &mut batch,
                from_resource_path,
            )
            .caused_by(trc::location!())?;
        etag
    };
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Copies an item under an existing container
async fn copy_item(
    server: &Server,
    access_token: &AccessToken,
    from_resource: UriResource<u32, FileItemId>,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let to_account_id = destination.account_id;
    let from_document_id = from_resource.resource.document_id;
    let parent_id = destination.document_id.map(|id| id + 1).unwrap_or(0);

    let mut node = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::FileNode,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    node.parent_id = parent_id;
    node.acls.clear();
    if let Some(new_name) = destination.new_name {
        node.name = new_name;
    }
    let mut batch = BatchBuilder::new();
    let to_document_id = batch.reserve_document_id(to_account_id, Collection::FileNode);
    let etag = node
        .insert(
            access_token.account_tenant_ids(),
            to_account_id,
            to_document_id,
            true,
            true,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

// Renames an item
async fn rename_item(
    server: &Server,
    access_token: &AccessToken,
    from_resources: &GroupwareResources,
    from_resource: UriResource<u32, FileItemId>,
    from_resource_name: &str,
    from_resource_path: String,
    destination: Destination,
) -> crate::Result<HttpResponse> {
    let from_account_id = from_resource.account_id;
    let from_document_id = from_resource.resource.document_id;

    let node_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::FileNode,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let node = node_
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
    if let Some(new_name) = destination.new_name {
        new_node.name = new_name;
    }
    let mut batch = BatchBuilder::new();
    let etag = new_node
        .update(
            access_token.account_tenant_ids(),
            node,
            from_account_id,
            from_document_id,
            true,
            &mut batch,
        )
        .caused_by(trc::location!())?
        .etag();
    if from_resource.resource.is_container {
        from_resources.log_descendant_updates(&mut batch, from_account_id, from_resource_name);
    }
    batch
        .with_account_id(from_account_id)
        .log_vanished_item(VanishedCollection::FileNode, from_resource_path);
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
}

impl FromDavResource for Destination {
    fn from_dav_resource(item: DavResourcePath<'_>) -> Self {
        Destination {
            account_id: u32::MAX,
            document_id: Some(item.document_id()),
            new_name: None,
        }
    }
}
