/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::acl::{JmapAcl, JmapRights},
    blob::download::BlobDownload,
};
use common::{DavResourceMetadata, DavResources, Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{DestroyArchive, cache::GroupwareCache, file::FileNode};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::file_node::{self, FileNodeProperty, FileNodeValue},
    references::resolve::ResolveCreatedReference,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Value};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

pub trait FileNodeSet: Sync + Send {
    fn file_node_set(
        &self,
        request: SetRequest<'_, file_node::FileNode>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<file_node::FileNode>>> + Send;
}

impl FileNodeSet for Server {
    async fn file_node_set(
        &self,
        mut request: SetRequest<'_, file_node::FileNode>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<file_node::FileNode>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::FileNode)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        let is_shared = access_token.is_shared(account_id);

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut created_folders = AHashMap::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut file_node = FileNode::default();

            // Process changes
            let has_acl_changes = match update_file_node(object, &mut file_node, &mut response) {
                Ok(result) => {
                    if let Some(blob_id) = result.blob_id {
                        let file_details = file_node.file.get_or_insert_default();
                        if !self.has_access_blob(&blob_id, access_token).await? {
                            response.not_created.append(
                                id,
                                SetError::forbidden().with_description(format!(
                                    "You do not have access to blobId {blob_id}."
                                )),
                            );
                            continue;
                        } else if let Some(blob_contents) = self
                            .blob_store()
                            .get_blob(blob_id.hash.as_slice(), 0..usize::MAX)
                            .await?
                        {
                            file_details.size = blob_contents.len() as u32;
                        } else {
                            response.not_created.append(
                                id,
                                SetError::invalid_properties()
                                    .with_property(FileNodeProperty::BlobId)
                                    .with_description("Blob could not be found."),
                            );
                            continue 'create;
                        }

                        file_details.blob_hash = blob_id.hash;
                    }

                    // Validate blob hash
                    if file_node
                        .file
                        .as_ref()
                        .is_some_and(|f| f.blob_hash.is_empty())
                    {
                        response.not_created.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(FileNodeProperty::BlobId)
                                .with_description("Missing blob id."),
                        );
                        continue 'create;
                    }

                    result.has_acl_changes
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            };

            // Validate hierarchy
            if let Err(err) =
                validate_file_node_hierarchy(None, &file_node, is_shared, &cache, &created_folders)
            {
                response.not_created.append(id, err);
                continue 'create;
            }

            // Inherit ACLs from parent
            if file_node.parent_id > 0 {
                let parent_id = file_node.parent_id - 1;
                let parent_acls = created_folders.get(&parent_id).cloned().or_else(|| {
                    cache
                        .container_resource_by_id(parent_id)
                        .and_then(|r| r.acls())
                        .map(|a| a.to_vec())
                });
                if !has_acl_changes {
                    if let Some(parent_acls) = parent_acls {
                        file_node.acls = parent_acls;
                    }
                } else if is_shared
                    && parent_acls
                        .is_none_or(|acls| !acls.effective_acl(access_token).contains(Acl::Share))
                {
                    response.not_created.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to share this file node."),
                    );
                    continue 'create;
                }
            }

            // Validate ACLs
            if !file_node.acls.is_empty() {
                if let Err(err) = self.acl_validate(&file_node.acls).await {
                    response.not_created.append(id, err.into());
                    continue 'create;
                }

                self.refresh_acls(&file_node.acls, None).await;
            }

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::FileNode, 1)
                .await
                .caused_by(trc::location!())?;
            if file_node.file.is_none() {
                created_folders.insert(document_id, file_node.acls.clone());
            }
            file_node
                .insert(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
            response.created(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain file node
            let document_id = id.document_id();
            let file_node_ = if let Some(file_node_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::FileNode,
                    document_id,
                ))
                .await?
            {
                file_node_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let file_node = file_node_
                .to_unarchived::<FileNode>()
                .caused_by(trc::location!())?;
            let mut new_file_node = file_node
                .deserialize::<FileNode>()
                .caused_by(trc::location!())?;

            // Apply changes
            let has_acl_changes = match update_file_node(object, &mut new_file_node, &mut response)
            {
                Ok(result) => {
                    if let Some(blob_id) = result.blob_id {
                        let file_details = new_file_node.file.get_or_insert_default();
                        if !self.has_access_blob(&blob_id, access_token).await? {
                            response.not_updated.append(
                                id,
                                SetError::forbidden().with_description(format!(
                                    "You do not have access to blobId {blob_id}."
                                )),
                            );
                            continue;
                        } else if let Some(blob_contents) = self
                            .blob_store()
                            .get_blob(blob_id.hash.as_slice(), 0..usize::MAX)
                            .await?
                        {
                            file_details.size = blob_contents.len() as u32;
                        } else {
                            response.not_updated.append(
                                id,
                                SetError::invalid_properties()
                                    .with_property(FileNodeProperty::BlobId)
                                    .with_description("Blob could not be found."),
                            );
                            continue 'update;
                        }

                        file_details.blob_hash = blob_id.hash;
                    }

                    result.has_acl_changes
                }
                Err(err) => {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            };

            // Validate hierarchy
            if let Err(err) = validate_file_node_hierarchy(
                Some(document_id),
                &new_file_node,
                is_shared,
                &cache,
                &created_folders,
            ) {
                response.not_updated.append(id, err);
                continue 'update;
            }

            // Validate ACL
            if is_shared {
                let acl = file_node.inner.acls.effective_acl(access_token);
                if !acl.contains(Acl::Modify) || (has_acl_changes && !acl.contains(Acl::Share)) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to modify this file node."),
                    );
                    continue 'update;
                }
            }
            if has_acl_changes {
                if let Err(err) = self.acl_validate(&new_file_node.acls).await {
                    response.not_updated.append(id, err.into());
                    continue 'update;
                }
                self.refresh_acls(
                    &new_file_node.acls,
                    Some(
                        file_node
                            .inner
                            .acls
                            .iter()
                            .map(AclGrant::from)
                            .collect::<Vec<_>>()
                            .as_slice(),
                    ),
                )
                .await;
            }

            // Update record
            new_file_node
                .update(access_token, file_node, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        let on_destroy_remove_children = request
            .arguments
            .on_destroy_remove_children
            .unwrap_or(false);
        let mut destroy_ids = AHashSet::with_capacity(will_destroy.len());
        'destroy: for id in will_destroy {
            let document_id = id.document_id();

            let Some(file_node) = cache.any_resource_path_by_id(document_id) else {
                response.not_destroyed.append(id, SetError::not_found());
                continue 'destroy;
            };

            // Find ids to delete
            let mut ids = cache.subtree(file_node.path()).collect::<Vec<_>>();
            if ids.is_empty() {
                debug_assert!(false, "Resource found in cache but not in subtree");
                continue 'destroy;
            }

            // Sort ids descending from the deepest to the root
            ids.sort_unstable_by_key(|b| std::cmp::Reverse(b.hierarchy_seq()));
            let mut sorted_ids = Vec::with_capacity(ids.len());
            sorted_ids.extend(ids.into_iter().map(|a| a.document_id()));

            // Validate not already deleted
            for child_id in &sorted_ids {
                if !destroy_ids.insert(*child_id) {
                    response.not_destroyed.append(
                        id,
                        SetError::will_destroy().with_description(
                            "File node or one of its children is already marked for deletion.",
                        ),
                    );
                    continue 'destroy;
                }
            }

            // Validate ACLs
            if !access_token.is_member(account_id) {
                let permissions = cache.shared_containers(access_token, [Acl::Delete], false);
                if permissions.len() < sorted_ids.len() as u64
                    || !sorted_ids.iter().all(|id| permissions.contains(*id))
                {
                    response.not_destroyed.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to delete this file node."),
                    );
                    continue 'destroy;
                }
            }

            // Obtain children ids
            if sorted_ids.len() > 1 && !on_destroy_remove_children {
                response
                    .not_destroyed
                    .append(id, SetError::node_has_children());
                continue 'destroy;
            }

            // Delete record
            response
                .destroyed
                .extend(sorted_ids.iter().copied().map(Id::from));

            DestroyArchive(sorted_ids)
                .delete_batch(
                    self,
                    access_token,
                    account_id,
                    cache.format_resource(file_node).into(),
                    &mut batch,
                )
                .await?;
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}

struct UpdateResult {
    has_acl_changes: bool,
    blob_id: Option<BlobId>,
}

fn update_file_node(
    updates: Value<'_, FileNodeProperty, FileNodeValue>,
    file_node: &mut FileNode,
    response: &mut SetResponse<file_node::FileNode>,
) -> Result<UpdateResult, SetError<FileNodeProperty>> {
    let mut has_acl_changes = false;
    let mut blob_id = None;

    for (property, mut value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        response.resolve_self_references(&mut value)?;

        match (property, value) {
            (FileNodeProperty::Name, Value::Str(value))
                if (1..=255).contains(&value.len())
                    && !value.contains('/')
                    && ![".", ".."].contains(&value.as_ref()) =>
            {
                file_node.name = value.into_owned();
            }
            (FileNodeProperty::ParentId, Value::Element(FileNodeValue::Id(value))) => {
                file_node.parent_id = value.document_id() + 1;
            }
            (FileNodeProperty::ParentId, Value::Null) => {
                file_node.parent_id = 0;
            }
            (FileNodeProperty::BlobId, Value::Element(FileNodeValue::BlobId(value))) => {
                if file_node
                    .file
                    .as_ref()
                    .is_none_or(|f| f.blob_hash != value.hash)
                {
                    blob_id = Some(value);
                }
            }
            (FileNodeProperty::BlobId, Value::Null) => {}
            (FileNodeProperty::Size, Value::Number(value)) => {
                file_node.file.get_or_insert_default().size = value.cast_to_u64() as u32;
            }
            (FileNodeProperty::Type, Value::Str(value)) if (1..=30).contains(&value.len()) => {
                file_node.file.get_or_insert_default().media_type = value.into_owned().into();
            }
            (FileNodeProperty::Type, Value::Null) => {
                file_node.file.get_or_insert_default().media_type = None;
            }
            (FileNodeProperty::Executable, Value::Bool(value)) => {
                file_node.file.get_or_insert_default().executable = value;
            }
            (FileNodeProperty::Executable, Value::Null) => {
                file_node.file.get_or_insert_default().executable = false;
            }
            (FileNodeProperty::Created, Value::Element(FileNodeValue::Date(value))) => {
                file_node.created = value.timestamp();
            }
            (FileNodeProperty::Modified, Value::Element(FileNodeValue::Date(value))) => {
                file_node.modified = value.timestamp();
            }
            (FileNodeProperty::ShareWith, value) => {
                file_node.acls = JmapRights::acl_set::<file_node::FileNode>(value)?;
                has_acl_changes = true;
            }
            (FileNodeProperty::Pointer(pointer), value)
                if matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(
                        FileNodeProperty::ShareWith
                    )))
                ) =>
            {
                let mut pointer = pointer.iter();
                pointer.next();

                file_node.acls = JmapRights::acl_patch::<file_node::FileNode>(
                    std::mem::take(&mut file_node.acls),
                    pointer,
                    value,
                )?;
                has_acl_changes = true;
            }
            (property, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Field could not be set."));
            }
        }
    }

    // Validate name
    if file_node.name.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(FileNodeProperty::Name)
            .with_description("Missing name."));
    }

    Ok(UpdateResult {
        has_acl_changes,
        blob_id,
    })
}

fn validate_file_node_hierarchy(
    document_id: Option<u32>,
    node: &FileNode,
    is_shared: bool,
    cache: &DavResources,
    created_folders: &AHashMap<u32, Vec<AclGrant>>,
) -> Result<(), SetError<FileNodeProperty>> {
    let node_parent_id = if node.parent_id == 0 {
        if is_shared && document_id.is_none() {
            return Err(SetError::invalid_properties()
                .with_property(FileNodeProperty::ParentId)
                .with_description("Cannot create top-level folder in a shared account."));
        }
        None
    } else {
        let parent_id = node.parent_id - 1;

        if let Some(document_id) = document_id {
            if document_id == parent_id {
                return Err(SetError::invalid_properties()
                    .with_property(FileNodeProperty::ParentId)
                    .with_description("A file node cannot be its own parent."));
            }

            // Validate circular references
            if let Some(file) = cache.container_resource_path_by_id(document_id)
                && cache
                    .subtree(file.path())
                    .any(|r| r.document_id() == parent_id)
            {
                return Err(SetError::invalid_properties()
                    .with_property(FileNodeProperty::ParentId)
                    .with_description("Circular reference in parent ids."));
            }
        }

        // Make sure the parent is a container
        if !created_folders.contains_key(&parent_id)
            && cache.container_resource_by_id(parent_id).is_none()
        {
            return Err(SetError::invalid_properties()
                .with_property(FileNodeProperty::ParentId)
                .with_description("Parent ID does not exist or is not a folder."));
        }

        Some(parent_id)
    };

    // Validate name uniqueness
    for resource in &cache.resources {
        if let DavResourceMetadata::File {
            name, parent_id, ..
        } = &resource.data
            && document_id.is_none_or(|id| id != resource.document_id)
            && node_parent_id == *parent_id
            && node.name == *name
        {
            return Err(SetError::invalid_properties()
                .with_property(FileNodeProperty::Name)
                .with_description("A node with the same name already exists in this folder."));
        }
    }

    Ok(())
}
