/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::acl::{JmapAcl, JmapRights},
    blob::download::BlobDownload,
    changes::state::JmapCacheState,
};
use common::{DavResourceMetadata, DavResources, Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{DestroyArchive, cache::GroupwareCache, file::FileNode};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::{
        AnyId,
        file_node::{self, FileNodeProperty, FileNodeValue, OnExists},
    },
    references::resolve::ResolveCreatedReference,
    request::MaybeInvalid,
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Value};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{AlignedBytes, Archive, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

const FORBIDDEN_NAME_CHARS: &str = "/<>:\"\\|?*";
const FORBIDDEN_NODE_NAMES: &[&str] = &[
    ".", "..", "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
    "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

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
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(cache.assert_state(false, &request.if_in_state)?);
        let mut will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let is_shared = access_token.is_shared(account_id);
        let on_destroy_remove_children = request
            .arguments
            .on_destroy_remove_children
            .unwrap_or(false);
        let on_exists = request.arguments.on_exists;
        let case_insensitive = request
            .arguments
            .compare_case_insensitively
            .unwrap_or(false);
        let mut pending_names: AHashMap<(u32, String), Option<u32>> = AHashMap::new();
        let mut implicit_destroys: AHashSet<u32> = AHashSet::new();

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut created_folders = AHashMap::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut file_node = FileNode::default();

            // Process changes
            let has_acl_changes =
                match update_file_node(None, object, &mut file_node, true, &response) {
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

            if file_node.modified == 0 {
                file_node.modified = now() as i64;
            }

            let renamed = match find_sibling_collision(
                None,
                &file_node,
                &cache,
                &pending_names,
                case_insensitive,
            ) {
                Collision::None => false,
                Collision::Existing(existing) => {
                    let effective = match on_exists {
                        OnExists::Newest => {
                            let existing_modified =
                                fetch_existing_modified(self.store(), account_id, existing).await?;
                            if file_node.modified > existing_modified {
                                OnExists::Replace
                            } else {
                                response.not_created.append(
                                    id,
                                    SetError::already_exists().with_existing_id(Id::from(existing)),
                                );
                                continue 'create;
                            }
                        }
                        other => other,
                    };
                    match effective {
                        OnExists::Reject => {
                            response.not_created.append(
                                id,
                                SetError::already_exists().with_existing_id(Id::from(existing)),
                            );
                            continue 'create;
                        }
                        OnExists::Rename => {
                            file_node.name = pick_unique_rename(
                                &file_node.name,
                                None,
                                file_node.parent_id,
                                &cache,
                                &pending_names,
                                case_insensitive,
                            );
                            true
                        }
                        OnExists::Replace => {
                            if let Some(target) = cache.any_resource_path_by_id(existing) {
                                let subtree_len = cache.subtree(target.path()).count();
                                if subtree_len > 1 && !on_destroy_remove_children {
                                    response
                                        .not_created
                                        .append(id, SetError::node_has_children());
                                    continue 'create;
                                }
                            }
                            implicit_destroys.insert(existing);
                            false
                        }
                        OnExists::Newest => unreachable!(),
                    }
                }
                Collision::Pending => match on_exists {
                    OnExists::Reject | OnExists::Replace | OnExists::Newest => {
                        let key = pending_key(&file_node, case_insensitive);
                        let mut err = SetError::already_exists();
                        if let Some(Some(doc_id)) = pending_names.get(&key) {
                            err = err.with_existing_id(Id::from(*doc_id));
                        }
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                    OnExists::Rename => {
                        file_node.name = pick_unique_rename(
                            &file_node.name,
                            None,
                            file_node.parent_id,
                            &cache,
                            &pending_names,
                            case_insensitive,
                        );
                        true
                    }
                },
            };

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

                self.refresh_acls(&file_node.acls, None)
                    .await
                    .caused_by(trc::location!())?;
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
            let final_name = file_node.name.clone();
            pending_names.insert(pending_key(&file_node, case_insensitive), None);
            let set_created = file_node.created == 0;
            let set_modified = file_node.modified == 0;
            file_node
                .insert(
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    set_created,
                    set_modified,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            let create_id = id.clone();
            response.created(id, document_id);
            if renamed && let Some(Value::Object(map)) = response.created.get_mut(&create_id) {
                map.insert_unchecked(
                    Key::Property(FileNodeProperty::Name),
                    Value::Str(std::borrow::Cow::Owned(final_name)),
                );
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) || implicit_destroys.contains(&id.document_id()) {
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
            let (has_acl_changes, modified_set) =
                match update_file_node(Some(id), object, &mut new_file_node, false, &response) {
                    Ok(result) => {
                        let modified_set = result.modified_set;
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

                        (result.has_acl_changes, modified_set)
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

            let renamed = match find_sibling_collision(
                Some(document_id),
                &new_file_node,
                &cache,
                &pending_names,
                case_insensitive,
            ) {
                Collision::None => false,
                Collision::Existing(existing) => {
                    let effective = match on_exists {
                        OnExists::Newest => {
                            let existing_modified =
                                fetch_existing_modified(self.store(), account_id, existing).await?;
                            if new_file_node.modified > existing_modified {
                                OnExists::Replace
                            } else {
                                response.not_updated.append(
                                    id,
                                    SetError::already_exists().with_existing_id(Id::from(existing)),
                                );
                                continue 'update;
                            }
                        }
                        other => other,
                    };
                    match effective {
                        OnExists::Reject => {
                            response.not_updated.append(
                                id,
                                SetError::already_exists().with_existing_id(Id::from(existing)),
                            );
                            continue 'update;
                        }
                        OnExists::Rename => {
                            new_file_node.name = pick_unique_rename(
                                &new_file_node.name,
                                Some(document_id),
                                new_file_node.parent_id,
                                &cache,
                                &pending_names,
                                case_insensitive,
                            );
                            true
                        }
                        OnExists::Replace => {
                            if let Some(target) = cache.any_resource_path_by_id(existing) {
                                let subtree_len = cache.subtree(target.path()).count();
                                if subtree_len > 1 && !on_destroy_remove_children {
                                    response
                                        .not_updated
                                        .append(id, SetError::node_has_children());
                                    continue 'update;
                                }
                            }
                            implicit_destroys.insert(existing);
                            false
                        }
                        OnExists::Newest => unreachable!(),
                    }
                }
                Collision::Pending => match on_exists {
                    OnExists::Reject | OnExists::Replace | OnExists::Newest => {
                        let key = pending_key(&new_file_node, case_insensitive);
                        let mut err = SetError::already_exists();
                        if let Some(Some(doc_id)) = pending_names.get(&key) {
                            err = err.with_existing_id(Id::from(*doc_id));
                        }
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                    OnExists::Rename => {
                        new_file_node.name = pick_unique_rename(
                            &new_file_node.name,
                            Some(document_id),
                            new_file_node.parent_id,
                            &cache,
                            &pending_names,
                            case_insensitive,
                        );
                        true
                    }
                },
            };

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
                .await
                .caused_by(trc::location!())?;
            }

            let final_name = new_file_node.name.clone();
            pending_names.insert(
                pending_key(&new_file_node, case_insensitive),
                Some(document_id),
            );
            // Update record. Bump modified to now() unless the client supplied a value.
            new_file_node
                .update(
                    access_token.account_tenant_ids(),
                    file_node,
                    account_id,
                    document_id,
                    !modified_set,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            let updated_value = if renamed {
                let mut map = jmap_tools::Map::with_capacity(1);
                map.insert_unchecked(
                    Key::Property(FileNodeProperty::Name),
                    Value::Str(std::borrow::Cow::Owned(final_name)),
                );
                Some(Value::Object(map))
            } else {
                None
            };
            response.updated.append(id, updated_value);
        }

        // Process deletions
        for did in &implicit_destroys {
            let id = Id::from(*did);
            if !will_destroy.contains(&id) {
                will_destroy.push(id);
            }
        }
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
                    access_token.account_tenant_ids(),
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

pub(super) struct UpdateResult {
    pub(super) has_acl_changes: bool,
    pub(super) blob_id: Option<BlobId>,
    pub(super) modified_set: bool,
}

pub(super) struct NoResolver;

impl ResolveCreatedReference<FileNodeProperty, FileNodeValue> for NoResolver {
    fn get_created_id(&self, _: &str) -> Option<AnyId> {
        None
    }
}

pub(super) fn update_file_node<R: ResolveCreatedReference<FileNodeProperty, FileNodeValue>>(
    expected_id: Option<Id>,
    updates: Value<'_, FileNodeProperty, FileNodeValue>,
    file_node: &mut FileNode,
    is_create: bool,
    resolver: &R,
) -> Result<UpdateResult, SetError<FileNodeProperty>> {
    let mut has_acl_changes = false;
    let mut blob_id = None;
    let mut pending_size: Option<u32> = None;
    let mut pending_type: Option<Option<String>> = None;
    let mut pending_executable: Option<bool> = None;
    let mut modified_set = false;

    for (property, mut value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        resolver.resolve_self_references(&mut value, 0, false)?;

        match (property, value) {
            (FileNodeProperty::Name, Value::Str(value)) => {
                if !(1..=255).contains(&value.len()) {
                    return Err(SetError::invalid_properties()
                        .with_property(FileNodeProperty::Name)
                        .with_description("Name must be between 1 and 255 octets."));
                } else if value.contains(|c: char| FORBIDDEN_NAME_CHARS.contains(c)) {
                    return Err(SetError::invalid_properties()
                        .with_property(FileNodeProperty::Name)
                        .with_description("Name contains a forbidden character."));
                } else if FORBIDDEN_NODE_NAMES
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(value.as_ref()))
                {
                    return Err(SetError::invalid_properties()
                        .with_property(FileNodeProperty::Name)
                        .with_description("Name is reserved and cannot be used."));
                }
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
                let value = value.cast_to_u64();
                if value > u32::MAX as u64 {
                    return Err(SetError::invalid_properties()
                        .with_property(FileNodeProperty::Size)
                        .with_description("size is too large."));
                }
                pending_size = Some(value as u32);
            }
            (FileNodeProperty::Size, Value::Null) => {
                pending_size = Some(0);
            }
            (FileNodeProperty::Type, Value::Str(value))
                if (1..=256).contains(&value.len()) && value.contains('/') =>
            {
                // TODO: validate full RFC 6838 Section 4.2 ABNF for media types
                pending_type = Some(Some(value.into_owned()));
            }
            (FileNodeProperty::Type, Value::Null) => {
                pending_type = Some(None);
            }
            (FileNodeProperty::Executable, Value::Bool(value)) => {
                pending_executable = Some(value);
            }
            (FileNodeProperty::Executable, Value::Null) => {
                pending_executable = Some(false);
            }
            (FileNodeProperty::Created, Value::Element(FileNodeValue::Date(value)))
                if is_create =>
            {
                file_node.created = value.timestamp();
            }
            (FileNodeProperty::Created, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(FileNodeProperty::Created)
                    .with_description("created is immutable after creation."));
            }
            (FileNodeProperty::Modified, Value::Element(FileNodeValue::Date(value))) => {
                file_node.modified = value.timestamp();
                modified_set = true;
            }
            (FileNodeProperty::Modified, Value::Null) => {
                file_node.modified = now() as i64;
                modified_set = true;
            }
            // TODO: persist accessed per-user (draft-13 section 3.1)
            (FileNodeProperty::Accessed, _) => {}
            (FileNodeProperty::NodeType, _) if is_create => {}
            (FileNodeProperty::NodeType, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(FileNodeProperty::NodeType)
                    .with_description("nodeType is immutable after creation."));
            }
            // TODO: implement symlink target storage and resolution
            (FileNodeProperty::Target, _) => {}
            (FileNodeProperty::Changed, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(FileNodeProperty::Changed)
                    .with_description("changed is server-set and not settable by clients."));
            }
            // TODO: store and validate FileNode role for directories
            (FileNodeProperty::Role, _) => {}
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
            (FileNodeProperty::Id, value) => {
                if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                    return Err(SetError::invalid_properties()
                        .with_property(FileNodeProperty::Id)
                        .with_description("The id property is immutable."));
                }
            }
            (property, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Field could not be set."));
            }
        }
    }

    let will_be_file = file_node.file.is_some() || blob_id.is_some();
    if will_be_file {
        let file = file_node.file.get_or_insert_default();
        if let Some(size) = pending_size {
            file.size = size;
        }
        if let Some(media_type) = pending_type {
            file.media_type = media_type;
        }
        if let Some(executable) = pending_executable {
            file.executable = executable;
        }
    } else {
        let sets_non_null = matches!(pending_type, Some(Some(_)))
            || matches!(pending_size, Some(s) if s != 0)
            || matches!(pending_executable, Some(true));
        if sets_non_null {
            return Err(SetError::invalid_properties()
                .with_property(FileNodeProperty::Type)
                .with_description("size, type and executable may only be set on file nodes."));
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
        modified_set,
    })
}

pub(super) fn validate_file_node_hierarchy(
    document_id: Option<u32>,
    node: &FileNode,
    is_shared: bool,
    cache: &DavResources,
    created_folders: &AHashMap<u32, Vec<AclGrant>>,
) -> Result<(), SetError<FileNodeProperty>> {
    if node.parent_id == 0 {
        if is_shared && document_id.is_none() {
            return Err(SetError::invalid_properties()
                .with_property(FileNodeProperty::ParentId)
                .with_description("Cannot create top-level folder in a shared account."));
        }
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
    }

    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum Collision {
    None,
    Existing(u32),
    Pending,
}

pub(super) async fn fetch_existing_modified(
    store: &store::Store,
    account_id: u32,
    document_id: u32,
) -> trc::Result<i64> {
    Ok(store
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::FileNode,
            document_id,
        ))
        .await?
        .map(|arch| {
            arch.unarchive::<FileNode>()
                .map(|node| node.modified.to_native())
                .unwrap_or(0)
        })
        .unwrap_or(0))
}

pub(super) fn names_equal(a: &str, b: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

pub(super) fn pending_key(node: &FileNode, case_insensitive: bool) -> (u32, String) {
    (
        node.parent_id,
        if case_insensitive {
            node.name.to_lowercase()
        } else {
            node.name.clone()
        },
    )
}

pub(super) fn find_sibling_collision(
    document_id: Option<u32>,
    node: &FileNode,
    cache: &DavResources,
    pending: &AHashMap<(u32, String), Option<u32>>,
    case_insensitive: bool,
) -> Collision {
    let node_parent_id = if node.parent_id == 0 {
        None
    } else {
        Some(node.parent_id - 1)
    };
    for resource in &cache.resources {
        if let DavResourceMetadata::File {
            name, parent_id, ..
        } = &resource.data
            && document_id.is_none_or(|id| id != resource.document_id)
            && node_parent_id == *parent_id
            && names_equal(&node.name, name, case_insensitive)
        {
            return Collision::Existing(resource.document_id);
        }
    }
    if pending.contains_key(&pending_key(node, case_insensitive)) {
        return Collision::Pending;
    }
    Collision::None
}

pub(super) fn pick_unique_rename(
    base: &str,
    document_id: Option<u32>,
    parent_id: u32,
    cache: &DavResources,
    pending: &AHashMap<(u32, String), Option<u32>>,
    case_insensitive: bool,
) -> String {
    let (stem, ext) = match base.rfind('.') {
        Some(i) if i > 0 && i < base.len() - 1 => (&base[..i], &base[i..]),
        _ => (base, ""),
    };
    let fold = |s: &str| {
        if case_insensitive {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let node_parent_id = if parent_id == 0 {
        None
    } else {
        Some(parent_id - 1)
    };

    // Collect all sibling names once, instead of rescanning per probe.
    let mut taken: AHashSet<String> = AHashSet::new();
    for resource in &cache.resources {
        if let DavResourceMetadata::File {
            name, parent_id, ..
        } = &resource.data
            && document_id.is_none_or(|id| id != resource.document_id)
            && node_parent_id == *parent_id
        {
            taken.insert(fold(name));
        }
    }
    for ((pending_parent, pending_name), _) in pending {
        if *pending_parent == parent_id {
            taken.insert(fold(pending_name));
        }
    }

    for n in 2u32.. {
        let candidate = format!("{stem} ({n}){ext}");
        if !taken.contains(&fold(&candidate)) {
            return candidate;
        }
    }
    unreachable!()
}
