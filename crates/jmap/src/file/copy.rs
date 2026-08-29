/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::parent_ref::ParentRef;
use crate::{
    api::acl::JmapAcl,
    blob::download::BlobDownload,
    changes::state::JmapCacheState,
    file::set::{
        Collision, NoResolver, fetch_existing_modified, find_sibling_collision, pick_unique_rename,
        update_file_node, validate_file_node_hierarchy,
    },
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse},
        set::SetRequest,
    },
    object::file_node::{self, FileNodeProperty, OnExists},
    request::{
        Call, IntoValid, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
    types::state::State,
};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, Slot, now},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    id::Id,
};
use utils::map::vec_map::VecMap;

pub trait FileNodeCopy: Sync + Send {
    fn file_node_copy<'x>(
        &self,
        request: CopyRequest<'x, file_node::FileNode>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse<file_node::FileNode>>> + Send;
}

impl FileNodeCopy for Server {
    async fn file_node_copy<'x>(
        &self,
        request: CopyRequest<'x, file_node::FileNode>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        _session: &HttpSessionData,
    ) -> trc::Result<CopyResponse<file_node::FileNode>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }

        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let old_state = cache.assert_state(false, &request.if_in_state)?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
        };

        let from_cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let from_node_ids = if access_token.is_member(from_account_id) {
            from_cache
                .resources
                .iter()
                .map(|r| r.document_id)
                .collect::<RoaringBitmap>()
        } else {
            let mut readable =
                from_cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true);
            readable |= from_cache.shared_items(access_token, [Acl::ReadItems], true);
            readable
        };

        let is_shared = access_token.is_shared(account_id);
        let can_add_to = if is_shared {
            Some(cache.shared_containers(access_token, [Acl::AddItems], true))
        } else {
            None
        };
        let on_exists = request.arguments.on_exists;
        let case_insensitive = request
            .arguments
            .compare_case_insensitively
            .unwrap_or(false);
        let on_destroy_remove_children = request
            .arguments
            .on_destroy_remove_children
            .unwrap_or(false);
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);

        let mut batch = BatchBuilder::new();
        let mut pending_names: AHashMap<(ParentRef, String), Option<u32>> = AHashMap::new();
        let mut implicit_destroys: AHashSet<u32> = AHashSet::new();
        let mut created_folders: AHashMap<ParentRef, Vec<types::acl::AclGrant>> = AHashMap::new();
        let mut created_slots: Vec<(Id, Slot, Option<String>)> = Vec::new();
        let mut destroy_ids = Vec::new();

        'create: for (id, create) in request.create.into_valid() {
            let from_document_id = id.document_id();
            if !from_node_ids.contains(from_document_id) {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            }

            let Some(source) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    from_account_id,
                    Collection::FileNode,
                    from_document_id,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            };

            let mut file_node = source
                .deserialize::<FileNode>()
                .caused_by(trc::location!())?;
            // ACLs are account-scoped; do not carry the source account's grants over.
            file_node.acls.clear();

            let parent;
            let has_acl_changes =
                match update_file_node(None, create, &mut file_node, true, &NoResolver) {
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
                                continue 'create;
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

                        parent = result.parent;
                        file_node.parent_id = parent.as_stored();
                        result.has_acl_changes
                    }
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };

            if let Err(err) =
                validate_file_node_hierarchy(None, parent, is_shared, &cache, &created_folders)
            {
                response.not_created.append(id, err);
                continue 'create;
            }

            if file_node.modified == 0 {
                file_node.modified = now() as i64;
            }

            let renamed = match find_sibling_collision(
                None,
                parent,
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
                                    SetError::already_exists()
                                        .with_existing_id(types::id::Id::from(existing)),
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
                                SetError::already_exists()
                                    .with_existing_id(types::id::Id::from(existing)),
                            );
                            continue 'create;
                        }
                        OnExists::Rename => {
                            file_node.name = pick_unique_rename(
                                &file_node.name,
                                None,
                                parent,
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
                    OnExists::Rename => {
                        file_node.name = pick_unique_rename(
                            &file_node.name,
                            None,
                            parent,
                            &cache,
                            &pending_names,
                            case_insensitive,
                        );
                        true
                    }
                    OnExists::Reject | OnExists::Replace | OnExists::Newest => {
                        let key =
                            crate::file::set::pending_key(parent, &file_node, case_insensitive);
                        let mut err = SetError::already_exists();
                        if let Some(Some(doc_id)) = pending_names.get(&key) {
                            err = err.with_existing_id(types::id::Id::from(*doc_id));
                        }
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                },
            };

            // Permission and ACL inheritance for the destination parent
            if let Some(parent_id) = parent.document_id() {
                // The user must be allowed to add children to the destination parent
                if let Some(allowed) = &can_add_to
                    && !created_folders.contains_key(&parent)
                    && !allowed.contains(parent_id)
                {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(
                            "You are not allowed to create file nodes in this folder.",
                        ),
                    );
                    continue 'create;
                }

                let parent_acls = created_folders.get(&parent).cloned().or_else(|| {
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
            } else if is_shared {
                response.not_created.append(
                    id,
                    SetError::forbidden()
                        .with_description("Cannot create top-level folder in a shared account."),
                );
                continue 'create;
            }

            if !file_node.acls.is_empty() {
                if let Err(err) = self.acl_validate(&file_node.acls).await {
                    response.not_created.append(id, err.into());
                    continue 'create;
                }
                self.refresh_acls(&file_node.acls, None)
                    .await
                    .caused_by(trc::location!())?;
            }

            let document_id = batch.reserve_document_id(account_id, Collection::FileNode);
            if file_node.file.is_none() {
                created_folders.insert(ParentRef::pending(document_id), file_node.acls.clone());
            }
            pending_names.insert(
                crate::file::set::pending_key(parent, &file_node, case_insensitive),
                None,
            );
            let final_name = file_node.name.clone();
            let set_created = file_node.created == 0;
            let set_modified = file_node.modified == 0;
            file_node
                .insert_with_parent(
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    parent.slot(),
                    set_created,
                    set_modified,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            created_slots.push((id, document_id, renamed.then_some(final_name)));

            if on_success_delete {
                destroy_ids.push(MaybeInvalid::Value(id));
            }
        }

        for did in &implicit_destroys {
            let Some(node) = cache.any_resource_path_by_id(*did) else {
                continue;
            };
            let mut ids = cache.subtree(node.path()).collect::<Vec<_>>();
            ids.sort_unstable_by_key(|b| std::cmp::Reverse(b.hierarchy_seq()));
            let sorted = ids.into_iter().map(|a| a.document_id()).collect::<Vec<_>>();
            groupware::DestroyArchive(sorted)
                .delete_batch(
                    self,
                    access_token.account_tenant_ids(),
                    account_id,
                    cache.format_resource(node).into(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }

        if !batch.is_empty() {
            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;

            for (create_id, slot, renamed) in created_slots {
                response.created(create_id, assigned_ids.slot(slot));
                if let Some(final_name) = renamed
                    && let Some(value) = response.created.get_mut(&create_id)
                    && let jmap_tools::Value::Object(map) = value
                {
                    map.insert_unchecked(
                        jmap_tools::Key::Property(FileNodeProperty::Name),
                        jmap_tools::Value::Str(std::borrow::Cow::Owned(final_name)),
                    );
                }
            }

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::FileNode));
        }

        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::FileNode, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::FileNode(Box::new(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                }))),
            }
            .into();
        }

        Ok(response)
    }
}
