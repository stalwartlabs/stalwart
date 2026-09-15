/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    node::NoResolver,
    set::create_node,
    writer::{FileNodeWriter, WriteOptions, fetch_archive},
};
use crate::changes::state::JmapCacheState;
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse},
        set::SetRequest,
    },
    object::file_node::{self, FileNodeProperty, FileNodeValue},
    request::{
        Call, IntoValid, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
    types::state::State,
};
use jmap_tools::{Key, Value};
use trc::AddContext;
use types::{collection::SyncCollection, id::Id};
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
            .fetch_groupware_resources(
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
            .fetch_groupware_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::FileNode,
            )
            .await
            .caused_by(trc::location!())?;
        let from_readable = (!access_token.is_member(from_account_id))
            .then(|| from_cache.file_access(access_token).readable);

        let options = WriteOptions {
            on_exists: request.arguments.on_exists,
            remove_children: request
                .arguments
                .on_destroy_remove_children
                .unwrap_or(false),
            case_insensitive: request
                .arguments
                .compare_case_insensitively
                .unwrap_or(false),
        };
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut writer = FileNodeWriter::new(self, access_token, account_id, &cache, options)
            .with_quota()
            .await?;
        let mut created = Vec::with_capacity(request.create.len());
        let mut awaiting_existing = Vec::new();
        let mut destroy_ids = Vec::new();

        for (id, create) in request.create.into_valid() {
            let from_document_id = id.document_id();
            let source = if from_cache.resources.find_any(from_document_id).is_some()
                && from_readable
                    .as_ref()
                    .is_none_or(|readable| readable.contains(from_document_id))
            {
                fetch_archive(self, from_account_id, from_document_id).await?
            } else {
                None
            };
            let Some(source) = source else {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            };

            let mut node = source
                .deserialize::<FileNode>()
                .caused_by(trc::location!())?;
            node.acls.clear();
            node.unsubscribed.clear();
            node.parent_id = 0;

            match create_node(&mut writer, String::new(), node, create, &NoResolver).await? {
                Ok(node) => {
                    created.push((id, node));
                    if on_success_delete {
                        destroy_ids.push(MaybeInvalid::Value(id));
                    }
                }
                Err((_, rejection)) => match rejection.existing {
                    Some(slot) => awaiting_existing.push((id, rejection.error, slot)),
                    None => response.not_created.append(id, rejection.error),
                },
            }
        }

        let _ = writer.execute_destroys(Vec::new()).await?;

        if !writer.batch.is_empty() {
            let assigned_ids = self
                .commit_batch(writer.batch)
                .await
                .caused_by(trc::location!())?;

            for (id, err, slot) in awaiting_existing {
                response
                    .not_created
                    .append(id, err.with_existing_id(Id::from(assigned_ids.slot(slot))));
            }
            for (create_id, node) in created {
                let mut values = node.values;
                values.insert_unchecked(
                    Key::Property(FileNodeProperty::Id),
                    Value::Element(FileNodeValue::Id(Id::from(assigned_ids.slot(node.slot)))),
                );
                response.created.append(create_id, Value::Object(values));
            }

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::FileNode));
        } else {
            for (id, err, _) in awaiting_existing {
                response.not_created.append(id, err);
            }
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
