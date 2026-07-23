/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::acl::JmapRights, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{cache::GroupwareCache, file::FileNode};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::file_node::{self, FileNodeNodeType, FileNodeProperty, FileNodeValue},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, now},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
};

pub trait FileNodeGet: Sync + Send {
    fn file_node_get(
        &self,
        request: GetRequest<file_node::FileNode>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<file_node::FileNode>>> + Send;
}

impl FileNodeGet for Server {
    async fn file_node_get(
        &self,
        mut request: GetRequest<file_node::FileNode>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<file_node::FileNode>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            FileNodeProperty::Id,
            FileNodeProperty::ParentId,
            FileNodeProperty::NodeType,
            FileNodeProperty::BlobId,
            FileNodeProperty::Target,
            FileNodeProperty::Size,
            FileNodeProperty::Name,
            FileNodeProperty::Type,
            FileNodeProperty::Created,
            FileNodeProperty::Modified,
            FileNodeProperty::Accessed,
            FileNodeProperty::Changed,
            FileNodeProperty::Executable,
            FileNodeProperty::IsSubscribed,
            FileNodeProperty::MyRights,
            FileNodeProperty::ShareWith,
            FileNodeProperty::Role,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await?;
        // TODO: draft-14 section 5 case 2 - ancestors of shared nodes should be discoverable with mayRead=false
        let file_node_ids = if access_token.is_member(account_id) {
            cache
                .resources
                .iter()
                .map(|r| r.document_id)
                .collect::<RoaringBitmap>()
        } else {
            cache.shared_documents(access_token, [Acl::Read, Acl::ReadItems], true)
        };

        let mut ids = if let Some(ids) = ids {
            ids
        } else {
            file_node_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };

        if request.arguments.fetch_parents.unwrap_or(false) {
            let mut seen: RoaringBitmap = ids.iter().map(|i| i.document_id()).collect();
            let mut extra: Vec<types::id::Id> = Vec::new();
            for id in &ids {
                let mut current = cache
                    .any_resource_path_by_id(id.document_id())
                    .and_then(|r| r.parent_id());
                while let Some(parent_id) = current {
                    if !seen.insert(parent_id) {
                        break;
                    }
                    if file_node_ids.contains(parent_id) {
                        extra.push(parent_id.into());
                    }
                    current = cache
                        .container_resource_by_id(parent_id)
                        .and_then(|r| r.parent_id());
                }
            }
            ids.extend(extra);
        }
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            // Obtain the file_node object
            let document_id = id.document_id();
            if !file_node_ids.contains(document_id) {
                response.push_not_found(id);
                continue;
            }
            let _file_node = if let Some(file_node) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::FileNode,
                    document_id,
                ))
                .await?
            {
                file_node
            } else {
                response.push_not_found(id);
                continue;
            };
            let file_node = _file_node
                .unarchive::<FileNode>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    FileNodeProperty::Id => {
                        result.insert_unchecked(FileNodeProperty::Id, FileNodeValue::Id(id));
                    }
                    FileNodeProperty::Name => {
                        result.insert_unchecked(FileNodeProperty::Name, file_node.name.to_string());
                    }
                    FileNodeProperty::ShareWith => {
                        result.insert_unchecked(
                            FileNodeProperty::ShareWith,
                            JmapRights::share_with::<file_node::FileNode>(
                                account_id,
                                access_token,
                                &file_node
                                    .acls
                                    .iter()
                                    .map(AclGrant::from)
                                    .collect::<Vec<_>>(),
                            ),
                        );
                    }
                    FileNodeProperty::MyRights => {
                        result.insert_unchecked(
                            FileNodeProperty::MyRights,
                            if access_token.is_shared(account_id) {
                                JmapRights::rights::<file_node::FileNode>(
                                    file_node.acls.effective_acl(access_token),
                                )
                            } else {
                                JmapRights::all_rights::<file_node::FileNode>()
                            },
                        );
                    }
                    FileNodeProperty::ParentId => {
                        let parent_id = file_node.parent_id.to_native();

                        result.insert_unchecked(
                            FileNodeProperty::ParentId,
                            if parent_id > 0 {
                                Value::Element(FileNodeValue::Id((parent_id - 1).into()))
                            } else {
                                Value::Null
                            },
                        );
                    }
                    FileNodeProperty::BlobId => {
                        result.insert_unchecked(
                            FileNodeProperty::BlobId,
                            if let Some(file) = file_node.file.as_ref() {
                                Value::Element(FileNodeValue::BlobId(BlobId::new(
                                    BlobHash::from(&file.blob_hash),
                                    BlobClass::Linked {
                                        account_id,
                                        collection: Collection::FileNode.into(),
                                        document_id: id.document_id(),
                                    },
                                )))
                            } else {
                                Value::Null
                            },
                        );
                    }
                    FileNodeProperty::Size => {
                        result.insert_unchecked(
                            FileNodeProperty::Size,
                            if let Some(file) = file_node.file.as_ref() {
                                Value::Number(file.size.to_native().into())
                            } else {
                                Value::Null
                            },
                        );
                    }
                    FileNodeProperty::Type => {
                        result.insert_unchecked(
                            FileNodeProperty::Type,
                            if let Some(file) = file_node.file.as_ref() {
                                Value::Str(
                                    file.media_type
                                        .as_ref()
                                        .map(|t| t.to_string())
                                        .unwrap_or_else(|| "application/octet-stream".to_string())
                                        .into(),
                                )
                            } else {
                                Value::Null
                            },
                        );
                    }
                    FileNodeProperty::Executable => {
                        result.insert_unchecked(
                            FileNodeProperty::Executable,
                            if let Some(file) = file_node.file.as_ref() {
                                Value::Bool(file.executable)
                            } else {
                                Value::Null
                            },
                        );
                    }
                    FileNodeProperty::Created => {
                        result.insert_unchecked(
                            FileNodeProperty::Created,
                            Value::Element(FileNodeValue::Date(UTCDate::from_timestamp(
                                file_node.created.to_native(),
                            ))),
                        );
                    }
                    FileNodeProperty::Modified => {
                        result.insert_unchecked(
                            FileNodeProperty::Modified,
                            Value::Element(FileNodeValue::Date(UTCDate::from_timestamp(
                                file_node.modified.to_native(),
                            ))),
                        );
                    }
                    FileNodeProperty::Accessed => {
                        // TODO: needs serialization change (per-user accessed timestamp); returns now() as a placeholder
                        result.insert_unchecked(
                            FileNodeProperty::Accessed,
                            Value::Element(FileNodeValue::Date(UTCDate::from_timestamp(
                                now() as i64
                            ))),
                        );
                    }
                    FileNodeProperty::Changed => {
                        // TODO: needs serialization change (dedicated server-set changed timestamp); returns modified as a placeholder
                        result.insert_unchecked(
                            FileNodeProperty::Changed,
                            Value::Element(FileNodeValue::Date(UTCDate::from_timestamp(
                                file_node.modified.to_native(),
                            ))),
                        );
                    }
                    FileNodeProperty::NodeType => {
                        let node_type = if file_node.file.is_some() {
                            FileNodeNodeType::File
                        } else {
                            FileNodeNodeType::Directory
                        };
                        result.insert_unchecked(
                            FileNodeProperty::NodeType,
                            Value::Str(node_type.as_str().into()),
                        );
                    }
                    FileNodeProperty::Target => {
                        result.insert_unchecked(FileNodeProperty::Target, Value::Null);
                    }
                    FileNodeProperty::Role => {
                        result.insert_unchecked(FileNodeProperty::Role, Value::Null);
                    }
                    FileNodeProperty::IsSubscribed => {
                        // TODO: needs serialization change (per-user subscription state); always true for now
                        result.insert_unchecked(FileNodeProperty::IsSubscribed, Value::Bool(true));
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
