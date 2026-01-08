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
    object::file_node::{self, FileNodeProperty, FileNodeValue},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use store::{ValueKey, roaring::RoaringBitmap, write::{AlignedBytes, Archive, now}};
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
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            FileNodeProperty::Id,
            FileNodeProperty::Name,
            FileNodeProperty::ParentId,
            FileNodeProperty::Size,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::FileNode)
            .await?;
        let file_node_ids = if access_token.is_member(account_id) {
            cache
                .resources
                .iter()
                .map(|r| r.document_id)
                .collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };

        let ids = if let Some(ids) = ids {
            ids
        } else {
            file_node_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(true).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the file_node object
            let document_id = id.document_id();
            if !file_node_ids.contains(document_id) {
                response.not_found.push(id);
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
                response.not_found.push(id);
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
                            if let Some(file) =
                                file_node.file.as_ref().and_then(|f| f.media_type.as_ref())
                            {
                                Value::Str(file.to_string().into())
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
                        result.insert_unchecked(
                            FileNodeProperty::Accessed,
                            Value::Element(FileNodeValue::Date(UTCDate::from_timestamp(
                                now() as i64
                            ))),
                        );
                    }
                    FileNodeProperty::IsSubscribed => {
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
