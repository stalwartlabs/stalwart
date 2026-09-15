/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    node::{default_media_type, node_type_from_id, target_value},
    writer::fetch_archive,
};
use crate::{api::acl::JmapRights, changes::state::JmapCacheState};
use common::{GroupwareResourceRef, Server, auth::AccessToken, storage::dav::FILE_KIND_FILE};
use groupware::{
    cache::GroupwareCache,
    file::{FileNode, FileNodeRole},
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::file_node::{self, FileNodeProperty, FileNodeValue},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{
    acl::Acl,
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    id::Id,
};
use utils::map::bitmap::Bitmap;

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
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await?;
        let is_owner = access_token.is_member(account_id);
        let access = (!is_owner).then(|| cache.file_access(access_token));
        let is_visible = |document_id: u32| {
            access
                .as_ref()
                .is_none_or(|access| access.discoverable.contains(document_id))
        };

        let mut ids = match ids {
            Some(ids) => ids,
            None => match &access {
                Some(access) => access
                    .discoverable
                    .iter()
                    .take(self.core.jmap.get_max_objects)
                    .map(Id::from)
                    .collect(),
                None => cache
                    .resources
                    .iter()
                    .take(self.core.jmap.get_max_objects)
                    .map(|resource| Id::from(resource.document_id()))
                    .collect(),
            },
        };

        if request.arguments.fetch_parents.unwrap_or(false) {
            let mut seen = ids
                .iter()
                .map(|id| id.document_id())
                .collect::<RoaringBitmap>();
            let mut ancestors = Vec::new();
            for id in ids.iter().filter(|id| is_visible(id.document_id())) {
                let mut current = cache
                    .resources
                    .find_any(id.document_id())
                    .and_then(|resource| resource.parent_id());
                while let Some(parent_id) = current {
                    if !seen.insert(parent_id) {
                        break;
                    }
                    if is_visible(parent_id) {
                        ancestors.push(Id::from(parent_id));
                    }
                    current = cache
                        .resources
                        .find_any(parent_id)
                        .and_then(|resource| resource.parent_id());
                }
            }
            ids.extend(ancestors);
        }

        let needs_archive = properties.iter().any(|property| {
            matches!(
                property,
                FileNodeProperty::BlobId
                    | FileNodeProperty::Target
                    | FileNodeProperty::Accessed
                    | FileNodeProperty::Changed
                    | FileNodeProperty::IsSubscribed
            )
        });
        let personal_id = access_token.personal_id(account_id, Collection::FileNode);
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            let document_id = id.document_id();
            let Some(resource) = cache
                .resources
                .find_any(document_id)
                .filter(|_| is_visible(document_id))
            else {
                response.push_not_found(id);
                continue;
            };
            let is_readable = access
                .as_ref()
                .is_none_or(|access| access.readable.contains(document_id));
            if !is_readable {
                response
                    .list
                    .push(discoverable_only(&properties, id, &resource).into());
                continue;
            }
            let archive = if needs_archive {
                match fetch_archive(self, account_id, document_id).await? {
                    Some(archive) => Some(archive),
                    None => {
                        response.push_not_found(id);
                        continue;
                    }
                }
            } else {
                None
            };
            let node = archive
                .as_ref()
                .map(|archive| archive.unarchive::<FileNode>())
                .transpose()
                .caused_by(trc::location!())?;
            let flags = resource.file_flags().unwrap_or_default();
            let is_file = flags.kind() == FILE_KIND_FILE;
            let rights = access.as_ref().map(|access| access.acl(document_id));

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    FileNodeProperty::Id => Value::Element(FileNodeValue::Id(id)),
                    FileNodeProperty::Name => Value::Str(
                        resource
                            .container_name()
                            .unwrap_or_default()
                            .to_string()
                            .into(),
                    ),
                    FileNodeProperty::ParentId => {
                        resource.parent_id().map_or(Value::Null, |parent_id| {
                            Value::Element(FileNodeValue::Id(parent_id.into()))
                        })
                    }
                    FileNodeProperty::NodeType => {
                        Value::Str(node_type_from_id(flags.kind()).as_str().into())
                    }
                    FileNodeProperty::BlobId => {
                        node.and_then(|node| node.file())
                            .map_or(Value::Null, |file| {
                                Value::Element(FileNodeValue::BlobId(BlobId::new(
                                    BlobHash::from(&file.blob_hash),
                                    BlobClass::Linked {
                                        account_id,
                                        collection: Collection::FileNode.into(),
                                        document_id,
                                    },
                                )))
                            })
                    }
                    FileNodeProperty::Target => node
                        .and_then(|node| node.symlink_target())
                        .map_or(Value::Null, target_value),
                    FileNodeProperty::Size => resource
                        .size()
                        .filter(|_| is_file)
                        .map_or(Value::Null, |size| Value::Number(size.into())),
                    FileNodeProperty::Type if is_file => Value::Str(
                        resource
                            .media_type()
                            .unwrap_or(default_media_type())
                            .to_string()
                            .into(),
                    ),
                    FileNodeProperty::Type => Value::Null,
                    FileNodeProperty::Executable => Value::Bool(flags.is_executable()),
                    FileNodeProperty::Created => date_value(resource.created_at()),
                    FileNodeProperty::Modified => date_value(resource.modified_at()),
                    FileNodeProperty::Accessed => {
                        date_value(node.map(|node| node.accessed.to_native()))
                    }
                    FileNodeProperty::Changed => {
                        date_value(node.map(|node| node.changed.to_native()))
                    }
                    FileNodeProperty::IsSubscribed => {
                        Value::Bool(node.is_none_or(|node| node.is_subscribed(personal_id)))
                    }
                    FileNodeProperty::Role => FileNodeRole::from_id(flags.role())
                        .map_or(Value::Null, |role| Value::Str(role.as_str().into())),
                    FileNodeProperty::MyRights => match rights {
                        Some(rights) => JmapRights::rights::<file_node::FileNode>(rights),
                        None => JmapRights::all_rights::<file_node::FileNode>(),
                    },
                    FileNodeProperty::ShareWith => {
                        let acls = resource.acls();
                        if !acls.is_empty()
                            && rights.is_none_or(|rights| rights.contains(Acl::Share))
                        {
                            JmapRights::grants_value::<file_node::FileNode>(acls)
                        } else {
                            Value::Null
                        }
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                        continue;
                    }
                };
                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}

fn discoverable_only(
    properties: &[FileNodeProperty],
    id: Id,
    resource: &GroupwareResourceRef<'_>,
) -> Map<'static, FileNodeProperty, FileNodeValue> {
    let mut result = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            FileNodeProperty::Id => Value::Element(FileNodeValue::Id(id)),
            FileNodeProperty::Name => Value::Str(
                resource
                    .container_name()
                    .unwrap_or_default()
                    .to_string()
                    .into(),
            ),
            FileNodeProperty::ParentId => resource.parent_id().map_or(Value::Null, |parent_id| {
                Value::Element(FileNodeValue::Id(parent_id.into()))
            }),
            FileNodeProperty::NodeType => Value::Str(
                node_type_from_id(resource.file_kind().unwrap_or_default())
                    .as_str()
                    .into(),
            ),
            FileNodeProperty::MyRights => JmapRights::rights::<file_node::FileNode>(Bitmap::new()),
            FileNodeProperty::IsSubscribed | FileNodeProperty::Executable => Value::Bool(false),
            _ => Value::Null,
        };
        result.insert_unchecked(property.clone(), value);
    }
    result
}

pub(super) fn date_value(
    timestamp: Option<i64>,
) -> Value<'static, FileNodeProperty, FileNodeValue> {
    timestamp.map_or(Value::Null, |timestamp| {
        Value::Element(FileNodeValue::Date(UTCDate::from_timestamp(timestamp)))
    })
}
