/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::{ItemError, create::ingest_error, props::ItemProp};
use crate::{
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    ews::{
        config::fai_node_data_type,
        context::{EwsCaller, EwsContext},
        filter::{Filter, PropValue},
        folder::folder_id,
    },
    folders::{FolderNode, access::ViewRights},
    mapi::emsmdb::message::{
        fai::{FaiRecordError, creation_stamp, fai_record},
        object_row::{carry_creation_time, decode_property, encode_key, stamp_creation_time},
    },
    store::{
        ArchivedExchangeProperty,
        account::ExchangeAccountStore,
        folder::{
            ArchivedFaiMessage, FaiChange, FaiCommit, FaiFolder, FaiKind, FaiMessage, FolderStore,
            TOMBSTONE_HORIZON_ID,
        },
        object::ObjectVersion,
    },
};
use common::Server;
use exchange_proto::{
    convert::model::{MessageContent, PropBag},
    ews::{
        bulk::{BulkRecord, RawProperty},
        types::{
            ids::{BaseItemId, EwsIdStr, ItemId},
            item::{Item, ItemFields},
            value::DateTime,
        },
    },
    ids::{
        ews::{EwsChangeKey, EwsObjectId},
        token::ObjectKind,
    },
    mapi::prop::{OwnedPropValue, PropKey, PropKeyRef, tags},
};
use std::borrow::Cow;
use store::write::{Archive, ArchiveBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssociatedId {
    pub account: u32,
    pub node: FolderNode,
    pub id: u32,
    folder_kind: ObjectKind,
    folder: u32,
}

impl AssociatedId {
    pub fn new(account: u32, node: FolderNode, id: u32) -> Option<Self> {
        let (folder_kind, folder) = node.object_id()?;
        Some(AssociatedId {
            account,
            node,
            id,
            folder_kind,
            folder,
        })
    }

    pub fn of(object: &EwsObjectId) -> Option<Result<Self, ItemError>> {
        let EwsObjectId::Associated {
            account,
            folder_kind,
            folder,
            id,
        } = *object
        else {
            return None;
        };
        Some(
            FolderNode::from_object_id(folder_kind, folder)
                .filter(|_| id != TOMBSTONE_HORIZON_ID)
                .and_then(|node| AssociatedId::new(account, node, id))
                .ok_or(ItemError::Malformed),
        )
    }

    pub fn decode(id: &BaseItemId<'_>) -> Option<Result<Self, ItemError>> {
        match id {
            BaseItemId::Item(id) => AssociatedId::of(&EwsObjectId::decode(id.id.as_str())?),
            _ => None,
        }
    }

    pub fn item_id(self, change_id: u64) -> ItemId<'static> {
        ItemId {
            id: EwsIdStr::Minted(
                EwsObjectId::Associated {
                    account: self.account,
                    folder_kind: self.folder_kind,
                    folder: self.folder,
                    id: self.id,
                }
                .encode(),
            ),
            change_key: Some(EwsIdStr::Minted(
                EwsChangeKey {
                    kind: ObjectKind::Email,
                    change_id,
                }
                .encode(),
            )),
        }
    }

    fn folder(self, ctx: &EwsContext) -> Result<FaiFolder, ItemError> {
        if self.account != ctx.account.account_id {
            return Err(ItemError::NotFound);
        }
        fai_folder_of(ctx, self.node)
    }
}

fn fai_folder_of(ctx: &EwsContext, node: FolderNode) -> Result<FaiFolder, ItemError> {
    if !matches!(ctx.access, ViewRights::Owner) {
        return Err(ItemError::AccessDenied);
    }
    if !ctx.account.data_types.contains(fai_node_data_type(node)) {
        return Err(ItemError::AccessDenied);
    }
    FaiFolder::new(node).ok_or(ItemError::NotFound)
}

pub(crate) async fn open_associated(
    server: &Server,
    ctx: &EwsContext,
    target: AssociatedId,
) -> trc::Result<Result<Archive<ArchiveBytes>, ItemError>> {
    let folder = match target.folder(ctx) {
        Ok(folder) => folder,
        Err(err) => return Ok(Err(err)),
    };
    Ok(server
        .fai_message(target.account, folder, target.id)
        .await?
        .ok_or(ItemError::NotFound))
}

pub(crate) async fn get_associated(
    server: &Server,
    ctx: &EwsContext,
    target: AssociatedId,
) -> trc::Result<Result<Item<'static>, ItemError>> {
    match open_associated(server, ctx, target).await? {
        Ok(row) => Ok(Ok(render(target, row.unarchive::<FaiMessage>()?))),
        Err(err) => Ok(Err(err)),
    }
}

pub(crate) async fn find_associated(
    server: &Server,
    ctx: &EwsContext,
    node: FolderNode,
    filter: Option<&Filter<'_, '_, ItemProp>>,
) -> trc::Result<Result<Vec<Item<'static>>, ItemError>> {
    let folder = match fai_folder_of(ctx, node) {
        Ok(folder) => folder,
        Err(ItemError::NotFound) => return Ok(Ok(Vec::new())),
        Err(err) => return Ok(Err(err)),
    };
    let account = ctx.account.account_id;
    let reads_subject =
        filter.is_some_and(|filter| filter.props().any(|prop| prop == ItemProp::Subject));
    let mut items = Vec::new();
    server
        .fai_messages(account, folder, |id, fai| {
            if FaiKind::from(&fai.kind) != FaiKind::Associated {
                return Ok(true);
            }
            let Some(target) = AssociatedId::new(account, node, id) else {
                return Ok(true);
            };
            if let Some(filter) = filter {
                let subject = if reads_subject { subject_of(fai) } else { None };
                let value = |prop| match prop {
                    ItemProp::ItemClass => Some(PropValue::Text(fai.message_class.as_str())),
                    ItemProp::Subject => subject.as_deref().map(PropValue::Text),
                    _ => None,
                };
                if !filter.matches(&value) {
                    return Ok(true);
                }
            }
            items.push(render(target, fai));
            Ok(true)
        })
        .await?;
    Ok(Ok(items))
}

pub(crate) async fn delete_associated(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    target: AssociatedId,
) -> trc::Result<Result<(), ItemError>> {
    let folder = match target.folder(ctx) {
        Ok(folder) => folder,
        Err(err) => return Ok(Err(err)),
    };
    let owner = server
        .exchange_quota_owner(caller.access_token, target.account)
        .await?;
    for _ in 0..MAX_STATE_ATTEMPTS {
        let Some(row) = server
            .fai_message(target.account, folder, target.id)
            .await?
        else {
            return Ok(Err(ItemError::NotFound));
        };
        let change = FaiChange::Delete {
            id: target.id,
            previous: &row,
        };
        match server.commit_fai(owner, folder, change).await {
            Ok(FaiCommit::Written { .. }) => return Ok(Ok(())),
            Ok(FaiCommit::Conflict) => {}
            Err(err) => return ingest_error(err).map(Err),
        }
    }
    Ok(Err(ItemError::Conflict))
}

pub(super) async fn write_associated(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    node: FolderNode,
    existing: Option<u32>,
    mut record: FaiMessage,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let account_id = ctx.account.account_id;
    let folder = match fai_folder_of(ctx, node) {
        Ok(folder) => folder,
        Err(err) => return Ok(Err(err)),
    };
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    if existing.is_none() {
        stamp_creation_time(&mut record.properties, creation_stamp());
    }
    for _ in 0..MAX_STATE_ATTEMPTS {
        let committed = match existing {
            None => {
                server
                    .commit_fai(
                        owner,
                        folder,
                        FaiChange::Create {
                            message: record.clone(),
                            version: ObjectVersion::Server,
                        },
                    )
                    .await
            }
            Some(id) => {
                let Some(row) = server.fai_message(account_id, folder, id).await? else {
                    return Ok(Err(ItemError::NotFound));
                };
                let mut message = record.clone();
                carry_creation_time(
                    &mut message.properties,
                    row.unarchive::<FaiMessage>()?.properties.iter(),
                );
                server
                    .commit_fai(
                        owner,
                        folder,
                        FaiChange::Update {
                            id,
                            previous: &row,
                            message,
                            version: ObjectVersion::Server,
                        },
                    )
                    .await
            }
        };
        match committed {
            Ok(FaiCommit::Written { id, change }) => {
                return Ok(AssociatedId::new(account_id, node, id)
                    .map(|target| target.item_id(change))
                    .ok_or(ItemError::NotFound));
            }
            Ok(FaiCommit::Conflict) => {}
            Err(err) => return ingest_error(err).map(Err),
        }
    }
    Ok(Err(ItemError::Conflict))
}

pub(super) fn fai_message(
    content: &MessageContent,
    rule_size_limit: Option<u64>,
) -> Result<FaiMessage, ItemError> {
    fai_record(content, rule_size_limit, FaiKind::Associated).map_err(|err| match err {
        FaiRecordError::Attachments => ItemError::AssociatedAttachments,
        FaiRecordError::RuleTooLarge => ItemError::ItemSave,
        FaiRecordError::InvalidClass => ItemError::CorruptData,
    })
}

pub(super) fn record_of(fai: &ArchivedFaiMessage) -> BulkRecord<'_> {
    BulkRecord::Associated {
        message_class: fai.message_class.as_str(),
        properties: raw_properties(fai.properties.as_slice()),
        recipients: fai
            .recipients
            .iter()
            .map(|recipient| raw_properties(recipient.properties.as_slice()))
            .collect(),
    }
}

pub(super) fn raw_properties(properties: &[ArchivedExchangeProperty]) -> Vec<RawProperty<'_>> {
    properties
        .iter()
        .map(|property| RawProperty {
            key: property.key.as_slice(),
            value: property.value.as_slice(),
        })
        .collect()
}

pub(super) fn merge_raw(
    bag: &mut PropBag,
    properties: &[RawProperty<'_>],
) -> Result<(), ItemError> {
    for property in properties {
        let (key, value) =
            decode_property(property.key, property.value).ok_or(ItemError::CorruptData)?;
        bag.set(key, value);
    }
    Ok(())
}

pub(super) fn associated_content(
    message_class: &str,
    properties: &[RawProperty<'_>],
    recipients: &[Vec<RawProperty<'_>>],
) -> Result<MessageContent, ItemError> {
    let mut content = MessageContent::default();
    merge_raw(&mut content.props, properties)?;
    content.props.set(
        PropKey::tag(tags::MESSAGE_CLASS.id()),
        OwnedPropValue::Unicode(message_class.into()),
    );
    content.recipients.reserve_exact(recipients.len());
    for recipient in recipients {
        let mut bag = PropBag::default();
        merge_raw(&mut bag, recipient)?;
        content.recipients.push(bag);
    }
    Ok(content)
}

fn render(target: AssociatedId, fai: &ArchivedFaiMessage) -> Item<'static> {
    let change_id = fai.change.to_native();
    let created_key = encode_key(PropKeyRef::Tag(tags::CREATION_TIME.id()));
    let created = fai
        .properties
        .iter()
        .find(|property| property.key.as_slice() == created_key.as_slice())
        .and_then(|property| decode_property(property.key.as_slice(), property.value.as_slice()))
        .and_then(|(_, value)| match value {
            OwnedPropValue::Time(time) => Some(DateTime::utc(time.to_utc().0)),
            _ => None,
        });
    let subject = subject_of(fai).map(Cow::Owned);
    Item::Item(Box::new(ItemFields {
        item_id: Some(target.item_id(change_id)),
        parent_folder_id: Some(folder_id(target.account, target.node, change_id)),
        item_class: Some(Cow::Owned(fai.message_class.as_str().to_string())),
        subject,
        size: Some(i32::try_from(fai.quota_size()).unwrap_or(i32::MAX)),
        date_time_created: created,
        is_associated: Some(true),
        ..Default::default()
    }))
}

fn subject_of(fai: &ArchivedFaiMessage) -> Option<String> {
    let subject_key = encode_key(PropKeyRef::Tag(tags::SUBJECT.id()));
    let property = fai
        .properties
        .iter()
        .find(|property| property.key.as_slice() == subject_key.as_slice())?;
    match decode_property(property.key.as_slice(), property.value.as_slice())?.1 {
        OwnedPropValue::Unicode(text) => Some(text.into_string()),
        OwnedPropValue::String8(bytes) => String::from_utf8(bytes.into_vec()).ok(),
        _ => None,
    }
}
