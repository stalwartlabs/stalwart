/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{auth::AccessToken, sharing::notification::ShareNotification};
use rkyv::{
    option::ArchivedOption,
    primitive::{ArchivedU32, ArchivedU64},
    string::ArchivedString,
};
use std::{borrow::Cow, fmt::Debug};
use store::{
    Serialize, SerializeInfallible,
    write::{
        Archive, Archiver, BatchBuilder, BlobLink, BlobOp, DirectoryClass, IntoOperations, Params,
        SearchIndex, TaskEpoch, TaskQueueClass, ValueClass,
    },
};
use types::{
    acl::AclGrant,
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::Field,
};
use utils::{cheeky_hash::CheekyHash, map::bitmap::Bitmap, snowflake::SnowflakeIdGenerator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue<'x> {
    Index {
        field: Field,
        value: IndexItem<'x>,
    },
    Property {
        field: ValueClass,
        value: IndexItem<'x>,
    },
    SearchIndex {
        index: SearchIndex,
        hash: u64,
    },
    Blob {
        value: BlobHash,
    },
    Quota {
        used: u32,
    },
    LogContainer {
        sync_collection: SyncCollection,
    },
    LogContainerProperty {
        sync_collection: SyncCollection,
        ids: Vec<u32>,
    },
    LogItem {
        sync_collection: SyncCollection,
        prefix: Option<u32>,
    },
    Acl {
        value: Cow<'x, [AclGrant]>,
    },
}

#[derive(Debug, Clone)]
pub enum IndexItem<'x> {
    Vec(Vec<u8>),
    Slice(&'x [u8]),
    ShortInt([u8; std::mem::size_of::<u32>()]),
    LongInt([u8; std::mem::size_of::<u64>()]),
    Hash(CheekyHash),
    None,
}

impl IndexItem<'_> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            IndexItem::Vec(v) => v,
            IndexItem::Slice(s) => s,
            IndexItem::ShortInt(s) => s,
            IndexItem::LongInt(s) => s,
            IndexItem::Hash(h) => h.as_bytes(),
            IndexItem::None => &[],
        }
    }

    pub fn into_owned(self) -> Vec<u8> {
        match self {
            IndexItem::Vec(v) => v,
            IndexItem::Slice(s) => s.to_vec(),
            IndexItem::ShortInt(s) => s.to_vec(),
            IndexItem::LongInt(s) => s.to_vec(),
            IndexItem::Hash(h) => h.as_bytes().to_vec(),
            IndexItem::None => vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            IndexItem::Vec(v) => v.is_empty(),
            IndexItem::Slice(s) => s.is_empty(),
            IndexItem::None => true,
            _ => false,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, IndexItem::None)
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }
}

impl PartialEq for IndexItem<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for IndexItem<'_> {}

impl std::hash::Hash for IndexItem<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            IndexItem::Vec(v) => v.as_slice().hash(state),
            IndexItem::Slice(s) => s.hash(state),
            IndexItem::ShortInt(s) => s.as_slice().hash(state),
            IndexItem::LongInt(s) => s.as_slice().hash(state),
            IndexItem::Hash(h) => h.hash(state),
            IndexItem::None => 0.hash(state),
        }
    }
}

impl From<u32> for IndexItem<'_> {
    fn from(value: u32) -> Self {
        IndexItem::ShortInt(value.to_be_bytes())
    }
}

impl From<&u32> for IndexItem<'_> {
    fn from(value: &u32) -> Self {
        IndexItem::ShortInt(value.to_be_bytes())
    }
}

impl From<u64> for IndexItem<'_> {
    fn from(value: u64) -> Self {
        IndexItem::LongInt(value.to_be_bytes())
    }
}

impl From<i64> for IndexItem<'_> {
    fn from(value: i64) -> Self {
        IndexItem::LongInt(value.to_be_bytes())
    }
}

impl<'x> From<&'x [u8]> for IndexItem<'x> {
    fn from(value: &'x [u8]) -> Self {
        IndexItem::Slice(value)
    }
}

impl From<Vec<u8>> for IndexItem<'_> {
    fn from(value: Vec<u8>) -> Self {
        IndexItem::Vec(value)
    }
}

impl<'x> From<&'x str> for IndexItem<'x> {
    fn from(value: &'x str) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl<'x> From<&'x String> for IndexItem<'x> {
    fn from(value: &'x String) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl From<String> for IndexItem<'_> {
    fn from(value: String) -> Self {
        IndexItem::Vec(value.into_bytes())
    }
}

impl<'x> From<&'x ArchivedString> for IndexItem<'x> {
    fn from(value: &'x ArchivedString) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl From<ArchivedU32> for IndexItem<'_> {
    fn from(value: ArchivedU32) -> Self {
        IndexItem::ShortInt(value.to_native().to_be_bytes())
    }
}

impl From<&ArchivedU32> for IndexItem<'_> {
    fn from(value: &ArchivedU32) -> Self {
        IndexItem::ShortInt(value.to_native().to_be_bytes())
    }
}

impl From<ArchivedU64> for IndexItem<'_> {
    fn from(value: ArchivedU64) -> Self {
        IndexItem::LongInt(value.to_native().to_be_bytes())
    }
}

impl<'x, T: Into<IndexItem<'x>>> From<Option<T>> for IndexItem<'x> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => v.into(),
            None => IndexItem::None,
        }
    }
}

impl<'x, T: Into<IndexItem<'x>>> From<ArchivedOption<T>> for IndexItem<'x> {
    fn from(value: ArchivedOption<T>) -> Self {
        match value {
            ArchivedOption::Some(v) => v.into(),
            ArchivedOption::None => IndexItem::None,
        }
    }
}

pub trait IndexableObject: Sync + Send {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>>;
}

pub trait IndexableAndSerializableObject:
    IndexableObject
    + rkyv::Archive
    + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    >
{
    fn is_versioned() -> bool;
}

#[derive(Debug)]
pub struct ObjectIndexBuilder<C: IndexableObject, N: IndexableAndSerializableObject> {
    changed_by: u32,
    tenant_id: Option<u32>,
    current: Option<Archive<C>>,
    changes: Option<N>,
}

impl<C: IndexableObject, N: IndexableAndSerializableObject> Default for ObjectIndexBuilder<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: IndexableObject, N: IndexableAndSerializableObject> ObjectIndexBuilder<C, N> {
    pub fn new() -> Self {
        Self {
            current: None,
            changes: None,
            tenant_id: None,
            changed_by: u32::MAX,
        }
    }

    pub fn with_current(mut self, current: Archive<C>) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: N) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_current_opt(mut self, current: Option<Archive<C>>) -> Self {
        self.current = current;
        self
    }

    pub fn changes(&self) -> Option<&N> {
        self.changes.as_ref()
    }

    pub fn changes_mut(&mut self) -> Option<&mut N> {
        self.changes.as_mut()
    }

    pub fn current(&self) -> Option<&Archive<C>> {
        self.current.as_ref()
    }

    pub fn with_access_token(mut self, access_token: &AccessToken) -> Self {
        self.tenant_id = access_token.tenant.as_ref().map(|t| t.id);
        self.changed_by = access_token.primary_id();
        self
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
    }
}

impl<C: IndexableObject, N: IndexableAndSerializableObject> IntoOperations
    for ObjectIndexBuilder<C, N>
{
    fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                for item in changes.index_values() {
                    build_index(batch, item, self.changed_by, self.tenant_id, true);
                }
                if N::is_versioned() {
                    let (offset, bytes) = Archiver::new(changes).serialize_versioned()?;
                    batch.set_fnc(
                        Field::ARCHIVE,
                        Params::with_capacity(2).with_bytes(bytes).with_u64(offset),
                        |params, ids| {
                            let change_id = ids.current_change_id()?;
                            let archive = params.bytes(0);
                            let offset = params.u64(1);

                            let mut bytes = Vec::with_capacity(archive.len());
                            bytes.extend_from_slice(&archive[..offset as usize]);
                            bytes.extend_from_slice(&change_id.to_be_bytes()[..]);
                            bytes.push(archive.last().copied().unwrap()); // Marker
                            Ok(bytes)
                        },
                    );
                } else {
                    batch.set(Field::ARCHIVE, Archiver::new(changes).serialize()?);
                }
            }
            (Some(current), Some(changes)) => {
                // Update
                batch.assert_value(Field::ARCHIVE, &current);
                for (current, change) in current.inner.index_values().zip(changes.index_values()) {
                    if current != change {
                        merge_index(batch, current, change, self.changed_by, self.tenant_id)?;
                    } else {
                        match current {
                            IndexValue::LogContainer { sync_collection } => {
                                batch.log_container_update(sync_collection);
                            }
                            IndexValue::LogItem {
                                sync_collection,
                                prefix,
                            } => {
                                batch.log_item_update(sync_collection, prefix);
                            }
                            _ => (),
                        }
                    }
                }
                if N::is_versioned() {
                    let (offset, bytes) = Archiver::new(changes).serialize_versioned()?;
                    batch.set_fnc(
                        Field::ARCHIVE,
                        Params::with_capacity(2).with_bytes(bytes).with_u64(offset),
                        |params, ids| {
                            let change_id = ids.current_change_id()?;
                            let archive = params.bytes(0);
                            let offset = params.u64(1);

                            let mut bytes = Vec::with_capacity(archive.len());
                            bytes.extend_from_slice(&archive[..offset as usize]);
                            bytes.extend_from_slice(&change_id.to_be_bytes()[..]);
                            bytes.push(archive.last().copied().unwrap()); // Marker
                            Ok(bytes)
                        },
                    );
                } else {
                    batch.set(Field::ARCHIVE, Archiver::new(changes).serialize()?);
                }
            }
            (Some(current), None) => {
                // Deletion
                batch.assert_value(Field::ARCHIVE, &current);
                for item in current.inner.index_values() {
                    build_index(batch, item, self.changed_by, self.tenant_id, false);
                }

                batch.clear(Field::ARCHIVE);
            }
            (None, None) => unreachable!(),
        }

        Ok(())
    }
}

fn build_index(
    batch: &mut BatchBuilder,
    item: IndexValue<'_>,
    changed_by: u32,
    tenant_id: Option<u32>,
    set: bool,
) {
    match item {
        IndexValue::Index { field, value } => {
            if !value.is_empty() {
                if set {
                    batch.index(field, value.into_owned());
                } else {
                    batch.unindex(field, value.into_owned());
                }
            }
        }
        IndexValue::SearchIndex { index, .. } => {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                    due: TaskEpoch::now().with_random_sequence_id(),
                    index,
                    is_insert: set,
                }),
                vec![],
            );
        }
        IndexValue::Property { field, value } => {
            if !value.is_none() {
                if set {
                    batch.set(field, value.into_owned());
                } else {
                    batch.clear(field);
                }
            }
        }
        IndexValue::Blob { value } => {
            if set {
                batch.set(
                    BlobOp::Link {
                        hash: value,
                        to: BlobLink::Document,
                    },
                    vec![],
                );
            } else {
                batch.clear(BlobOp::Link {
                    hash: value,
                    to: BlobLink::Document,
                });
            }
        }
        IndexValue::Acl { value } => {
            let object_account_id = batch.last_account_id().unwrap_or_default();
            let object_type = batch.last_collection().unwrap_or(Collection::None);
            let object_id = batch.last_document_id().unwrap_or_default();
            let notification_id = SnowflakeIdGenerator::from_sequence_and_node_id(
                object_type as u64 ^ object_account_id as u64,
                None,
            )
            .unwrap_or_default();

            for item in value.as_ref() {
                if set {
                    batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                    batch.log_share_notification(
                        notification_id,
                        item.account_id,
                        ShareNotification {
                            object_account_id,
                            object_id,
                            object_type,
                            changed_by,
                            old_rights: Default::default(),
                            new_rights: item.grants,
                            name: Default::default(),
                        },
                    );
                } else {
                    batch.acl_revoke(item.account_id);
                    batch.log_share_notification(
                        notification_id,
                        item.account_id,
                        ShareNotification {
                            object_account_id,
                            object_id,
                            object_type,
                            changed_by,
                            old_rights: item.grants,
                            new_rights: Default::default(),
                            name: Default::default(),
                        },
                    );
                }
            }
        }
        IndexValue::Quota { used } => {
            let value = if set { used as i64 } else { -(used as i64) };

            if let Some(account_id) = batch.last_account_id() {
                batch.add(DirectoryClass::UsedQuota(account_id), value);
            }

            if let Some(tenant_id) = tenant_id {
                batch.add(DirectoryClass::UsedQuota(tenant_id), value);
            }
        }
        IndexValue::LogItem {
            sync_collection,
            prefix,
        } => {
            if set {
                batch.log_item_insert(sync_collection, prefix);
            } else {
                batch.log_item_delete(sync_collection, prefix);
            }
        }
        IndexValue::LogContainer { sync_collection } => {
            if set {
                batch.log_container_insert(sync_collection);
            } else {
                batch.log_container_delete(sync_collection);
            }
        }
        IndexValue::LogContainerProperty {
            sync_collection,
            ids,
        } => {
            for parent_id in ids {
                batch.log_container_property_change(sync_collection, parent_id);
            }
        }
    }
}

fn merge_index(
    batch: &mut BatchBuilder,
    current: IndexValue<'_>,
    change: IndexValue<'_>,
    changed_by: u32,
    tenant_id: Option<u32>,
) -> trc::Result<()> {
    match (current, change) {
        (
            IndexValue::Index {
                field,
                value: old_value,
            },
            IndexValue::Index {
                value: new_value, ..
            },
        ) => {
            if !old_value.is_empty() {
                batch.unindex(field, old_value.into_owned());
            }

            if !new_value.is_empty() {
                batch.index(field, new_value.into_owned());
            }
        }
        (IndexValue::SearchIndex { index, .. }, IndexValue::SearchIndex { .. }) => {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                    due: TaskEpoch::now().with_random_sequence_id(),
                    index,
                    is_insert: true,
                }),
                vec![],
            );
        }
        (
            IndexValue::Property {
                field: old_field,
                value: old_value,
            },
            IndexValue::Property {
                field: new_field,
                value: new_value,
                ..
            },
        ) => {
            if old_field != new_field {
                batch.clear(old_field);
                batch.set(new_field, new_value.into_owned());
            } else if new_value != old_value {
                if new_value.is_some() {
                    batch.set(old_field, new_value.into_owned());
                } else {
                    batch.clear(old_field);
                }
            }
        }
        (IndexValue::Blob { value: old_hash }, IndexValue::Blob { value: new_hash }) => {
            batch.clear(BlobOp::Link {
                hash: old_hash,
                to: BlobLink::Document,
            });
            batch.set(
                BlobOp::Link {
                    hash: new_hash,
                    to: BlobLink::Document,
                },
                vec![],
            );
        }
        (IndexValue::Acl { value: old_acl }, IndexValue::Acl { value: new_acl }) => {
            let has_old_acl = !old_acl.is_empty();
            let has_new_acl = !new_acl.is_empty();

            if !has_old_acl && !has_new_acl {
                return Ok(());
            }

            let object_account_id = batch.last_account_id().unwrap_or_default();
            let object_type = batch.last_collection().unwrap_or(Collection::None);
            let object_id = batch.last_document_id().unwrap_or_default();
            let notification_id = SnowflakeIdGenerator::from_sequence_and_node_id(
                object_type as u64 ^ object_account_id as u64,
                None,
            )
            .unwrap_or_default();

            match (has_old_acl, has_new_acl) {
                (true, true) => {
                    // Remove deleted ACLs
                    for current_item in old_acl.as_ref() {
                        if !new_acl
                            .iter()
                            .any(|item| item.account_id == current_item.account_id)
                        {
                            batch.acl_revoke(current_item.account_id);
                            batch.log_share_notification(
                                notification_id,
                                current_item.account_id,
                                ShareNotification {
                                    object_account_id,
                                    object_id,
                                    object_type,
                                    changed_by,
                                    old_rights: current_item.grants,
                                    new_rights: Default::default(),
                                    name: Default::default(),
                                },
                            );
                        }
                    }

                    // Update ACLs
                    for item in new_acl.as_ref() {
                        let mut add_item = true;
                        let mut old_rights = Bitmap::default();
                        for current_item in old_acl.as_ref() {
                            if item.account_id == current_item.account_id {
                                if item.grants == current_item.grants {
                                    add_item = false;
                                } else {
                                    old_rights = current_item.grants;
                                }
                                break;
                            }
                        }
                        if add_item {
                            batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                            batch.log_share_notification(
                                notification_id,
                                item.account_id,
                                ShareNotification {
                                    object_account_id,
                                    object_id,
                                    object_type,
                                    changed_by,
                                    old_rights,
                                    new_rights: item.grants,
                                    name: Default::default(),
                                },
                            );
                        }
                    }
                }
                (false, true) => {
                    // Add all ACLs
                    for item in new_acl.as_ref() {
                        batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                        batch.log_share_notification(
                            notification_id,
                            item.account_id,
                            ShareNotification {
                                object_account_id,
                                object_id,
                                object_type,
                                changed_by,
                                old_rights: Default::default(),
                                new_rights: item.grants,
                                name: Default::default(),
                            },
                        );
                    }
                }
                (true, false) => {
                    // Remove all ACLs
                    for item in old_acl.as_ref() {
                        batch.acl_revoke(item.account_id);
                        batch.log_share_notification(
                            notification_id,
                            item.account_id,
                            ShareNotification {
                                object_account_id,
                                object_id,
                                object_type,
                                changed_by,
                                old_rights: item.grants,
                                new_rights: Default::default(),
                                name: Default::default(),
                            },
                        );
                    }
                }
                _ => {}
            }
        }
        (IndexValue::Quota { used: old_used }, IndexValue::Quota { used: new_used }) => {
            let value = new_used as i64 - old_used as i64;
            if let Some(account_id) = batch.last_account_id() {
                batch.add(DirectoryClass::UsedQuota(account_id), value);
            }

            if let Some(tenant_id) = tenant_id {
                batch.add(DirectoryClass::UsedQuota(tenant_id), value);
            }
        }
        (
            IndexValue::LogItem {
                sync_collection,
                prefix: old_prefix,
            },
            IndexValue::LogItem {
                prefix: new_prefix, ..
            },
        ) => {
            batch.log_item_delete(sync_collection, old_prefix);
            batch.log_item_insert(sync_collection, new_prefix);
        }
        (
            IndexValue::LogContainerProperty {
                sync_collection,
                ids: old_ids,
            },
            IndexValue::LogContainerProperty { ids: new_ids, .. },
        ) => {
            for parent_id in &old_ids {
                if !new_ids.contains(parent_id) {
                    batch.log_container_property_change(sync_collection, *parent_id);
                }
            }
            for parent_id in new_ids {
                if !old_ids.contains(&parent_id) {
                    batch.log_container_property_change(sync_collection, parent_id);
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

impl IndexableObject for () {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        std::iter::empty()
    }
}

impl IndexableAndSerializableObject for () {
    fn is_versioned() -> bool {
        false
    }
}
