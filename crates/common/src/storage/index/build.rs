/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::IndexValue;
use crate::sharing::notification::ShareNotification;
use store::{
    SerializeInfallible,
    write::{BatchBuilder, BlobLink, BlobOp, PendingId, QueueDocumentId, ValueClass},
};
use types::collection::Collection;
use utils::{map::bitmap::Bitmap, snowflake::SnowflakeIdGenerator};

pub(crate) fn build_index(
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
            let account_id = batch.last_account_id().unwrap();

            if set {
                batch.queue_document_index(index, account_id, QueueDocumentId::Current);
            } else {
                batch.queue_document_unindex(index, account_id, QueueDocumentId::Current);
            }
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
            let object_id = batch.last_document_id().unwrap_or(PendingId::Assigned(0));
            let notification_id = SnowflakeIdGenerator::global_id().unwrap_or_default();

            for item in value.as_ref() {
                if set {
                    batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                    batch.log_share_notification(
                        notification_id,
                        item.account_id,
                        ShareNotification {
                            object_account_id,
                            object_type,
                            changed_by,
                            old_rights: Default::default(),
                            new_rights: item.grants,
                            ..Default::default()
                        }
                        .into_value(object_id),
                    );
                } else {
                    batch.acl_revoke(item.account_id);
                    batch.log_share_notification(
                        notification_id,
                        item.account_id,
                        ShareNotification {
                            object_account_id,
                            object_type,
                            changed_by,
                            old_rights: item.grants,
                            new_rights: Default::default(),
                            ..Default::default()
                        }
                        .into_value(object_id),
                    );
                }
            }
        }
        IndexValue::Quota { used } => {
            let value = if set { used as i64 } else { -(used as i64) };

            batch.add(ValueClass::Quota, value);

            if let Some(tenant_id) = tenant_id {
                batch.add(ValueClass::TenantQuota(tenant_id), value);
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

pub(crate) fn merge_index(
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
            batch.queue_document_index(
                index,
                batch.last_account_id().unwrap(),
                QueueDocumentId::Current,
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
            let object_id = batch.last_document_id().unwrap_or(PendingId::Assigned(0));
            let notification_id = SnowflakeIdGenerator::global_id().unwrap_or_default();

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
                                    object_type,
                                    changed_by,
                                    old_rights: current_item.grants,
                                    new_rights: Default::default(),
                                    ..Default::default()
                                }
                                .into_value(object_id),
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
                                    object_type,
                                    changed_by,
                                    old_rights,
                                    new_rights: item.grants,
                                    ..Default::default()
                                }
                                .into_value(object_id),
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
                                object_type,
                                changed_by,
                                old_rights: Default::default(),
                                new_rights: item.grants,
                                ..Default::default()
                            }
                            .into_value(object_id),
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
                                object_type,
                                changed_by,
                                old_rights: item.grants,
                                new_rights: Default::default(),
                                ..Default::default()
                            }
                            .into_value(object_id),
                        );
                    }
                }
                _ => {}
            }
        }
        (IndexValue::Quota { used: old_used }, IndexValue::Quota { used: new_used }) => {
            let value = new_used as i64 - old_used as i64;
            batch.add(ValueClass::Quota, value);

            if let Some(tenant_id) = tenant_id {
                batch.add(ValueClass::TenantQuota(tenant_id), value);
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
