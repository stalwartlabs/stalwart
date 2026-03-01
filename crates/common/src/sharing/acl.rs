/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation};
use types::acl::{AclGrant, ArchivedAclGrant};

impl Server {
    pub async fn refresh_acls(&self, acl_changes: &[AclGrant], current: Option<&[AclGrant]>) {
        let mut changed_principals = CacheInvalidationBuilder::default();
        if let Some(acl_current) = current {
            for current_item in acl_current {
                let mut invalidate = true;
                for change_item in acl_changes {
                    if change_item.account_id == current_item.account_id {
                        invalidate = change_item.grants != current_item.grants;
                        break;
                    }
                }
                if invalidate {
                    changed_principals
                        .invalidate(CacheInvalidation::AccessToken(current_item.account_id));
                }
            }

            for change_item in acl_changes {
                let mut invalidate = true;
                for current_item in acl_current {
                    if change_item.account_id == current_item.account_id {
                        invalidate = change_item.grants != current_item.grants;
                        break;
                    }
                }
                if invalidate {
                    changed_principals
                        .invalidate(CacheInvalidation::AccessToken(change_item.account_id));
                }
            }
        } else {
            for value in acl_changes {
                changed_principals.invalidate(CacheInvalidation::AccessToken(value.account_id));
            }
        }

        self.invalidate_caches(changed_principals).await;
    }

    pub async fn refresh_archived_acls(
        &self,
        acl_changes: &[AclGrant],
        acl_current: &[ArchivedAclGrant],
    ) {
        let mut changed_principals = CacheInvalidationBuilder::default();

        for current_item in acl_current.iter() {
            let mut invalidate = true;
            for change_item in acl_changes {
                if change_item.account_id == current_item.account_id {
                    invalidate = change_item.grants != current_item.grants;
                    break;
                }
            }
            if invalidate {
                changed_principals.invalidate(CacheInvalidation::AccessToken(
                    current_item.account_id.to_native(),
                ));
            }
        }

        for change_item in acl_changes {
            let mut invalidate = true;
            for current_item in acl_current.iter() {
                if change_item.account_id == current_item.account_id {
                    invalidate = change_item.grants != current_item.grants;
                    break;
                }
            }
            if invalidate {
                changed_principals
                    .invalidate(CacheInvalidation::AccessToken(change_item.account_id));
            }
        }

        self.invalidate_caches(changed_principals).await;
    }
}
