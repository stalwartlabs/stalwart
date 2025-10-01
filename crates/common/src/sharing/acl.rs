/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use directory::{
    Type,
    backend::internal::{PrincipalField, manage::ChangedPrincipals},
};
use types::acl::{AclGrant, ArchivedAclGrant};

impl Server {
    pub async fn refresh_acls(&self, acl_changes: &[AclGrant], current: Option<&[AclGrant]>) {
        let mut changed_principals = ChangedPrincipals::new();
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
                    changed_principals.add_change(
                        current_item.account_id,
                        Type::Individual,
                        PrincipalField::EnabledPermissions,
                    );
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
                    changed_principals.add_change(
                        change_item.account_id,
                        Type::Individual,
                        PrincipalField::EnabledPermissions,
                    );
                }
            }
        } else {
            for value in acl_changes {
                changed_principals.add_change(
                    value.account_id,
                    Type::Individual,
                    PrincipalField::EnabledPermissions,
                );
            }
        }

        self.invalidate_principal_caches(changed_principals).await;
    }

    pub async fn refresh_archived_acls(
        &self,
        acl_changes: &[AclGrant],
        acl_current: &[ArchivedAclGrant],
    ) {
        let mut changed_principals = ChangedPrincipals::new();
        for current_item in acl_current.iter() {
            let mut invalidate = true;
            for change_item in acl_changes {
                if change_item.account_id == current_item.account_id {
                    invalidate = change_item.grants != current_item.grants;
                    break;
                }
            }
            if invalidate {
                changed_principals.add_change(
                    current_item.account_id.to_native(),
                    Type::Individual,
                    PrincipalField::EnabledPermissions,
                );
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
                changed_principals.add_change(
                    change_item.account_id,
                    Type::Individual,
                    PrincipalField::EnabledPermissions,
                );
            }
        }

        self.invalidate_principal_caches(changed_principals).await;
    }
}
