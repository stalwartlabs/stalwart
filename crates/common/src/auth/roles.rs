/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{Permissions, PermissionsGroup},
};
use ahash::AHashSet;
use std::sync::{Arc, LazyLock};
use trc::AddContext;
use utils::cache::CacheItemWeight;

impl Server {
    pub async fn get_role_permissions(&self, role_id: u32) -> trc::Result<Arc<PermissionsGroup>> {
        match role_id {
            ROLE_USER => Ok(USER_PERMISSIONS.clone()),
            ROLE_ADMIN => Ok(ADMIN_PERMISSIONS.clone()),
            ROLE_TENANT_ADMIN => Ok(TENANT_ADMIN_PERMISSIONS.clone()),
            role_id => {
                match self
                    .inner
                    .cache
                    .permissions
                    .get_value_or_guard_async(&role_id)
                    .await
                {
                    Ok(permissions) => Ok(permissions),
                    Err(guard) => {
                        let permissions = self.build_role_permissions(role_id).await?;
                        let _ = guard.insert(permissions.clone());
                        Ok(permissions)
                    }
                }
            }
        }
    }

    async fn build_role_permissions(&self, role_id: u32) -> trc::Result<Arc<PermissionsGroup>> {
        let mut role_ids = vec![role_id].into_iter();
        let mut role_ids_stack = vec![];
        let mut fetched_role_ids = AHashSet::new();
        let mut return_permissions = PermissionsGroup::default();

        'outer: loop {
            if let Some(role_id) = role_ids.next() {
                // Skip if already fetched
                if !fetched_role_ids.insert(role_id) {
                    continue;
                }

                match role_id {
                    ROLE_USER => {
                        return_permissions.enabled.union(&USER_PERMISSIONS.enabled);
                        return_permissions
                            .disabled
                            .union(&USER_PERMISSIONS.disabled);
                    }
                    ROLE_ADMIN => {
                        return_permissions.enabled.union(&ADMIN_PERMISSIONS.enabled);
                        return_permissions
                            .disabled
                            .union(&ADMIN_PERMISSIONS.disabled);
                        break 'outer;
                    }
                    ROLE_TENANT_ADMIN => {
                        return_permissions
                            .enabled
                            .union(&TENANT_ADMIN_PERMISSIONS.enabled);
                        return_permissions
                            .disabled
                            .union(&TENANT_ADMIN_PERMISSIONS.disabled);
                    }
                    role_id => {
                        // Try with the cache
                        if let Some(role_permissions) = self.inner.cache.permissions.get(&role_id) {
                            return_permissions.union(role_permissions.as_ref());
                        } else {
                            let mut role_permissions = PermissionsGroup::default();

                            // Obtain principal
                            let principal = self
                                .store()
                                .query(QueryParams::id(role_id).with_return_member_of(true))
                                .await
                                .caused_by(trc::location!())?
                                .ok_or_else(|| {
                                    trc::SecurityEvent::Unauthorized
                                        .into_err()
                                        .details(
                                            "Principal not found while building role permissions",
                                        )
                                        .ctx(trc::Key::Id, role_id)
                                })?;

                            // Add permissions
                            for permission in principal.permissions() {
                                if permission.grant {
                                    role_permissions.enabled.set(permission.permission as usize);
                                } else {
                                    role_permissions
                                        .disabled
                                        .set(permission.permission as usize);
                                }
                            }

                            // Add permissions
                            return_permissions.union(&role_permissions);

                            // Add parent roles
                            let mut principal_roles = principal.roles().peekable();
                            if principal_roles.peek().is_some() {
                                role_ids_stack.push(role_ids);
                                role_ids = principal_roles.collect::<Vec<_>>().into_iter();
                            } else {
                                // Cache role
                                self.inner
                                    .cache
                                    .permissions
                                    .insert(role_id, Arc::new(role_permissions));
                            }
                        }
                    }
                }
            } else if let Some(prev_role_ids) = role_ids_stack.pop() {
                role_ids = prev_role_ids;
            } else {
                break;
            }
        }

        Ok(Arc::new(return_permissions))
    }
}

impl PermissionsGroup {
    pub fn union(&mut self, other: &PermissionsGroup) {
        self.enabled.union(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn finalize(mut self) -> Permissions {
        self.enabled.difference(&self.disabled);
        self.enabled
    }

    pub fn finalize_as_ref(&self) -> Permissions {
        let mut enabled = self.enabled.clone();
        enabled.difference(&self.disabled);
        enabled
    }
}
