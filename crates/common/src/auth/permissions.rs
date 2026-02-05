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
use trc::AddContext;

impl Server {
    pub async fn effective_permissions(
        &self,
        mut base_permissions: PermissionsGroup,
        role_id: u32,
    ) -> trc::Result<Permissions> {
        let mut role_ids = vec![role_id];
        let mut fetched_role_ids = AHashSet::new();

        while let Some(role_id) = role_ids.pop() {
            if fetched_role_ids.insert(role_id) {
                let role = self.role(role_id).await.caused_by(trc::location!())?;

                base_permissions.union(&role.permissions);
                role_ids.extend(role.id_roles.iter().copied());
            }
        }

        Ok(base_permissions.finalize())
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
