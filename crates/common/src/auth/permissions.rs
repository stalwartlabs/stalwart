/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{AccessToken, Permissions, PermissionsGroup},
};
use ahash::AHashSet;
use registry::{
    schema::{
        enums::Permission,
        structs::{self, Account, PermissionsList, UserRoles},
    },
    types::EnumImpl,
};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

impl Server {
    pub async fn add_role_permissions(
        &self,
        mut base_permissions: PermissionsGroup,
        roles: impl IntoIterator<Item = u32>,
    ) -> trc::Result<PermissionsGroup> {
        let mut role_ids = roles.into_iter().collect::<Vec<u32>>();
        let mut fetched_role_ids = AHashSet::new();

        while let Some(role_id) = role_ids.pop() {
            if fetched_role_ids.insert(role_id) {
                let role = self.role(role_id).await.caused_by(trc::location!())?;

                base_permissions.union(&role.permissions);
                role_ids.extend(role.id_roles.iter().copied());
            }
        }

        Ok(base_permissions)
    }

    pub async fn effective_permissions(
        &self,
        permissions: &structs::Permissions,
        role_ids: &[Id],
        tenant_id: Option<u32>,
    ) -> trc::Result<PermissionsGroup> {
        // Calculate effective permissions
        let (mut permissions, roles) = match permissions {
            structs::Permissions::Inherit => (PermissionsGroup::default(), role_ids),
            structs::Permissions::Merge(permissions) => {
                (PermissionsGroup::from(permissions), role_ids)
            }
            structs::Permissions::Replace(permissions) => {
                (PermissionsGroup::from(permissions), &[][..])
            }
        };
        if !roles.is_empty() {
            permissions = self
                .add_role_permissions(permissions, roles.iter().map(|v| v.id() as u32))
                .await
                .caused_by(trc::location!())?
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        {
            if let Some(tenant_id) = tenant_id {
                if self.is_enterprise_edition() {
                    // Limit tenant permissions
                    let tenant = self.tenant(tenant_id).await.caused_by(trc::location!())?;
                    let (mut tenant_permissions, tenant_roles) =
                        if let Some(permissions) = &tenant.permissions {
                            if permissions.merge {
                                ((**permissions).clone(), tenant.id_roles.as_slice())
                            } else {
                                ((**permissions).clone(), &[][..])
                            }
                        } else {
                            (PermissionsGroup::default(), tenant.id_roles.as_slice())
                        };
                    if !tenant_roles.is_empty() {
                        tenant_permissions = self
                            .add_role_permissions(tenant_permissions, tenant_roles.iter().copied())
                            .await
                            .caused_by(trc::location!())?
                    }

                    permissions.restrict(&tenant_permissions);
                } else {
                    // Enterprise edition downgrade, remove any tenant administrator permissions
                    permissions.restrict(&PermissionsGroup::user());
                }
            }
        }

        // SPDX-SnippetEnd

        Ok(permissions)
    }

    pub async fn can_set_permissions(
        &self,
        access_token: &AccessToken,
        account: &Account,
    ) -> trc::Result<Result<(), Vec<Permission>>> {
        let (permissions, role_ids, tenant_id) = match account {
            Account::User(account) => (
                &account.permissions,
                match &account.roles {
                    UserRoles::User => self.core.network.security.default_role_ids_user.as_slice(),
                    UserRoles::Admin => {
                        if access_token.tenant_id().is_none() {
                            self.core.network.security.default_role_ids_admin.as_slice()
                        } else {
                            self.core
                                .network
                                .security
                                .default_role_ids_tenant
                                .as_slice()
                        }
                    }
                    UserRoles::Custom(custom_roles) => custom_roles.role_ids.as_slice(),
                },
                account.member_tenant_id.map(|t| t.document_id()),
            ),
            Account::Group(account) => (
                &account.permissions,
                account
                    .roles
                    .role_ids()
                    .unwrap_or(self.core.network.security.default_role_ids_group.as_slice()),
                account.member_tenant_id.map(|t| t.document_id()),
            ),
        };

        self.effective_permissions(permissions, role_ids, tenant_id)
            .await
            .map(|permissions| access_token.can_grant_permissions(permissions.finalize()))
    }
}

impl AccessToken {
    pub fn can_grant_permissions(
        &self,
        mut requested_permissions: Permissions,
    ) -> Result<(), Vec<Permission>> {
        requested_permissions.difference(self.permissions_bits());
        if requested_permissions.is_empty() {
            Ok(())
        } else {
            Err(requested_permissions.build_permissions_list())
        }
    }
}

pub trait PermissionsListBuilder {
    fn build_permissions_list(&self) -> Vec<Permission>;
}

impl PermissionsListBuilder for Permissions {
    fn build_permissions_list(&self) -> Vec<Permission> {
        const USIZE_BITS: usize = std::mem::size_of::<usize>() * 8;
        const USIZE_MASK: u32 = USIZE_BITS as u32 - 1;
        let mut permissions = Vec::new();

        for (block_num, bytes) in self.inner().iter().enumerate() {
            let mut bytes = *bytes;

            while bytes != 0 {
                let item = USIZE_MASK - bytes.leading_zeros();
                bytes ^= 1 << item;
                if let Some(permission) =
                    Permission::from_id(((block_num * USIZE_BITS) + item as usize) as u16)
                {
                    permissions.push(permission);
                }
            }
        }
        permissions
    }
}

pub struct DefaultPermissions {
    pub user: Vec<Permission>,
    pub group: Vec<Permission>,
    pub tenant: Vec<Permission>,
    pub superuser: Vec<Permission>,
}

impl PermissionsGroup {
    pub fn with_merge(mut self, merge: bool) -> Self {
        self.merge = merge;
        self
    }

    pub fn union(&mut self, other: &PermissionsGroup) {
        self.enabled.union(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn restrict(&mut self, other: &PermissionsGroup) {
        self.enabled.intersection(&other.enabled);
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

    pub fn user() -> Self {
        let mut permissions = PermissionsGroup::default();
        for permission in DefaultPermissions::default().user {
            permissions.enabled.set(permission as usize);
        }

        permissions
    }
}

impl Default for DefaultPermissions {
    fn default() -> Self {
        let mut default = Self {
            user: Default::default(),
            group: Default::default(),
            tenant: Default::default(),
            superuser: Default::default(),
        };

        for permission_id in 0..Permission::COUNT {
            let permission = Permission::from_id(permission_id as u16).unwrap();
            match permission {
                Permission::Authenticate
                | Permission::AuthenticateWithAlias
                | Permission::InteractAi => {
                    default.user.push(permission);
                    default.superuser.push(permission);
                    default.tenant.push(permission);
                }
                Permission::Impersonate
                | Permission::UnlimitedRequests
                | Permission::UnlimitedUploads
                | Permission::LiveMetrics
                | Permission::LiveTracing => {
                    default.superuser.push(permission);
                }
                Permission::FetchAnyBlob | Permission::LiveDeliveryTest => {
                    default.superuser.push(permission);
                    default.tenant.push(permission);
                }
                permission => {
                    let name = permission.as_str();
                    if name.starts_with("jmap")
                        || name.starts_with("imap")
                        || name.starts_with("pop3")
                        || name.starts_with("calendar")
                        || name.starts_with("email")
                        || name.starts_with("dav")
                        || name.starts_with("sieve")
                    {
                        default.user.push(permission);
                        default.group.push(permission);
                    } else if name.starts_with("sysMaskedEmail")
                        || name.starts_with("sysArchivedItem")
                        || name.starts_with("sysAccountSettings")
                        || name.starts_with("sysPublicKey")
                        || (name.starts_with("sysSpamTrainingSample") && !name.contains("Create"))
                    {
                        default.user.push(permission);
                        default.group.push(permission);
                        default.superuser.push(permission);
                    } else if name.starts_with("sysAccountPassword")
                        || name.starts_with("sysApiKey")
                        || name.starts_with("sysAppPassword")
                    {
                        default.user.push(permission);
                        default.superuser.push(permission);
                    } else if name.starts_with("sysDomain")
                        || name.starts_with("sysDkimSignature")
                        || name.starts_with("sysAcmeProvider")
                        || name.starts_with("sysAccount")
                        || name.starts_with("sysRole")
                        || name.starts_with("sysOAuthClient")
                        || name.starts_with("sysMailingList")
                        || name.starts_with("sysExternalReport")
                        || name.starts_with("sysDnsServer")
                        || name.starts_with("sysQueuedMessage")
                    {
                        default.tenant.push(permission);
                        default.superuser.push(permission);
                    } else {
                        default.superuser.push(permission);
                    }
                }
            }
        }

        default
    }
}

impl From<PermissionsList> for PermissionsGroup {
    fn from(value: PermissionsList) -> Self {
        Self::from(&value)
    }
}

impl From<&PermissionsList> for PermissionsGroup {
    fn from(value: &PermissionsList) -> Self {
        PermissionsGroup {
            enabled: Permissions::from_permission(value.enabled_permissions.as_slice()),
            disabled: Permissions::from_permission(value.disabled_permissions.as_slice()),
            merge: false,
        }
    }
}

impl From<&VecMap<Permission, bool>> for PermissionsGroup {
    fn from(value: &VecMap<Permission, bool>) -> Self {
        let mut permissions = PermissionsGroup::default();
        for (permission, is_set) in value {
            if *is_set {
                permissions.enabled.set(*permission as usize);
            } else {
                permissions.disabled.set(*permission as usize);
            }
        }
        permissions
    }
}

pub trait BuildPermissions {
    fn from_permission(list: &[Permission]) -> Permissions;
}

impl BuildPermissions for Permissions {
    fn from_permission(list: &[Permission]) -> Permissions {
        let mut permission = Permissions::default();
        for p in list {
            permission.set(*p as usize);
        }
        permission
    }
}
