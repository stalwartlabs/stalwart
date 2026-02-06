/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AccessToken;
use crate::{
    Server,
    auth::{
        AccessScope, AccessTo, AccessTokenInner, FALLBACK_ADMIN_ID, Permissions, PermissionsGroup,
    },
    network::limiter::{ConcurrencyLimiter, LimiterResult},
};
use registry::{
    schema::{
        enums::Permission,
        structs::{self, Account},
    },
    types::EnumType,
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};
use store::{query::acl::AclQuery, rand, write::now};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{acl::Acl, collection::Collection};
use utils::map::bitmap::{Bitmap, BitmapItem};

impl Server {
    async fn build_account_access_token(
        &self,
        account: Account,
        account_id: u32,
        revision: u64,
    ) -> trc::Result<AccessTokenInner> {
        // Calculate effective permissions
        let (mut permissions, roles) = match account.permissions {
            structs::Permissions::Inherit => {
                (PermissionsGroup::default(), account.role_ids.as_slice())
            }
            structs::Permissions::Merge(permissions) => (
                PermissionsGroup::from(permissions),
                account.role_ids.as_slice(),
            ),
            structs::Permissions::Replace(permissions) => {
                (PermissionsGroup::from(permissions), &[][..])
            }
        };
        if !roles.is_empty() {
            permissions = self
                .add_role_permissions(permissions, roles.into_iter().map(|v| v.id() as u32))
                .await
                .caused_by(trc::location!())?
        }

        let tenant_id = account.member_tenant_id.map(|t| t.id() as u32);

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

        let can_impersonate = permissions.enabled.get(Permission::Impersonate as usize)
            && !permissions.disabled.get(Permission::Impersonate as usize);
        let member_of = account
            .role_ids
            .iter()
            .map(|m| m.id() as u32)
            .collect::<TinyVec<[u32; 3]>>();
        let mut access_to: Vec<AccessTo> = Vec::new();
        for grant_account_id in [account_id].into_iter().chain(member_of.iter().copied()) {
            for acl_item in self
                .store()
                .acl_query(AclQuery::HasAccess { grant_account_id })
                .await
                .caused_by(trc::location!())?
            {
                if acl_item.to_account_id != account_id
                    && !member_of.contains(&acl_item.to_account_id)
                    && !can_impersonate
                {
                    let acl = Bitmap::<Acl>::from(acl_item.permissions);
                    let collection = acl_item.to_collection;
                    if !collection.is_valid() {
                        return Err(trc::StoreEvent::DataCorruption
                            .ctx(trc::Key::Reason, "Corrupted collection found in ACL key.")
                            .details(format!("{acl_item:?}"))
                            .account_id(grant_account_id)
                            .caused_by(trc::location!()));
                    }

                    let mut collections: Bitmap<Collection> = Bitmap::new();
                    if acl.contains(Acl::Read) {
                        collections.insert(collection);
                    }
                    if acl.contains(Acl::ReadItems)
                        && let Some(child_col) = collection.child_collection()
                    {
                        collections.insert(child_col);
                    }

                    if !collections.is_empty() {
                        if let Some(idx) = access_to
                            .iter()
                            .position(|a| a.account_id == acl_item.to_account_id)
                        {
                            access_to[idx].collections.union(&collections);
                        } else {
                            access_to.push(AccessTo {
                                account_id: acl_item.to_account_id,
                                collections,
                            });
                        }
                    }
                }
            }
        }

        let now = now();
        let app_password_scopes = account
            .app_passwords
            .into_iter()
            .filter_map(|pass| {
                let expires_at = pass
                    .expires_at
                    .map(|v| v.timestamp() as u64)
                    .unwrap_or(u64::MAX);
                if expires_at > now {
                    let permissions = match pass.permissions {
                        structs::Permissions::Inherit => permissions.clone().finalize(),
                        structs::Permissions::Merge(merge) => {
                            let mut permissions = permissions.clone();
                            permissions.union(&PermissionsGroup::from(merge));
                            permissions.finalize()
                        }
                        structs::Permissions::Replace(replace) => {
                            PermissionsGroup::from(replace).finalize()
                        }
                    };
                    Some(AccessScope {
                        permissions,
                        expires_at,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(AccessTokenInner {
            concurrent_imap_requests: self.core.imap.rate_concurrent.map(ConcurrencyLimiter::new),
            concurrent_http_requests: self
                .core
                .jmap
                .request_max_concurrent
                .map(ConcurrencyLimiter::new),
            concurrent_uploads: self
                .core
                .jmap
                .upload_max_concurrent
                .map(ConcurrencyLimiter::new),
            obj_size: 0,
            revision,
            account_id,
            tenant_id,
            member_of,
            access_to: access_to.into_boxed_slice(),
            scopes: [AccessScope::new(permissions.finalize())]
                .into_iter()
                .chain(app_password_scopes)
                .collect::<Box<[AccessScope]>>(),
        }
        .update_size())
    }

    pub async fn account_access_token(
        &self,
        account_id: u32,
    ) -> trc::Result<Arc<AccessTokenInner>> {
        match self
            .inner
            .cache
            .access_tokens
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(token) => Ok(token),
            Err(guard) => {
                let revision = rand::random::<u64>();
                let account = self
                    .registry()
                    .object::<Account>(account_id)
                    .await?
                    .ok_or_else(|| {
                        trc::SecurityEvent::Unauthorized
                            .into_err()
                            .details("Account not found")
                            .account_id(account_id)
                            .caused_by(trc::location!())
                    })?;
                let token: Arc<AccessTokenInner> = self
                    .build_account_access_token(account, account_id, revision)
                    .await?
                    .into();
                let _ = guard.insert(token.clone());
                Ok(token)
            }
        }
    }

    async fn access_token_from_account(
        &self,
        account_id: u32,
        account: Account,
    ) -> trc::Result<Arc<AccessTokenInner>> {
        match self
            .inner
            .cache
            .access_tokens
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(token) => Ok(token),
            Err(guard) => {
                let revision = rand::random::<u64>();
                let token: Arc<AccessTokenInner> = self
                    .build_account_access_token(account, account_id, revision)
                    .await?
                    .into();
                let _ = guard.insert(token.clone());
                Ok(token)
            }
        }
    }
}

impl AccessToken {
    pub fn state(&self) -> u32 {
        // Hash state
        let mut s = DefaultHasher::new();
        self.inner.member_of.hash(&mut s);
        self.inner.access_to.hash(&mut s);
        s.finish() as u32
    }

    #[inline(always)]
    pub fn account_id(&self) -> u32 {
        self.inner.account_id
    }

    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.inner.tenant_id
    }

    pub fn secondary_ids(&self) -> impl Iterator<Item = &u32> {
        self.inner
            .member_of
            .iter()
            .chain(self.inner.access_to.iter().map(|a| &a.account_id))
    }

    pub fn member_ids(&self) -> impl Iterator<Item = u32> {
        [self.inner.account_id]
            .into_iter()
            .chain(self.inner.member_of.iter().copied())
    }

    pub fn all_ids(&self) -> impl Iterator<Item = u32> {
        [self.inner.account_id]
            .into_iter()
            .chain(self.inner.member_of.iter().copied())
            .chain(self.inner.access_to.iter().map(|a| a.account_id))
    }

    pub fn all_ids_by_collection(&self, collection: Collection) -> impl Iterator<Item = u32> {
        [self.inner.account_id]
            .into_iter()
            .chain(self.inner.member_of.iter().copied())
            .chain(self.inner.access_to.iter().filter_map(move |a| {
                if a.collections.contains(collection) {
                    Some(a.account_id)
                } else {
                    None
                }
            }))
    }

    pub fn is_member(&self, account_id: u32) -> bool {
        self.inner.account_id == account_id
            || self.inner.member_of.contains(&account_id)
            || self.has_permission(Permission::Impersonate)
    }

    pub fn is_account_id(&self, account_id: u32) -> bool {
        self.inner.account_id == account_id
    }

    #[inline(always)]
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.inner
            .scopes
            .get(self.scope_id as usize)
            .map_or(false, |scope| scope.permissions.get(permission as usize))
    }

    pub fn is_valid(&self) -> bool {
        let todo = "use this function";
        self.inner
            .scopes
            .get(self.scope_id as usize)
            .map_or(false, |scope| scope.expires_at > now())
    }

    pub fn assert_has_permission(&self, permission: Permission) -> trc::Result<bool> {
        if self.has_permission(permission) {
            Ok(true)
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .details(permission.as_str()))
        }
    }

    pub fn permissions(&self) -> Vec<Permission> {
        const USIZE_BITS: usize = std::mem::size_of::<usize>() * 8;
        const USIZE_MASK: u32 = USIZE_BITS as u32 - 1;
        let mut permissions = Vec::new();

        let Some(scope) = self.inner.scopes.get(self.scope_id as usize) else {
            return permissions;
        };

        for (block_num, bytes) in scope.permissions.inner().iter().enumerate() {
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

    pub fn is_shared(&self, account_id: u32) -> bool {
        !self.is_member(account_id)
            && self
                .inner
                .access_to
                .iter()
                .any(|a| a.account_id == account_id)
    }

    pub fn shared_accounts(&self, collection: Collection) -> impl Iterator<Item = &u32> {
        self.inner
            .member_of
            .iter()
            .chain(self.inner.access_to.iter().filter_map(move |a| {
                if a.collections.contains(collection) {
                    Some(&a.account_id)
                } else {
                    None
                }
            }))
    }

    pub fn has_access(&self, to_account_id: u32, to_collection: impl Into<Collection>) -> bool {
        let to_collection = to_collection.into();
        self.is_member(to_account_id)
            || self
                .inner
                .access_to
                .iter()
                .any(|a| a.account_id == to_account_id && a.collections.contains(to_collection))
    }

    pub fn has_account_access(&self, to_account_id: u32) -> bool {
        self.is_member(to_account_id)
            || self
                .inner
                .access_to
                .iter()
                .any(|a| a.account_id == to_account_id)
    }

    pub fn is_http_request_allowed(&self) -> LimiterResult {
        self.inner
            .concurrent_http_requests
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn is_imap_request_allowed(&self) -> LimiterResult {
        self.inner
            .concurrent_imap_requests
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn is_upload_allowed(&self) -> LimiterResult {
        self.inner
            .concurrent_uploads
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }
}

impl AccessTokenInner {
    pub fn from_id(account_id: u32) -> Self {
        Self {
            account_id,
            ..Default::default()
        }
    }

    pub fn with_access_to(self, access_to: impl IntoIterator<Item = AccessTo>) -> Self {
        Self {
            access_to: access_to.into_iter().collect(),
            ..self
        }
    }

    pub fn with_scopes(self, scopes: impl IntoIterator<Item = AccessScope>) -> Self {
        Self {
            scopes: scopes.into_iter().collect(),
            ..self
        }
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    pub fn new_admin() -> Self {
        AccessTokenInner {
            account_id: FALLBACK_ADMIN_ID,
            tenant_id: Default::default(),
            member_of: Default::default(),
            access_to: Default::default(),
            scopes: Box::new([AccessScope::new(Permissions::all())]),
            concurrent_http_requests: Default::default(),
            concurrent_imap_requests: Default::default(),
            concurrent_uploads: Default::default(),
            revision: Default::default(),
            obj_size: Default::default(),
        }
    }

    pub fn update_size(mut self) -> Self {
        self.obj_size = (std::mem::size_of::<AccessToken>()
            + (self.member_of.len() * std::mem::size_of::<u32>())
            + (self.access_to.len() * (std::mem::size_of::<u32>() + std::mem::size_of::<u64>()))
            + (self.scopes.len() * std::mem::size_of::<AccessScope>()))
            as u64;
        self
    }
}

impl AccessScope {
    pub fn new(permissions: Permissions) -> Self {
        Self {
            permissions,
            expires_at: u64::MAX,
        }
    }

    pub fn expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }
}
