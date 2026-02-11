/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AccessToken;
use crate::{
    Server,
    auth::{
        AccessScope, AccessTo, AccessTokenInner, AccountTenantIds, FALLBACK_ADMIN_ID, Permissions,
        PermissionsGroup,
    },
    network::limiter::{ConcurrencyLimiter, LimiterResult},
};
use ahash::AHasher;
use registry::{
    schema::{
        enums::Permission,
        structs::{self, Account},
    },
    types::EnumType,
};
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};
use store::{query::acl::AclQuery, rand, write::now};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{acl::Acl, collection::Collection};
use utils::map::bitmap::{Bitmap, BitmapItem};

impl Server {
    async fn build_access_token(
        &self,
        account: Account,
        account_id: u32,
        revision: u64,
        revision_account: u64,
    ) -> trc::Result<AccessTokenInner> {
        match account {
            Account::User(account) => {
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
                        .add_role_permissions(permissions, roles.iter().map(|v| v.id() as u32))
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
                            let tenant =
                                self.tenant(tenant_id).await.caused_by(trc::location!())?;
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
                                    .add_role_permissions(
                                        tenant_permissions,
                                        tenant_roles.iter().copied(),
                                    )
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
                    .member_group_ids
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
                let credential_scopes = account
                    .credentials
                    .into_iter()
                    .filter_map(|(credential_id, credential)| {
                        let expires_at = credential
                            .expires_at
                            .map(|v| v.timestamp() as u64)
                            .unwrap_or(u64::MAX);
                        if expires_at > now {
                            let permissions = match credential.permissions {
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
                                credential_id,
                                permissions,
                                expires_at,
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                Ok(AccessTokenInner {
                    concurrent_imap_requests: self
                        .core
                        .imap
                        .rate_concurrent
                        .map(ConcurrencyLimiter::new),
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
                    revision_account,
                    account_id,
                    tenant_id,
                    member_of,
                    access_to: access_to.into_boxed_slice(),
                    scopes: [AccessScope::new(permissions.finalize(), u32::MAX)]
                        .into_iter()
                        .chain(credential_scopes)
                        .collect::<Box<[AccessScope]>>(),
                }
                .update_size())
            }
            Account::Group(account) => {
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
                        .add_role_permissions(permissions, roles.iter().map(|v| v.id() as u32))
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
                            let tenant =
                                self.tenant(tenant_id).await.caused_by(trc::location!())?;
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
                                    .add_role_permissions(
                                        tenant_permissions,
                                        tenant_roles.iter().copied(),
                                    )
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

                Ok(AccessTokenInner {
                    concurrent_imap_requests: self
                        .core
                        .imap
                        .rate_concurrent
                        .map(ConcurrencyLimiter::new),
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
                    revision_account,
                    account_id,
                    tenant_id,
                    member_of: Default::default(),
                    access_to: Default::default(),
                    scopes: Box::new([AccessScope::new(permissions.finalize(), u32::MAX)]),
                }
                .update_size())
            }
        }
    }

    pub async fn access_token(&self, account_id: u32) -> trc::Result<Arc<AccessTokenInner>> {
        match self
            .inner
            .cache
            .access_tokens
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(token) => Ok(token),
            Err(guard) => {
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
                let revision = rand::random::<u64>();
                let revision_account = hash_account(&account);
                let token: Arc<AccessTokenInner> = self
                    .build_access_token(account, account_id, revision, revision_account)
                    .await?
                    .into();
                let _ = guard.insert(token.clone());
                Ok(token)
            }
        }
    }

    pub(crate) async fn access_token_from_account(
        &self,
        account_id: u32,
        account: Account,
    ) -> trc::Result<Arc<AccessTokenInner>> {
        let revision_account = hash_account(&account);
        match self
            .inner
            .cache
            .access_tokens
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(token) => {
                if token.revision_account == revision_account {
                    Ok(token)
                } else {
                    // Token is stale, rebuild it
                    debug_assert!(
                        false,
                        "Token is stale, invalidation should have been triggered"
                    );
                    let revision = rand::random::<u64>();
                    let token: Arc<AccessTokenInner> = self
                        .build_access_token(account, account_id, revision, revision_account)
                        .await?
                        .into();
                    self.inner
                        .cache
                        .access_tokens
                        .update(account_id, token.clone());
                    Ok(token)
                }
            }
            Err(guard) => {
                let revision = rand::random::<u64>();
                let token: Arc<AccessTokenInner> = self
                    .build_access_token(account, account_id, revision, revision_account)
                    .await?
                    .into();
                let _ = guard.insert(token.clone());
                Ok(token)
            }
        }
    }
}

impl AccessToken {
    pub fn new(inner: Arc<AccessTokenInner>) -> Self {
        AccessToken {
            scope_idx: 0,
            inner,
        }
    }

    pub fn scoped(inner: Arc<AccessTokenInner>, credential_id: u32) -> trc::Result<Self> {
        inner
            .scopes
            .iter()
            .position(|scope| scope.credential_id == credential_id)
            .ok_or_else(|| {
                trc::SecurityEvent::Unauthorized
                    .into_err()
                    .ctx(trc::Key::AccountId, inner.account_id)
                    .ctx(trc::Key::Id, credential_id)
                    .reason("Credential expired or removed.")
            })
            .map(|scope_idx| AccessToken { scope_idx, inner })
            .and_then(|token| token.assert_is_valid())
    }

    pub fn renew(inner: Arc<AccessTokenInner>, credential_id: Option<u32>) -> trc::Result<Self> {
        if let Some(credential_id) = credential_id {
            Self::scoped(inner, credential_id)
        } else {
            Ok(AccessToken {
                scope_idx: 0,
                inner,
            })
        }
    }

    pub fn state(&self) -> u32 {
        // Hash state
        let mut s = AHasher::default();
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
            .get(self.scope_idx)
            .is_some_and(|scope| scope.permissions.get(permission as usize))
    }

    pub fn assert_is_valid(self) -> trc::Result<Self> {
        if self
            .inner
            .scopes
            .get(self.scope_idx)
            .is_some_and(|scope| scope.expires_at > now())
        {
            Ok(self)
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .ctx(trc::Key::AccountId, self.inner.account_id)
                .reason("Credential expired."))
        }
    }

    #[inline(always)]
    pub fn credential_id(&self) -> Option<u32> {
        self.inner
            .scopes
            .get(self.scope_idx)
            .map(|scope| scope.credential_id)
    }

    #[inline(always)]
    pub fn revision(&self) -> u64 {
        self.inner.revision
    }

    pub fn assert_has_permissions(self, permissions: &[Permission]) -> trc::Result<Self> {
        for permission in permissions {
            if !self.has_permission(*permission) {
                return Err(trc::SecurityEvent::Unauthorized
                    .into_err()
                    .details(permission.as_str())
                    .account_id(self.account_id()));
            }
        }

        Ok(self)
    }

    pub fn assert_has_permission(self, permission: Permission) -> trc::Result<Self> {
        if self.has_permission(permission) {
            Ok(self)
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .details(permission.as_str())
                .account_id(self.account_id()))
        }
    }

    pub fn enforce_permission(&self, permission: Permission) -> trc::Result<()> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .details(permission.as_str())
                .account_id(self.account_id()))
        }
    }

    pub fn permissions(&self) -> Vec<Permission> {
        const USIZE_BITS: usize = std::mem::size_of::<usize>() * 8;
        const USIZE_MASK: u32 = USIZE_BITS as u32 - 1;
        let mut permissions = Vec::new();

        let Some(scope) = self.inner.scopes.get(self.scope_idx) else {
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

    pub fn account_tenant_ids(&self) -> AccountTenantIds {
        AccountTenantIds {
            account_id: self.account_id(),
            tenant_id: self.tenant_id(),
        }
    }

    pub fn new_admin() -> AccessToken {
        AccessToken {
            scope_idx: 0,
            inner: Arc::new(AccessTokenInner {
                account_id: FALLBACK_ADMIN_ID,
                tenant_id: Default::default(),
                member_of: Default::default(),
                access_to: Default::default(),
                scopes: Box::new([AccessScope::new(Permissions::all(), u32::MAX)]),
                concurrent_http_requests: Default::default(),
                concurrent_imap_requests: Default::default(),
                concurrent_uploads: Default::default(),
                revision: Default::default(),
                revision_account: Default::default(),
                obj_size: Default::default(),
            }),
        }
    }

    pub fn from_permissions(
        account_id: u32,
        set_permissions: impl IntoIterator<Item = Permission>,
    ) -> AccessToken {
        let mut permissions = Permissions::new();
        for permission in set_permissions {
            permissions.set(permission as usize);
        }
        AccessToken {
            scope_idx: 0,
            inner: Arc::new(AccessTokenInner {
                account_id,
                tenant_id: Default::default(),
                member_of: Default::default(),
                access_to: Default::default(),
                scopes: Box::new([AccessScope::new(permissions, u32::MAX)]),
                concurrent_http_requests: Default::default(),
                concurrent_imap_requests: Default::default(),
                concurrent_uploads: Default::default(),
                revision: Default::default(),
                revision_account: Default::default(),
                obj_size: Default::default(),
            }),
        }
    }

    pub fn from_id(account_id: u32) -> Self {
        AccessToken::new(Arc::new(AccessTokenInner::from_id(account_id)))
    }
}

impl AccessTokenInner {
    pub fn from_id(account_id: u32) -> Self {
        Self {
            account_id,
            ..Default::default()
        }
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
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
    pub fn new(permissions: Permissions, credential_id: u32) -> Self {
        Self {
            permissions,
            credential_id,
            expires_at: u64::MAX,
        }
    }
}

fn hash_account(account: &Account) -> u64 {
    let mut s = AHasher::default();

    match account {
        Account::User(account) => {
            account.member_tenant_id.hash(&mut s);
            account.role_ids.hash(&mut s);
            hash_permissions(&mut s, &account.permissions);
            for (credential_id, credential) in &account.credentials {
                credential_id.hash(&mut s);
                credential.expires_at.hash(&mut s);
                hash_permissions(&mut s, &credential.permissions);
            }
        }
        Account::Group(account) => {
            account.member_tenant_id.hash(&mut s);
            account.role_ids.hash(&mut s);
            hash_permissions(&mut s, &account.permissions);
        }
    }

    s.finish()
}

fn hash_permissions(hasher: &mut AHasher, permissions: &structs::Permissions) {
    match permissions {
        structs::Permissions::Inherit => {
            0u8.hash(hasher);
        }
        structs::Permissions::Merge(permissions) => {
            2u8.hash(hasher);
            for (perm, enabled) in permissions.permissions.iter() {
                if *enabled {
                    perm.hash(hasher);
                }
            }
        }
        structs::Permissions::Replace(permissions) => {
            3u8.hash(hasher);
            for (perm, enabled) in permissions.permissions.iter() {
                if *enabled {
                    perm.hash(hasher);
                }
            }
        }
    }
}
