/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AccessToken;
use crate::{
    Server,
    auth::{
        AccessScope, AccessTo, AccessTokenInner, AccountTenantIds, Permissions, RECOVERY_ADMIN_ID,
        permissions::{BuildPermissions, PermissionsListBuilder},
    },
    network::limiter::{ConcurrencyLimiter, LimiterResult},
};
use ahash::AHasher;
use registry::{
    schema::{
        enums::Permission,
        structs::{self, Account, Roles, UserRoles},
    },
    types::EnumImpl,
};
use std::{
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
};
use store::{query::acl::AclQuery, rand, write::now};
use tinyvec::TinyVec;
use trc::{AddContext, StoreEvent};
use types::{acl::Acl, collection::Collection};
use utils::map::bitmap::{Bitmap, BitmapItem};
use xxhash_rust::xxh3;

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
                let tenant_id = account.member_tenant_id.map(|t| t.id() as u32);
                let permissions = self
                    .effective_permissions(
                        &account.permissions,
                        match &account.roles {
                            UserRoles::User => {
                                self.core.network.security.default_role_ids_user.as_slice()
                            }
                            UserRoles::Admin => {
                                if tenant_id.is_none() {
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
                        tenant_id,
                    )
                    .await?;

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
                let mut credential_version = 0;
                let mut credential_scopes = Vec::with_capacity(account.credentials.len());

                credential_scopes.push(AccessScope::new(permissions.finalize(), u32::MAX));

                for credential in account.credentials {
                    match credential {
                        structs::Credential::Password(credential) => {
                            credential_version = xxh3::xxh3_64(credential.secret.as_bytes()).max(1);

                            if credential.expires_at.is_some() || !credential.allowed_ips.is_empty()
                            {
                                let credential_scope = &mut credential_scopes[0];
                                credential_scope.expires_at = credential
                                    .expires_at
                                    .map(|v| v.timestamp() as u64)
                                    .unwrap_or(u64::MAX);
                                credential_scope.allowed_ips =
                                    credential.allowed_ips.into_inner().into_boxed_slice();
                            }
                        }
                        structs::Credential::ApiKey(credential)
                        | structs::Credential::AppPassword(credential) => {
                            let credential_id = credential.credential_id.document_id();
                            let expires_at = credential
                                .expires_at
                                .map(|v| v.timestamp() as u64)
                                .unwrap_or(u64::MAX);
                            if expires_at > now {
                                let permissions = &credential_scopes[0].permissions;
                                let permissions = match credential.permissions {
                                    structs::CredentialPermissions::Inherit => permissions.clone(),
                                    structs::CredentialPermissions::Disable(list) => {
                                        let mut permissions = permissions.clone();
                                        permissions.clear_many(&Permissions::from_permission(
                                            list.permissions.as_slice(),
                                        ));
                                        permissions
                                    }
                                    structs::CredentialPermissions::Replace(list) => {
                                        let mut replace_permissions = Permissions::from_permission(
                                            list.permissions.as_slice(),
                                        );
                                        replace_permissions.intersection(permissions);
                                        replace_permissions
                                    }
                                };
                                credential_scopes.push(AccessScope {
                                    credential_id,
                                    permissions,
                                    expires_at,
                                    allowed_ips: credential
                                        .allowed_ips
                                        .into_inner()
                                        .into_boxed_slice(),
                                })
                            }
                        }
                    }
                }

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
                    credential_version,
                    account_id,
                    tenant_id,
                    member_of,
                    access_to: access_to.into_boxed_slice(),
                    scopes: []
                        .into_iter()
                        .chain(credential_scopes)
                        .collect::<Box<[AccessScope]>>(),
                }
                .update_size())
            }
            Account::Group(account) => {
                let tenant_id = account.member_tenant_id.map(|t| t.id() as u32);
                let permissions = self
                    .effective_permissions(
                        &account.permissions,
                        account.roles.role_ids().unwrap_or(
                            self.core.network.security.default_role_ids_group.as_slice(),
                        ),
                        tenant_id,
                    )
                    .await?;

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
                    credential_version: 0,
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
            Ok(token) => {
                trc::event!(
                    Store(StoreEvent::CacheHit),
                    Key = account_id,
                    Collection = "accessToken",
                );

                Ok(token)
            }
            Err(guard) => {
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = account_id,
                    Collection = "accessToken",
                );

                let token: Arc<AccessTokenInner> = if let Some(account) =
                    self.registry().object::<Account>(account_id.into()).await?
                {
                    let revision = rand::random::<u64>();
                    let revision_account = hash_account(&account);
                    self.build_access_token(account, account_id, revision, revision_account)
                        .await?
                        .into()
                } else if account_id == RECOVERY_ADMIN_ID {
                    AccessTokenInner::new_admin().into()
                } else {
                    return Err(trc::SecurityEvent::Unauthorized
                        .into_err()
                        .details("Account not found")
                        .account_id(account_id)
                        .caused_by(trc::location!()));
                };

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
                    trc::event!(
                        Store(StoreEvent::CacheHit),
                        Key = account_id,
                        Collection = "accessToken",
                    );

                    Ok(token)
                } else {
                    // Token is stale, rebuild it
                    trc::event!(
                        Store(StoreEvent::CacheStale),
                        Key = account_id,
                        Collection = "accessToken",
                    );

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
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = account_id,
                    Collection = "accessToken",
                );

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
    pub fn new(inner: Arc<AccessTokenInner>, remote_ip: IpAddr) -> trc::Result<Self> {
        AccessToken {
            scope_idx: 0,
            inner,
        }
        .assert_is_valid(remote_ip)
    }

    pub fn new_maybe_invalid(inner: Arc<AccessTokenInner>) -> Self {
        AccessToken {
            scope_idx: 0,
            inner,
        }
    }

    pub fn new_scoped(
        inner: Arc<AccessTokenInner>,
        credential_id: u32,
        remote_ip: IpAddr,
    ) -> trc::Result<Self> {
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
            .and_then(|token| token.assert_is_valid(remote_ip))
    }

    pub fn renew(
        inner: Arc<AccessTokenInner>,
        credential_id: Option<u32>,
        remote_ip: IpAddr,
    ) -> trc::Result<Self> {
        if let Some(credential_id) = credential_id {
            Self::new_scoped(inner, credential_id, remote_ip)
        } else {
            AccessToken {
                scope_idx: 0,
                inner,
            }
            .assert_is_valid(remote_ip)
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

    pub fn assert_is_valid(self, remote_ip: IpAddr) -> trc::Result<Self> {
        if let Some(scope) = self.inner.scopes.get(self.scope_idx) {
            let has_expired = scope.expires_at <= now();
            let is_valid_ip = scope.allowed_ips.is_empty()
                || scope
                    .allowed_ips
                    .iter()
                    .any(|ip_mask| ip_mask.matches(&remote_ip));

            let mut access_token = self;
            if has_expired {
                if access_token.scope_idx > 0 {
                    return Err(trc::AuthEvent::CredentialExpired
                        .into_err()
                        .ctx(trc::Key::AccountId, access_token.inner.account_id)
                        .reason("Credential expired."));
                } else {
                    trc::event!(
                        Auth(trc::AuthEvent::CredentialExpired),
                        AccountId = access_token.inner.account_id,
                        Reason = "Main credential expired, downgrading permissions.",
                    );
                }

                // Downgrade permissions to allow password change
                let mut scopes = Vec::with_capacity(access_token.inner.scopes.len());
                for (idx, scope) in access_token.inner.scopes.iter().enumerate() {
                    if idx == 0 {
                        let mut permissions = Permissions::new();

                        for permission in [
                            Permission::Authenticate,
                            Permission::AuthenticateWithAlias,
                            Permission::SysAccountPasswordGet,
                            Permission::SysAccountPasswordUpdate,
                            Permission::EmailReceive,
                        ] {
                            if scope.permissions.get(permission as usize) {
                                permissions.set(permission as usize);
                            }
                        }

                        scopes.push(AccessScope {
                            permissions,
                            credential_id: scope.credential_id,
                            expires_at: u64::MAX,
                            allowed_ips: scope.allowed_ips.clone(),
                        });
                    } else {
                        scopes.push(scope.clone());
                    }
                }
                let old_inner = &access_token.inner;
                let inner = AccessTokenInner {
                    scopes: scopes.into_boxed_slice(),
                    account_id: old_inner.account_id,
                    tenant_id: old_inner.tenant_id,
                    member_of: old_inner.member_of.clone(),
                    access_to: old_inner.access_to.clone(),
                    concurrent_http_requests: old_inner.concurrent_http_requests.clone(),
                    concurrent_imap_requests: old_inner.concurrent_imap_requests.clone(),
                    concurrent_uploads: old_inner.concurrent_uploads.clone(),
                    revision_account: old_inner.revision_account,
                    revision: old_inner.revision,
                    credential_version: old_inner.credential_version,
                    obj_size: old_inner.obj_size,
                };

                access_token = AccessToken {
                    scope_idx: access_token.scope_idx,
                    inner: Arc::new(inner),
                };
            }

            if is_valid_ip {
                Ok(access_token)
            } else {
                Err(trc::SecurityEvent::IpUnauthorized
                    .into_err()
                    .ctx(trc::Key::AccountId, access_token.inner.account_id)
                    .reason("IP address not allowed."))
            }
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .ctx(trc::Key::AccountId, self.inner.account_id)
                .reason("Credential not valid."))
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
        if let Some(scope) = self.inner.scopes.get(self.scope_idx) {
            scope.permissions.build_permissions_list()
        } else {
            vec![]
        }
    }

    #[inline(always)]
    pub fn access_scope(&self) -> Option<&AccessScope> {
        self.inner.scopes.get(self.scope_idx)
    }

    pub(crate) fn permissions_bits(&self) -> &Permissions {
        &self
            .inner
            .scopes
            .get(self.scope_idx)
            .unwrap_or(&self.inner.scopes[0])
            .permissions
    }

    pub fn account_permissions(&self) -> &Permissions {
        &self.inner.scopes[0].permissions
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

    pub fn concurrent_http_requests(&self) -> u64 {
        self.inner
            .concurrent_http_requests
            .as_ref()
            .map(|limiter| limiter.max_concurrent())
            .unwrap_or(0)
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

    pub fn concurrent_uploads(&self) -> u64 {
        self.inner
            .concurrent_uploads
            .as_ref()
            .map(|limiter| limiter.max_concurrent())
            .unwrap_or(0)
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
            inner: Arc::new(AccessTokenInner::new_admin()),
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
                credential_version: Default::default(),
                obj_size: Default::default(),
            }),
        }
    }

    pub fn from_id_maybe_invalid(account_id: u32) -> Self {
        AccessToken::new_maybe_invalid(Arc::new(AccessTokenInner::from_id(account_id)))
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

    pub fn new_admin() -> Self {
        AccessTokenInner {
            account_id: RECOVERY_ADMIN_ID,
            tenant_id: Default::default(),
            member_of: Default::default(),
            access_to: Default::default(),
            scopes: Box::new([AccessScope::new(Permissions::all(), u32::MAX)]),
            concurrent_http_requests: Default::default(),
            concurrent_imap_requests: Default::default(),
            concurrent_uploads: Default::default(),
            revision: Default::default(),
            revision_account: Default::default(),
            credential_version: Default::default(),
            obj_size: Default::default(),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn revision_account(&self) -> u64 {
        self.revision_account
    }

    pub fn credential_version(&self) -> u64 {
        self.credential_version
    }
}

impl AccessScope {
    pub fn new(permissions: Permissions, credential_id: u32) -> Self {
        Self {
            permissions,
            credential_id,
            expires_at: u64::MAX,
            allowed_ips: Default::default(),
        }
    }
}

fn hash_account(account: &Account) -> u64 {
    let mut s = AHasher::default();

    match account {
        Account::User(account) => {
            account.member_tenant_id.hash(&mut s);
            match &account.roles {
                UserRoles::User => {
                    0u8.hash(&mut s);
                }
                UserRoles::Admin => {
                    1u8.hash(&mut s);
                }
                UserRoles::Custom(custom_roles) => {
                    2u8.hash(&mut s);
                    custom_roles.role_ids.as_slice().hash(&mut s);
                }
            }
            hash_permissions(&mut s, &account.permissions);
            for credential in account
                .credentials
                .iter()
                .filter_map(|credential| credential.as_secondary_credential())
            {
                credential.credential_id.hash(&mut s);
                credential.expires_at.hash(&mut s);
                hash_credential_permissions(&mut s, &credential.permissions);
            }
            for group_id in account.member_group_ids.iter() {
                group_id.hash(&mut s);
            }
        }
        Account::Group(account) => {
            account.member_tenant_id.hash(&mut s);
            match &account.roles {
                Roles::Default => {}
                Roles::Custom(custom_roles) => {
                    custom_roles.role_ids.as_slice().hash(&mut s);
                }
            }
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
            permissions.enabled_permissions.as_slice().hash(hasher);
            permissions.disabled_permissions.as_slice().hash(hasher);
        }
        structs::Permissions::Replace(permissions) => {
            3u8.hash(hasher);
            permissions.enabled_permissions.as_slice().hash(hasher);
            permissions.disabled_permissions.as_slice().hash(hasher);
        }
    }
}

fn hash_credential_permissions(hasher: &mut AHasher, permissions: &structs::CredentialPermissions) {
    match permissions {
        structs::CredentialPermissions::Inherit => {
            0u8.hash(hasher);
        }
        structs::CredentialPermissions::Disable(permissions) => {
            2u8.hash(hasher);
            permissions.permissions.as_slice().hash(hasher);
        }
        structs::CredentialPermissions::Replace(permissions) => {
            3u8.hash(hasher);
            permissions.permissions.as_slice().hash(hasher);
        }
    }
}
