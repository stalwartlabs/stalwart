/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AccessToken;
use crate::{
    Server,
    auth::{
        AccessScope, AccessTo, AccessTokenInner, AccountCache, ChangedBy, Permissions,
        RECOVERY_ADMIN_ID, TokenScope,
        oauth::scope::{OAuthScopes, scope_data_types},
        permissions::{BuildPermissions, PermissionsListBuilder},
    },
    network::limiter::{AccountLimit, AccountLimits, AccountRate, LimiterResult, RateCounter},
};
use ahash::AHasher;
use compact_str::format_compact;
use registry::{
    schema::{
        enums::Permission,
        structs::{self, Account, Roles, UserRoles},
    },
    types::{EnumImpl, ipmask::IpAddrOrMask},
};
use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
};
use store::{
    Deserialize, IterateParams, ValueKey,
    query::acl::{AclItem, AclQuery},
    rand,
    write::{ValueClass, key::DeserializeBigEndian, now},
};
use tinyvec::TinyVec;
use trc::{AddContext, CacheEvent};
use types::{acl::Acl, collection::Collection, type_state::DataType};
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
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let tenant_id = account.member_tenant_id.map(|t| t.id() as u32);
                // SPDX-SnippetEnd
                let role_ids = match &account.roles {
                    UserRoles::User => self.core.network.security.default_role_ids_user.as_slice(),
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    UserRoles::Admin if tenant_id.is_some() => self
                        .core
                        .network
                        .security
                        .default_role_ids_tenant
                        .as_slice(),
                    // SPDX-SnippetEnd
                    UserRoles::Admin => {
                        self.core.network.security.default_role_ids_admin.as_slice()
                    }
                    UserRoles::Custom(custom_roles) => custom_roles.role_ids.as_slice(),
                };
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let permissions = self
                    .effective_permissions(&account.permissions, role_ids, tenant_id)
                    .await?;
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let permissions = self
                    .effective_permissions(&account.permissions, role_ids)
                    .await?;

                let member_of = account
                    .member_group_ids
                    .iter()
                    .map(|m| m.id() as u32)
                    .collect::<Box<[u32]>>();
                let access_to = AccessTo::from_acl_items(
                    account_id,
                    &member_of,
                    self.acl_items_by_grantee(account_id, &member_of).await?,
                )?;

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
                        structs::Credential::Passkey(_) => {}
                    }
                }

                Ok(AccessTokenInner {
                    limits: self.account_limits(),
                    obj_size: 0,
                    revision,
                    revision_account,
                    credential_version,
                    account_id,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    tenant_id,
                    // SPDX-SnippetEnd
                    member_of,
                    access_to,
                    scopes: []
                        .into_iter()
                        .chain(credential_scopes)
                        .collect::<Box<[AccessScope]>>(),
                }
                .update_size())
            }
            Account::Group(account) => {
                let role_ids = account
                    .roles
                    .role_ids()
                    .unwrap_or(self.core.network.security.default_role_ids_group.as_slice());
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let tenant_id = account.member_tenant_id.map(|t| t.id() as u32);
                #[cfg(feature = "enterprise")]
                let permissions = self
                    .effective_permissions(&account.permissions, role_ids, tenant_id)
                    .await?;
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let permissions = self
                    .effective_permissions(&account.permissions, role_ids)
                    .await?;

                Ok(AccessTokenInner {
                    limits: self.account_limits(),
                    obj_size: 0,
                    revision,
                    revision_account,
                    credential_version: 0,
                    account_id,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    tenant_id,
                    // SPDX-SnippetEnd
                    member_of: Default::default(),
                    access_to: Default::default(),
                    scopes: Box::new([AccessScope::new(permissions.finalize(), u32::MAX)]),
                }
                .update_size())
            }
        }
    }

    async fn acl_items_by_grantee(
        &self,
        account_id: u32,
        member_of: &[u32],
    ) -> trc::Result<Vec<(u32, AclItem)>> {
        if member_of.is_empty() {
            return self
                .store()
                .acl_query(AclQuery::HasAccess {
                    grant_account_id: account_id,
                })
                .await
                .caused_by(trc::location!())
                .map(|items| items.into_iter().map(|item| (account_id, item)).collect());
        }

        let grantees = [account_id]
            .into_iter()
            .chain(member_of.iter().copied())
            .collect::<TinyVec<[u32; 4]>>();
        let mut ordered = grantees.clone();
        ordered.sort_unstable();
        let mut previous = None;
        ordered.retain(|id| previous.replace(*id) != Some(*id));
        let mut items = Vec::new();
        self.store()
            .iterate_many(
                ordered
                    .iter()
                    .map(|&grant_account_id| {
                        IterateParams::new(
                            ValueKey {
                                account_id: 0,
                                collection: 0,
                                document_id: 0,
                                class: ValueClass::Acl(grant_account_id),
                            },
                            ValueKey {
                                account_id: u32::MAX,
                                collection: u8::MAX,
                                document_id: u32::MAX,
                                class: ValueClass::Acl(grant_account_id),
                            },
                        )
                        .ascending()
                    })
                    .collect(),
                |key, value| {
                    let grant_account_id = key.deserialize_be_u32(0)?;
                    let mut item = AclItem::deserialize(key)?;
                    item.permissions = u64::deserialize(value)?;
                    items.push((grant_account_id, item));
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        items.sort_unstable_by_key(|(grant_account_id, item)| {
            (
                grantees
                    .iter()
                    .position(|id| id == grant_account_id)
                    .unwrap_or(usize::MAX),
                item.to_account_id,
                u8::from(item.to_collection),
                item.to_document_id,
            )
        });

        Ok(items)
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
                    Cache(CacheEvent::Hit),
                    Key = account_id,
                    Name = "accessToken",
                );

                Ok(token)
            }
            Err(guard) => {
                trc::event!(
                    Cache(CacheEvent::Miss),
                    Key = account_id,
                    Name = "accessToken",
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

                guard.insert(token.clone());
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
                        Cache(CacheEvent::Hit),
                        Key = account_id,
                        Name = "accessToken",
                    );

                    Ok(token)
                } else {
                    // Token is stale, rebuild it
                    trc::event!(
                        Cache(CacheEvent::Stale),
                        Key = account_id,
                        Name = "accessToken",
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
                    Cache(CacheEvent::Miss),
                    Key = account_id,
                    Name = "accessToken",
                );

                let revision = rand::random::<u64>();
                let token: Arc<AccessTokenInner> = self
                    .build_access_token(account, account_id, revision, revision_account)
                    .await?
                    .into();
                guard.insert(token.clone());
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
            token_scope: None,
        }
        .assert_is_valid(remote_ip)
    }

    pub fn new_maybe_invalid(inner: Arc<AccessTokenInner>) -> Self {
        AccessToken {
            scope_idx: 0,
            inner,
            token_scope: None,
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
            .map(|scope_idx| AccessToken {
                scope_idx,
                inner,
                token_scope: None,
            })
            .and_then(|token| token.assert_is_valid(remote_ip))
    }

    pub fn renew(
        inner: Arc<AccessTokenInner>,
        credential_id: Option<u32>,
        token_scope: Option<TokenScope>,
        remote_ip: IpAddr,
    ) -> trc::Result<Self> {
        if let Some(credential_id) = credential_id.filter(|id| *id != u32::MAX) {
            Self::new_scoped(inner, credential_id, remote_ip)
        } else {
            AccessToken {
                scope_idx: 0,
                inner,
                token_scope,
            }
            .assert_is_valid(remote_ip)
        }
    }

    pub fn is_built_from(&self, inner: &Arc<AccessTokenInner>) -> bool {
        Arc::ptr_eq(&self.inner, inner)
    }

    pub fn with_token_scope(mut self, token_scope: Option<TokenScope>) -> Self {
        self.token_scope = token_scope;
        self
    }

    #[inline(always)]
    pub fn token_scope(&self) -> Option<TokenScope> {
        self.token_scope
    }

    #[inline(always)]
    pub fn grant_id(&self) -> Option<u64> {
        self.token_scope.and_then(TokenScope::grant_id)
    }

    pub fn oauth_scopes(&self) -> Option<OAuthScopes> {
        self.token_scope.and_then(TokenScope::restricted_scopes)
    }

    pub fn allows_oauth_scopes(&self, required: OAuthScopes) -> bool {
        self.oauth_scopes()
            .is_none_or(|scopes| scopes.intersects(required))
    }

    pub fn assert_allows_oauth_scopes(self, required: OAuthScopes) -> trc::Result<Self> {
        if self.allows_oauth_scopes(required) {
            Ok(self)
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .details("The token scope does not allow this request")
                .account_id(self.account_id()))
        }
    }

    pub fn restrict_data_types(&self, types: &mut Bitmap<DataType>) {
        if let Some(scopes) = self.oauth_scopes() {
            types.intersection(&scope_data_types(scopes));
        }
    }

    #[inline(always)]
    pub fn credential_version(&self) -> u64 {
        self.inner.credential_version
    }

    #[inline(always)]
    pub fn is_main_credential_expired(&self) -> bool {
        self.inner.is_main_credential_expired()
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

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.inner.tenant_id
    }
    // SPDX-SnippetEnd

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

    pub fn personal_id(&self, account_id: u32, collection: Collection) -> u32 {
        let child_collection = collection.child_collection();
        if self.is_account_id(account_id)
            || self.inner.member_of.contains(&account_id)
            || self.inner.shared_access(account_id).is_some_and(|a| {
                a.collections.contains(collection)
                    || child_collection.is_some_and(|child| a.collections.contains(child))
            })
        {
            self.inner.account_id
        } else {
            account_id
        }
    }

    #[inline(always)]
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.inner
            .scopes
            .get(self.scope_idx)
            .is_some_and(|scope| scope.permissions.get(permission as usize))
            && self
                .token_scope
                .and_then(TokenScope::permissions)
                .is_none_or(|permissions| permissions.get(permission as usize))
    }

    pub fn assert_is_valid(self, remote_ip: IpAddr) -> trc::Result<Self> {
        if let Some(scope) = self.inner.scopes.get(self.scope_idx) {
            if !scope.allowed_ips.is_empty()
                && !scope
                    .allowed_ips
                    .iter()
                    .any(|ip_mask| ip_mask.matches(&remote_ip))
            {
                return Err(trc::SecurityEvent::IpUnauthorized
                    .into_err()
                    .ctx(trc::Key::AccountId, self.inner.account_id)
                    .reason("IP address not allowed."));
            }

            let has_expired = scope.expires_at <= now();
            let mut access_token = self;
            if has_expired {
                if access_token.scope_idx > 0 {
                    return Err(trc::AuthEvent::CredentialExpired
                        .into_err()
                        .ctx(trc::Key::AccountId, access_token.inner.account_id)
                        .reason("Credential expired."));
                } else if access_token
                    .token_scope
                    .is_some_and(|token_scope| !token_scope.allows_expired_credential())
                {
                    return Err(trc::AuthEvent::CredentialExpired
                        .into_err()
                        .ctx(trc::Key::AccountId, access_token.inner.account_id)
                        .reason(
                            "Main credential expired, grant scopes do not allow a password change.",
                        ));
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
                            expires_at: scope.expires_at,
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
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    tenant_id: old_inner.tenant_id,
                    // SPDX-SnippetEnd
                    member_of: old_inner.member_of.clone(),
                    access_to: old_inner.access_to.clone(),
                    limits: old_inner.limits.clone(),
                    revision_account: old_inner.revision_account,
                    revision: old_inner.revision,
                    credential_version: old_inner.credential_version,
                    obj_size: old_inner.obj_size,
                };

                access_token = AccessToken {
                    scope_idx: access_token.scope_idx,
                    inner: Arc::new(inner),
                    token_scope: access_token.token_scope,
                };
            }

            Ok(access_token)
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .ctx(trc::Key::AccountId, self.inner.account_id)
                .reason("Credential not valid."))
        }
    }

    #[inline(always)]
    pub fn is_secondary_credential(&self) -> bool {
        self.scope_idx > 0
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
        self.effective_permissions().build_permissions_list()
    }

    #[inline(always)]
    pub fn access_scope(&self) -> Option<&AccessScope> {
        self.inner.scopes.get(self.scope_idx)
    }

    pub fn effective_permissions(&self) -> Cow<'_, Permissions> {
        let Some(scope) = self.inner.scopes.get(self.scope_idx) else {
            return Cow::Owned(Permissions::new());
        };
        match self.token_scope.and_then(TokenScope::permissions) {
            Some(filter) => {
                let mut permissions = scope.permissions.clone();
                permissions.intersection(filter);
                Cow::Owned(permissions)
            }
            None => Cow::Borrowed(&scope.permissions),
        }
    }

    pub fn account_permissions(&self) -> &Permissions {
        &self.inner.scopes[0].permissions
    }

    pub fn is_shared(&self, account_id: u32) -> bool {
        !self.is_member(account_id) && self.inner.shared_access(account_id).is_some()
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
                .shared_access(to_account_id)
                .is_some_and(|a| a.collections.contains(to_collection))
    }

    pub fn is_read_only(&self, to_account_id: u32) -> bool {
        !self.is_member(to_account_id)
            && !self
                .inner
                .shared_access(to_account_id)
                .is_some_and(|a| a.is_writable)
    }

    pub fn has_account_access(&self, to_account_id: u32) -> bool {
        self.is_member(to_account_id) || self.inner.shared_access(to_account_id).is_some()
    }

    pub fn is_http_request_allowed(&self) -> LimiterResult {
        self.inner.is_allowed(AccountLimit::HttpRequests)
    }

    pub fn concurrent_http_requests(&self) -> u64 {
        self.inner.max_concurrent(AccountLimit::HttpRequests)
    }

    pub fn is_imap_request_allowed(&self) -> LimiterResult {
        self.inner.is_allowed(AccountLimit::ImapRequests)
    }

    pub fn is_upload_allowed(&self) -> LimiterResult {
        self.inner.is_allowed(AccountLimit::Uploads)
    }

    pub fn concurrent_uploads(&self) -> u64 {
        self.inner.max_concurrent(AccountLimit::Uploads)
    }

    pub fn changed_by(&self) -> ChangedBy {
        ChangedBy {
            account_id: self.account_id(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            tenant_id: self.tenant_id(),
            // SPDX-SnippetEnd
        }
    }

    pub fn new_admin() -> AccessToken {
        AccessToken {
            scope_idx: 0,
            inner: Arc::new(AccessTokenInner::new_admin()),
            token_scope: None,
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
            token_scope: None,
            inner: Arc::new(AccessTokenInner {
                account_id,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                tenant_id: Default::default(),
                // SPDX-SnippetEnd
                member_of: Default::default(),
                access_to: Default::default(),
                scopes: Box::new([AccessScope::new(permissions, u32::MAX)]),
                limits: Default::default(),
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

    pub fn from_account_maybe_invalid(account: &AccountCache) -> Self {
        AccessToken::new_maybe_invalid(Arc::new(AccessTokenInner {
            account_id: account.id,
            member_of: account.id_member_of.clone(),
            ..Default::default()
        }))
    }
}

impl AccessTokenInner {
    pub fn from_id(account_id: u32) -> Self {
        Self {
            account_id,
            ..Default::default()
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
    }
    // SPDX-SnippetEnd

    pub fn update_size(mut self) -> Self {
        let size = std::mem::size_of::<AccessTokenInner>()
            + std::mem::size_of_val::<[u32]>(&self.member_of)
            + std::mem::size_of_val::<[AccessTo]>(&self.access_to)
            + std::mem::size_of_val::<[AccessScope]>(&self.scopes)
            + self
                .scopes
                .iter()
                .map(|scope| std::mem::size_of_val::<[IpAddrOrMask]>(&scope.allowed_ips))
                .sum::<usize>()
            + self
                .limits
                .as_ref()
                .map_or(0, |_| std::mem::size_of::<AccountLimits>());
        self.obj_size = u32::try_from(size).unwrap_or(u32::MAX);
        self
    }

    fn shared_access(&self, account_id: u32) -> Option<&AccessTo> {
        self.access_to
            .binary_search_by_key(&account_id, |a| a.account_id)
            .ok()
            .and_then(|idx| self.access_to.get(idx))
    }

    #[inline]
    fn is_allowed(&self, limit: AccountLimit) -> LimiterResult {
        self.limits
            .as_ref()
            .map_or(LimiterResult::Disabled, |limits| limits.is_allowed(limit))
    }

    #[inline]
    fn max_concurrent(&self, limit: AccountLimit) -> u64 {
        self.limits
            .as_ref()
            .map_or(0, |limits| limits.max_concurrent(limit))
    }

    #[inline]
    pub(crate) fn rate_counter(&self, rate: AccountRate) -> Option<&RateCounter> {
        self.limits
            .as_ref()
            .and_then(|limits| limits.rate_counter(rate))
    }

    pub fn new_admin() -> Self {
        AccessTokenInner {
            account_id: RECOVERY_ADMIN_ID,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            tenant_id: Default::default(),
            // SPDX-SnippetEnd
            member_of: Default::default(),
            access_to: Default::default(),
            scopes: Box::new([AccessScope::new(Permissions::all(), u32::MAX)]),
            limits: Default::default(),
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

    pub fn is_main_credential_expired(&self) -> bool {
        self.scopes
            .first()
            .is_some_and(|scope| scope.expires_at <= now())
    }
}

impl AccessTo {
    fn from_acl_items(
        account_id: u32,
        member_of: &[u32],
        items: Vec<(u32, AclItem)>,
    ) -> trc::Result<Box<[AccessTo]>> {
        let mut access_to: Vec<AccessTo> = Vec::new();
        let mut is_sorted = true;
        for (grant_account_id, acl_item) in items {
            if acl_item.to_account_id == account_id || member_of.contains(&acl_item.to_account_id) {
                continue;
            }

            let acl = Bitmap::<Acl>::from(acl_item.permissions);
            let collection = acl_item.to_collection;
            if !collection.is_valid() {
                return Err(trc::StoreEvent::DataCorruption
                    .ctx(trc::Key::Reason, "Corrupted collection found in ACL key.")
                    .details(format_compact!("{acl_item:?}"))
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
                let is_writable = acl.intersects(&Acl::WRITE);
                match access_to.last_mut() {
                    Some(last) if last.account_id == acl_item.to_account_id => {
                        last.collections.union(&collections);
                        last.is_writable |= is_writable;
                    }
                    last => {
                        is_sorted &=
                            last.is_none_or(|last| last.account_id < acl_item.to_account_id);
                        access_to.push(AccessTo {
                            account_id: acl_item.to_account_id,
                            collections,
                            is_writable,
                        });
                    }
                }
            }
        }

        if !is_sorted {
            access_to.sort_unstable_by_key(|a| a.account_id);
            access_to.dedup_by(|next, kept| {
                if next.account_id == kept.account_id {
                    kept.collections.union(&next.collections);
                    kept.is_writable |= next.is_writable;
                    true
                } else {
                    false
                }
            });
        }

        Ok(access_to.into_boxed_slice())
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
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            account.member_tenant_id.hash(&mut s);
            // SPDX-SnippetEnd
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
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            account.member_tenant_id.hash(&mut s);
            // SPDX-SnippetEnd
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/auth/access_token/tests.rs"]
mod tests;
