/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AccessToken, ResourceToken, TenantInfo, roles::RolePermissions};
use crate::{
    Server,
    ipc::BroadcastEvent,
    listener::limiter::{ConcurrencyLimiter, LimiterResult},
};
use ahash::AHashSet;
use directory::{
    Permission, Principal, PrincipalData, QueryParams, Type,
    backend::internal::{
        lookup::DirectoryStore,
        manage::{ChangedPrincipals, ManageDirectory},
    },
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};
use store::{query::acl::AclQuery, rand};
use trc::AddContext;
use types::{acl::Acl, collection::Collection};
use utils::map::{
    bitmap::{Bitmap, BitmapItem},
    vec_map::VecMap,
};

pub enum PrincipalOrId {
    Principal(Principal),
    Id(u32),
}

impl Server {
    async fn build_access_token_from_principal(
        &self,
        principal: Principal,
        revision: u64,
    ) -> trc::Result<AccessToken> {
        let mut role_permissions = RolePermissions::default();

        // Extract data
        let mut object_quota = self.core.jmap.max_objects;
        let mut description = None;
        let mut tenant_id = None;
        let mut quota = None;
        let mut locale = None;
        let mut member_of = Vec::new();
        let mut emails = Vec::new();
        for data in principal.data {
            match data {
                PrincipalData::Tenant(v) => tenant_id = Some(v),
                PrincipalData::MemberOf(v) => member_of.push(v),
                PrincipalData::Role(v) => {
                    role_permissions.union(self.get_role_permissions(v).await?.as_ref());
                }
                PrincipalData::Permission {
                    permission_id,
                    grant,
                } => {
                    if grant {
                        role_permissions.enabled.set(permission_id as usize);
                    } else {
                        role_permissions.disabled.set(permission_id as usize);
                    }
                }
                PrincipalData::DiskQuota(v) => quota = Some(v),
                PrincipalData::ObjectQuota { quota, typ } => {
                    object_quota[typ as usize] = quota;
                }
                PrincipalData::Description(v) => description = Some(v),
                PrincipalData::PrimaryEmail(v) => {
                    if emails.is_empty() {
                        emails.push(v);
                    } else {
                        emails.insert(0, v);
                    }
                }
                PrincipalData::EmailAlias(v) => {
                    emails.push(v);
                }
                PrincipalData::Locale(v) => locale = Some(v),
                _ => (),
            }
        }

        // Apply principal permissions
        let mut permissions = role_permissions.finalize();
        let mut tenant = None;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        {
            use directory::{QueryParams, ROLE_USER};

            if let Some(tenant_id) = tenant_id {
                if self.is_enterprise_edition() {
                    // Limit tenant permissions
                    permissions.intersection(&self.get_role_permissions(tenant_id).await?.enabled);

                    // Obtain tenant quota
                    tenant = Some(TenantInfo {
                        id: tenant_id,
                        quota: self
                            .store()
                            .query(QueryParams::id(tenant_id).with_return_member_of(false))
                            .await
                            .caused_by(trc::location!())?
                            .ok_or_else(|| {
                                trc::SecurityEvent::Unauthorized
                                    .into_err()
                                    .details("Tenant not found")
                                    .id(tenant_id)
                                    .caused_by(trc::location!())
                            })?
                            .quota()
                            .unwrap_or_default(),
                    });
                } else {
                    // Enterprise edition downgrade, remove any tenant administrator permissions
                    permissions.intersection(&self.get_role_permissions(ROLE_USER).await?.enabled);
                }
            }
        }

        // SPDX-SnippetEnd

        // Build member of and e-mail addresses
        for &group_id in &member_of {
            if let Some(group) = self
                .store()
                .query(QueryParams::id(group_id).with_return_member_of(false))
                .await
                .caused_by(trc::location!())?
                && group.typ == Type::Group
            {
                emails.extend(group.into_email_addresses());
            }
        }

        // Build access token
        let mut access_token = AccessToken {
            primary_id: principal.id,
            member_of,
            access_to: VecMap::new(),
            tenant,
            name: principal.name,
            description,
            emails,
            quota: quota.unwrap_or_default(),
            locale,
            permissions,
            object_quota,
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
        };

        for grant_account_id in [access_token.primary_id]
            .into_iter()
            .chain(access_token.member_of.iter().copied())
        {
            for acl_item in self
                .store()
                .acl_query(AclQuery::HasAccess { grant_account_id })
                .await
                .caused_by(trc::location!())?
            {
                if !access_token.is_member(acl_item.to_account_id) {
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
                        access_token
                            .access_to
                            .get_mut_or_insert_with(acl_item.to_account_id, Bitmap::new)
                            .union(&collections);
                    }
                }
            }
        }

        Ok(access_token.update_size())
    }

    async fn build_access_token(&self, account_id: u32, revision: u64) -> trc::Result<AccessToken> {
        let err = match self
            .directory()
            .query(QueryParams::id(account_id).with_return_member_of(true))
            .await
        {
            Ok(Some(principal)) => {
                return self
                    .build_access_token_from_principal(principal, revision)
                    .await;
            }
            Ok(None) => Err(trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .caused_by(trc::location!())),
            Err(err) => Err(err),
        };

        match &self.core.jmap.fallback_admin {
            Some((_, secret)) if account_id == u32::MAX => {
                self.build_access_token_from_principal(Principal::fallback_admin(secret), revision)
                    .await
            }
            _ => err,
        }
    }

    pub async fn get_access_token(
        &self,
        principal: impl Into<PrincipalOrId>,
    ) -> trc::Result<Arc<AccessToken>> {
        let principal = principal.into();

        // Obtain current revision
        let principal_id = principal.id();

        match self
            .inner
            .cache
            .access_tokens
            .get_value_or_guard_async(&principal_id)
            .await
        {
            Ok(token) => Ok(token),
            Err(guard) => {
                let revision = rand::random::<u64>();
                let token: Arc<AccessToken> = match principal {
                    PrincipalOrId::Principal(principal) => {
                        self.build_access_token_from_principal(principal, revision)
                            .await?
                    }
                    PrincipalOrId::Id(account_id) => {
                        self.build_access_token(account_id, revision).await?
                    }
                }
                .into();
                let _ = guard.insert(token.clone());
                Ok(token)
            }
        }
    }

    pub async fn invalidate_principal_caches(&self, changed_principals: ChangedPrincipals) {
        let mut nested_principals = Vec::new();
        let mut changed_ids = AHashSet::new();
        let mut changed_names = Vec::new();

        for (id, changed_principal) in changed_principals.iter() {
            changed_ids.insert(*id);

            if changed_principal.name_change {
                self.inner.cache.files.remove(id);
                self.inner.cache.contacts.remove(id);
                self.inner.cache.events.remove(id);
                self.inner.cache.scheduling.remove(id);
                changed_names.push(*id);
            }

            if changed_principal.member_change {
                if changed_principal.typ == Type::Tenant {
                    match self
                        .store()
                        .list_principals(
                            None,
                            (*id).into(),
                            &[Type::Individual, Type::Group, Type::Role, Type::ApiKey],
                            false,
                            0,
                            0,
                        )
                        .await
                    {
                        Ok(principals) => {
                            for principal in principals.items {
                                changed_ids.insert(principal.id());
                            }
                        }
                        Err(err) => {
                            trc::error!(
                                err.details("Failed to list principals")
                                    .caused_by(trc::location!())
                                    .account_id(*id)
                            );
                        }
                    }
                } else {
                    nested_principals.push(*id);
                }
            }
        }

        if !nested_principals.is_empty() {
            let mut ids = nested_principals.into_iter();
            let mut ids_stack = vec![];

            loop {
                if let Some(id) = ids.next() {
                    // Skip if already fetched
                    if !changed_ids.insert(id) {
                        continue;
                    }

                    // Obtain principal
                    match self.store().get_members(id).await {
                        Ok(members) => {
                            ids_stack.push(ids);
                            ids = members.into_iter();
                        }
                        Err(err) => {
                            trc::error!(
                                err.details("Failed to obtain principal")
                                    .caused_by(trc::location!())
                                    .account_id(id)
                            );
                        }
                    }
                } else if let Some(prev_ids) = ids_stack.pop() {
                    ids = prev_ids;
                } else {
                    break;
                }
            }
        }

        // Invalidate access tokens in cluster
        if !changed_ids.is_empty() {
            let mut ids = Vec::with_capacity(changed_ids.len());
            for id in changed_ids {
                self.inner.cache.permissions.remove(&id);
                self.inner.cache.access_tokens.remove(&id);
                ids.push(id);
            }
            self.cluster_broadcast(BroadcastEvent::InvalidateAccessTokens(ids))
                .await;
        }

        // Invalidate DAV caches
        if !changed_names.is_empty() {
            self.cluster_broadcast(BroadcastEvent::InvalidateGroupwareCache(changed_names))
                .await;
        }
    }
}

impl From<u32> for PrincipalOrId {
    fn from(id: u32) -> Self {
        Self::Id(id)
    }
}

impl From<Principal> for PrincipalOrId {
    fn from(principal: Principal) -> Self {
        Self::Principal(principal)
    }
}

impl PrincipalOrId {
    pub fn id(&self) -> u32 {
        match self {
            Self::Principal(principal) => principal.id(),
            Self::Id(id) => *id,
        }
    }
}

impl AccessToken {
    pub fn from_id(primary_id: u32) -> Self {
        Self {
            primary_id,
            ..Default::default()
        }
    }

    pub fn with_access_to(self, access_to: VecMap<u32, Bitmap<Collection>>) -> Self {
        Self { access_to, ..self }
    }

    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.set(permission.id() as usize);
        self
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant = tenant_id.map(|id| TenantInfo { id, quota: 0 });
        self
    }

    pub fn state(&self) -> u32 {
        // Hash state
        let mut s = DefaultHasher::new();
        self.member_of.hash(&mut s);
        self.access_to.hash(&mut s);
        s.finish() as u32
    }

    #[inline(always)]
    pub fn primary_id(&self) -> u32 {
        self.primary_id
    }

    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.tenant.as_ref().map(|t| t.id)
    }

    pub fn secondary_ids(&self) -> impl Iterator<Item = &u32> {
        self.member_of
            .iter()
            .chain(self.access_to.iter().map(|(id, _)| id))
    }

    pub fn member_ids(&self) -> impl Iterator<Item = u32> {
        [self.primary_id]
            .into_iter()
            .chain(self.member_of.iter().copied())
    }

    pub fn all_ids(&self) -> impl Iterator<Item = u32> {
        [self.primary_id]
            .into_iter()
            .chain(self.member_of.iter().copied())
            .chain(self.access_to.iter().map(|(id, _)| *id))
    }

    pub fn all_ids_by_collection(&self, collection: Collection) -> impl Iterator<Item = u32> {
        [self.primary_id]
            .into_iter()
            .chain(self.member_of.iter().copied())
            .chain(self.access_to.iter().filter_map(move |(id, cols)| {
                if cols.contains(collection) {
                    Some(*id)
                } else {
                    None
                }
            }))
    }

    pub fn is_member(&self, account_id: u32) -> bool {
        self.primary_id == account_id
            || self.member_of.contains(&account_id)
            || self.has_permission(Permission::Impersonate)
    }

    pub fn is_primary_id(&self, account_id: u32) -> bool {
        self.primary_id == account_id
    }

    #[inline(always)]
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.get(permission.id() as usize)
    }

    pub fn assert_has_permission(&self, permission: Permission) -> trc::Result<bool> {
        if self.has_permission(permission) {
            Ok(true)
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .details(permission.name()))
        }
    }

    pub fn permissions(&self) -> Vec<Permission> {
        const USIZE_BITS: usize = std::mem::size_of::<usize>() * 8;
        const USIZE_MASK: u32 = USIZE_BITS as u32 - 1;
        let mut permissions = Vec::new();

        for (block_num, bytes) in self.permissions.inner().iter().enumerate() {
            let mut bytes = *bytes;

            while bytes != 0 {
                let item = USIZE_MASK - bytes.leading_zeros();
                bytes ^= 1 << item;
                if let Some(permission) =
                    Permission::from_id(((block_num * USIZE_BITS) + item as usize) as u32)
                {
                    permissions.push(permission);
                }
            }
        }
        permissions
    }

    #[inline(always)]
    pub fn object_quota(&self, collection: Collection) -> u32 {
        self.object_quota[collection as usize]
    }

    pub fn is_shared(&self, account_id: u32) -> bool {
        !self.is_member(account_id) && self.access_to.iter().any(|(id, _)| *id == account_id)
    }

    pub fn shared_accounts(&self, collection: Collection) -> impl Iterator<Item = &u32> {
        self.member_of
            .iter()
            .chain(self.access_to.iter().filter_map(move |(id, cols)| {
                if cols.contains(collection) {
                    id.into()
                } else {
                    None
                }
            }))
    }

    pub fn has_access(&self, to_account_id: u32, to_collection: impl Into<Collection>) -> bool {
        let to_collection = to_collection.into();
        self.is_member(to_account_id)
            || self.access_to.iter().any(|(id, collections)| {
                *id == to_account_id && collections.contains(to_collection)
            })
    }

    pub fn has_account_access(&self, to_account_id: u32) -> bool {
        self.is_member(to_account_id) || self.access_to.iter().any(|(id, _)| *id == to_account_id)
    }

    pub fn as_resource_token(&self) -> ResourceToken {
        ResourceToken {
            account_id: self.primary_id,
            quota: self.quota,
            tenant: self.tenant,
        }
    }

    pub fn is_http_request_allowed(&self) -> LimiterResult {
        self.concurrent_http_requests
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn is_imap_request_allowed(&self) -> LimiterResult {
        self.concurrent_imap_requests
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn is_upload_allowed(&self) -> LimiterResult {
        self.concurrent_uploads
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn update_size(mut self) -> Self {
        self.obj_size = (std::mem::size_of::<AccessToken>()
            + (self.member_of.len() * std::mem::size_of::<u32>())
            + (self.access_to.len() * (std::mem::size_of::<u32>() + std::mem::size_of::<u64>()))
            + self.name.len()
            + self.description.as_ref().map_or(0, |v| v.len())
            + self.locale.as_ref().map_or(0, |v| v.len())
            + self.emails.iter().map(|v| v.len()).sum::<usize>()) as u64;
        self
    }
}
