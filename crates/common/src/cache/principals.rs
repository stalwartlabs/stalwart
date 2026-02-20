/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{
        AccountCache, AccountInfo, AccountTenantIds, DOMAIN_FLAG_RELAY, DOMAIN_FLAG_SUB_ADDRESSING,
        DomainCache, EmailAddress, EmailAddressRef, EmailCache, MailingListCache, PermissionsGroup,
        RoleCache, TenantCache,
    },
    config::smtp::auth::DkimSigner,
    expr::if_block::BootstrapExprExt,
    network::{masked::MaskedAddress, mta::AddressResolver},
    storage::{ObjectQuota, TenantQuota},
};
use ahash::AHashSet;
use arcstr::ArcStr;
use registry::{
    schema::{
        enums::{Locale, StorageQuota, TenantStorageQuota},
        prelude::{Object, Property},
        structs::{
            Account, DkimSignature, Domain, MailingList, MaskedEmail, Permissions, PermissionsList,
            Role, SubAddressing, Tenant,
        },
    },
    types::{
        id::ObjectId,
        index::{IndexKey, IndexValue},
    },
};
use std::{borrow::Cow, sync::Arc};
use store::{
    registry::{RegistryQuery, bootstrap::Bootstrap},
    write::{RegistryClass, now},
};
use trc::AddContext;
use types::id::Id;

impl Server {
    pub async fn domain(&self, domain: &str) -> trc::Result<Option<Arc<DomainCache>>> {
        let domain_names = &self.inner.cache.domain_names;

        if let Some(domain_id) = domain_names.get(domain) {
            let result = self.domain_by_id(domain_id).await?;
            if result.is_none() {
                // Domain no longer exists, remove from name cache
                domain_names.remove(domain);
            }
            Ok(result)
        } else {
            let domain_names_negative = &self.inner.cache.domain_names_negative;
            if domain_names_negative.get(domain).is_none() {
                if let Some(domain_id) = self
                    .registry()
                    .query::<AHashSet<u64>>(
                        RegistryQuery::new(Object::Domain).equal(Property::Name, domain),
                    )
                    .await?
                    .into_iter()
                    .next()
                {
                    // Cache positive result
                    let domain_id = domain_id as u32;
                    let domain = self.domain_by_id(domain_id).await?;
                    if let Some(domain) = &domain {
                        for name in domain.names.iter() {
                            domain_names.insert(name.clone(), domain_id);
                        }
                    }

                    Ok(domain)
                } else {
                    // Cache negative result
                    domain_names_negative.insert(
                        domain.into(),
                        (),
                        self.inner.cache.negative_cache_ttl,
                    );
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }
    }

    pub async fn domain_by_id(&self, domain_id: u32) -> trc::Result<Option<Arc<DomainCache>>> {
        match self
            .inner
            .cache
            .domains
            .get_value_or_guard_async(&domain_id)
            .await
        {
            Ok(domain) => Ok(Some(domain)),
            Err(guard) => {
                let Some(domain) = self.registry().object::<Domain>(domain_id.into()).await? else {
                    return Ok(None);
                };
                let mut flags = 0;
                if domain.allow_relaying {
                    flags |= DOMAIN_FLAG_RELAY;
                }
                let sub_addressing_custom = match domain.sub_addressing {
                    SubAddressing::Enabled => {
                        flags |= DOMAIN_FLAG_SUB_ADDRESSING;
                        None
                    }
                    SubAddressing::Custom(custom) => {
                        flags |= DOMAIN_FLAG_SUB_ADDRESSING;
                        let mut bp = Bootstrap::new(self.registry().clone());
                        let custom = bp.compile_expr(
                            ObjectId::new(Object::Domain, domain_id.into()),
                            &custom.ctx_custom_rule(),
                        );
                        if bp.errors.is_empty() {
                            Some(Box::new(custom))
                        } else {
                            bp.log_errors();
                            None
                        }
                    }
                    SubAddressing::Disabled => None,
                };

                let cache = Arc::new(DomainCache {
                    names: [ArcStr::from(domain.name)]
                        .into_iter()
                        .chain(domain.aliases.into_iter().map(ArcStr::from))
                        .collect(),
                    id: domain_id,
                    id_directory: domain.directory_id.map(|id| id.document_id()),
                    id_tenant: domain.member_tenant_id.map(|id| id.document_id()),
                    catch_all: domain.catch_all_address.map(|s| s.into_boxed_str()),
                    sub_addressing_custom,
                    flags,
                });

                let _ = guard.insert(cache.clone());
                Ok(Some(cache))
            }
        }
    }

    pub async fn rcpt_id_from_parts(
        &self,
        local_part: &str,
        domain_id: u32,
    ) -> trc::Result<Option<EmailCache>> {
        let emails = &self.inner.cache.emails;

        if let Some(email) = emails.get(&EmailAddressRef::new(local_part, domain_id)) {
            Ok(Some(email))
        } else {
            let emails_negative = &self.inner.cache.emails_negative;
            if emails_negative
                .get(&EmailAddressRef::new(local_part, domain_id))
                .is_none()
            {
                let key = IndexKey::Global {
                    property: Property::Email,
                    value_1: IndexValue::Text(local_part.into()),
                    value_2: IndexValue::U64(domain_id.into()),
                };
                if let Some(object) = self
                    .registry()
                    .validate_primary_key(
                        RegistryClass::from_index_key(&key, 0, 0),
                        RegistryClass::from_index_key(&key, u16::MAX, u64::MAX),
                        None,
                    )
                    .await?
                {
                    let item_id = object.id().document_id();
                    let result = match object.object() {
                        Object::Account => EmailCache::Account(item_id),
                        Object::MailingList => EmailCache::MailingList(item_id),
                        _ => {
                            return Err(trc::AuthEvent::Error
                                .into_err()
                                .details(
                                    "Object with email property is not an account or mailing list.",
                                )
                                .ctx(trc::Key::Id, object.to_string())
                                .caused_by(trc::location!()));
                        }
                    };
                    emails.insert(EmailAddress::new(local_part, domain_id), result);

                    Ok(Some(result))
                } else {
                    // Cache negative result
                    emails_negative.insert(
                        EmailAddress::new(local_part, domain_id),
                        (),
                        self.inner.cache.negative_cache_ttl,
                    );
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }
    }

    pub async fn rcpt_id_from_email(&self, address: &str) -> trc::Result<Option<EmailCache>> {
        if let Some((local_part, domain)) = address.split_once('@') {
            if let Some(domain) = self.domain(domain).await? {
                self.rcpt_id_from_parts(local_part, domain.id).await
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub async fn account(&self, account_id: u32) -> trc::Result<Arc<AccountCache>> {
        self.try_account(account_id).await?.ok_or_else(|| {
            trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .ctx(trc::Key::AccountId, account_id)
                .caused_by(trc::location!())
        })
    }

    pub async fn try_account(&self, account_id: u32) -> trc::Result<Option<Arc<AccountCache>>> {
        match self
            .inner
            .cache
            .accounts
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(account) => Ok(Some(account)),
            Err(guard) => {
                let Some(account) = self.registry().object::<Account>(account_id.into()).await?
                else {
                    return Ok(None);
                };

                let cache = Arc::new(match account {
                    Account::User(account) => {
                        let domain = self
                            .domain_by_id(account.domain_id.document_id())
                            .await?
                            .ok_or_else(|| {
                                trc::AuthEvent::Error
                                    .into_err()
                                    .details("Domain not found for user account.")
                                    .ctx(trc::Key::AccountId, account_id)
                                    .ctx(trc::Key::Id, account.domain_id.document_id())
                                    .caused_by(trc::location!())
                            })?;
                        let mut name =
                            String::with_capacity(domain.names[0].len() + account.name.len() + 1);
                        name.push_str(account.name.as_ref());
                        name.push('@');
                        name.push_str(domain.names[0].as_ref());

                        let mut quota_objects: Option<ObjectQuota> = None;
                        let mut quota_disk = 0;
                        for (resource, limit) in account.quotas {
                            if resource == StorageQuota::MaxDiskQuota {
                                quota_disk = limit;
                            } else {
                                quota_objects
                                    .get_or_insert_with(|| self.core.email.max_objects.clone())
                                    .set(resource, limit as u32);
                            }
                        }

                        AccountCache {
                            id: account_id,
                            name: name.into_boxed_str(),
                            addresses: [EmailAddress {
                                local_part: account.name.into(),
                                domain_id: account.domain_id.document_id(),
                            }]
                            .into_iter()
                            .chain(account.aliases.into_iter().map(|alias| EmailAddress {
                                local_part: alias.name.into(),
                                domain_id: alias.domain_id.document_id(),
                            }))
                            .collect(),
                            id_tenant: account.member_tenant_id.map(|id| id.document_id()),
                            id_member_of: account
                                .member_group_ids
                                .into_iter()
                                .map(|id| id.document_id())
                                .collect(),
                            quota_disk,
                            quota_objects: quota_objects.map(Box::new),
                            description: account.description.map(Into::into),
                            locale: account.locale,
                            is_user: true,
                        }
                    }
                    Account::Group(account) => {
                        let domain = self
                            .domain_by_id(account.domain_id.document_id())
                            .await?
                            .ok_or_else(|| {
                                trc::AuthEvent::Error
                                    .into_err()
                                    .details("Domain not found for group account.")
                                    .ctx(trc::Key::AccountId, account_id)
                                    .ctx(trc::Key::Id, account.domain_id.document_id())
                                    .caused_by(trc::location!())
                            })?;
                        let mut name =
                            String::with_capacity(domain.names[0].len() + account.name.len() + 1);
                        name.push_str(account.name.as_ref());
                        name.push('@');
                        name.push_str(domain.names[0].as_ref());

                        let mut quota_objects: Option<ObjectQuota> = None;
                        let mut quota_disk = 0;
                        for (resource, limit) in account.quotas {
                            if resource == StorageQuota::MaxDiskQuota {
                                quota_disk = limit;
                            } else {
                                quota_objects
                                    .get_or_insert_with(|| self.core.email.max_objects.clone())
                                    .set(resource, limit as u32);
                            }
                        }

                        AccountCache {
                            id: account_id,
                            name: name.into_boxed_str(),
                            addresses: [EmailAddress {
                                local_part: account.name.into(),
                                domain_id: account.domain_id.document_id(),
                            }]
                            .into_iter()
                            .chain(account.aliases.into_iter().map(|alias| EmailAddress {
                                local_part: alias.name.into(),
                                domain_id: alias.domain_id.document_id(),
                            }))
                            .collect(),
                            id_tenant: account.member_tenant_id.map(|id| id.document_id()),
                            id_member_of: Default::default(),
                            quota_disk,
                            quota_objects: quota_objects.map(Box::new),
                            description: account.description.map(Into::into),
                            locale: account.locale,
                            is_user: false,
                        }
                    }
                });

                let _ = guard.insert(cache.clone());
                Ok(Some(cache))
            }
        }
    }

    pub async fn account_id_from_parts(
        &self,
        local_part: &str,
        domain_id: u32,
    ) -> trc::Result<Option<u32>> {
        self.rcpt_id_from_parts(local_part, domain_id)
            .await
            .map(|result| {
                if let Some(EmailCache::Account(account_id)) = result {
                    Some(account_id)
                } else {
                    None
                }
            })
    }

    pub async fn account_id_from_email(
        &self,
        address: &str,
        resolve: bool,
    ) -> trc::Result<Option<u32>> {
        if let Some((local_part, domain)) = address.split_once('@') {
            if let Some(domain) = self.domain(domain).await? {
                let mut local_part = Cow::Borrowed(local_part);
                if resolve {
                    if domain.flags & DOMAIN_FLAG_SUB_ADDRESSING != 0 {
                        if let Some(sub_addressing) = &domain.sub_addressing_custom {
                            // Custom sub-addressing resolution
                            if let Some(result) = self
                                .eval_if::<String, _>(
                                    sub_addressing,
                                    &AddressResolver(local_part.as_ref()),
                                    0,
                                )
                                .await
                            {
                                local_part = Cow::Owned(result);
                            }
                        } else if let Some((new_local_part, _)) = address.split_once('+') {
                            local_part = Cow::Borrowed(new_local_part);
                        }
                    }
                    if let Cow::Borrowed(addr) = &local_part
                        && let Some(masked_id) = MaskedAddress::parse(addr)
                        && let Some(masked_entry) = self
                            .registry()
                            .object::<MaskedEmail>(Id::new(masked_id))
                            .await
                            .caused_by(trc::location!())?
                        && masked_entry.enabled
                        && masked_entry
                            .expires_at
                            .is_none_or(|at| at.timestamp() > now() as i64)
                    {
                        return Ok(Some(masked_entry.account_id.document_id()));
                    }
                }

                let mut result = self
                    .rcpt_id_from_parts(local_part.as_ref(), domain.id)
                    .await?;
                if resolve
                    && result.is_none()
                    && let Some(catch_all) = &domain.catch_all
                {
                    result = self.rcpt_id_from_email(catch_all).await?;
                }

                Ok(result.and_then(|result| {
                    if let EmailCache::Account(account_id) = result {
                        Some(account_id)
                    } else {
                        None
                    }
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub async fn account_info(&self, id: u32) -> trc::Result<AccountInfo> {
        let account = self.account(id).await?;
        let mut addresses =
            Vec::with_capacity(account.id_member_of.len() + account.addresses.len());
        for address in account.addresses.iter() {
            if let Some(domain) = self.domain_by_id(address.domain_id).await? {
                for name in domain.names.iter() {
                    let mut addr = String::with_capacity(name.len() + address.local_part.len() + 1);
                    addr.push_str(address.local_part.as_ref());
                    addr.push('@');
                    addr.push_str(name.as_ref());
                    addresses.push(addr);
                }
            }
        }

        for &group_id in &account.id_member_of {
            if let Some(group) = self.try_account(group_id).await? {
                for address in group.addresses.iter() {
                    if let Some(domain) = self.domain_by_id(address.domain_id).await? {
                        for name in domain.names.iter() {
                            let mut addr =
                                String::with_capacity(name.len() + address.local_part.len() + 1);
                            addr.push_str(address.local_part.as_ref());
                            addr.push('@');
                            addr.push_str(name.as_ref());
                            addresses.push(addr);
                        }
                    }
                }
            }
        }

        Ok(AccountInfo {
            account_id: id,
            account,
            addresses,
        })
    }

    pub async fn role(&self, id: u32) -> trc::Result<Arc<RoleCache>> {
        let cache = &self.inner.cache.roles;
        match cache.get_value_or_guard_async(&id).await {
            Ok(role) => Ok(role),
            Err(guard) => {
                let Some(role) = self.registry().object::<Role>(id.into()).await? else {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .details("Role not found.")
                        .ctx(trc::Key::Id, id)
                        .caused_by(trc::location!()));
                };

                let cache = Arc::new(RoleCache {
                    id_roles: role
                        .role_ids
                        .into_iter()
                        .map(|id| id.document_id())
                        .collect(),
                    permissions: PermissionsGroup::from(PermissionsList {
                        permissions: role.permissions,
                    }),
                });

                let _ = guard.insert(cache.clone());
                Ok(cache)
            }
        }
    }

    pub async fn tenant(&self, id: u32) -> trc::Result<Arc<TenantCache>> {
        let cache = &self.inner.cache.tenants;
        match cache.get_value_or_guard_async(&id).await {
            Ok(tenant) => Ok(tenant),
            Err(guard) => {
                let Some(tenant) = self.registry().object::<Tenant>(id.into()).await? else {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .details("Tenant not found.")
                        .ctx(trc::Key::Id, id)
                        .caused_by(trc::location!()));
                };

                let mut quota_objects: Option<TenantQuota> = None;
                let mut quota_disk = 0;
                for (resource, limit) in tenant.quotas {
                    if resource == TenantStorageQuota::MaxDiskQuota {
                        quota_disk = limit;
                    } else {
                        quota_objects
                            .get_or_insert_default()
                            .set(resource, limit as u32);
                    }
                }

                // Calculate effective permissions
                let permissions = match tenant.permissions {
                    Permissions::Inherit => None,
                    Permissions::Merge(permissions) => Some(Box::new(
                        PermissionsGroup::from(permissions).with_merge(true),
                    )),
                    Permissions::Replace(permissions) => Some(Box::new(
                        PermissionsGroup::from(permissions).with_merge(false),
                    )),
                };

                let cache = Arc::new(TenantCache {
                    id_roles: tenant
                        .role_ids
                        .into_iter()
                        .map(|id| id.document_id())
                        .collect(),
                    quota_disk,
                    quota_objects: quota_objects.map(Box::new),
                    permissions,
                });

                let _ = guard.insert(cache.clone());
                Ok(cache)
            }
        }
    }

    pub async fn try_list(&self, id: u32) -> trc::Result<Option<Arc<MailingListCache>>> {
        let cache = &self.inner.cache.lists;
        match cache.get_value_or_guard_async(&id).await {
            Ok(list) => Ok(Some(list)),
            Err(guard) => {
                let Some(list) = self.registry().object::<MailingList>(id.into()).await? else {
                    return Ok(None);
                };
                let cache = Arc::new(MailingListCache {
                    recipients: list.recipients.into_iter().map(Into::into).collect(),
                });
                let _ = guard.insert(cache.clone());
                Ok(Some(cache))
            }
        }
    }

    pub async fn dkim_signers(&self, domain: &str) -> trc::Result<Option<Arc<[DkimSigner]>>> {
        let Some(domain) = self.domain(domain).await? else {
            return Ok(None);
        };
        let cache = &self.inner.cache.dkim_signers;
        match cache.get_value_or_guard_async(&domain.id).await {
            Ok(signers) => Ok(Some(signers)),
            Err(guard) => {
                let ids = self
                    .registry()
                    .query::<AHashSet<u64>>(
                        RegistryQuery::new(Object::DkimSignature)
                            .equal(Property::DomainId, domain.id),
                    )
                    .await?;
                let mut signatures = Vec::with_capacity(ids.len());
                for id in ids {
                    if let Some(signature) =
                        self.registry().object::<DkimSignature>(id.into()).await?
                    {
                        match DkimSigner::new(domain.names[0].to_string(), signature) {
                            Ok(signer) => signatures.push(signer),
                            Err(err) => {
                                trc::error!(err.ctx(trc::Key::Id, id).caused_by(trc::location!()));
                            }
                        }
                    }
                }

                if !signatures.is_empty() {
                    let signatures: Arc<[DkimSigner]> = signatures.into();
                    let _ = guard.insert(signatures.clone());
                    Ok(Some(signatures))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

impl AccountInfo {
    #[inline(always)]
    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    pub fn name(&self) -> &str {
        self.account.name.as_ref()
    }

    #[inline(always)]
    pub fn description(&self) -> Option<&str> {
        self.account.description.as_deref()
    }

    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.account.id_tenant
    }

    #[inline(always)]
    pub fn account_tenant_ids(&self) -> AccountTenantIds {
        AccountTenantIds {
            account_id: self.account_id,
            tenant_id: self.account.id_tenant,
        }
    }

    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    #[inline(always)]
    pub fn is_user_account(&self) -> bool {
        self.account.is_user
    }

    #[inline(always)]
    pub fn locale(&self) -> Locale {
        self.account.locale
    }

    #[inline(always)]
    pub fn object_quotas(&self) -> Option<&ObjectQuota> {
        self.account.quota_objects.as_deref()
    }
}

impl AccountCache {
    #[inline(always)]
    pub fn account_id(&self) -> u32 {
        self.id
    }

    #[inline(always)]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    #[inline(always)]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.id_tenant
    }

    #[inline(always)]
    pub fn is_user_account(&self) -> bool {
        self.is_user
    }

    #[inline(always)]
    pub fn disk_quota(&self) -> u64 {
        self.quota_disk
    }

    #[inline(always)]
    pub fn object_quotas(&self) -> Option<&ObjectQuota> {
        self.quota_objects.as_deref()
    }

    #[inline(always)]
    pub fn account_tenant_ids(&self) -> AccountTenantIds {
        AccountTenantIds {
            account_id: self.id,
            tenant_id: self.id_tenant,
        }
    }
}
