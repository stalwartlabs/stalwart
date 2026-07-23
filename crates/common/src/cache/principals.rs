/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{
        ACCOUNT_FLAG_ENCRYPT_ALGO_AES128, ACCOUNT_FLAG_ENCRYPT_ALGO_AES256,
        ACCOUNT_FLAG_ENCRYPT_ALGO_AES256_GCM, ACCOUNT_FLAG_ENCRYPT_ALGO_CHACHA20_POLY1305,
        ACCOUNT_FLAG_ENCRYPT_APPEND, ACCOUNT_FLAG_ENCRYPT_METHOD_PGP,
        ACCOUNT_FLAG_ENCRYPT_METHOD_SMIME, ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER, ACCOUNT_IS_USER,
        AccountCache, AccountInfo, AccountTenantIds, DOMAIN_FLAG_RELAY, DOMAIN_FLAG_SUB_ADDRESSING,
        DomainCache, EmailAddress, EmailAddressRef, EmailCache, MailingListCache, PermissionsGroup,
        RECOVERY_ADMIN_ID, RoleCache, TenantCache, permissions::BuildPermissions,
    },
    config::smtp::auth::DkimSigners,
    expr::if_block::BootstrapExprExt,
    network::mta::AddressResolver,
    storage::{
        ObjectQuota, TenantQuota,
        encryption::{EncryptionMethod, parse_public_key},
    },
};
use registry::{
    schema::{
        enums::{DkimRotationStage, Locale, StorageQuota, TenantStorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            Account, DkimSignature, Domain, EncryptionAtRest, MailingList, MaskedEmail,
            Permissions, PublicKey, Role, SubAddressing, Tenant,
        },
    },
    types::id::ObjectId,
};
use std::{borrow::Cow, sync::Arc};
use store::{
    U64_LEN,
    registry::{RegistryQuery, bootstrap::Bootstrap},
    write::{key::KeySerializer, now},
};
use trc::{AddContext, StoreEvent};
use types::id::Id;
use utils::DomainPart;

impl Server {
    pub async fn domain(&self, domain: &str) -> trc::Result<Option<Arc<DomainCache>>> {
        let Some(domain) = domain.to_ascii_domain() else {
            return Ok(None);
        };
        let domain = domain.as_ref();
        let domain_names = &self.inner.cache.domain_names;

        if let Some(domain_id) = domain_names.get(domain) {
            trc::event!(
                Store(StoreEvent::CacheHit),
                Key = domain.to_string(),
                Collection = "domainName",
            );

            let result = self.domain_by_id(domain_id).await?;
            if result.is_none() {
                // Domain no longer exists, remove from name cache
                domain_names.remove(domain);
            }
            Ok(result)
        } else {
            let domain_names_negative = &self.inner.cache.domain_names_negative;
            if domain_names_negative.get(domain).is_none() {
                if let Some(domain) = self
                    .registry()
                    .primary_key(
                        ObjectType::Domain.into(),
                        Property::Name,
                        domain.as_bytes().to_vec(),
                    )
                    .await
                    .caused_by(trc::location!())?
                {
                    // Cache positive result
                    let domain_id = domain.id().document_id();
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

                    trc::event!(
                        Store(StoreEvent::CacheMiss),
                        Key = domain.to_string(),
                        Collection = "domainName",
                    );

                    Ok(None)
                }
            } else {
                trc::event!(
                    Store(StoreEvent::CacheHit),
                    Key = domain.to_string(),
                    Collection = "domainNameNegative",
                );

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
            Ok(domain) => {
                trc::event!(
                    Store(StoreEvent::CacheHit),
                    Key = domain_id,
                    Collection = "domainId",
                );

                Ok(Some(domain))
            }
            Err(guard) => {
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = domain_id,
                    Collection = "domainId",
                );
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
                        let mut bp = Bootstrap::new_uninitialized(self.registry().clone());
                        let custom = bp.compile_expr(
                            ObjectId::new(ObjectType::Domain, domain_id.into()),
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
                    names: [domain.name.into_boxed_str()]
                        .into_iter()
                        .chain(
                            domain
                                .aliases
                                .into_iter()
                                .map(|alias| alias.into_boxed_str()),
                        )
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
            trc::event!(
                Store(StoreEvent::CacheHit),
                Key = local_part.to_string(),
                Domain = domain_id,
                Collection = "email",
            );

            Ok(Some(email))
        } else {
            let emails_negative = &self.inner.cache.emails_negative;
            if emails_negative
                .get(&EmailAddressRef::new(local_part, domain_id))
                .is_none()
            {
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = local_part.to_string(),
                    Domain = domain_id,
                    Collection = "email",
                );

                if let Some(object) = self
                    .registry()
                    .primary_key(
                        None,
                        Property::Email,
                        KeySerializer::new(local_part.len() + U64_LEN)
                            .write(local_part.as_bytes())
                            .write(domain_id as u64)
                            .finalize(),
                    )
                    .await
                    .caused_by(trc::location!())?
                {
                    let item_id = object.id().document_id();
                    let result = match object.object() {
                        ObjectType::Account => {
                            if self
                                .account(item_id)
                                .await
                                .caused_by(trc::location!())?
                                .addresses
                                .iter()
                                .any(|address| {
                                    address.domain_id == domain_id
                                        && address.local_part.as_ref() == local_part
                                })
                            {
                                EmailCache::Account(item_id)
                            } else {
                                EmailCache::DisabledAccountAddress(item_id)
                            }
                        }
                        ObjectType::MailingList => {
                            if let Some(list) = self.try_list(item_id).await?
                                && !list.addresses.iter().any(|address| {
                                    address.domain_id == domain_id
                                        && address.local_part.as_ref() == local_part
                                })
                            {
                                EmailCache::DisabledListAddress(item_id)
                            } else {
                                EmailCache::MailingList(item_id)
                            }
                        }
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
                trc::event!(
                    Store(StoreEvent::CacheHit),
                    Key = local_part.to_string(),
                    Domain = domain_id,
                    Collection = "emailNegative",
                );
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
        if let Some(account) = self.try_account(account_id).await? {
            Ok(account)
        } else if account_id == RECOVERY_ADMIN_ID {
            Ok(Arc::new(AccountCache {
                name: self
                    .registry()
                    .recovery_admin()
                    .map(|(name, _)| name.as_str())
                    .unwrap_or("recovery-admin")
                    .into(),
                id: RECOVERY_ADMIN_ID,
                addresses: Default::default(),
                id_tenant: Default::default(),
                id_member_of: Default::default(),
                quota_disk: Default::default(),
                quota_objects: Default::default(),
                description: Some("Recovery admin account".into()),
                encryption_key: Default::default(),
                locale: Default::default(),
                flags: Default::default(),
            }))
        } else {
            Err(trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .ctx(trc::Key::AccountId, account_id)
                .caused_by(trc::location!()))
        }
    }

    pub async fn try_account(&self, account_id: u32) -> trc::Result<Option<Arc<AccountCache>>> {
        match self
            .inner
            .cache
            .accounts
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(account) => {
                trc::event!(
                    Store(StoreEvent::CacheHit),
                    Key = account_id,
                    Collection = "account",
                );

                Ok(Some(account))
            }
            Err(guard) => {
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = account_id,
                    Collection = "account",
                );

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

                        let mut flags = ACCOUNT_IS_USER;
                        let encryption_settings = match account.encryption_at_rest {
                            EncryptionAtRest::Disabled => None,
                            EncryptionAtRest::Aes256(settings) => {
                                flags |= ACCOUNT_FLAG_ENCRYPT_ALGO_AES256;
                                settings.into()
                            }
                            EncryptionAtRest::Aes128(settings) => {
                                flags |= ACCOUNT_FLAG_ENCRYPT_ALGO_AES128;
                                settings.into()
                            }
                            EncryptionAtRest::Aes256Gcm(settings) => {
                                flags |= ACCOUNT_FLAG_ENCRYPT_ALGO_AES256_GCM;
                                settings.into()
                            }
                            EncryptionAtRest::ChaCha20Poly1305(settings) => {
                                flags |= ACCOUNT_FLAG_ENCRYPT_ALGO_CHACHA20_POLY1305;
                                settings.into()
                            }
                        };
                        let encryption_key = if let Some(settings) = encryption_settings {
                            if settings.allow_spam_training {
                                flags |= ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER;
                            }
                            if settings.encrypt_on_append {
                                flags |= ACCOUNT_FLAG_ENCRYPT_APPEND;
                            }
                            if let Some(public_key) = self
                                .registry()
                                .object::<PublicKey>(settings.public_key)
                                .await
                                .caused_by(trc::location!())?
                            {
                                parse_public_key(&public_key)
                                    .unwrap_or_default()
                                    .map(|params| {
                                        match params.method {
                                            EncryptionMethod::PGP => {
                                                flags |= ACCOUNT_FLAG_ENCRYPT_METHOD_PGP
                                            }
                                            EncryptionMethod::SMIME => {
                                                flags |= ACCOUNT_FLAG_ENCRYPT_METHOD_SMIME
                                            }
                                        }
                                        params.certs
                                    })
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        AccountCache {
                            id: account_id,
                            name: name.into_boxed_str(),
                            addresses: [EmailAddress {
                                local_part: account.name.into(),
                                domain_id: account.domain_id.document_id(),
                            }]
                            .into_iter()
                            .chain(
                                account
                                    .aliases
                                    .into_iter()
                                    .filter(|alias| alias.enabled)
                                    .map(|alias| EmailAddress {
                                        local_part: alias.name.into(),
                                        domain_id: alias.domain_id.document_id(),
                                    }),
                            )
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
                            encryption_key,
                            flags,
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
                            .chain(
                                account
                                    .aliases
                                    .into_iter()
                                    .filter(|alias| alias.enabled)
                                    .map(|alias| EmailAddress {
                                        local_part: alias.name.into(),
                                        domain_id: alias.domain_id.document_id(),
                                    }),
                            )
                            .collect(),
                            id_tenant: account.member_tenant_id.map(|id| id.document_id()),
                            id_member_of: Default::default(),
                            quota_disk,
                            quota_objects: quota_objects.map(Box::new),
                            description: account.description.map(Into::into),
                            encryption_key: None,
                            locale: account.locale,
                            flags: 0,
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
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL

                    #[cfg(feature = "enterprise")]
                    if self.is_enterprise_edition()
                        && let Cow::Borrowed(addr) = &local_part
                        && let Some(masked_id) =
                            crate::enterprise::masked::MaskedAddress::parse(addr)
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
                    // SPDX-SnippetEnd
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
        self.build_account_info(account).await
    }

    pub async fn scheduling_account_info(
        &self,
        authenticated_account_id: u32,
        owner_account_id: u32,
    ) -> trc::Result<AccountInfo> {
        let account = self.account(authenticated_account_id).await?;
        let mut account_info = self.build_account_info(account).await?;

        if owner_account_id != authenticated_account_id {
            let owner_account = self.account(owner_account_id).await?;
            let owner_account_info = self.build_account_info(owner_account).await?;

            for address in owner_account_info.addresses {
                if !account_info.addresses.contains(&address) {
                    account_info.addresses.push(address);
                }
            }
        }

        Ok(account_info)
    }

    pub async fn build_account_info(&self, account: Arc<AccountCache>) -> trc::Result<AccountInfo> {
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
            account_id: account.id,
            account,
            addresses,
        })
    }

    pub async fn role(&self, id: u32) -> trc::Result<Arc<RoleCache>> {
        let cache = &self.inner.cache.roles;
        match cache.get_value_or_guard_async(&id).await {
            Ok(role) => {
                trc::event!(Store(StoreEvent::CacheHit), Key = id, Collection = "role");

                Ok(role)
            }
            Err(guard) => {
                trc::event!(Store(StoreEvent::CacheMiss), Key = id, Collection = "role");

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
                    permissions: PermissionsGroup {
                        enabled: crate::auth::Permissions::from_permission(
                            role.enabled_permissions.as_slice(),
                        ),
                        disabled: crate::auth::Permissions::from_permission(
                            role.disabled_permissions.as_slice(),
                        ),
                        merge: false,
                    },
                });

                let _ = guard.insert(cache.clone());
                Ok(cache)
            }
        }
    }

    pub async fn tenant(&self, id: u32) -> trc::Result<Arc<TenantCache>> {
        let cache = &self.inner.cache.tenants;
        match cache.get_value_or_guard_async(&id).await {
            Ok(tenant) => {
                trc::event!(Store(StoreEvent::CacheHit), Key = id, Collection = "tenant");

                Ok(tenant)
            }
            Err(guard) => {
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = id,
                    Collection = "tenant"
                );

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
                        .roles
                        .role_ids()
                        .unwrap_or(
                            self.core
                                .network
                                .security
                                .default_role_ids_tenant
                                .as_slice(),
                        )
                        .iter()
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
            Ok(list) => {
                trc::event!(Store(StoreEvent::CacheHit), Key = id, Collection = "list");

                Ok(Some(list))
            }
            Err(guard) => {
                trc::event!(Store(StoreEvent::CacheMiss), Key = id, Collection = "list");

                let Some(list) = self.registry().object::<MailingList>(id.into()).await? else {
                    return Ok(None);
                };
                let cache =
                    Arc::new(MailingListCache {
                        addresses: [EmailAddress {
                            local_part: list.name.into(),
                            domain_id: list.domain_id.document_id(),
                        }]
                        .into_iter()
                        .chain(list.aliases.into_iter().filter(|alias| alias.enabled).map(
                            |alias| EmailAddress {
                                local_part: alias.name.into(),
                                domain_id: alias.domain_id.document_id(),
                            },
                        ))
                        .collect(),
                        recipients: list.recipients.into_iter().map(Into::into).collect(),
                    });
                let _ = guard.insert(cache.clone());
                Ok(Some(cache))
            }
        }
    }

    pub async fn dkim_signers(&self, domain: &str) -> trc::Result<Option<Arc<DkimSigners>>> {
        let Some(domain) = self.domain(domain).await? else {
            return Ok(None);
        };
        let cache = &self.inner.cache.dkim_signers;
        match cache.get_value_or_guard_async(&domain.id).await {
            Ok(signers) => {
                trc::event!(
                    Store(StoreEvent::CacheHit),
                    Key = domain.id,
                    Collection = "dkimSigners",
                );

                Ok(Some(signers))
            }
            Err(guard) => {
                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    Key = domain.id,
                    Collection = "dkimSigners",
                );

                let ids = self
                    .registry()
                    .query::<Vec<Id>>(
                        RegistryQuery::new(ObjectType::DkimSignature)
                            .equal(Property::DomainId, domain.id),
                    )
                    .await?;
                let domain_name = &domain.names[0];
                let mut signers = DkimSigners {
                    dkim1: Vec::with_capacity(ids.len()),
                    dkim2: None,
                };
                for id in ids {
                    if let Some(signature) = self.registry().object::<DkimSignature>(id).await?
                        && matches!(signature.stage(), DkimRotationStage::Active)
                        && let Err(err) = signers.insert(domain_name.to_string(), signature).await
                    {
                        trc::error!(err.ctx(trc::Key::Id, id.id()).caused_by(trc::location!()));
                    }
                }

                if !signers.dkim1.is_empty() || signers.dkim2.is_some() {
                    let signers = Arc::new(signers);
                    let _ = guard.insert(signers.clone());
                    Ok(Some(signers))
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
        self.account.flags & ACCOUNT_IS_USER != 0
    }

    #[inline(always)]
    pub fn locale(&self) -> Locale {
        self.account.locale
    }

    #[inline(always)]
    pub fn object_quotas(&self) -> Option<&ObjectQuota> {
        self.account.quota_objects.as_deref()
    }

    #[inline(always)]
    pub fn account(&self) -> &AccountCache {
        &self.account
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
        self.flags & ACCOUNT_IS_USER != 0
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
