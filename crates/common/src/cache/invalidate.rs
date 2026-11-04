/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Inner, Server,
    auth::{EmailAddressRef, EmailCache},
    gateway::resolver::KeyCacheKey,
    ipc::{BroadcastEvent, CacheInvalidation, PushNotification},
};
use ahash::AHashSet;
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::{Account, Credential, EmailAlias},
    },
    types::{id::ObjectId, list::List},
};
use store::{registry::RegistryQuery, roaring::RoaringBitmap, write::AssignedIds};
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

const _: () = assert!(SyncCollection::MAX_CHANGE_GROUP < u32::BITS as u8);

impl Inner {
    pub fn mark_cache_stale(&self, account_id: u32, collection: SyncCollection) {
        let caches = &self.cache;
        match collection {
            SyncCollection::Email | SyncCollection::Thread => {
                if let Some(cache) = caches.peek_messages(account_id) {
                    cache.update_lock.mark_stale();
                }
            }
            _ => {
                if let Some(cache) = caches.peek_resources(account_id, collection) {
                    cache.update_lock.mark_stale();
                }
            }
        }
    }

    pub fn mark_caches_stale_from(&self, assigned_ids: &AssignedIds) {
        for counter in assigned_ids.change_counters() {
            self.mark_cache_stale(counter.account_id, counter.group.to_u8().into());
        }
    }

    pub fn mark_caches_stale(&self, account_id: u32, types: Bitmap<DataType>) {
        let mut marked_groups = 0u32;
        for data_type in types {
            if let Ok(collection) = Collection::try_from(data_type) {
                let group = collection.change_group().to_u8();
                let group_bit = 1u32 << group;
                if marked_groups & group_bit == 0 {
                    marked_groups |= group_bit;
                    self.mark_cache_stale(account_id, group.into());
                }
            }
        }
    }

    pub fn mark_caches_stale_for(&self, notification: &PushNotification) {
        match notification {
            PushNotification::StateChange(state_change) => {
                self.mark_caches_stale(state_change.account_id, state_change.types);
            }
            PushNotification::EmailPush(email_push) => {
                self.mark_cache_stale(email_push.account_id, SyncCollection::Email);
            }
            PushNotification::ViewerStateChange(_) | PushNotification::CalendarAlert(_) => {}
        }
    }
}

#[derive(Debug, Default)]
pub struct CacheInvalidationBuilder {
    changes: AHashSet<CacheInvalidation>,
    revoke_oauth_grants: Vec<u32>,
}

impl CacheInvalidationBuilder {
    pub fn process_update(&mut self, id: Id, current_object: &Object, new_object: &Object) {
        let id = id.document_id();
        match (&current_object.inner, &new_object.inner) {
            (ObjectInner::Account(current), ObjectInner::Account(new))
                if let (Account::User(current), Account::User(new)) =
                    (current.as_ref(), new.as_ref()) =>
            {
                let was_renamed =
                    (current.name != new.name) || (current.domain_id != new.domain_id);
                let quota_changed = current.quotas != new.quotas;
                let permissions_changed = current.permissions != new.permissions;
                let roles_changed = current.roles != new.roles;
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let tenant_changed = current.member_tenant_id != new.member_tenant_id;
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let tenant_changed = false;
                let details_changed =
                    current.locale != new.locale || current.description != new.description;
                let groups_changed = current.member_group_ids != new.member_group_ids;
                let aliases_changed = current.aliases != new.aliases;
                let credentials_changed = current.credentials != new.credentials;
                if credentials_changed {
                    self.process_credentials_update(id, &current.credentials, &new.credentials);
                }
                let encryption_changed = current.encryption_at_rest != new.encryption_at_rest;

                if was_renamed
                    || aliases_changed
                    || tenant_changed
                    || groups_changed
                    || quota_changed
                    || details_changed
                    || encryption_changed
                {
                    self.invalidate(CacheInvalidation::Account(id));
                }

                if was_renamed || aliases_changed {
                    self.invalidate_negative_email(&new_object.inner);
                }

                if tenant_changed
                    || groups_changed
                    || credentials_changed
                    || roles_changed
                    || permissions_changed
                {
                    self.invalidate(CacheInvalidation::AccessToken(id));
                }

                if was_renamed {
                    self.invalidate(CacheInvalidation::GroupwareResources(id));
                }
            }

            (ObjectInner::Account(current), ObjectInner::Account(new))
                if let (Account::Group(current), Account::Group(new)) =
                    (current.as_ref(), new.as_ref()) =>
            {
                let was_renamed =
                    (current.name != new.name) || (current.domain_id != new.domain_id);
                let quota_changed = current.quotas != new.quotas;
                let permissions_changed = current.permissions != new.permissions;
                let roles_changed = current.roles != new.roles;
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let tenant_changed = current.member_tenant_id != new.member_tenant_id;
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let tenant_changed = false;
                let details_changed =
                    current.locale != new.locale || current.description != new.description;
                let aliases_changed = current.aliases != new.aliases;

                if was_renamed
                    || aliases_changed
                    || tenant_changed
                    || quota_changed
                    || details_changed
                {
                    self.invalidate(CacheInvalidation::Account(id));
                }

                if was_renamed || aliases_changed {
                    self.invalidate_negative_email(&new_object.inner);
                }

                if tenant_changed || roles_changed || permissions_changed {
                    self.invalidate(CacheInvalidation::AccessToken(id));
                }

                if was_renamed {
                    self.invalidate(CacheInvalidation::GroupwareResources(id));
                }
            }

            (ObjectInner::Domain(current), ObjectInner::Domain(new)) => {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let enterprise_changed = (current.directory_id != new.directory_id)
                    || (current.member_tenant_id != new.member_tenant_id);
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let enterprise_changed = false;

                if (current.name != new.name)
                    || (current.aliases != new.aliases)
                    || enterprise_changed
                    || (current.catch_all_address != new.catch_all_address)
                    || (current.sub_addressing != new.sub_addressing)
                    || (current.allow_relaying != new.allow_relaying)
                    || (current.enable != new.enable)
                {
                    self.invalidate(CacheInvalidation::Domain(id));
                }

                if (current.name != new.name) || (current.aliases != new.aliases) {
                    self.invalidate(CacheInvalidation::DomainNegative);
                }

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                if current.logo != new.logo {
                    self.invalidate(CacheInvalidation::DomainLogo(id));
                }
                // SPDX-SnippetEnd
            }

            (ObjectInner::DkimSignature(current), ObjectInner::DkimSignature(new)) => {
                let current_domain_id = current.domain_id().document_id();
                let new_domain_id = new.domain_id().document_id();
                self.invalidate(CacheInvalidation::DkimSignature(current_domain_id));
                if current_domain_id != new_domain_id {
                    self.invalidate(CacheInvalidation::DkimSignature(new_domain_id));
                }
            }

            (ObjectInner::PublicKey(current), ObjectInner::PublicKey(new))
                if current.key != new.key
                    || current.strict_key_wrap_encoding != new.strict_key_wrap_encoding
                    || current.authenticated_encryption != new.authenticated_encryption =>
            {
                self.invalidate(CacheInvalidation::Account(new.account_id.document_id()));
            }

            (ObjectInner::ExternalPublicKey(current), ObjectInner::ExternalPublicKey(new)) => {
                self.invalidate(CacheInvalidation::ExternalPublicKey(
                    KeyCacheKey::address_hash(&current.email_address),
                ));
                self.invalidate(CacheInvalidation::ExternalPublicKey(
                    KeyCacheKey::address_hash(&new.email_address),
                ));
            }

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            (ObjectInner::Tenant(current), ObjectInner::Tenant(new)) => {
                if (current.permissions != new.permissions)
                    || (current.roles != new.roles)
                    || (current.quotas != new.quotas)
                {
                    self.invalidate(CacheInvalidation::Tenant(id));
                }

                if current.logo != new.logo {
                    self.invalidate(CacheInvalidation::TenantLogo(id));
                }
            }
            // SPDX-SnippetEnd
            (ObjectInner::Role(current), ObjectInner::Role(new))
                if (current.enabled_permissions != new.enabled_permissions)
                    || (current.disabled_permissions != new.disabled_permissions)
                    || (current.role_ids != new.role_ids) =>
            {
                self.invalidate(CacheInvalidation::Role(id));
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            (ObjectInner::Role(current), ObjectInner::Role(new))
                if current.member_tenant_id != new.member_tenant_id =>
            {
                self.invalidate(CacheInvalidation::Role(id));
            }
            // SPDX-SnippetEnd
            (ObjectInner::MailingList(current), ObjectInner::MailingList(new))
                if (current.aliases != new.aliases)
                    || (current.name != new.name)
                    || (current.recipients != new.recipients)
                    || (current.domain_id != new.domain_id) =>
            {
                self.invalidate(CacheInvalidation::List(id));
                if (current.aliases != new.aliases)
                    || (current.name != new.name)
                    || (current.domain_id != new.domain_id)
                {
                    self.invalidate_negative_email(&new_object.inner);
                }
            }
            _ => {}
        }
    }

    pub fn process_delete(&mut self, id: Id, object: &Object) {
        let grant_id = id.id();
        let id = id.document_id();
        match &object.inner {
            ObjectInner::ExternalPublicKey(key) => {
                self.invalidate(CacheInvalidation::ExternalPublicKey(
                    KeyCacheKey::address_hash(&key.email_address),
                ));
            }
            ObjectInner::OAuthGrant(grant) => {
                self.invalidate(CacheInvalidation::OAuthGrant {
                    account_id: grant.account_id.document_id(),
                    grant_id,
                });
            }
            ObjectInner::Account(_) => {
                self.invalidate(CacheInvalidation::AccessToken(id));
                self.invalidate(CacheInvalidation::Account(id));
                self.invalidate(CacheInvalidation::GroupwareResources(id));
                self.invalidate(CacheInvalidation::MessageCache(id));
            }
            ObjectInner::Domain(_) => {
                self.invalidate(CacheInvalidation::Domain(id));
                self.invalidate(CacheInvalidation::DomainLogo(id));
            }
            ObjectInner::DkimSignature(object) => {
                self.invalidate(CacheInvalidation::DkimSignature(
                    object.domain_id().document_id(),
                ));
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(_) => {
                self.invalidate(CacheInvalidation::Tenant(id));
                self.invalidate(CacheInvalidation::TenantLogo(id));
            }
            // SPDX-SnippetEnd
            ObjectInner::Role(_) => {
                self.invalidate(CacheInvalidation::Role(id));
            }
            ObjectInner::MailingList(_) => {
                self.invalidate(CacheInvalidation::List(id));
            }
            _ => {}
        }
    }

    pub fn process_create(&mut self, object: &Object) {
        match &object.inner {
            ObjectInner::ExternalPublicKey(key) => {
                self.invalidate(CacheInvalidation::ExternalPublicKey(
                    KeyCacheKey::address_hash(&key.email_address),
                ));
            }
            ObjectInner::Domain(_) => {
                self.invalidate(CacheInvalidation::DomainNegative);
            }
            ObjectInner::DkimSignature(object) => {
                self.invalidate(CacheInvalidation::DkimSignature(
                    object.domain_id().document_id(),
                ));
            }
            _ => {}
        }
        self.invalidate_negative_email(&object.inner);
    }

    fn invalidate_negative_email(&mut self, object: &ObjectInner) {
        let (name, domain_id, aliases) = match object {
            ObjectInner::Account(account) => match account.as_ref() {
                Account::User(account) => (&account.name, account.domain_id, &account.aliases),
                Account::Group(account) => (&account.name, account.domain_id, &account.aliases),
            },
            ObjectInner::MailingList(list) => (&list.name, list.domain_id, &list.aliases),
            _ => return,
        };

        self.invalidate(CacheInvalidation::EmailNegative {
            domain_id: domain_id.document_id(),
            local_part_hash: hash_local_part(name),
        });
        for alias in aliases.iter().filter(|alias: &&EmailAlias| alias.enable) {
            self.invalidate(CacheInvalidation::EmailNegative {
                domain_id: alias.domain_id.document_id(),
                local_part_hash: hash_local_part(&alias.name),
            });
        }
    }

    pub fn invalidate(&mut self, change: CacheInvalidation) {
        self.changes.insert(change);
    }

    pub fn process_credentials_update(
        &mut self,
        account_id: u32,
        current: &List<Credential>,
        new: &List<Credential>,
    ) {
        if password_secret(current) != password_secret(new)
            && !self.revoke_oauth_grants.contains(&account_id)
        {
            self.revoke_oauth_grants.push(account_id);
        }
    }

    pub fn with_invalidation(mut self, change: CacheInvalidation) -> Self {
        self.invalidate(change);
        self
    }
}

impl Server {
    pub async fn invalidate_grantee(
        &self,
        changes: &mut CacheInvalidationBuilder,
        grantee_id: u32,
    ) {
        changes.invalidate(CacheInvalidation::AccessToken(grantee_id));
        let result = match self.try_account(grantee_id).await {
            Ok(Some(grantee)) if !grantee.is_user_account() => self
                .registry()
                .query::<RoaringBitmap>(
                    RegistryQuery::new(ObjectType::Account)
                        .equal(Property::MemberGroupIds, u64::from(grantee_id)),
                )
                .await
                .map(|members| {
                    for member_id in members {
                        changes.invalidate(CacheInvalidation::AccessToken(member_id));
                    }
                }),
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        };
        if let Err(err) = result {
            trc::error!(
                err.account_id(grantee_id)
                    .details("Failed to invalidate group member access tokens")
                    .caused_by(trc::location!())
            );
        }
    }

    pub async fn invalidate_caches(
        &self,
        mut changes: CacheInvalidationBuilder,
    ) -> trc::Result<()> {
        for account_id in std::mem::take(&mut changes.revoke_oauth_grants) {
            if let Err(err) = self.revoke_oauth_grants(account_id, &mut changes).await {
                trc::error!(
                    err.account_id(account_id)
                        .details("Failed to revoke OAuth grants after a password change")
                        .caused_by(trc::location!())
                );
            }
        }

        let mut changes = changes.changes;
        if changes.is_empty() {
            return Ok(());
        }

        // Invalidate objects linking roles
        let mut role_ids = changes
            .iter()
            .filter_map(|change| {
                if let CacheInvalidation::Role(role_id) = change {
                    Some(*role_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if !role_ids.is_empty() {
            let mut fetched_role_ids = AHashSet::new();

            while let Some(role_id) = role_ids.pop() {
                if fetched_role_ids.insert(role_id) {
                    let linked_objects = self
                        .registry()
                        .linked_objects(ObjectId::new(ObjectType::Role, role_id.into()))
                        .await?;
                    for linked_object in linked_objects {
                        match linked_object.object() {
                            ObjectType::Account => {
                                changes.insert(CacheInvalidation::AccessToken(
                                    linked_object.id().document_id(),
                                ));
                            }
                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            ObjectType::Tenant => {
                                // Invalidate all accounts of the tenant
                                let tenant_id = linked_object.id().document_id();
                                changes.insert(CacheInvalidation::Tenant(tenant_id));
                                for account_id in self
                                    .registry()
                                    .query::<RoaringBitmap>(
                                        RegistryQuery::new(ObjectType::Account)
                                            .with_tenant(tenant_id.into()),
                                    )
                                    .await?
                                {
                                    changes.insert(CacheInvalidation::AccessToken(account_id));
                                }
                            }
                            // SPDX-SnippetEnd
                            ObjectType::Role => {
                                let parent_id = linked_object.id().document_id();
                                if self.core.network.security.is_default_role(parent_id) {
                                    changes.insert(CacheInvalidation::Role(parent_id));
                                }
                                role_ids.push(parent_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let changes = changes.into_iter().collect::<Vec<_>>();
        self.invalidate_local_caches(&changes);
        self.cluster_broadcast(BroadcastEvent::CacheInvalidate(changes))
            .await;
        Ok(())
    }

    pub fn invalidate_all_local_caches(&self) {
        self.invalidate_all_local_negative_caches();
        self.inner.cache.access_tokens.clear();
        self.inner
            .cache
            .grant_revocations
            .clear(&self.inner.cache.http_auth);
        self.inner.cache.domains.clear();
        self.inner.cache.domain_names.clear();
        self.inner.cache.emails.clear();
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        self.inner.cache.tenants.clear();
        // SPDX-SnippetEnd
        self.inner.cache.clear_resources();
        self.inner.cache.metadata_viewers.clear();
        self.inner.cache.dkim_signers.clear();
        self.inner.cache.accounts.clear();
        self.inner.cache.roles.clear();
        self.inner.cache.lists.clear();
        self.inner.cache.directory_recipients.clear();
        self.inner.data.logos.lock().clear();
    }

    pub fn invalidate_all_local_negative_caches(&self) {
        self.inner.cache.domain_names_negative.clear();
        self.inner.cache.emails_negative.clear();
        self.inner.cache.directory_recipients.clear();
    }

    pub fn invalidate_local_negative_account_cache(
        &self,
        local_part: &str,
        domain_id: u32,
    ) -> bool {
        self.inner
            .cache
            .emails_negative
            .remove(&EmailAddressRef::new(local_part, domain_id))
            .is_some()
    }

    pub fn invalidate_local_caches(&self, changes: &[CacheInvalidation]) {
        let cache = &self.inner.cache;
        let mut negative_emails: AHashSet<(u32, u32)> = AHashSet::new();
        let mut http_auth_accounts = IdFilter::default();
        let mut revoked_grants: Vec<u64> = Vec::new();
        let mut domain_names = IdFilter::default();
        let mut email_accounts = IdFilter::default();
        let mut email_lists = IdFilter::default();
        let mut domain_logos = IdFilter::default();
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let mut tenant_logos = IdFilter::default();
        // SPDX-SnippetEnd
        let mut default_role_changed = false;

        for change in changes {
            match change {
                CacheInvalidation::AccessToken(id) => {
                    cache.access_tokens.remove(id);
                    http_auth_accounts.insert(*id);
                }
                CacheInvalidation::GroupwareResources(id) => {
                    cache.remove_resources(*id);
                    let inner = self.inner.clone();
                    let account_id = *id;
                    tokio::spawn(async move {
                        inner.cache.swap.remove_resources(account_id).await;
                    });
                }
                CacheInvalidation::MessageCache(id) => {
                    cache.remove_messages(*id);
                    cache.swap.forget(*id);
                }
                CacheInvalidation::Domain(id) => {
                    cache.domains.remove(id);
                    cache.dkim_signers.remove(id);
                    domain_names.insert(*id);
                }
                CacheInvalidation::Account(id) => {
                    cache.accounts.remove(id);
                    email_accounts.insert(*id);
                }
                CacheInvalidation::DkimSignature(id) => {
                    cache.dkim_signers.remove(id);
                }
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                CacheInvalidation::Tenant(id) => {
                    cache.tenants.remove(id);
                }
                // SPDX-SnippetEnd
                CacheInvalidation::Role(id) => {
                    cache.roles.remove(id);
                    default_role_changed |= self.core.network.security.is_default_role(*id);
                }
                CacheInvalidation::List(id) => {
                    cache.lists.remove(id);
                    email_lists.insert(*id);
                }
                CacheInvalidation::DomainLogo(id) => {
                    domain_logos.insert(*id);
                }
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                CacheInvalidation::TenantLogo(id) => {
                    tenant_logos.insert(*id);
                }
                // SPDX-SnippetEnd
                CacheInvalidation::EmailNegative {
                    domain_id,
                    local_part_hash,
                } => {
                    negative_emails.insert((*domain_id, *local_part_hash));
                }
                CacheInvalidation::DomainNegative => {
                    cache.domain_names_negative.clear();
                }
                CacheInvalidation::ExternalPublicKey(address_hash) => {
                    cache
                        .external_public_keys
                        .retain(|key| KeyCacheKey::address_hash(&key.address) != *address_hash);
                }
                CacheInvalidation::PrivateMetadata(id) => {
                    cache.metadata_viewers.invalidate(*id);
                }
                CacheInvalidation::OAuthGrant { grant_id, .. } => {
                    revoked_grants.push(*grant_id);
                }
                CacheInvalidation::ActiveSieveScript(id) => {
                    if let Some(account) = cache.accounts.peek(id) {
                        account.active_script.invalidate();
                    }
                }
            }
        }

        for filter in [
            &mut http_auth_accounts,
            &mut domain_names,
            &mut email_accounts,
            &mut email_lists,
            &mut domain_logos,
        ] {
            filter.seal();
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        tenant_logos.seal();
        // SPDX-SnippetEnd

        if default_role_changed {
            cache.access_tokens.clear();
            cache.http_auth.retain(|_| false);
        } else {
            match http_auth_accounts.0.as_slice() {
                [] => {}
                &[account_id] => {
                    cache.http_auth.retain(move |v| v.account_id != account_id);
                }
                _ => {
                    cache
                        .http_auth
                        .retain(|v| !http_auth_accounts.contains(v.account_id));
                }
            }
        }

        if !revoked_grants.is_empty() {
            cache
                .grant_revocations
                .evict(&cache.http_auth, &revoked_grants);
        }

        if !domain_names.is_empty() {
            cache
                .domain_names
                .inner()
                .retain(|_, v| !domain_names.contains(*v));
        }

        if !email_accounts.is_empty() || !email_lists.is_empty() {
            cache.emails.inner().retain(|_, v| match v {
                EmailCache::Account(id) | EmailCache::DisabledAccountAddress(id) => {
                    !email_accounts.contains(*id)
                }
                EmailCache::MailingList(id) | EmailCache::DisabledListAddress(id) => {
                    !email_lists.contains(*id)
                }
            });
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if !domain_logos.is_empty() || !tenant_logos.is_empty() {
            self.inner.data.logos.lock().retain(|_, v| {
                !domain_logos.contains(v.domain_id)
                    && v.tenant_id.is_none_or(|id| !tenant_logos.contains(id))
            });
        }
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        if !domain_logos.is_empty() {
            self.inner
                .data
                .logos
                .lock()
                .retain(|_, v| !domain_logos.contains(v.domain_id));
        }

        if !negative_emails.is_empty() {
            cache.emails_negative.retain(|key| {
                !negative_emails.contains(&(key.domain_id, hash_local_part(&key.local_part)))
            });
        }

        trc::event!(Cache(trc::CacheEvent::Invalidate), Total = changes.len());
    }
}

#[derive(Default)]
struct IdFilter(Vec<u32>);

impl IdFilter {
    const LINEAR_SCAN_MAX: usize = 16;

    fn insert(&mut self, id: u32) {
        self.0.push(id);
    }

    fn seal(&mut self) {
        if self.0.len() > Self::LINEAR_SCAN_MAX {
            self.0.sort_unstable();
            self.0.dedup();
        }
    }

    fn contains(&self, id: u32) -> bool {
        match self.0.as_slice() {
            [single] => *single == id,
            ids if ids.len() <= Self::LINEAR_SCAN_MAX => ids.contains(&id),
            ids => ids.binary_search(&id).is_ok(),
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl CacheInvalidation {
    pub fn is_covered_by_invalidate_all(&self) -> bool {
        !matches!(
            self,
            CacheInvalidation::MessageCache(_) | CacheInvalidation::GroupwareResources(_)
        )
    }
}

#[inline(always)]
fn hash_local_part(local_part: &str) -> u32 {
    xxhash_rust::xxh3::xxh3_64(local_part.as_bytes()) as u32
}

impl From<CacheInvalidation> for CacheInvalidationBuilder {
    fn from(invalidation: CacheInvalidation) -> Self {
        let mut builder = CacheInvalidationBuilder::default();
        builder.invalidate(invalidation);
        builder
    }
}

fn password_secret(credentials: &List<Credential>) -> Option<&str> {
    credentials.iter().find_map(|credential| match credential {
        Credential::Password(password) => Some(password.secret.as_str()),
        _ => None,
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/cache/invalidate/tests.rs"]
mod tests;
