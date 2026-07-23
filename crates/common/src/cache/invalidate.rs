/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{EmailAddressRef, EmailCache},
    ipc::{BroadcastEvent, CacheInvalidation},
};
use ahash::AHashSet;
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs::{Account, EmailAlias},
    },
    types::id::ObjectId,
};
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use types::id::Id;

#[derive(Debug, Default)]
pub struct CacheInvalidationBuilder {
    changes: AHashSet<CacheInvalidation>,
}

impl CacheInvalidationBuilder {
    pub fn process_update(&mut self, id: Id, current_object: &Object, new_object: &Object) {
        let id = id.document_id();
        match (&current_object.inner, &new_object.inner) {
            (
                ObjectInner::Account(Account::User(current)),
                ObjectInner::Account(Account::User(new)),
            ) => {
                let was_renamed =
                    (current.name != new.name) || (current.domain_id != new.domain_id);
                let quota_changed = current.quotas != new.quotas;
                let permissions_changed = current.permissions != new.permissions;
                let roles_changed = current.roles != new.roles;
                let tenant_changed = current.member_tenant_id != new.member_tenant_id;
                let details_changed =
                    current.locale != new.locale || current.description != new.description;
                let groups_changed = current.member_group_ids != new.member_group_ids;
                let aliases_changed = current.aliases != new.aliases;
                let credentials_changed = current.credentials != new.credentials;
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
                    self.invalidate(CacheInvalidation::DavResources(id));
                }
            }

            (
                ObjectInner::Account(Account::Group(current)),
                ObjectInner::Account(Account::Group(new)),
            ) => {
                let was_renamed =
                    (current.name != new.name) || (current.domain_id != new.domain_id);
                let quota_changed = current.quotas != new.quotas;
                let permissions_changed = current.permissions != new.permissions;
                let roles_changed = current.roles != new.roles;
                let tenant_changed = current.member_tenant_id != new.member_tenant_id;
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
                    self.invalidate(CacheInvalidation::DavResources(id));
                }
            }

            (ObjectInner::Domain(current), ObjectInner::Domain(new)) => {
                if (current.name != new.name)
                    || (current.directory_id != new.directory_id)
                    || (current.member_tenant_id != new.member_tenant_id)
                    || (current.catch_all_address != new.catch_all_address)
                    || (current.sub_addressing != new.sub_addressing)
                    || (current.allow_relaying != new.allow_relaying)
                    || (current.is_enabled != new.is_enabled)
                {
                    self.invalidate(CacheInvalidation::Domain(id));
                }

                if current.logo != new.logo {
                    self.invalidate(CacheInvalidation::DomainLogo(id));
                }
            }

            (ObjectInner::DkimSignature(current), ObjectInner::DkimSignature(new)) => {
                let current_domain_id = current.domain_id().document_id();
                let new_domain_id = new.domain_id().document_id();
                self.invalidate(CacheInvalidation::DkimSignature(current_domain_id));
                if current_domain_id != new_domain_id {
                    self.invalidate(CacheInvalidation::DkimSignature(new_domain_id));
                }
            }

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

            (ObjectInner::Role(current), ObjectInner::Role(new))
                if (current.enabled_permissions != new.enabled_permissions)
                    || (current.disabled_permissions != new.disabled_permissions)
                    || (current.member_tenant_id != new.member_tenant_id)
                    || (current.role_ids != new.role_ids) =>
            {
                self.invalidate(CacheInvalidation::Role(id));
            }

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
        let id = id.document_id();
        match &object.inner {
            ObjectInner::Account(_) => {
                self.invalidate(CacheInvalidation::AccessToken(id));
                self.invalidate(CacheInvalidation::Account(id));
                self.invalidate(CacheInvalidation::DavResources(id));
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
            ObjectInner::Tenant(_) => {
                self.invalidate(CacheInvalidation::Tenant(id));
                self.invalidate(CacheInvalidation::TenantLogo(id));
            }
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
        self.invalidate_negative_email(&object.inner);
    }

    fn invalidate_negative_email(&mut self, object: &ObjectInner) {
        let (name, domain_id, aliases) = match object {
            ObjectInner::Account(Account::User(account)) => {
                (&account.name, account.domain_id, &account.aliases)
            }
            ObjectInner::Account(Account::Group(account)) => {
                (&account.name, account.domain_id, &account.aliases)
            }
            ObjectInner::MailingList(list) => (&list.name, list.domain_id, &list.aliases),
            _ => return,
        };

        self.invalidate(CacheInvalidation::EmailNegative {
            domain_id: domain_id.document_id(),
            local_part_hash: hash_local_part(name),
        });
        for alias in aliases.iter().filter(|alias: &&EmailAlias| alias.enabled) {
            self.invalidate(CacheInvalidation::EmailNegative {
                domain_id: alias.domain_id.document_id(),
                local_part_hash: hash_local_part(&alias.name),
            });
        }
    }

    pub fn invalidate(&mut self, change: CacheInvalidation) {
        self.changes.insert(change);
    }

    pub fn with_invalidation(mut self, change: CacheInvalidation) -> Self {
        self.invalidate(change);
        self
    }
}

impl Server {
    pub async fn invalidate_caches(&self, changes: CacheInvalidationBuilder) -> trc::Result<()> {
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
                                role_ids.push(linked_object.id().document_id());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let changes = changes.into_iter().collect::<Vec<_>>();
        self.invalidate_local_caches(&changes).await;
        self.cluster_broadcast(BroadcastEvent::CacheInvalidate(changes))
            .await;
        Ok(())
    }

    pub fn invalidate_all_local_caches(&self) {
        self.invalidate_all_local_negative_caches();
        self.inner.cache.access_tokens.clear();
        self.inner.cache.domains.clear();
        self.inner.cache.domain_names.clear();
        self.inner.cache.emails.clear();
        self.inner.cache.tenants.clear();
        self.inner.cache.files.clear();
        self.inner.cache.contacts.clear();
        self.inner.cache.events.clear();
        self.inner.cache.scheduling.clear();
        self.inner.cache.dkim_signers.clear();
        self.inner.cache.accounts.clear();
        self.inner.cache.roles.clear();
        self.inner.cache.lists.clear();
        self.inner.data.logos.lock().clear();
    }

    pub fn invalidate_all_local_negative_caches(&self) {
        self.inner.cache.domain_names_negative.clear();
        self.inner.cache.emails_negative.clear();
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

    pub async fn invalidate_local_caches(&self, changes: &[CacheInvalidation]) {
        let cache = &self.inner.cache;
        let mut negative_emails: AHashSet<(u32, u32)> = AHashSet::new();

        for change in changes {
            match change {
                CacheInvalidation::AccessToken(id) => {
                    cache.access_tokens.remove(id);
                    cache.http_auth.inner().retain(|_, v| v.account_id != *id);
                }
                CacheInvalidation::DavResources(id) => {
                    cache.files.remove(id);
                    cache.contacts.remove(id);
                    cache.events.remove(id);
                    cache.scheduling.remove(id);
                }
                CacheInvalidation::Domain(id) => {
                    cache.domains.remove(id);
                    cache.dkim_signers.remove(id);
                    cache.domain_names.inner().retain(|_, v| v != id);
                }
                CacheInvalidation::Account(id) => {
                    cache.accounts.remove(id);
                    cache.emails.inner().retain(|_, v| {
                        !matches!(
                            v,
                            EmailCache::Account(account_id)
                                | EmailCache::DisabledAccountAddress(account_id)
                            if account_id == id
                        )
                    });
                }
                CacheInvalidation::DkimSignature(id) => {
                    cache.dkim_signers.remove(id);
                }
                CacheInvalidation::Tenant(id) => {
                    cache.tenants.remove(id);
                }
                CacheInvalidation::Role(id) => {
                    cache.roles.remove(id);
                }
                CacheInvalidation::List(id) => {
                    cache.lists.remove(id);
                    cache.emails.inner().retain(|_, v| {
                        !matches!(
                            v,
                            EmailCache::MailingList(list_id)
                                | EmailCache::DisabledListAddress(list_id)
                            if list_id == id
                        )
                    });
                }
                CacheInvalidation::DomainLogo(id) => {
                    self.inner
                        .data
                        .logos
                        .lock()
                        .retain(|_, v| v.domain_id != *id);
                }
                CacheInvalidation::TenantLogo(id) => {
                    self.inner
                        .data
                        .logos
                        .lock()
                        .retain(|_, v| v.tenant_id != Some(*id));
                }
                CacheInvalidation::EmailNegative {
                    domain_id,
                    local_part_hash,
                } => {
                    negative_emails.insert((*domain_id, *local_part_hash));
                }
            }
        }

        if !negative_emails.is_empty() {
            cache.emails_negative.retain(|key| {
                !negative_emails.contains(&(key.domain_id, hash_local_part(&key.local_part)))
            });
        }
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
