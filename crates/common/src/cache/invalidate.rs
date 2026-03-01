/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::EmailCache,
    ipc::{BroadcastEvent, CacheInvalidation},
};
use ahash::AHashSet;
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs::Account,
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
                let credentials_changed = current.credentials != new.credentials
                    || current.secret != new.secret
                    || current.otp_auth != new.otp_auth;

                if was_renamed
                    || aliases_changed
                    || tenant_changed
                    || groups_changed
                    || quota_changed
                    || details_changed
                {
                    self.invalidate(CacheInvalidation::Account(id));
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

            (ObjectInner::DkimSignature(_), ObjectInner::DkimSignature(_)) => {
                self.invalidate(CacheInvalidation::DkimSignature(id));
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

            (ObjectInner::Role(current), ObjectInner::Role(new)) => {
                if (current.permissions != new.permissions)
                    || (current.member_tenant_id != new.member_tenant_id)
                    || (current.role_ids != new.role_ids)
                {
                    self.invalidate(CacheInvalidation::Role(id));
                }
            }

            (ObjectInner::MailingList(current), ObjectInner::MailingList(new)) => {
                if (current.aliases != new.aliases)
                    || (current.name != new.name)
                    || (current.recipients != new.recipients)
                    || (current.domain_id != new.domain_id)
                {
                    self.invalidate(CacheInvalidation::List(id));
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
            ObjectInner::DkimSignature(_) => {
                self.invalidate(CacheInvalidation::DkimSignature(id));
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

    pub fn invalidate(&mut self, change: CacheInvalidation) {
        self.changes.insert(change);
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
        self.cluster_broadcast(BroadcastEvent::CacheInvalidation(changes))
            .await;
        Ok(())
    }

    pub async fn invalidate_local_caches(&self, changes: &[CacheInvalidation]) {
        let cache = &self.inner.cache;

        for change in changes {
            match change {
                CacheInvalidation::AccessToken(id) => {
                    cache.access_tokens.remove(id);
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
                    cache.emails.inner().retain(
                        |_, v| !matches!(v, EmailCache::Account(account_id) if account_id == id),
                    );
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
                    cache.emails.inner().retain(
                        |_, v| !matches!(v, EmailCache::MailingList(list_id) if list_id == id),
                    );
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
            }
        }
    }
}

impl From<CacheInvalidation> for CacheInvalidationBuilder {
    fn from(invalidation: CacheInvalidation) -> Self {
        let mut builder = CacheInvalidationBuilder::default();
        builder.invalidate(invalidation);
        builder
    }
}
