/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::error::{IntoScimError, IntoScimResourceError, Result};
use common::cache::invalidate::CacheInvalidationBuilder;
use common::{
    Server,
    auth::{AccessToken, DomainCache, Permissions},
};
use registry::{
    schema::{
        enums::Permission,
        prelude::{Object, ObjectType},
        structs::{Account, GroupAccount, UserAccount, UserRoles},
    },
    types::id::ObjectId,
};
use scim_proto::{BASE_PATH, ResourceType, message::error::Error};
use std::{fmt::Write, sync::Arc};
use store::registry::write::{RegistryWrite, RegistryWriteResult};
use trc::AddContext;
use types::id::Id;
use utils::sanitize_email_local;

pub struct ScimContext<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub session_id: u64,
}

impl ScimContext<'_> {
    pub fn base_url(&self) -> &str {
        &self.server.core.network.http.url_https
    }

    pub fn location(&self, resource_type: ResourceType, id: Id) -> String {
        let base_url = self.base_url();
        let endpoint = resource_type.endpoint();
        let mut location =
            String::with_capacity(base_url.len() + BASE_PATH.len() + endpoint.len() + 16);
        location.push_str(base_url);
        location.push_str(BASE_PATH);
        location.push_str(endpoint);
        location.push('/');
        let _ = write!(&mut location, "{id}");
        location
    }

    pub fn endpoint_location(&self, path: &str) -> String {
        let base_url = self.base_url();
        let mut location = String::with_capacity(base_url.len() + BASE_PATH.len() + path.len());
        location.push_str(base_url);
        location.push_str(BASE_PATH);
        location.push_str(path);
        location
    }

    pub fn tenant_id(&self) -> Option<u32> {
        self.access_token.tenant_id()
    }

    pub async fn domain_by_id(&self, domain_id: Id) -> Result<Arc<DomainCache>> {
        self.server
            .domain_by_id(domain_id.document_id())
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::EventType::Resource(trc::ResourceEvent::NotFound)
                    .into_err()
                    .caused_by(trc::location!())
                    .details("The domain of this resource no longer exists")
                    .ctx(trc::Key::Id, domain_id.document_id())
                    .into()
            })
    }

    pub async fn email_address(&self, name: &str, domain_id: Id) -> Result<String> {
        let domain = self.domain_by_id(domain_id).await?;
        let domain = domain.name();
        let mut address = String::with_capacity(name.len() + domain.len() + 1);
        address.push_str(name);
        address.push('@');
        address.push_str(domain);
        Ok(address)
    }

    pub async fn resolve_address(
        &self,
        address: &str,
        attribute: &str,
    ) -> Result<(String, Arc<DomainCache>)> {
        let Some((local_part, domain_name)) = address.rsplit_once('@') else {
            return Err(Error::invalid_value(format!(
                "The '{attribute}' value '{address}' is not a valid email address."
            ))
            .into());
        };

        let local_part = sanitize_email_local(local_part).ok_or_else(|| {
            Error::invalid_value(format!(
                "The '{attribute}' value '{address}' is not a valid email address."
            ))
        })?;

        let domain = self
            .server
            .domain(domain_name)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                Error::invalid_value(format!(
                    "The domain '{domain_name}' does not exist on this server."
                ))
            })?;

        if self
            .tenant_id()
            .is_some_and(|tenant_id| domain.id_tenant != Some(tenant_id))
        {
            return Err(Error::not_found()
                .with_detail(format!(
                    "The domain '{domain_name}' does not exist on this server."
                ))
                .into());
        }

        if !domain.allows_scim_provisioning() {
            return Err(Error::invalid_value(format!(
                "SCIM provisioning is not enabled for the domain '{domain_name}'."
            ))
            .into());
        }

        Ok((local_part, domain))
    }

    pub async fn account(&self, id: Id) -> Result<Object> {
        self.try_account(id)
            .await?
            .ok_or_else(|| Error::not_found().into())
    }

    pub async fn try_account(&self, id: Id) -> Result<Option<Object>> {
        let Some(object) = self
            .server
            .registry()
            .get(ObjectId::new(ObjectType::Account, id))
            .await
            .caused_by(trc::location!())?
            .filter(|object| self.is_visible(object))
        else {
            return Ok(None);
        };

        match account_domain_id(&object) {
            Some(domain_id) if self.is_provisionable(domain_id).await? => Ok(Some(object)),
            _ => Ok(None),
        }
    }

    pub fn is_visible(&self, object: &Object) -> bool {
        self.tenant_id()
            .is_none_or(|tenant_id| object.inner.member_tenant_id() == Some(Id::from(tenant_id)))
    }

    pub async fn is_provisionable(&self, domain_id: Id) -> Result<bool> {
        Ok(self
            .server
            .domain_by_id(domain_id.document_id())
            .await
            .caused_by(trc::location!())?
            .is_some_and(|domain| {
                domain.allows_scim_provisioning()
                    && self
                        .tenant_id()
                        .is_none_or(|tenant_id| domain.id_tenant == Some(tenant_id))
            }))
    }

    pub async fn is_provisionable_account(&self, id: Id) -> Result<bool> {
        match self
            .server
            .try_account(id.document_id())
            .await
            .caused_by(trc::location!())?
            .and_then(|account| account.domain_id())
        {
            Some(domain_id) => self.is_provisionable(Id::from(domain_id)).await,
            None => Ok(false),
        }
    }

    pub async fn user_permissions(&self, account: &UserAccount) -> Result<Permissions> {
        let tenant_id = account.member_tenant_id.map(|id| id.document_id());
        let security = &self.server.core.network.security;

        self.server
            .effective_permissions(
                &account.permissions,
                match &account.roles {
                    UserRoles::User => security.default_role_ids_user.as_slice(),
                    UserRoles::Admin if tenant_id.is_none() => {
                        security.default_role_ids_admin.as_slice()
                    }
                    UserRoles::Admin => security.default_role_ids_tenant.as_slice(),
                    UserRoles::Custom(roles) => roles.role_ids.as_slice(),
                },
                tenant_id,
            )
            .await
            .caused_by(trc::location!())
            .map(|permissions| permissions.finalize())
            .map_err(Into::into)
    }

    pub async fn is_active(&self, account: &UserAccount) -> Result<bool> {
        self.user_permissions(account)
            .await
            .map(|permissions| permissions.get(Permission::Authenticate as usize))
    }

    pub async fn insert(&self, object: &Object, resource_type: ResourceType) -> Result<Id> {
        match self
            .server
            .registry()
            .write(RegistryWrite::insert(object))
            .await
            .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(id) => {
                let mut invalidator = CacheInvalidationBuilder::default();
                invalidator.process_create(object);
                self.server
                    .invalidate_caches(invalidator)
                    .await
                    .caused_by(trc::location!())?;
                Ok(id)
            }
            result => Err(result.into_scim_error_for(resource_type).into()),
        }
    }

    pub async fn update(
        &self,
        id: Id,
        object: &Object,
        old_object: &Object,
        resource_type: ResourceType,
    ) -> Result<()> {
        if object.inner == old_object.inner {
            return Ok(());
        }

        match self
            .server
            .registry()
            .write(RegistryWrite::update(id, object, old_object))
            .await
            .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(id) => {
                let mut invalidator = CacheInvalidationBuilder::default();
                invalidator.process_update(id, old_object, object);
                self.server
                    .invalidate_caches(invalidator)
                    .await
                    .caused_by(trc::location!())?;
                Ok(())
            }
            result => Err(result.into_scim_error_for(resource_type).into()),
        }
    }

    pub async fn delete(&self, id: Id, object: &Object) -> Result<()> {
        match self
            .server
            .registry()
            .write(RegistryWrite::Delete {
                object_id: ObjectId::new(ObjectType::Account, id),
                object: Some(object),
                allowed_orphan_types: &[ObjectType::PublicKey, ObjectType::MaskedEmail],
            })
            .await
            .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(_) => {
                let mut invalidator = CacheInvalidationBuilder::default();
                for sharee_id in self
                    .server
                    .store()
                    .acl_revoke_all(id.document_id())
                    .await
                    .caused_by(trc::location!())?
                {
                    invalidator.invalidate(common::ipc::CacheInvalidation::AccessToken(sharee_id));
                }

                if let registry::schema::prelude::ObjectInner::Account(account) = &object.inner {
                    jmap::registry::mapping::principal::schedule_account_destruction(
                        self.server,
                        id,
                        account,
                    )
                    .await
                    .caused_by(trc::location!())?;
                }

                invalidator.process_delete(id, object);
                self.server
                    .invalidate_caches(invalidator)
                    .await
                    .caused_by(trc::location!())?;
                Ok(())
            }
            result => Err(result.into_scim_error().into()),
        }
    }
}

pub fn parse_id(value: &str) -> Result<Id> {
    value
        .parse::<Id>()
        .ok()
        .filter(|id| id.to_string() == value)
        .ok_or_else(|| Error::not_found().into())
}

pub fn revision_of(object: &Object) -> u64 {
    xxhash_rust::xxh3::xxh3_64(&object.inner.to_pickled_vec())
}

pub fn account_domain_id(object: &Object) -> Option<Id> {
    match &object.inner {
        registry::schema::prelude::ObjectInner::Account(Account::User(account)) => {
            Some(account.domain_id)
        }
        registry::schema::prelude::ObjectInner::Account(Account::Group(account)) => {
            Some(account.domain_id)
        }
        _ => None,
    }
}

pub fn account_of(object: &Object) -> Result<&Account> {
    match &object.inner {
        registry::schema::prelude::ObjectInner::Account(account) => Ok(account),
        _ => Err(Error::not_found().into()),
    }
}

pub fn user_account(object: &Object) -> Result<&UserAccount> {
    match &object.inner {
        registry::schema::prelude::ObjectInner::Account(Account::User(account)) => Ok(account),
        _ => Err(Error::not_found().into()),
    }
}

pub fn group_account(object: &Object) -> Result<&GroupAccount> {
    match &object.inner {
        registry::schema::prelude::ObjectInner::Account(Account::Group(account)) => Ok(account),
        _ => Err(Error::not_found().into()),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_id;
    use types::id::Id;

    #[test]
    fn identifiers_round_trip() {
        for id in [0u64, 1, 42, 1 << 32, u64::MAX] {
            let id = Id::new(id);

            assert_eq!(parse_id(&id.to_string()).unwrap(), id);
        }
    }

    #[test]
    fn identifiers_are_case_exact() {
        let id = Id::new(12345);
        let rendered = id.to_string();

        assert!(parse_id(&rendered.to_uppercase()).is_err(), "{rendered}");
    }

    #[test]
    fn overflowing_identifiers_are_rejected() {
        for value in [
            "",
            "!",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "vvvvvvvvvvvvvvvv",
        ] {
            assert!(parse_id(value).is_err(), "{value}");
        }
    }
}
