/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::{
    Server,
    auth::{AccessToken, Permissions, PermissionsGroup, permissions::BuildPermissions},
};
use directory::core::secret::{hash_secret, is_password_hash};
use groupware::{cache::GroupwareCache, calendar::Calendar};
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{schema::structs::TaskStatus, types::datetime::UTCDateTime};
use registry::{
    schema::{
        enums::{AccountType, Permission},
        prelude::{MASKED_PASSWORD, ObjectType, Property},
        structs::{Account, Credential, Role, Task, TaskDestroyAccount},
    },
    types::EnumImpl,
};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, RegistryClass, ValueClass, now},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::Collection,
    id::Id,
};
use utils::map::bitmap::Bitmap;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use registry::schema::{enums::TenantStorageQuota, prelude::ObjectInner};
// SPDX-SnippetEnd

#[derive(Clone, Copy)]
pub enum AccountUpdate<'x> {
    Update(&'x Account),
    Create(&'x str),
}

pub async fn validate_account(
    server: &Server,
    access_token: &AccessToken,
    mut account: &mut Account,
    old_account: AccountUpdate<'_>,
) -> ValidationResult {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if server.core.is_enterprise_edition()
        && matches!(old_account, AccountUpdate::Create(_))
        && !server.can_create_account().await?
    {
        return Ok(Err(SetError::forbidden().with_description(format!(
            "Enterprise licensed account limit reached: {} accounts licensed.",
            server.licensed_accounts()
        ))));
    }
    // SPDX-SnippetEnd

    let is_external_directory = if let Account::User(account) = account {
        server
            .domain_by_id(account.domain_id.document_id())
            .await?
            .and_then(|domain| server.get_directory_for_cached_domain(&domain))
            .is_some()
    } else {
        false
    };
    let recover_account_id = if server.registry().is_recovery_mode()
        && let AccountUpdate::Create(client_id) = old_account
        && let Some(account_id) = client_id
            .strip_prefix("restore-")
            .and_then(|id| id.parse::<u32>().ok())
    {
        Some(account_id)
    } else {
        None
    };

    if let AccountUpdate::Update(old_account) = old_account
        && let Err(err) = validate_account_access(server, access_token, old_account).await?
    {
        return Ok(Err(err));
    }

    if let Account::Resource(resource) = account
        && resource.delegate_ids.len() > server.core.groupware.max_shares_per_item
    {
        return Ok(Err(SetError::invalid_properties()
            .with_property(Property::DelegateIds)
            .with_description(format!(
                "A resource can have at most {} delegates.",
                server.core.groupware.max_shares_per_item
            ))));
    }

    let validate_permissions = match (&mut account, old_account) {
        (Account::User(account), AccountUpdate::Update(Account::User(old_account))) => {
            // Validate credentials
            let has_password = account.credentials.values().any(|credential| {
                matches!(credential, Credential::Password(credential) if credential.credential_id.is_valid())
            });
            let mut max_credential_id = 0;
            let mut has_new_credentials = false;
            for credential in account.credentials.values_mut() {
                let credential_id = credential.credential_id();

                if credential_id.is_valid() && credential_id.id() > max_credential_id {
                    max_credential_id = credential_id.id();
                }

                if let Some(old_credential) = old_account
                    .credentials
                    .values()
                    .find(|c| c.credential_id() == credential_id)
                {
                    if credential != old_credential {
                        match (credential, old_credential) {
                            (
                                Credential::Password(credential),
                                Credential::Password(old_credential),
                            ) => {
                                if is_external_directory {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        "Cannot change credentials for accounts in an external directory.",
                                    )));
                                }

                                // Reset the original password if the client accidentally sent the masked password
                                if credential.secret == MASKED_PASSWORD {
                                    credential.secret = old_credential.secret.clone();
                                }
                                if credential
                                    .otp_url
                                    .as_ref()
                                    .is_some_and(|otp_url| otp_url == MASKED_PASSWORD)
                                {
                                    credential.otp_url = old_credential.otp_url.clone();
                                }

                                if credential.secret != old_credential.secret {
                                    if credential.expires_at == old_credential.expires_at
                                        && credential
                                            .expires_at
                                            .is_some_and(|exp| exp.timestamp() <= now() as i64)
                                        && let Some(expires_at) =
                                            server.core.network.security.password_default_expiration
                                    {
                                        credential.expires_at = Some(UTCDateTime::from_timestamp(
                                            (now() + expires_at) as i64,
                                        ));
                                    }

                                    if !(matches!(
                                        credential.secret.as_bytes().first(),
                                        Some(&b'$' | &b'{')
                                    ) && is_password_hash(&credential.secret))
                                    {
                                        if let Err(err) =
                                            server.is_secure_password(&credential.secret, &[])
                                        {
                                            return Ok(Err(SetError::invalid_properties()
                                                .with_property(Property::Secret)
                                                .with_description(err)));
                                        }

                                        credential.secret = hash_secret(
                                            &server.inner.data.password_verifier,
                                            server.core.network.security.password_hash_algorithm,
                                            std::mem::take(&mut credential.secret).into_bytes(),
                                        )
                                        .await
                                        .caused_by(trc::location!())?;
                                    }
                                }
                            }
                            (
                                Credential::AppPassword(credential),
                                Credential::AppPassword(old_credential),
                            )
                            | (
                                Credential::ApiKey(credential),
                                Credential::ApiKey(old_credential),
                            ) => {
                                // Reset the original password if the client accidentally sent the masked password
                                if credential.secret == MASKED_PASSWORD {
                                    credential.secret = old_credential.secret.clone();
                                }

                                if credential.secret != old_credential.secret {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        "Cannot change app password or API credentials through this method.",
                                    )));
                                }
                            }
                            (
                                Credential::Passkey(credential),
                                Credential::Passkey(old_credential),
                            ) => {
                                if credential.key_id != old_credential.key_id
                                    || credential.public_key != old_credential.public_key
                                    || credential.algorithm != old_credential.algorithm
                                    || credential.created_at != old_credential.created_at
                                {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        "Only the name of a passkey can be changed.",
                                    )));
                                }
                            }
                            _ => {
                                return Ok(Err(SetError::invalid_properties()
                                    .with_property(Property::Credentials)
                                    .with_description("Credential type cannot be changed.")));
                            }
                        }
                    }
                } else if let Err(err) = validate_credential_creation(
                    server,
                    credential,
                    is_external_directory,
                    has_password,
                )
                .await?
                {
                    return Ok(Err(err));
                } else {
                    has_new_credentials = true;
                }
            }

            if has_new_credentials {
                for credential in account.credentials.values_mut() {
                    if !credential.credential_id().is_valid() {
                        max_credential_id += 1;
                        credential.set_credential_id(Id::from(max_credential_id));
                    }
                }
            }

            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::Group(account), AccountUpdate::Update(Account::Group(old_account))) => {
            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::Resource(account), AccountUpdate::Update(Account::Resource(old_account))) => {
            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::User(account), AccountUpdate::Create(_)) => {
            // Validate credentials
            for (index, credential) in account.credentials.values_mut().enumerate() {
                if let Err(err) = validate_credential_creation(
                    server,
                    credential,
                    is_external_directory,
                    index > 0,
                )
                .await?
                {
                    return Ok(Err(err));
                }
                credential.set_credential_id(Id::from(index as u64));
            }

            true
        }
        (Account::Group(_) | Account::Resource(_), AccountUpdate::Create(_)) => true,
        (_, AccountUpdate::Update(_)) => {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::Type)
                .with_description(
                    "Cannot change the type of an existing account.",
                )));
        }
    };

    let mut result = if validate_permissions {
        Ok(server
            .can_set_permissions(access_token, account)
            .await?
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
    };

    if let Some(account_id) = recover_account_id
        && let Ok(Ok(result)) = &mut result
    {
        restore_account_id(server, account_id).await?;
        result.id = Some(account_id.into());
    }

    result
}

pub async fn validate_account_access(
    server: &Server,
    access_token: &AccessToken,
    account: &Account,
) -> trc::Result<Result<(), SetError<Property>>> {
    server
        .can_set_permissions(access_token, account)
        .await
        .map(|result| result.map_err(build_set_error))
}

async fn validate_credential_creation(
    server: &Server,
    credential: &mut Credential,
    is_external_directory: bool,
    has_password: bool,
) -> trc::Result<Result<(), SetError<Property>>> {
    match credential {
        Credential::Password(credential) => {
            if is_external_directory {
                return Ok(Err(SetError::forbidden().with_description(
                    "Cannot set credentials for accounts in an external directory.",
                )));
            } else if has_password {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Credentials)
                    .with_description("Only one password credential is allowed.")));
            }

            if credential.expires_at.is_none()
                && let Some(expires_at) = server.core.network.security.password_default_expiration
            {
                credential.expires_at =
                    Some(UTCDateTime::from_timestamp((now() + expires_at) as i64));
            }

            if matches!(credential.secret.as_bytes().first(), Some(&b'$' | &b'{'))
                && is_password_hash(&credential.secret)
            {
                Ok(Ok(()))
            } else if let Err(err) = server.is_secure_password(&credential.secret, &[]) {
                Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Secret)
                    .with_description(err)))
            } else {
                credential.secret = hash_secret(
                    &server.inner.data.password_verifier,
                    server.core.network.security.password_hash_algorithm,
                    std::mem::take(&mut credential.secret).into_bytes(),
                )
                .await
                .caused_by(trc::location!())?;
                Ok(Ok(()))
            }
        }
        Credential::AppPassword(_) | Credential::ApiKey(_) => {
            Ok(Err(SetError::invalid_properties()
                .with_property(Property::Credentials)
                .with_description(
                    "Secondary credentials cannot be set directly.",
                )))
        }
        Credential::Passkey(_) => Ok(Err(SetError::invalid_properties()
            .with_property(Property::Credentials)
            .with_description("Passkeys can only be registered by the account owner."))),
    }
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub(crate) async fn validate_role(
    server: &Server,
    access_token: &AccessToken,
    role: &mut Role,
    old_role: Option<&Role>,
) -> ValidationResult {
    if old_role.is_none_or(|old_role| {
        old_role.enabled_permissions != role.enabled_permissions
            || old_role.disabled_permissions != role.disabled_permissions
            || old_role.role_ids != role.role_ids
    }) {
        let permissions = match server
            .add_role_permissions(
                PermissionsGroup {
                    enabled: Permissions::from_permission(role.enabled_permissions.as_slice()),
                    disabled: Permissions::from_permission(role.disabled_permissions.as_slice()),
                    merge: false,
                },
                role.role_ids.iter().map(|id| id.document_id()),
            )
            .await
        {
            Ok(permissions) => permissions,
            Err(err) if err.matches(trc::EventType::Auth(trc::AuthEvent::Error)) => {
                return Ok(Err(
                    SetError::new(SetErrorType::InvalidForeignKey).with_property(Property::RoleIds)
                ));
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        };
        Ok(access_token
            .can_grant_permissions(permissions.finalize())
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub fn tenant_object_quota(object: &ObjectInner) -> Option<TenantStorageQuota> {
    match object {
        ObjectInner::Account(account) => Some(match account.as_ref() {
            Account::User(_) => TenantStorageQuota::MaxAccounts,
            Account::Group(_) => TenantStorageQuota::MaxGroups,
            Account::Resource(_) => TenantStorageQuota::MaxAccounts,
        }),
        ObjectInner::Domain(_) => Some(TenantStorageQuota::MaxDomains),
        ObjectInner::MailingList(_) => Some(TenantStorageQuota::MaxMailingLists),
        ObjectInner::Role(_) => Some(TenantStorageQuota::MaxRoles),
        ObjectInner::OAuthClient(_) => Some(TenantStorageQuota::MaxOauthClients),
        ObjectInner::DkimSignature(_) => Some(TenantStorageQuota::MaxDkimKeys),
        ObjectInner::DnsServer(_) => Some(TenantStorageQuota::MaxDnsServers),
        ObjectInner::Directory(_) => Some(TenantStorageQuota::MaxDirectories),
        ObjectInner::AcmeProvider(_) => Some(TenantStorageQuota::MaxAcmeProviders),
        _ => None,
    }
}

#[cfg(feature = "enterprise")]
pub async fn validate_tenant_quota(
    server: &Server,
    tenant_id: Option<u32>,
    quota: TenantStorageQuota,
) -> ValidationResult {
    if let Some(tenant_id) = tenant_id
        && let Some(reached) = server.tenant_quota_reached(tenant_id, quota).await?
    {
        return Ok(Err(SetError::over_quota().with_description(format!(
            "You have exceeded your quota of {} {}.",
            reached.limit, reached.objects
        ))));
    }

    Ok(Ok(ObjectResponse::default()))
}
// SPDX-SnippetEnd

pub async fn schedule_account_destruction(
    server: &Server,
    account_id: Id,
    account: &Account,
) -> trc::Result<()> {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let status = server
        .core
        .enterprise
        .as_ref()
        .and_then(|e| e.deleted_accounts_retention.as_ref())
        .map(|retention| TaskStatus::at(store::write::now() as i64 + retention.as_secs() as i64))
        .unwrap_or_else(TaskStatus::now);
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    let status = TaskStatus::now();

    let (account_domain_id, account_name, account_type, member_group_ids) = match account {
        Account::User(account) => (
            account.domain_id,
            account.name.clone(),
            AccountType::User,
            account.member_group_ids.clone(),
        ),
        Account::Group(account) => (
            account.domain_id,
            account.name.clone(),
            AccountType::Group,
            Default::default(),
        ),
        Account::Resource(account) => (
            account.domain_id,
            account.name.clone(),
            AccountType::Resource,
            Default::default(),
        ),
    };

    let mut batch = BatchBuilder::new();
    batch.schedule_task(Task::DestroyAccount(TaskDestroyAccount {
        account_domain_id,
        account_id,
        account_name,
        account_type,
        member_group_ids,
        status,
    }));

    server.commit_batch(batch).await?;

    Ok(())
}

pub(crate) fn build_set_error(permissions: Vec<Permission>) -> SetError<Property> {
    let mut missing_permissions = String::with_capacity(16);
    let mut total_missing = permissions.len();
    for permission in permissions.into_iter().take(5) {
        if !missing_permissions.is_empty() {
            missing_permissions.push_str(", ");
        }
        missing_permissions.push_str(permission.as_str());
        total_missing -= 1;
    }
    if total_missing > 0 {
        missing_permissions.push_str(&format!(" and {} more", total_missing));
    }

    SetError::forbidden().with_description(format!(
        "You are not authorized to grant permissions: {}",
        missing_permissions
    ))
}

async fn restore_account_id(server: &Server, id: u32) -> trc::Result<()> {
    // Obtain current counter value
    let object_id = ObjectType::Account.to_id();
    let last_id = server
        .store()
        .get_counter(ValueClass::Registry(RegistryClass::IdCounter { object_id }))
        .await
        .caused_by(trc::location!())?
        .cast_unsigned() as u32;

    if last_id < id {
        let mut id_batch = BatchBuilder::new();
        id_batch.add_and_get(
            ValueClass::Registry(RegistryClass::IdCounter { object_id }),
            (id - last_id) as i64,
        );
        let last_id = server
            .store()
            .write_batch(&mut id_batch)
            .await?
            .last_counter_id();

        if last_id < id as i64 {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to update id counter")
                .caused_by(trc::location!()));
        }
    }

    Ok(())
}

const RESOURCE_DELEGATE_RIGHTS: Bitmap<Acl> = Bitmap::from_bits(
    (1 << Acl::Read as u64)
        | (1 << Acl::ReadItems as u64)
        | (1 << Acl::AddItems as u64)
        | (1 << Acl::ModifyItems as u64)
        | (1 << Acl::RemoveItems as u64)
        | (1 << Acl::ModifyRSVP as u64)
        | (1 << Acl::SchedulingReadFreeBusy as u64)
        | (1 << Acl::SchedulingReply as u64),
);
const MAX_DELEGATE_WRITE_ATTEMPTS: usize = 3;

pub struct ResourceDelegates {
    resource_id: u32,
    delegates: Vec<u32>,
}

impl ResourceDelegates {
    pub fn reconcile(resource_id: Id, account: &Account) -> Option<Self> {
        let Account::Resource(account) = account else {
            return None;
        };
        Some(ResourceDelegates {
            resource_id: resource_id.document_id(),
            delegates: account.delegate_ids.iter().map(Id::document_id).collect(),
        })
    }

    pub fn resource_id(&self) -> u32 {
        self.resource_id
    }

    fn apply_to(&self, acls: &mut Vec<AclGrant>) {
        acls.retain_mut(|grant| {
            if self.delegates.contains(&grant.account_id) {
                grant.grants.union(&RESOURCE_DELEGATE_RIGHTS);
                true
            } else {
                grant.grants != RESOURCE_DELEGATE_RIGHTS
            }
        });
        for &account_id in &self.delegates {
            if !acls.iter().any(|grant| grant.account_id == account_id) {
                acls.push(AclGrant {
                    account_id,
                    grants: RESOURCE_DELEGATE_RIGHTS,
                });
            }
        }
    }
}

pub async fn apply_resource_delegates(
    server: &Server,
    access_token: &AccessToken,
    delegates: &ResourceDelegates,
) -> trc::Result<()> {
    let account_id = delegates.resource_id;
    let resource = server
        .account(account_id)
        .await
        .caused_by(trc::location!())?;
    let Some(calendar_id) = server
        .get_or_create_default_calendar(&resource, &resource)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(());
    };

    for attempt in 1..=MAX_DELEGATE_WRITE_ATTEMPTS {
        let Some(calendar_) = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Calendar,
                calendar_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let calendar = calendar_
            .to_unarchived::<Calendar>()
            .caused_by(trc::location!())?;
        let mut new_calendar = calendar
            .deserialize::<Calendar>()
            .caused_by(trc::location!())?;
        delegates.apply_to(&mut new_calendar.acls);
        if new_calendar.acls.len() == calendar.inner.acls.len()
            && calendar
                .inner
                .acls
                .iter()
                .zip(new_calendar.acls.iter())
                .all(|(current, new)| current == new)
        {
            return Ok(());
        }

        let mut batch = BatchBuilder::new();
        new_calendar
            .update(
                access_token.changed_by(),
                calendar,
                account_id,
                calendar_id,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        match server.commit_batch(batch).await {
            Ok(_) => return Ok(()),
            Err(err) if err.is_assertion_failure() && attempt < MAX_DELEGATE_WRITE_ATTEMPTS => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }

    Ok(())
}
