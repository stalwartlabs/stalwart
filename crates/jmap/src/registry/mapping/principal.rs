/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, RegistrySetResponse, ValidationResult};
use common::{
    Server,
    auth::{Permissions, PermissionsGroup, permissions::BuildPermissions},
};
use directory::core::secret::{hash_secret, is_password_hash};
use jmap_proto::error::set::SetError;
use registry::{schema::structs::TaskStatus, types::datetime::UTCDateTime};
use registry::{
    schema::{
        enums::{AccountType, Permission, TenantStorageQuota},
        prelude::{MASKED_PASSWORD, ObjectType, Property},
        structs::{Account, Credential, Role, Task, TaskDestroyAccount},
    },
    types::EnumImpl,
};
use store::{
    registry::{RegistryObjectCounter, RegistryQuery},
    write::{BatchBuilder, RegistryClass, ValueClass, now},
};
use trc::AddContext;
use types::id::Id;

#[derive(Clone, Copy)]
pub enum AccountUpdate<'x> {
    Update(&'x Account),
    Create(&'x str),
}

pub(crate) async fn validate_account(
    set: &RegistrySetResponse<'_>,
    mut account: &mut Account,
    old_account: AccountUpdate<'_>,
) -> ValidationResult {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if set.server.core.is_enterprise_edition()
        && matches!(old_account, AccountUpdate::Create(_))
        && !set.server.can_create_account().await?
    {
        return Ok(Err(SetError::forbidden().with_description(format!(
            "Enterprise licensed account limit reached: {} accounts licensed.",
            set.server.licensed_accounts()
        ))));
    }
    // SPDX-SnippetEnd

    let is_external_directory = if let Account::User(account) = account {
        set.server
            .domain_by_id(account.domain_id.document_id())
            .await?
            .and_then(|domain| set.server.get_directory_for_cached_domain(&domain))
            .is_some()
    } else {
        false
    };
    let recover_account_id = if set.server.registry().is_recovery_mode()
        && let AccountUpdate::Create(client_id) = old_account
        && let Some(account_id) = client_id
            .strip_prefix("restore-")
            .and_then(|id| id.parse::<u32>().ok())
    {
        Some(account_id)
    } else {
        None
    };

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
                                    .otp_auth
                                    .as_ref()
                                    .is_some_and(|otp_auth| otp_auth == MASKED_PASSWORD)
                                {
                                    credential.otp_auth = old_credential.otp_auth.clone();
                                }

                                if credential.secret != old_credential.secret {
                                    if credential.expires_at == old_credential.expires_at
                                        && credential
                                            .expires_at
                                            .is_some_and(|exp| exp.timestamp() <= now() as i64)
                                        && let Some(expires_at) = set
                                            .server
                                            .core
                                            .network
                                            .security
                                            .password_default_expiration
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
                                            set.server.is_secure_password(&credential.secret, &[])
                                        {
                                            return Ok(Err(SetError::invalid_properties()
                                                .with_property(Property::Secret)
                                                .with_description(err)));
                                        }

                                        credential.secret = hash_secret(
                                            set.server
                                                .core
                                                .network
                                                .security
                                                .password_hash_algorithm,
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
                            _ => {
                                return Ok(Err(SetError::invalid_properties()
                                    .with_property(Property::Credentials)
                                    .with_description("Credential type cannot be changed.")));
                            }
                        }
                    }
                } else if let Err(err) = validate_credential_creation(
                    set.server,
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
        (Account::User(account), AccountUpdate::Create(_)) => {
            // Validate tenant quotas
            if let Err(err) = validate_tenant_quota(set, TenantStorageQuota::MaxAccounts).await? {
                return Ok(Err(err));
            }

            // Validate credentials
            for (index, credential) in account.credentials.values_mut().enumerate() {
                if let Err(err) = validate_credential_creation(
                    set.server,
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
        (Account::Group(_), AccountUpdate::Create(_)) => {
            // Validate tenant quotas
            if let Err(err) = validate_tenant_quota(set, TenantStorageQuota::MaxGroups).await? {
                return Ok(Err(err));
            }

            true
        }
        (Account::User(_), AccountUpdate::Update(Account::Group(_)))
        | (Account::Group(_), AccountUpdate::Update(Account::User(_))) => {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::Type)
                .with_description(
                    "Cannot change the type of an existing account.",
                )));
        }
    };

    let mut result = if validate_permissions {
        Ok(set
            .server
            .can_set_permissions(set.access_token, account)
            .await?
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
    };

    if let Some(account_id) = recover_account_id
        && let Ok(Ok(result)) = &mut result
    {
        restore_account_id(set.server, account_id).await?;
        result.id = Some(account_id.into());
    }

    result
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
    }
}

pub(crate) async fn validate_role(
    set: &RegistrySetResponse<'_>,
    role: &mut Role,
    old_role: Option<&Role>,
) -> ValidationResult {
    if old_role.is_none() {
        // Validate tenant quotas
        if let Err(err) = validate_tenant_quota(set, TenantStorageQuota::MaxRoles).await? {
            return Ok(Err(err));
        }
    }

    if old_role.is_none_or(|old_role| {
        old_role.enabled_permissions != role.enabled_permissions
            || old_role.disabled_permissions != role.disabled_permissions
            || old_role.role_ids != role.role_ids
    }) {
        Ok(set
            .access_token
            .can_grant_permissions(
                PermissionsGroup {
                    enabled: Permissions::from_permission(role.enabled_permissions.as_slice()),
                    disabled: Permissions::from_permission(role.disabled_permissions.as_slice()),
                    merge: false,
                }
                .finalize(),
            )
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
pub(crate) async fn validate_tenant_quota(
    set: &RegistrySetResponse<'_>,
    quota: TenantStorageQuota,
) -> ValidationResult {
    if let Some(tenant_id) = set.access_token.tenant_id() {
        let tenant = set.server.tenant(tenant_id).await?;
        if let Some(quotas) = tenant
            .quota_objects
            .as_ref()
            .map(|quotas| quotas.get(quota))
            .filter(|quota| *quota != u32::MAX)
        {
            let (object_type, type_filter, description) = match quota {
                TenantStorageQuota::MaxAccounts => {
                    (ObjectType::Account, Some(AccountType::User), "accounts")
                }
                TenantStorageQuota::MaxGroups => {
                    (ObjectType::Account, Some(AccountType::Group), "groups")
                }
                TenantStorageQuota::MaxDomains => (ObjectType::Domain, None, "domains"),
                TenantStorageQuota::MaxMailingLists => {
                    (ObjectType::MailingList, None, "mailing lists")
                }
                TenantStorageQuota::MaxRoles => (ObjectType::Role, None, "roles"),
                TenantStorageQuota::MaxOauthClients => {
                    (ObjectType::OAuthClient, None, "OAuth clients")
                }
                TenantStorageQuota::MaxDkimKeys => (ObjectType::DkimSignature, None, "DKIM keys"),
                TenantStorageQuota::MaxDnsServers => (ObjectType::DnsServer, None, "DNS servers"),
                TenantStorageQuota::MaxDirectories => (ObjectType::Directory, None, "directories"),
                TenantStorageQuota::MaxAcmeProviders => {
                    (ObjectType::AcmeProvider, None, "ACME providers")
                }
                TenantStorageQuota::MaxDiskQuota => unreachable!(),
            };
            let query = RegistryQuery::new(object_type).with_tenant(tenant_id.into());
            let count = if let Some(type_filter) = type_filter {
                set.server
                    .registry()
                    .query::<Vec<Id>>(query.equal(Property::Type, type_filter.to_id()))
                    .await?
                    .len() as u32
            } else {
                set.server
                    .registry()
                    .query::<RegistryObjectCounter>(query)
                    .await?
                    .0 as u32
            };

            if count >= quotas {
                return Ok(Err(SetError::over_quota().with_description(format!(
                    "You have exceeded your quota of {} {}.",
                    quotas, description
                ))));
            }
        }
    }

    Ok(Ok(ObjectResponse::default()))
}
// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
pub(crate) async fn validate_tenant_quota(
    _set: &RegistrySetResponse<'_>,
    _quota: TenantStorageQuota,
) -> ValidationResult {
    ValidationResult::Ok(Ok(ObjectResponse::default()))
}

pub(crate) async fn schedule_account_destruction(
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

    let account_domain_id;
    let account_name;
    let account_type;

    match account {
        Account::User(account) => {
            account_domain_id = account.domain_id;
            account_name = account.name.clone();
            account_type = AccountType::User;
        }
        Account::Group(account) => {
            account_domain_id = account.domain_id;
            account_name = account.name.clone();
            account_type = AccountType::Group;
        }
    }

    let mut batch = BatchBuilder::new();
    batch.schedule_task(Task::DestroyAccount(TaskDestroyAccount {
        account_domain_id,
        account_id,
        account_name,
        account_type,
        status,
    }));

    server.store().write(batch.build_all()).await?;
    server.notify_task_queue();

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
            .write(id_batch.build_all())
            .await
            .and_then(|v| v.last_counter_id())?;

        if last_id < id as i64 {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to update id counter")
                .caused_by(trc::location!()));
        }
    }

    Ok(())
}
