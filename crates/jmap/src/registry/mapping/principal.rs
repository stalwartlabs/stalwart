/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, RegistrySetResponse, ValidationResult};
use common::auth::PermissionsGroup;
use directory::core::secret::hash_secret;
use jmap_proto::error::set::SetError;
use rand::{Rng, distr::Alphanumeric};
use registry::{
    schema::{
        enums::{AccountType, Permission, TenantStorageQuota},
        prelude::{MASKED_PASSWORD, ObjectType, Property},
        structs::{Account, Role},
    },
    types::EnumImpl,
};
use store::registry::RegistryQuery;
use trc::AddContext;

pub(crate) async fn validate_account(
    set: &RegistrySetResponse<'_>,
    mut account: &mut Account,
    old_account: Option<&Account>,
) -> ValidationResult {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if set.server.core.is_enterprise_edition()
        && old_account.is_none()
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
            .and_then(|domain| domain.id_directory)
            .and_then(|domain_id| set.server.get_directory(&domain_id))
            .or_else(|| set.server.get_default_directory())
            .is_some()
    } else {
        false
    };

    let validate_permissions = match (&mut account, old_account) {
        (Account::User(account), Some(Account::User(old_account))) => {
            // Reset the original password if the client accidentally sent the masked password
            if account.secret == MASKED_PASSWORD {
                account.secret = old_account.secret.clone();
            }
            if account
                .otp_auth
                .as_ref()
                .is_some_and(|otp_auth| otp_auth == MASKED_PASSWORD)
            {
                account.otp_auth = old_account.otp_auth.clone();
            }

            // Hash secret if it was changed and not using external auth
            if account.secret != old_account.secret {
                if is_external_directory {
                    return Ok(Err(SetError::forbidden().with_description(
                        "Cannot change password for accounts in an external directory.",
                    )));
                }
                if !account.secret.is_empty() {
                    account.secret = hash_secret(
                        set.server.core.network.security.password_hash_algorithm,
                        std::mem::take(&mut account.secret),
                    )
                    .await
                    .caused_by(trc::location!())?;
                } else {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::Secret)
                        .with_description("Password cannot be empty.")));
                }
            }

            if is_external_directory && account.otp_auth.is_some() {
                return Ok(Err(SetError::forbidden().with_description(
                    "Cannot set OTP auth for accounts in an external directory.",
                )));
            }

            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::Group(account), Some(Account::Group(old_account))) => {
            account.permissions != old_account.permissions || account.roles != old_account.roles
        }
        (Account::User(account), None) => {
            // Validate tenant quotas
            if let Err(err) = validate_tenant_quota(set, TenantStorageQuota::MaxAccounts).await? {
                return Ok(Err(err));
            }

            if is_external_directory {
                if account.otp_auth.is_some() {
                    return Ok(Err(SetError::forbidden().with_description(
                        "Cannot set OTP auth for accounts in an external directory.",
                    )));
                }

                account.secret = rand::rng()
                    .sample_iter(Alphanumeric)
                    .take(32)
                    .map(char::from)
                    .collect::<String>();
            }

            if !account.secret.is_empty() {
                account.secret = hash_secret(
                    set.server.core.network.security.password_hash_algorithm,
                    std::mem::take(&mut account.secret),
                )
                .await
                .caused_by(trc::location!())?;
            } else {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Secret)
                    .with_description("Password cannot be empty.")));
            }

            true
        }
        (Account::Group(_), None) => {
            // Validate tenant quotas
            if let Err(err) = validate_tenant_quota(set, TenantStorageQuota::MaxGroups).await? {
                return Ok(Err(err));
            }

            true
        }
        _ => unreachable!(),
    };

    if validate_permissions {
        Ok(set
            .server
            .can_set_permissions(set.access_token, account)
            .await?
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
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
        old_role.permissions != role.permissions || old_role.role_ids != role.role_ids
    }) {
        Ok(set
            .access_token
            .can_grant_permissions(PermissionsGroup::from(&role.permissions).finalize())
            .map(|_| ObjectResponse::default())
            .map_err(build_set_error))
    } else {
        Ok(Ok(ObjectResponse::default()))
    }
}

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
                TenantStorageQuota::MaxDiskQuota => unreachable!(),
            };
            let mut query = RegistryQuery::new(object_type).with_tenant(tenant_id.into());
            if let Some(type_filter) = type_filter {
                query = query.equal(Property::Type, type_filter.to_id());
            }
            let count = set.server.registry().count(query).await? as u32;
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

fn build_set_error(permissions: Vec<Permission>) -> SetError<Property> {
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
