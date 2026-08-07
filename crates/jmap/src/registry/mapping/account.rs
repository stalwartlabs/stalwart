/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{
            RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse,
            principal::build_set_error,
        },
        query::RegistryQueryFilters,
        set::map_write_error,
    },
};
use common::{
    Server,
    auth::{
        AccessToken, Permissions,
        credential::{ApiKey, AppPassword},
        permissions::BuildPermissions,
    },
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
    storage::encryption::{EncryptionMethod, parse_public_key},
};
use directory::core::secret::{SecretVerificationResult, hash_secret, verify_mfa_secret_hash};
use jmap_proto::{error::set::SetError, request::MaybeInvalid, types::state::State};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, MaybeUnpatched, RegistryJsonPatch, RegistryValue},
    schema::{
        enums::{CredentialType, StorageQuota},
        prelude::{MASKED_PASSWORD, Object, ObjectInner, ObjectType, Property},
        structs::{
            Account, AccountPassword, AccountSettings, Credential, CredentialPermissions,
            EncryptionAtRest, OtpAuth, PublicKey, SecondaryCredential,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId},
};
use std::str::FromStr;
use store::{
    registry::{
        RegistryFilterOp,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub(crate) async fn account_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let item_id = Id::from(set.account_id);
    let Some(object) = set
        .server
        .registry()
        .get(ObjectId::new(ObjectType::Account, item_id))
        .await?
    else {
        set.fail_all(SetError::not_found());
        return Ok(set);
    };
    let revision = object.revision;
    let old_account = if let ObjectInner::Account(Account::User(account)) = object.inner {
        account
    } else {
        set.fail_all(SetError::not_found());
        return Ok(set);
    };
    let mut account = old_account.clone();

    match set.object_type {
        ObjectType::AccountSettings => {
            'outer: for (id, value) in set.update.drain(..) {
                if id != Id::singleton() {
                    set.response.not_updated.append(id, SetError::not_found());
                }

                for (key, value) in value.into_expanded_object() {
                    if let Key::Property(
                        property @ (Property::EncryptionAtRest
                        | Property::Locale
                        | Property::Description
                        | Property::TimeZone),
                    ) = key
                    {
                        let ptr =
                            JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(property))]);
                        if let Err(err) =
                            account.patch(JsonPointerPatch::new(&ptr).with_create(false), value)
                        {
                            set.response.not_updated.append(id, err.into());
                            break 'outer;
                        }
                    } else {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_properties().with_property(key.into_owned()),
                        );
                        break 'outer;
                    }
                }

                if account.encryption_at_rest != old_account.encryption_at_rest
                    && let Some(algorithm) =
                        unsupported_pgp_algorithm(set.server, &account.encryption_at_rest).await?
                {
                    account = old_account.clone();
                    set.response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::EncryptionAtRest)
                            .with_description(format!(
                                "{algorithm} is only supported for S/MIME encryption, but the selected public key is an OpenPGP key."
                            )),
                    );
                    break 'outer;
                }

                set.response.updated.append(id, None);
            }
        }
        ObjectType::AccountPassword => {
            if let Some(old_credential) = account.credentials.values_mut().find_map(|credential| {
                if let Credential::Password(pass) = credential {
                    Some(pass)
                } else {
                    None
                }
            }) {
                'outer: for (id, value) in set.update.drain(..) {
                    if id != Id::singleton() {
                        set.response.not_updated.append(id, SetError::not_found());
                    }

                    let mut account_pass = AccountPassword {
                        secret: None,
                        current_secret: None,
                        otp_auth: OtpAuth {
                            otp_code: None,
                            otp_url: if old_credential.otp_auth.is_some() {
                                Some(MASKED_PASSWORD.to_string())
                            } else {
                                None
                            },
                        },
                    };

                    for (key, value) in value.into_expanded_object() {
                        let ptr = match key {
                            Key::Property(prop) => {
                                JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                            }
                            Key::Borrowed(other) => JsonPointer::parse(other),
                            Key::Owned(other) => JsonPointer::parse(&other),
                        };

                        match account_pass
                            .patch(JsonPointerPatch::new(&ptr).with_create(false), value)
                        {
                            Ok(MaybeUnpatched::Patched) => {}
                            Ok(MaybeUnpatched::Unpatched { .. })
                            | Ok(MaybeUnpatched::UnpatchedMany { .. }) => {
                                set.response
                                    .not_updated
                                    .append(id, SetError::invalid_properties());
                                continue 'outer;
                            }
                            Err(err) => {
                                set.response.not_updated.append(id, err.into());
                                continue 'outer;
                            }
                        }
                    }

                    let is_empty_secret = account_pass
                        .secret
                        .as_ref()
                        .is_none_or(|secret| secret == MASKED_PASSWORD);
                    let is_empty_otp = account_pass.otp_auth.otp_url.as_deref()
                        == Some(MASKED_PASSWORD)
                        || (account_pass.otp_auth.otp_url.is_none()
                            && old_credential.otp_auth.is_none());
                    if !is_empty_secret || !is_empty_otp {
                        let user_provided_secret = if !is_empty_secret {
                            account_pass.secret.as_ref().unwrap()
                        } else {
                            old_credential.secret.as_str()
                        };
                        if is_empty_otp {
                            account_pass.otp_auth.otp_url = old_credential.otp_auth.clone();
                        }

                        // Password changes are not supported when using external directories
                        if (user_provided_secret != old_credential.secret
                            || account_pass.otp_auth.otp_url != old_credential.otp_auth)
                            && set
                                .server
                                .domain_by_id(account.domain_id.document_id())
                                .await?
                                .and_then(|domain| {
                                    set.server.get_directory_for_cached_domain(&domain)
                                })
                                .is_some()
                        {
                            set.response.not_updated.append(
                                id,
                                SetError::forbidden().with_description("Operation not allowed."),
                            );
                            continue 'outer;
                        }

                        if user_provided_secret != old_credential.secret
                            || account_pass.otp_auth.otp_url != old_credential.otp_auth
                        {
                            if old_credential.secret.is_empty() {
                                set.response.not_updated.append(
                                        id,
                                        SetError::forbidden().with_description(
                                            "Cannot set a password or OTP auth on an account that doesn't have one.",
                                        ),
                                    );
                                continue 'outer;
                            }

                            let current_otp_code = account_pass.otp_auth.otp_code;
                            if let Some(current_secret) = account_pass.current_secret {
                                match verify_mfa_secret_hash(
                                    old_credential.otp_auth.as_deref(),
                                    current_otp_code.as_deref(),
                                    &old_credential.secret,
                                    current_secret.as_ref(),
                                )
                                .await?
                                {
                                    SecretVerificationResult::Valid => {}
                                    SecretVerificationResult::Invalid => {
                                        let account = set.server.account(set.account_id).await?;
                                        if set.server.has_auth_fail2ban()
                                            && set
                                                .server
                                                .is_auth_fail2banned(
                                                    set.remote_ip,
                                                    account.name().into(),
                                                )
                                                .await?
                                        {
                                            return Err(trc::SecurityEvent::AuthenticationBan
                                                .into_err()
                                                .details(
                                                    "Too many failed password change attempts.",
                                                )
                                                .ctx(trc::Key::RemoteIp, set.remote_ip)
                                                .ctx(
                                                    trc::Key::AccountName,
                                                    account.name().to_string(),
                                                ));
                                        } else {
                                            set.response.not_updated.append(
                                                id,
                                                SetError::forbidden().with_description(
                                                    "Current secret is incorrect.",
                                                ),
                                            );
                                            continue 'outer;
                                        }
                                    }
                                    SecretVerificationResult::MissingMfaToken => {
                                        set.response.not_updated.append(
                                                id,
                                                SetError::forbidden().with_description(
                                                    "Current OTP code is required to change the password or OTP auth.",
                                                ),
                                            );
                                        continue 'outer;
                                    }
                                }

                                if user_provided_secret != old_credential.secret {
                                    if let Err(err) =
                                        set.server.is_secure_password(user_provided_secret, &[])
                                    {
                                        set.response.not_updated.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property(Property::Secret)
                                                .with_description(err),
                                        );
                                        continue 'outer;
                                    }

                                    if let Some(expires_at) =
                                        set.server.core.network.security.password_default_expiration
                                    {
                                        old_credential.expires_at =
                                            Some(UTCDateTime::from_timestamp(
                                                (now() + expires_at) as i64,
                                            ));
                                    } else if old_credential
                                        .expires_at
                                        .is_some_and(|exp| exp.timestamp() <= now() as i64)
                                    {
                                        old_credential.expires_at = None;
                                    }

                                    old_credential.secret = hash_secret(
                                        set.server.core.network.security.password_hash_algorithm,
                                        user_provided_secret.as_bytes().to_vec(),
                                    )
                                    .await
                                    .caused_by(trc::location!())?;
                                }

                                if account_pass.otp_auth.otp_url != old_credential.otp_auth {
                                    old_credential.otp_auth = account_pass.otp_auth.otp_url;
                                }
                            } else {
                                set.response.not_updated.append(
                                        id,
                                        SetError::forbidden().with_description(
                                            "Current secret must be provided to change the password or OTP auth.",
                                        ),
                                    );
                                continue 'outer;
                            }
                        }
                    }

                    set.response.updated.append(id, None);
                    break;
                }
            } else {
                set.fail_all(
                    SetError::forbidden()
                        .with_description("Your account does not support password changes"),
                );
            }
        }

        ObjectType::AppPassword | ObjectType::ApiKey => {
            // Process creations
            if !set.create.is_empty() {
                let account_cache = set.server.account(set.account_id).await?;
                let app_pass_quota = set
                    .server
                    .object_quota(account_cache.object_quotas(), StorageQuota::MaxAppPasswords);
                let api_key_quota = set
                    .server
                    .object_quota(account_cache.object_quotas(), StorageQuota::MaxApiKeys);
                let mut last_credential_id = 0;
                let mut app_pass_total = 0;
                let mut api_key_total = 0;

                for credential in account.credentials.values() {
                    match credential {
                        Credential::Password(c) => {
                            let credential_id = c.credential_id.id();
                            if credential_id > last_credential_id {
                                last_credential_id = credential_id;
                            }
                        }
                        Credential::AppPassword(c) => {
                            let credential_id = c.credential_id.id();
                            if credential_id > last_credential_id {
                                last_credential_id = credential_id;
                            }
                            app_pass_total += 1;
                        }
                        Credential::ApiKey(c) => {
                            let credential_id = c.credential_id.id();
                            if credential_id > last_credential_id {
                                last_credential_id = credential_id;
                            }
                            api_key_total += 1;
                        }
                    }
                }

                'outer: for (id, value) in set.create.drain() {
                    let mut credential = SecondaryCredential::default();

                    // Patch object
                    match credential.patch(
                        JsonPointerPatch::new(&JsonPointer::new(vec![])).with_create(true),
                        value,
                    ) {
                        Ok(MaybeUnpatched::Patched) => {}
                        Ok(
                            MaybeUnpatched::Unpatched { .. } | MaybeUnpatched::UnpatchedMany { .. },
                        ) => {
                            set.response.not_created.append(
                                id,
                                SetError::invalid_properties()
                                    .with_description("Cannot set property during creation."),
                            );
                            continue 'outer;
                        }
                        Err(err) => {
                            set.response.not_created.append(id, err.into());
                            continue 'outer;
                        }
                    }

                    // Validate credential
                    match set.object_type {
                        ObjectType::AppPassword => {
                            if app_pass_total >= app_pass_quota {
                                set.response.not_created.append(
                                    id,
                                    SetError::over_quota().with_description(format!(
                                        "You have exceeded your quota of {} app passwords.",
                                        app_pass_quota
                                    )),
                                );
                                continue 'outer;
                            }
                            if let Err(err) =
                                validate_credential_permissions(set.access_token, &credential)
                            {
                                set.response.not_created.append(id, err);
                                continue 'outer;
                            }

                            // Assign id
                            last_credential_id += 1;
                            app_pass_total += 1;
                            credential.credential_id = last_credential_id.into();

                            // Generate App password and hash secret
                            let app_pass = AppPassword::new(last_credential_id as u32);
                            credential.secret = hash_secret(
                                set.server.core.network.security.password_hash_algorithm,
                                app_pass.secret.to_vec(),
                            )
                            .await
                            .caused_by(trc::location!())?;

                            // Add credential to account
                            account
                                .credentials
                                .push(Credential::AppPassword(credential));

                            set.response.created.insert(
                                id,
                                Value::Object(Map::from(vec![
                                    (
                                        Key::Property(Property::Id),
                                        Value::Element(RegistryValue::Id(
                                            last_credential_id.into(),
                                        )),
                                    ),
                                    (
                                        Key::Property(Property::Secret),
                                        Value::Str(app_pass.build().into()),
                                    ),
                                ])),
                            );
                        }
                        ObjectType::ApiKey => {
                            if api_key_total >= api_key_quota {
                                set.response.not_created.append(
                                    id,
                                    SetError::over_quota().with_description(format!(
                                        "You have exceeded your quota of {} API keys.",
                                        api_key_quota
                                    )),
                                );
                                continue 'outer;
                            }
                            if let Err(err) =
                                validate_credential_permissions(set.access_token, &credential)
                            {
                                set.response.not_created.append(id, err);
                                continue 'outer;
                            }

                            // Assign id
                            last_credential_id += 1;
                            api_key_total += 1;
                            credential.credential_id = last_credential_id.into();

                            // Generate API key and hash secret
                            let api_key = ApiKey::new(set.account_id, last_credential_id as u32);
                            credential.secret = hash_secret(
                                set.server.core.network.security.password_hash_algorithm,
                                api_key.secret.to_vec(),
                            )
                            .await
                            .caused_by(trc::location!())?;

                            // Add credential to account
                            account.credentials.push(Credential::ApiKey(credential));

                            set.response.created.insert(
                                id,
                                Value::Object(Map::from(vec![
                                    (
                                        Key::Property(Property::Id),
                                        Value::Element(RegistryValue::Id(
                                            last_credential_id.into(),
                                        )),
                                    ),
                                    (
                                        Key::Property(Property::Secret),
                                        Value::Str(api_key.build().into()),
                                    ),
                                ])),
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }

            // Process updates
            'outer: for (id, value) in set.update.drain(..) {
                if let Some(mut old_credential) = account
                    .credentials
                    .values_mut()
                    .find(|credential| credential.credential_id() == id)
                {
                    let mut credential = old_credential.clone();
                    let mut unpatched_properties = VecMap::new();

                    for (key, value) in value.into_expanded_object() {
                        let ptr = match key {
                            Key::Property(prop) => {
                                JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                            }
                            Key::Borrowed(other) => JsonPointer::parse(other),
                            Key::Owned(other) => JsonPointer::parse(&other),
                        };

                        match credential
                            .patch(JsonPointerPatch::new(&ptr).with_create(false), value)
                        {
                            Ok(MaybeUnpatched::Patched) => {}
                            Ok(MaybeUnpatched::Unpatched { property, value }) => {
                                unpatched_properties.append(property, value);
                            }
                            Ok(MaybeUnpatched::UnpatchedMany { properties }) => {
                                if unpatched_properties.is_empty() {
                                    unpatched_properties = properties;
                                } else {
                                    unpatched_properties.extend(properties);
                                }
                            }
                            Err(err) => {
                                set.response.not_updated.append(id, err.into());
                                continue 'outer;
                            }
                        }
                    }

                    if &credential == old_credential {
                        set.response.updated.append(id, None);
                        continue 'outer;
                    }

                    match (&mut credential, &mut old_credential) {
                        (
                            Credential::AppPassword(credential),
                            Credential::AppPassword(old_credential),
                        )
                        | (Credential::ApiKey(credential), Credential::ApiKey(old_credential))
                            if credential.secret != old_credential.secret =>
                        {
                            // Paranoid check, this is verified in the patch implementation
                            set.response.not_updated.append(
                                id,
                                SetError::forbidden().with_description(
                                    "Cannot change the value of an app password or API key.",
                                ),
                            );
                            continue 'outer;
                        }
                        _ => {}
                    }

                    if let Credential::AppPassword(new_sc) | Credential::ApiKey(new_sc) =
                        &credential
                        && let Credential::AppPassword(old_sc) | Credential::ApiKey(old_sc) =
                            &*old_credential
                        && old_sc.permissions != new_sc.permissions
                        && let Err(err) = validate_credential_permissions(set.access_token, new_sc)
                    {
                        set.response.not_updated.append(id, err);
                        continue 'outer;
                    }

                    *old_credential = credential;

                    set.response.updated.append(id, None);
                } else {
                    set.response.not_updated.append(id, SetError::not_found());
                }
            }

            // Process deletions
            for id in set.destroy.drain(..) {
                if let Some(idx) = account
                    .credentials
                    .0
                    .inner
                    .iter_mut()
                    .position(|c| c.value.credential_id() == id)
                {
                    let credentials = &mut account.credentials.inner_mut().inner;
                    if !matches!(credentials[idx].value, Credential::Password(_)) {
                        credentials.remove(idx);
                        set.response.destroyed.push(id);
                    } else {
                        set.response.not_destroyed.append(
                            id,
                            SetError::forbidden().with_description(
                                "Users are not allowed to destroy their own credentials.",
                            ),
                        );
                    }
                } else {
                    set.response.not_destroyed.append(id, SetError::not_found());
                }
            }
        }
        _ => unreachable!(),
    }

    if account != old_account {
        let mut cache_invalidator = CacheInvalidationBuilder::default();
        if account.encryption_at_rest != old_account.encryption_at_rest
            || account.description != old_account.description
            || account.locale != old_account.locale
        {
            cache_invalidator.invalidate(CacheInvalidation::Account(set.account_id));
        }
        if account.credentials != old_account.credentials {
            cache_invalidator.invalidate(CacheInvalidation::AccessToken(set.account_id));
        }

        let object = Object::new(ObjectInner::Account(Account::User(account)));
        let old_object = Object::with_revision(
            ObjectInner::Account(Account::User(old_account.clone())),
            revision,
        );

        match set
            .server
            .registry()
            .write(RegistryWrite::Update {
                object: &object,
                id: item_id,
                old_object: &old_object,
            })
            .await?
        {
            RegistryWriteResult::Success(_) => {
                // Invalidate caches
                set.server.invalidate_caches(cache_invalidator).await?;
            }
            err => {
                let err = map_write_error(err);
                let failed_create = set
                    .response
                    .created
                    .into_keys()
                    .map(|id| (id, err.clone()))
                    .collect::<Vec<_>>();
                let failed_update = set
                    .response
                    .updated
                    .into_keys()
                    .map(|id| (MaybeInvalid::Value(id), err.clone()))
                    .collect::<Vec<_>>();
                let failed_delete = set
                    .response
                    .destroyed
                    .into_iter()
                    .map(|id| (MaybeInvalid::Value(id), err.clone()))
                    .collect::<Vec<_>>();

                set.response.not_created.extend(failed_create);
                set.response.not_updated.extend(failed_update);
                set.response.not_destroyed.extend(failed_delete);
                set.response.created = Default::default();
                set.response.updated = Default::default();
                set.response.destroyed = Default::default();
            }
        }
    }

    Ok(set)
}

pub(crate) async fn account_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let Some(Account::User(account)) = get
        .server
        .registry()
        .object::<Account>(get.account_id.into())
        .await?
    else {
        return Ok(get.not_found_any());
    };

    match get.object_type {
        ObjectType::AccountSettings => {
            let mut ids = get
                .ids
                .take()
                .unwrap_or_else(|| vec![Id::singleton()])
                .into_iter();

            for id in ids.by_ref() {
                if id == Id::singleton() {
                    get.insert(
                        id,
                        AccountSettings {
                            encryption_at_rest: account.encryption_at_rest,
                            locale: account.locale,
                            description: account.description,
                            time_zone: account.time_zone,
                        }
                        .into_value(),
                    );
                    break;
                } else {
                    get.not_found(id);
                }
            }

            get.response.not_found.extend(ids.map(MaybeInvalid::Value));
        }
        ObjectType::AccountPassword => {
            let mut ids = get
                .ids
                .take()
                .unwrap_or_else(|| vec![Id::singleton()])
                .into_iter();

            for id in ids.by_ref() {
                if id == Id::singleton()
                    && let Some(pass) = account.credentials.iter().find_map(|pass| {
                        if let Credential::Password(pass) = pass {
                            Some(pass)
                        } else {
                            None
                        }
                    })
                {
                    get.insert(
                        id,
                        AccountPassword {
                            current_secret: None,
                            otp_auth: OtpAuth {
                                otp_code: None,
                                otp_url: if pass.otp_auth.is_some() {
                                    MASKED_PASSWORD.to_string().into()
                                } else {
                                    None
                                },
                            },
                            secret: MASKED_PASSWORD.to_string().into(),
                        }
                        .into_value(),
                    );
                    break;
                } else {
                    get.not_found(id);
                }
            }

            get.response.not_found.extend(ids.map(MaybeInvalid::Value));
        }
        ObjectType::ApiKey | ObjectType::AppPassword => {
            let mut ids = if let Some(ids) = get.ids.take() {
                ids
            } else {
                account
                    .credentials
                    .values()
                    .map(|credential| credential.credential_id())
                    .collect::<Vec<_>>()
            };

            for credential in account.credentials {
                match (credential, get.object_type) {
                    (Credential::AppPassword(pass), ObjectType::AppPassword)
                    | (Credential::ApiKey(pass), ObjectType::ApiKey)
                        if ids.contains(&pass.credential_id) =>
                    {
                        let id = pass.credential_id;
                        let mut credential = pass.into_value();
                        credential
                            .as_object_mut()
                            .unwrap()
                            .as_mut_vec()
                            .retain(|(k, _)| !matches!(k, Key::Property(Property::CredentialId)));
                        get.insert(id, credential);
                        ids.retain(|i| i != &id);
                    }
                    _ => {}
                }
            }

            for id in ids {
                get.not_found(id);
            }
        }
        _ => unreachable!(),
    }

    Ok(get)
}

pub(crate) async fn credential_query(
    mut query: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let Some(Account::User(account)) = query
        .server
        .registry()
        .object::<Account>(query.request.account_id)
        .await?
    else {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Account not found."));
    };

    let credential_type = match query.object_type {
        ObjectType::AppPassword => CredentialType::AppPassword,
        ObjectType::ApiKey => CredentialType::ApiKey,
        _ => unreachable!(),
    };
    let mut expires_at_filter = None;

    query
        .request
        .extract_filters(|property, op, value| match property {
            Property::ExpiresAt => {
                if let Some(value) = value
                    .as_str()
                    .and_then(|value| UTCDateTime::from_str(value).ok())
                {
                    expires_at_filter = Some((op, value));
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let mut matches = Vec::new();
    for credential in account.credentials.iter() {
        if credential.object_type() == credential_type {
            let (credential_id, expires_at) = match credential {
                Credential::AppPassword(credential) => {
                    (credential.credential_id, credential.expires_at)
                }
                Credential::ApiKey(credential) => (credential.credential_id, credential.expires_at),
                _ => unreachable!(),
            };
            if expires_at_filter.is_none_or(|(op, filter_value)| {
                expires_at.is_some_and(|expires_at| match op {
                    RegistryFilterOp::Equal => expires_at == filter_value,
                    RegistryFilterOp::GreaterThan => expires_at > filter_value,
                    RegistryFilterOp::GreaterEqualThan => expires_at >= filter_value,
                    RegistryFilterOp::LowerThan => expires_at < filter_value,
                    RegistryFilterOp::LowerEqualThan => expires_at <= filter_value,
                    RegistryFilterOp::TextMatch => false,
                })
            }) {
                matches.push((credential_id, expires_at));
            }
        }
    }

    let params = query
        .request
        .extract_parameters(query.server.core.jmap.query_max_results, None)?;

    match params.sort_by {
        Property::ExpiresAt => {
            if params.sort_ascending {
                matches.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            } else {
                matches.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
        }
        Property::Id => {
            if params.sort_ascending {
                matches.sort_by_key(|a| a.0);
            } else {
                matches.sort_by_key(|b| std::cmp::Reverse(b.0));
            }
        }
        property => {
            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
                "Property {} is not supported for sorting",
                property
            )));
        }
    }

    // Build response
    let mut response = QueryResponseBuilder::new(
        matches.len(),
        query.server.core.jmap.query_max_results,
        State::Initial,
        &query.request,
    );

    for (id, _) in matches {
        if !response.add_id(id) {
            break;
        }
    }

    Ok(response)
}

async fn unsupported_pgp_algorithm(
    server: &Server,
    encryption_at_rest: &EncryptionAtRest,
) -> trc::Result<Option<&'static str>> {
    let (settings, algorithm) = match encryption_at_rest {
        EncryptionAtRest::Aes256Gcm(settings) => (settings, "AES-256-GCM"),
        EncryptionAtRest::ChaCha20Poly1305(settings) => (settings, "ChaCha20-Poly1305"),
        _ => return Ok(None),
    };

    if let Some(public_key) = server
        .registry()
        .object::<PublicKey>(settings.public_key)
        .await
        .caused_by(trc::location!())?
        && matches!(
            parse_public_key(&public_key),
            Ok(Some(params)) if params.method == EncryptionMethod::PGP
        )
    {
        Ok(Some(algorithm))
    } else {
        Ok(None)
    }
}

pub(crate) fn validate_credential_permissions(
    access_token: &AccessToken,
    credential: &SecondaryCredential,
) -> Result<(), SetError<Property>> {
    let effective = match &credential.permissions {
        CredentialPermissions::Inherit => access_token.account_permissions().clone(),
        CredentialPermissions::Disable(list) => {
            let mut effective = access_token.account_permissions().clone();
            effective.clear_many(&Permissions::from_permission(list.permissions.as_slice()));
            effective
        }
        CredentialPermissions::Replace(list) => {
            Permissions::from_permission(list.permissions.as_slice())
        }
    };

    access_token
        .can_grant_permissions(effective)
        .map_err(build_set_error)
}
