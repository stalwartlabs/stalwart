/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{RegistryGetResponse, RegistrySetResponse};
use common::{
    Server,
    auth::passkey::{
        PASSKEY_ALGORITHMS, PASSKEY_TIMEOUT_MS, PasskeyCeremony, PasskeyRp, PasskeyUserHandle,
        registration::verify_registration,
    },
};
use compact_str::CompactString;
use directory::core::secret::{SecretVerificationResult, verify_mfa_secret_hash};
use encodify::base64::URL_SAFE_NO_PAD;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::passkey::{
        PasskeyAuthenticatorSelection, PasskeyCreationOptions, PasskeyCredentialDescriptor,
        PasskeyCredentialParameters, PasskeyRegistrationOptionsRequest,
        PasskeyRegistrationOptionsResponse, PasskeyRpEntity, PasskeyUserEntity,
    },
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, MaybeUnpatched, RegistryJsonPatch, RegistryValue},
    schema::{
        enums::StorageQuota,
        prelude::Property,
        structs::{Account, Credential, Passkey, PasskeyCredential, UserAccount},
    },
    types::{ObjectImpl, datetime::UTCDateTime},
};
use std::{future::Future, net::IpAddr};
use types::id::Id;

const PUBLIC_KEY_TYPE: &str = "public-key";

pub trait PasskeyRegistrationOptions: Sync + Send {
    fn passkey_registration_options(
        &self,
        request: PasskeyRegistrationOptionsRequest,
        remote_ip: IpAddr,
    ) -> impl Future<Output = trc::Result<PasskeyRegistrationOptionsResponse>> + Send;
}

impl PasskeyRegistrationOptions for Server {
    async fn passkey_registration_options(
        &self,
        request: PasskeyRegistrationOptionsRequest,
        remote_ip: IpAddr,
    ) -> trc::Result<PasskeyRegistrationOptionsResponse> {
        let account_id = request.account_id.document_id();
        let rp = PasskeyRp::from_issuer(&self.core.network.http.url_https)
            .ok_or_else(|| forbidden("Passkeys are not available on this server."))?;
        let account = self
            .registry()
            .object::<Account>(account_id.into())
            .await?
            .and_then(Account::into_user)
            .ok_or_else(|| forbidden("Account not found."))?;

        if self
            .domain_by_id(account.domain_id.document_id())
            .await?
            .is_none_or(|domain| self.get_directory_for_cached_domain(&domain).is_some())
        {
            return Err(forbidden(
                "Passkeys are not available for accounts in an external directory.",
            ));
        }

        let password = account
            .password_credential()
            .filter(|credential| !credential.secret.is_empty())
            .ok_or_else(|| forbidden("Passkeys require an account with a password."))?;
        let current_secret = request
            .current_secret
            .ok_or_else(|| forbidden("Current secret must be provided to create a passkey."))?;
        let account_cache = self.account(account_id).await?;

        match verify_mfa_secret_hash(
            &self.inner.data.password_verifier,
            password.otp_url.as_deref(),
            request.otp_code.as_deref(),
            &password.secret,
            current_secret.as_ref(),
        )
        .await?
        {
            SecretVerificationResult::Valid => {}
            SecretVerificationResult::Invalid => {
                return Err(
                    if self.has_auth_fail2ban()
                        && self
                            .is_auth_fail2banned(remote_ip, account_cache.name().into())
                            .await?
                    {
                        trc::SecurityEvent::AuthenticationBan
                            .into_err()
                            .details("Too many failed passkey registration attempts.")
                            .ctx(trc::Key::RemoteIp, remote_ip)
                            .ctx(
                                trc::Key::AccountName,
                                CompactString::from(account_cache.name()),
                            )
                    } else {
                        forbidden("Current secret is incorrect.")
                    },
                );
            }
            SecretVerificationResult::MissingMfaToken => {
                return Err(forbidden(
                    "Current OTP code is required to create a passkey.",
                ));
            }
        }

        let quota = self.object_quota(account_cache.object_quotas(), StorageQuota::MaxPasskeys);
        let exclude_credentials = account
            .credentials
            .into_iter()
            .filter_map(|credential| match credential {
                Credential::Passkey(passkey) => Some(PasskeyCredentialDescriptor {
                    typ: PUBLIC_KEY_TYPE,
                    id: passkey.key_id,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        if exclude_credentials.len() >= quota as usize {
            return Err(forbidden(format!(
                "You have exceeded your quota of {quota} passkeys."
            )));
        }

        let challenge = self
            .issue_passkey_challenge(PasskeyCeremony::Registration { account_id })
            .await?;
        let name = account_cache.name();

        Ok(PasskeyRegistrationOptionsResponse {
            account_id: request.account_id,
            public_key: PasskeyCreationOptions {
                rp: PasskeyRpEntity {
                    name: rp.id.to_string(),
                    id: rp.id.into_owned(),
                },
                user: PasskeyUserEntity {
                    id: PasskeyUserHandle(account_id).encode(),
                    name: name.into(),
                    display_name: account_cache.description().unwrap_or(name).into(),
                },
                challenge: challenge.encode(),
                pub_key_cred_params: PASSKEY_ALGORITHMS
                    .iter()
                    .map(|&alg| PasskeyCredentialParameters {
                        typ: PUBLIC_KEY_TYPE,
                        alg,
                    })
                    .collect(),
                timeout: PASSKEY_TIMEOUT_MS,
                exclude_credentials,
                authenticator_selection: PasskeyAuthenticatorSelection {
                    resident_key: "required",
                    require_resident_key: true,
                    user_verification: "required",
                },
                attestation: "none",
            },
        })
    }
}

pub(crate) async fn passkey_set(
    set: &mut RegistrySetResponse<'_>,
    account: &mut UserAccount,
) -> trc::Result<()> {
    if !set.create.is_empty() {
        let Some(rp) = PasskeyRp::from_issuer(&set.server.core.network.http.url_https) else {
            set.fail_all_create("Passkeys are not available on this server.");
            return Ok(());
        };
        let account_cache = set.server.account(set.account_id).await?;
        let quota = set
            .server
            .object_quota(account_cache.object_quotas(), StorageQuota::MaxPasskeys)
            as usize;
        let mut total = account.passkeys().count();
        let mut last_credential_id = account.next_credential_id();

        for (id, value) in set.create.drain() {
            let mut passkey = Passkey::default();
            if let Err(err) = patch_passkey(&mut passkey, JsonPointer::new(vec![]), value, true) {
                set.response.not_created.append(id, err);
                continue;
            }
            let Some(registration) = passkey.registration.take() else {
                set.response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::Registration)
                        .with_description("A passkey registration is required."),
                );
                continue;
            };
            if let Err(err) = validate_passkey(&passkey) {
                set.response.not_created.append(id, err);
                continue;
            }
            if total >= quota {
                set.response.not_created.append(
                    id,
                    SetError::over_quota().with_description(format!(
                        "You have exceeded your quota of {quota} passkeys."
                    )),
                );
                continue;
            }

            let registered = match verify_registration(
                &registration.client_data_json,
                &registration.attestation_object,
                &rp,
            ) {
                Ok(registered) => registered,
                Err(err) => {
                    set.response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::Registration)
                            .with_description(err.as_str()),
                    );
                    continue;
                }
            };
            if !set
                .server
                .consume_passkey_challenge(
                    &registered.challenge,
                    PasskeyCeremony::Registration {
                        account_id: set.account_id,
                    },
                )
                .await?
            {
                set.response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::Registration)
                        .with_description("Passkey challenge expired or already used."),
                );
                continue;
            }

            let key_id = URL_SAFE_NO_PAD.encode(&registered.key_id);
            if account.passkeys().any(|passkey| passkey.key_id == key_id) {
                set.response.not_created.append(
                    id,
                    SetError::new(SetErrorType::AlreadyExists)
                        .with_description("This passkey is already registered."),
                );
                continue;
            }

            let credential_id = Id::from(last_credential_id);
            last_credential_id += 1;
            total += 1;
            account
                .credentials
                .push(Credential::Passkey(PasskeyCredential {
                    credential_id,
                    key_id,
                    public_key: URL_SAFE_NO_PAD.encode(&registered.public_key.key),
                    algorithm: registered.public_key.algorithm,
                    description: passkey.description,
                    created_at: UTCDateTime::now(),
                }));
            set.response.created.insert(
                id,
                Value::Object(Map::from(vec![(
                    Key::Property(Property::Id),
                    Value::Element(RegistryValue::Id(credential_id)),
                )])),
            );
        }
    }

    for (id, value) in set.update.drain(..) {
        let Some(credential) = account.credentials.values_mut().find_map(|credential| {
            if let Credential::Passkey(credential) = credential
                && credential.credential_id == id
            {
                Some(credential)
            } else {
                None
            }
        }) else {
            set.response.not_updated.append(id, SetError::not_found());
            continue;
        };

        let mut passkey = Passkey {
            registration: None,
            description: credential.description.clone(),
            created_at: credential.created_at,
        };
        let result = value
            .into_expanded_object()
            .try_for_each(|(key, value)| {
                let ptr = match key {
                    Key::Property(prop) => {
                        JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                    }
                    Key::Borrowed(other) => JsonPointer::parse(other),
                    Key::Owned(other) => JsonPointer::parse(&other),
                };
                patch_passkey(&mut passkey, ptr, value, false)
            })
            .and_then(|_| validate_passkey(&passkey));

        match result {
            Ok(()) => {
                credential.description = passkey.description;
                set.response.updated.append(id, None);
            }
            Err(err) => {
                set.response.not_updated.append(id, err);
            }
        }
    }

    for id in set.destroy.drain(..) {
        let credentials = &mut account.credentials.inner_mut().inner;
        if let Some(idx) = credentials.iter().position(|credential| {
            matches!(&credential.value, Credential::Passkey(passkey) if passkey.credential_id == id)
        }) {
            credentials.remove(idx);
            set.response.destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    Ok(())
}

pub(crate) fn passkey_get(get: &mut RegistryGetResponse<'_>, account: UserAccount) {
    let mut ids = get.ids.take();

    for credential in account.credentials {
        let Credential::Passkey(credential) = credential else {
            continue;
        };
        let id = credential.credential_id;
        if let Some(ids) = &mut ids {
            let Some(idx) = ids.iter().position(|requested| *requested == id) else {
                continue;
            };
            ids.swap_remove(idx);
        }
        get.insert(
            id,
            Passkey {
                registration: None,
                description: credential.description,
                created_at: credential.created_at,
            }
            .into_value(),
        );
    }

    for id in ids.into_iter().flatten() {
        get.not_found(id);
    }
}

fn patch_passkey(
    passkey: &mut Passkey,
    ptr: JsonPointer<Property>,
    value: Value<'_, Property, RegistryValue>,
    is_create: bool,
) -> Result<(), SetError<Property>> {
    match passkey.patch(JsonPointerPatch::new(&ptr).with_create(is_create), value) {
        Ok(MaybeUnpatched::Patched) => Ok(()),
        Ok(MaybeUnpatched::Unpatched { .. } | MaybeUnpatched::UnpatchedMany { .. }) => {
            Err(SetError::invalid_properties().with_description("Cannot set property."))
        }
        Err(err) => Err(err.into()),
    }
}

fn validate_passkey(passkey: &Passkey) -> Result<(), SetError<Property>> {
    let mut errors = Vec::new();
    if passkey.validate(&mut errors) {
        Ok(())
    } else {
        Err(SetError::new(SetErrorType::ValidationFailed).with_validation_errors(errors))
    }
}

#[cold]
fn forbidden(details: impl Into<trc::Value>) -> trc::Error {
    trc::JmapEvent::Forbidden.into_err().details(details)
}
