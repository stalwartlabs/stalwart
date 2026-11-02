/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::{Server, storage::encryption::PublicKeyParse};
use crypto::{KeyCapability, KeyKind, KeyWarning, ParsedKeys};
use jmap_proto::error::set::SetError;
use registry::{
    jmap::{IntoValue, JmapValue},
    schema::{
        enums::{
            HeaderProtection, PublicKeyCapability, PublicKeyKind, PublicKeyWarning, StorageQuota,
        },
        prelude::{ObjectType, Property},
        structs::{EncryptionAtRest, PublicKey},
    },
    types::{EnumImpl, datetime::UTCDateTime, map::Map},
};
use std::future::Future;
use store::{
    ahash::AHashSet,
    registry::{RegistryObjectCounter, RegistryQuery},
    write::now,
};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub(crate) trait PublicKeyManagement: Sync + Send {
    fn validate_public_key(
        &self,
        account_id: u32,
        key: &mut PublicKey,
        old_key: Option<(Id, &PublicKey)>,
    ) -> impl Future<Output = ValidationResult> + Send;

    fn validate_encryption_at_rest(
        &self,
        account_id: Option<Id>,
        encryption: &EncryptionAtRest,
    ) -> impl Future<Output = trc::Result<Result<(), SetError<Property>>>> + Send;

    fn public_key_properties(
        &self,
        key: &PublicKey,
        properties: &AHashSet<Property>,
        extra_properties: &mut VecMap<Property, JmapValue<'static>>,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn public_key_matches_account(
        &self,
        account_id: Id,
        parsed: &ParsedKeys,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl PublicKeyManagement for Server {
    async fn validate_public_key(
        &self,
        account_id: u32,
        key: &mut PublicKey,
        old_key: Option<(Id, &PublicKey)>,
    ) -> ValidationResult {
        let mut response = ObjectResponse::default();

        if let Some((_, old_key)) = old_key {
            if key.key == old_key.key {
                return Ok(Ok(response));
            }
        } else {
            let num_keys = self
                .registry()
                .query::<RegistryObjectCounter>(
                    RegistryQuery::new(ObjectType::PublicKey).with_account(account_id),
                )
                .await?
                .0 as u32;
            let account = self.account(account_id).await?;
            let key_quota = self.object_quota(account.object_quotas(), StorageQuota::MaxPublicKeys);
            if num_keys >= key_quota {
                return Ok(Err(SetError::over_quota().with_description(format!(
                    "You have exceeded your quota of {} public keys.",
                    key_quota
                ))));
            }
        }

        let parsed = match key.parse_keys(now()) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Key)
                    .with_description(err.description())));
            }
        };

        key.expires_at = parsed
            .expires_at
            .map(|expires_at| UTCDateTime::from_timestamp(expires_at as i64));
        key.email_addresses = Map::new(
            parsed
                .addresses
                .iter()
                .map(|address| address.to_string())
                .collect(),
        );
        response
            .object
            .insert_unchecked(Property::ExpiresAt, key.expires_at.into_value());
        response.object.insert_unchecked(
            Property::EmailAddresses,
            key.email_addresses.clone().into_value(),
        );

        Ok(Ok(response))
    }

    async fn public_key_properties(
        &self,
        key: &PublicKey,
        properties: &AHashSet<Property>,
        extra_properties: &mut VecMap<Property, JmapValue<'static>>,
    ) -> trc::Result<()> {
        let wants = |property: Property| properties.is_empty() || properties.contains(&property);
        if !wants(Property::Kind)
            && !wants(Property::KeyType)
            && !wants(Property::Fingerprints)
            && !wants(Property::Capabilities)
            && !wants(Property::Warnings)
        {
            return Ok(());
        }

        let parsed = key.parse_keys(now()).ok();

        if wants(Property::Kind) {
            extra_properties.append(
                Property::Kind,
                parsed
                    .as_ref()
                    .map(|parsed| match parsed.kind {
                        KeyKind::OpenPgp => PublicKeyKind::OpenPgp,
                        KeyKind::Smime => PublicKeyKind::Smime,
                    })
                    .into_value(),
            );
        }
        if wants(Property::KeyType) {
            extra_properties.append(
                Property::KeyType,
                parsed
                    .as_ref()
                    .map(|parsed| parsed.set.key_type())
                    .into_value(),
            );
        }
        if wants(Property::Fingerprints) {
            extra_properties.append(
                Property::Fingerprints,
                JmapValue::Array(
                    parsed
                        .iter()
                        .flat_map(|parsed| parsed.fingerprints.iter())
                        .map(|fingerprint| JmapValue::Str(fingerprint.to_hex().into()))
                        .collect(),
                ),
            );
        }
        if wants(Property::Capabilities) {
            extra_properties.append(
                Property::Capabilities,
                JmapValue::Array(
                    parsed
                        .iter()
                        .flat_map(|parsed| parsed.capabilities.iter())
                        .map(|capability| {
                            JmapValue::Str(
                                match capability {
                                    KeyCapability::Aead => PublicKeyCapability::Aead,
                                    KeyCapability::PostQuantum => PublicKeyCapability::PostQuantum,
                                }
                                .as_str()
                                .into(),
                            )
                        })
                        .collect(),
                ),
            );
        }
        if wants(Property::Warnings) {
            let warnings = match &parsed {
                Some(parsed) => {
                    let mut warnings = parsed
                        .warnings
                        .iter()
                        .map(|warning| match warning {
                            KeyWarning::WeakRsa => PublicKeyWarning::WeakRsa,
                            KeyWarning::NoKnownDecryptor => PublicKeyWarning::NoKnownDecryptor,
                            KeyWarning::PostQuantumOnly => PublicKeyWarning::PostQuantumOnly,
                            KeyWarning::ExpiresSoon => PublicKeyWarning::ExpiresSoon,
                        })
                        .collect::<Vec<_>>();
                    if !parsed.addresses.is_empty()
                        && !self
                            .public_key_matches_account(key.account_id, parsed)
                            .await?
                    {
                        warnings.push(PublicKeyWarning::AddressMismatch);
                    }
                    warnings
                }
                None => vec![PublicKeyWarning::Unusable],
            };
            extra_properties.append(
                Property::Warnings,
                JmapValue::Array(
                    warnings
                        .into_iter()
                        .map(|warning| JmapValue::Str(warning.as_str().into()))
                        .collect(),
                ),
            );
        }

        Ok(())
    }

    async fn public_key_matches_account(
        &self,
        account_id: Id,
        parsed: &ParsedKeys,
    ) -> trc::Result<bool> {
        let account = self.account_info(account_id.document_id()).await?;
        Ok(parsed.addresses.iter().any(|address| {
            account
                .addresses()
                .iter()
                .any(|account_address| account_address.eq_ignore_ascii_case(address))
        }))
    }

    async fn validate_encryption_at_rest(
        &self,
        account_id: Option<Id>,
        encryption: &EncryptionAtRest,
    ) -> trc::Result<Result<(), SetError<Property>>> {
        let EncryptionAtRest::Enabled(settings) = encryption else {
            return Ok(Ok(()));
        };
        let invalid = |description: String| {
            Ok(Err(SetError::invalid_properties()
                .with_property(Property::EncryptionAtRest)
                .with_description(description)))
        };

        if settings.header_protection == HeaderProtection::Baseline {
            return invalid(
                "Header protection with a hidden Subject is not available for encryption at rest."
                    .to_string(),
            );
        }
        let Some(account_id) = account_id else {
            return Ok(Ok(()));
        };
        let Some(public_key) = self
            .registry()
            .object::<PublicKey>(settings.public_key)
            .await
            .caused_by(trc::location!())?
            .filter(|key| key.account_id == account_id)
        else {
            return invalid("The selected public key does not exist.".to_string());
        };
        match public_key.parse_keys(now()) {
            Ok(_) => Ok(Ok(())),
            Err(err) => invalid(format!(
                "The selected public key cannot be used: {}",
                err.description()
            )),
        }
    }
}
