/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::{
    Server,
    gateway::{
        discovery::DiscoveryMethod,
        store::{ExternalPublicKeyData, KeySourceKind, RegistryKeyCapabilities, RegistryKeyKind},
    },
    storage::encryption::PublicKeyParse,
};
use crypto::TrustAnchors;
use jmap_proto::error::set::SetError;
use registry::{
    schema::{
        enums::{ExternalPublicKeyStatus, KeyTrust},
        prelude::Property,
        structs::{ExternalPublicKey, KeySource, SmimeTrustAnchor},
    },
    types::{datetime::UTCDateTime, map::Map},
};
use std::future::Future;
use store::write::now;
use types::id::Id;

pub(crate) trait ExternalPublicKeyManagement: Sync + Send {
    fn validate_external_public_key(
        &self,
        key: &mut ExternalPublicKey,
        current: Option<(Id, &ExternalPublicKey)>,
    ) -> impl Future<Output = ValidationResult> + Send;

    fn validate_trust_anchor(
        &self,
        anchor: &mut SmimeTrustAnchor,
    ) -> impl Future<Output = ValidationResult> + Send;
}

trait KeyMaterialUpdate {
    fn apply_key_data(&mut self, now: u64) -> Result<(), SetError<Property>>;

    fn copy_key_data(&mut self, current: &ExternalPublicKey);

    fn copy_server_data(&mut self, current: &ExternalPublicKey);

    fn apply_status(&mut self, current: &ExternalPublicKey);
}

impl ExternalPublicKeyManagement for Server {
    async fn validate_external_public_key(
        &self,
        key: &mut ExternalPublicKey,
        current: Option<(Id, &ExternalPublicKey)>,
    ) -> ValidationResult {
        let time = now();
        let date = UTCDateTime::from_timestamp(time as i64);
        let gateway = self.core.email.gateway.as_deref();
        match current {
            Some((_, current)) => {
                if key.source != current.source {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::Source)
                        .with_description(
                            "The source of an external public key cannot be changed.",
                        )));
                }
                let readdressed = key.email_address != current.email_address;
                if readdressed && key.source.harvested_kind().is_some() {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(Property::EmailAddress)
                        .with_description(
                            "The address of a harvested key cannot be changed.",
                        )));
                }
                let moved = readdressed && key.source.is_automatic();
                key.copy_server_data(current);
                if !matches!(key.source, KeySource::Manual) || key.key == current.key {
                    key.copy_key_data(current);
                } else if let Err(err) = key.apply_key_data(time) {
                    return Ok(Err(err));
                }
                key.apply_status(current);
                if moved {
                    key.clear_next_key();
                    key.clear_key();
                    key.next_check_at =
                        (key.status != ExternalPublicKeyStatus::Disabled).then_some(date);
                } else if key.status != current.status || key.pinned != current.pinned {
                    if key.status != ExternalPublicKeyStatus::Disabled
                        && key.source.is_automatic()
                        && current.status == ExternalPublicKeyStatus::Disabled
                    {
                        key.next_check_at = Some(date);
                    } else if let Some(gateway) = gateway {
                        key.schedule_next_check(gateway, time);
                    } else {
                        key.next_check_at =
                            (key.status != ExternalPublicKeyStatus::Disabled).then_some(date);
                    }
                }
            }
            None => {
                key.first_seen = date;
                key.last_seen = date;
                if key.status != ExternalPublicKeyStatus::Disabled {
                    key.status = ExternalPublicKeyStatus::Active;
                }
                match &key.source {
                    KeySource::Manual => {
                        if let Err(err) = key.apply_key_data(time) {
                            return Ok(Err(err));
                        }
                        key.trust = KeyTrust::Manual;
                    }
                    KeySource::Automatic(source) => {
                        let method = source.method;
                        key.clear_key();
                        key.trust = method.trust();
                        key.next_check_at =
                            (key.status != ExternalPublicKeyStatus::Disabled).then_some(date);
                    }
                    KeySource::HarvestedSmime | KeySource::HarvestedPgp | KeySource::Autocrypt => {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(Property::Source)
                            .with_description("Harvested keys are created by the server.")));
                    }
                }
            }
        }
        Ok(Ok(ObjectResponse::default()))
    }

    async fn validate_trust_anchor(&self, anchor: &mut SmimeTrustAnchor) -> ValidationResult {
        let Ok(details) = TrustAnchors::inspect(anchor.certificate.as_bytes()) else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::Certificate)
                .with_description("Must be a single CA certificate.")));
        };
        anchor.subject = details.subject;
        anchor.expires_at = UTCDateTime::from_timestamp(details.expires_at as i64);
        Ok(Ok(ObjectResponse::default()))
    }
}

impl KeyMaterialUpdate for ExternalPublicKey {
    fn apply_key_data(&mut self, now: u64) -> Result<(), SetError<Property>> {
        let parsed = self.parse_keys(now).map_err(|err| {
            SetError::invalid_properties()
                .with_property(Property::Key)
                .with_description(err.description())
        })?;
        let [fingerprint] = parsed.fingerprints.as_slice() else {
            return Err(SetError::invalid_properties()
                .with_property(Property::Key)
                .with_description(
                    "An external public key must hold a single key or certificate.",
                ));
        };
        let fingerprint = fingerprint.to_hex();
        if self.fingerprint.as_deref() != Some(fingerprint.as_str()) {
            self.smime_ciphers = Map::default();
            self.smime_oaep = false;
            self.smime_signed_at = None;
        }
        self.kind = Some(parsed.kind.registry_kind());
        self.key_type = Some(parsed.set.key_type());
        self.fingerprint = Some(fingerprint);
        self.capabilities = parsed.registry_capabilities();
        self.expires_at = parsed
            .expires_at
            .map(|at| UTCDateTime::from_timestamp(at as i64));
        Ok(())
    }

    fn copy_key_data(&mut self, current: &ExternalPublicKey) {
        self.key = current.key.clone();
        self.kind = current.kind;
        self.key_type = current.key_type.clone();
        self.fingerprint = current.fingerprint.clone();
        self.capabilities = current.capabilities.clone();
        self.expires_at = current.expires_at;
    }

    fn copy_server_data(&mut self, current: &ExternalPublicKey) {
        self.trust = current.trust;
        self.first_seen = current.first_seen;
        self.last_seen = current.last_seen;
        self.last_checked = current.last_checked;
        self.next_check_at = current.next_check_at;
        self.next_key = current.next_key.clone();
        self.next_key_type = current.next_key_type.clone();
        self.next_fingerprint = current.next_fingerprint.clone();
        self.next_capabilities = current.next_capabilities.clone();
        self.next_expires_at = current.next_expires_at;
        self.blocked_fingerprints = current.blocked_fingerprints.clone();
    }

    fn apply_status(&mut self, current: &ExternalPublicKey) {
        let pending = current.status == ExternalPublicKeyStatus::PendingApproval;
        match self.status {
            ExternalPublicKeyStatus::Active if pending => {
                self.promote_next_key();
                if !self.source.is_automatic() {
                    self.trust = KeyTrust::Manual;
                }
            }
            ExternalPublicKeyStatus::Rejected if pending => {
                if let Some(fingerprint) = current.next_fingerprint.as_deref() {
                    self.block_fingerprint(fingerprint);
                }
                self.clear_next_key();
                self.status = ExternalPublicKeyStatus::Active;
            }
            ExternalPublicKeyStatus::Disabled if pending => {
                self.clear_next_key();
                self.status = ExternalPublicKeyStatus::Disabled;
            }
            ExternalPublicKeyStatus::PendingApproval | ExternalPublicKeyStatus::Rejected => {
                self.status = current.status;
            }
            _ => {}
        }
    }
}
