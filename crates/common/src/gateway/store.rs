/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::{GatewayConfig, KeyTrustRank},
    resolver::{KeyCacheKey, KeyEntry, ResolvedKey},
};
use crate::{
    Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation,
    storage::encryption::PublicKeyParse,
};
use crypto::{KeyCapability, KeyKind, ParsedKeys, SmimeCapabilities};
use encodify::base64::{LENIENT, STANDARD};
use registry::{
    schema::{
        enums::{
            ExternalPublicKeyStatus, KeyTrust, PublicKeyCapability, PublicKeyKind, SmimeCipher,
        },
        prelude::{Object, ObjectType, Property},
        structs::{ExternalPublicKey, KeySource},
    },
    types::{datetime::UTCDateTime, id::ObjectId, map::Map},
};
use std::{sync::Arc, time::Duration};
use store::{
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::AddContext;
use types::id::Id;

pub const LAST_SEEN_RESOLUTION: u64 = 86400;
pub const KEY_CHECK_INTERVAL: Duration = Duration::from_secs(300);
pub const MAX_KEYS_PER_RUN: usize = 1024;
const MAX_DUE_KEYS: usize = 2 * MAX_KEYS_PER_RUN;
const MAX_SIGNING_TIME_SKEW: u64 = 86400;
const MAX_BLOCKED_FINGERPRINTS: usize = 8;
const EXPIRY_MARGIN_SECS: u64 = 2 * KEY_CHECK_INTERVAL.as_secs();
pub const MAX_STORED_KEY_SIZE: usize = 64 * 1024;
const SMIME_RECHECK_SECS: u64 = 86400;

pub struct KeyCandidate {
    pub address: Box<str>,
    pub key: Vec<u8>,
    pub parsed: ParsedKeys,
    pub source: KeySource,
    pub trust: KeyTrust,
    pub valid_until: Option<u64>,
    pub capabilities: Option<SmimeCapabilities>,
    pub signed_at: Option<u64>,
}

pub struct ExternalPublicKeyRow {
    pub id: Id,
    pub revision: u64,
    pub key: ExternalPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChange {
    Unchanged,
    Updated,
    Stored,
    Replaced,
    PendingApproval,
}

pub trait ExternalPublicKeyStore: Sync + Send {
    fn load_key_entry(
        &self,
        key: &KeyCacheKey,
    ) -> impl Future<Output = trc::Result<Option<KeyEntry>>> + Send;

    fn store_key_candidate(
        &self,
        candidate: KeyCandidate,
    ) -> impl Future<Output = trc::Result<KeyChange>> + Send;

    fn external_public_key_row(
        &self,
        id: Id,
    ) -> impl Future<Output = trc::Result<Option<ExternalPublicKeyRow>>> + Send;

    fn external_public_key_for(
        &self,
        address: &str,
    ) -> impl Future<Output = trc::Result<Option<ExternalPublicKeyRow>>> + Send;

    fn due_external_public_keys(
        &self,
        now: u64,
    ) -> impl Future<Output = trc::Result<Vec<Id>>> + Send;

    fn has_due_external_public_keys(
        &self,
        now: u64,
    ) -> impl Future<Output = trc::Result<bool>> + Send;

    fn update_external_public_key(
        &self,
        row: &ExternalPublicKeyRow,
        new: ExternalPublicKey,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn invalidate_external_public_key(
        &self,
        address: &str,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

pub trait ExternalPublicKeyData {
    fn key_text(&self) -> &str;

    fn key_bytes(&self) -> Vec<u8>;

    fn set_key(&mut self, candidate: &KeyCandidate, fingerprint: String);

    fn set_next_key(&mut self, candidate: &KeyCandidate, fingerprint: String);

    fn clear_key(&mut self);

    fn clear_next_key(&mut self);

    fn promote_next_key(&mut self) -> bool;

    fn replacement_due(&self, now: u64) -> bool;

    fn block_fingerprint(&mut self, fingerprint: &str);

    fn revoke(&mut self, fingerprints: &[String]) -> bool;

    fn accept_candidate(
        &mut self,
        candidate: &KeyCandidate,
        fingerprint: String,
        now: u64,
    ) -> KeyChange;

    fn schedule_next_check(&mut self, gateway: &GatewayConfig, now: u64);

    fn schedule_retry(&mut self, gateway: &GatewayConfig, now: u64);

    fn differs_when_resolved(&self, other: &ExternalPublicKey) -> bool;
}

pub trait KeySourceKind {
    fn harvested_kind(&self) -> Option<KeyKind>;

    fn is_automatic(&self) -> bool;
}

pub trait RegistryKeyCapabilities {
    fn registry_capabilities(&self) -> Map<PublicKeyCapability>;
}

pub trait RegistryKeyKind {
    fn registry_kind(self) -> PublicKeyKind;
}

impl ExternalPublicKeyStore for Server {
    async fn load_key_entry(&self, key: &KeyCacheKey) -> trc::Result<Option<KeyEntry>> {
        let Some(ExternalPublicKeyRow { key: row, .. }) =
            self.external_public_key_for(&key.address).await?
        else {
            return Ok(None);
        };

        Ok(Some(KeyEntry {
            key: (row.status != ExternalPublicKeyStatus::Disabled && row.key.is_some())
                .then(|| row.parse_keys(now()).ok())
                .flatten()
                .map(|parsed| Arc::new(ResolvedKey::new(&row, parsed))),
            fingerprints: row
                .fingerprint
                .iter()
                .chain(row.next_fingerprint.iter())
                .chain(row.blocked_fingerprints.iter())
                .map(|fingerprint| Box::from(fingerprint.as_str()))
                .collect(),
            last_seen: row.last_seen.timestamp() as u64,
        }))
    }

    async fn external_public_key_row(&self, id: Id) -> trc::Result<Option<ExternalPublicKeyRow>> {
        Ok(self
            .registry()
            .get(ObjectId::new(ObjectType::ExternalPublicKey, id))
            .await?
            .map(|object| ExternalPublicKeyRow {
                id,
                revision: object.revision,
                key: object.into(),
            }))
    }

    async fn external_public_key_for(
        &self,
        address: &str,
    ) -> trc::Result<Option<ExternalPublicKeyRow>> {
        match self
            .registry()
            .primary_key(
                ObjectType::ExternalPublicKey.into(),
                Property::EmailAddress,
                address.as_bytes().to_vec(),
            )
            .await
            .caused_by(trc::location!())?
        {
            Some(id) => self.external_public_key_row(id.id()).await,
            None => Ok(None),
        }
    }

    async fn due_external_public_keys(&self, now: u64) -> trc::Result<Vec<Id>> {
        self.registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::ExternalPublicKey)
                    .less_than_or_equal(Property::NextCheckAt, now)
                    .with_limit(MAX_DUE_KEYS),
            )
            .await
            .caused_by(trc::location!())
    }

    async fn has_due_external_public_keys(&self, now: u64) -> trc::Result<bool> {
        self.registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::ExternalPublicKey)
                    .less_than_or_equal(Property::NextCheckAt, now)
                    .with_limit(1),
            )
            .await
            .caused_by(trc::location!())
            .map(|due| !due.is_empty())
    }

    async fn store_key_candidate(&self, mut candidate: KeyCandidate) -> trc::Result<KeyChange> {
        let time = now();
        candidate.address = candidate.address.to_lowercase().into_boxed_str();
        let Some(fingerprint) = candidate
            .fingerprint()
            .filter(|_| candidate.key.len() <= MAX_STORED_KEY_SIZE)
        else {
            return Ok(KeyChange::Unchanged);
        };
        let Some(row) = self.external_public_key_for(&candidate.address).await? else {
            let address = candidate.address.clone();
            let mut row = candidate.into_row(fingerprint, time);
            if let Some(gateway) = self.core.email.gateway.as_deref() {
                row.schedule_next_check(gateway, time);
            }
            let object = Object::new(row.into());
            let result = match self.registry().write(RegistryWrite::insert(&object)).await {
                Err(err) if err.is_assertion_failure() => return Ok(KeyChange::Unchanged),
                result => result.caused_by(trc::location!())?,
            };
            if matches!(result, RegistryWriteResult::PrimaryKeyConflict { .. }) {
                return Ok(KeyChange::Unchanged);
            }
            assert_key_written(result)?;
            self.invalidate_external_public_key(&address).await?;
            return Ok(KeyChange::Stored);
        };

        if row.key.fingerprint.as_deref() == Some(fingerprint.as_str()) {
            return match candidate.refreshed(&row.key, time) {
                Some(updated) => {
                    self.update_external_public_key(&row, updated).await?;
                    Ok(KeyChange::Updated)
                }
                None => Ok(KeyChange::Unchanged),
            };
        }
        if row.key.status == ExternalPublicKeyStatus::Disabled
            || (row.key.source.harvested_kind() != Some(candidate.parsed.kind)
                && !candidate.outranks_harvested(&row.key))
            || row.key.next_fingerprint.as_deref() == Some(fingerprint.as_str())
            || row
                .key
                .blocked_fingerprints
                .iter()
                .any(|blocked| *blocked == fingerprint)
        {
            return Ok(KeyChange::Unchanged);
        }

        let mut updated = row.key.clone();
        let change = updated.accept_candidate(&candidate, fingerprint, time);
        if change != KeyChange::Unchanged {
            if let Some(gateway) = self.core.email.gateway.as_deref() {
                updated.schedule_next_check(gateway, time);
            }
            self.update_external_public_key(&row, updated).await?;
        }
        Ok(change)
    }

    async fn update_external_public_key(
        &self,
        row: &ExternalPublicKeyRow,
        new: ExternalPublicKey,
    ) -> trc::Result<()> {
        let address = new.email_address.clone();
        let affects_cache = new.differs_when_resolved(&row.key);
        let new = Object::new(new.into());
        let mut current = Object::new(row.key.clone().into());
        current.revision = row.revision;
        let result = self
            .registry()
            .write(RegistryWrite::update(row.id, &new, &current))
            .await
            .caused_by(trc::location!())?;
        assert_key_written(result)?;
        if affects_cache {
            self.invalidate_external_public_key(&address).await
        } else {
            Ok(())
        }
    }

    async fn invalidate_external_public_key(&self, address: &str) -> trc::Result<()> {
        self.invalidate_caches(CacheInvalidationBuilder::default().with_invalidation(
            CacheInvalidation::ExternalPublicKey(KeyCacheKey::address_hash(address)),
        ))
        .await
    }
}

impl ExternalPublicKeyData for ExternalPublicKey {
    fn key_text(&self) -> &str {
        self.key.as_deref().unwrap_or_default()
    }

    fn key_bytes(&self) -> Vec<u8> {
        let key = self.key_text().trim_ascii();
        if key.starts_with("-----") {
            key.as_bytes().to_vec()
        } else {
            LENIENT
                .decode(key.as_bytes())
                .unwrap_or_else(|_| key.as_bytes().to_vec())
        }
    }

    fn set_key(&mut self, candidate: &KeyCandidate, fingerprint: String) {
        self.key = Some(STANDARD.encode(&candidate.key));
        self.kind = Some(candidate.parsed.kind.registry_kind());
        self.key_type = Some(candidate.parsed.set.key_type());
        self.fingerprint = Some(fingerprint);
        self.capabilities = candidate.parsed.registry_capabilities();
        self.expires_at = candidate.expires_at();
        self.source = candidate.source.clone();
        self.trust = candidate.trust;
        self.smime_ciphers = Map::default();
        self.smime_oaep = false;
        self.smime_signed_at = None;
        candidate.apply_capabilities(self);
        self.clear_next_key();
    }

    fn set_next_key(&mut self, candidate: &KeyCandidate, fingerprint: String) {
        self.next_key = Some(STANDARD.encode(&candidate.key));
        self.next_key_type = Some(candidate.parsed.set.key_type());
        self.next_fingerprint = Some(fingerprint);
        self.next_capabilities = candidate.parsed.registry_capabilities();
        self.next_expires_at = candidate.expires_at();
        self.status = ExternalPublicKeyStatus::PendingApproval;
    }

    fn clear_key(&mut self) {
        self.key = None;
        self.kind = None;
        self.key_type = None;
        self.fingerprint = None;
        self.capabilities = Map::default();
        self.expires_at = None;
        self.smime_ciphers = Map::default();
        self.smime_oaep = false;
        self.smime_signed_at = None;
    }

    fn clear_next_key(&mut self) {
        self.next_key = None;
        self.next_key_type = None;
        self.next_fingerprint = None;
        self.next_capabilities = Map::default();
        self.next_expires_at = None;
        if self.status == ExternalPublicKeyStatus::PendingApproval {
            self.status = ExternalPublicKeyStatus::Active;
        }
    }

    fn promote_next_key(&mut self) -> bool {
        if self.next_key.is_none() {
            return false;
        }
        self.key = self.next_key.take();
        self.key_type = self.next_key_type.take();
        self.fingerprint = self.next_fingerprint.take();
        self.capabilities = std::mem::take(&mut self.next_capabilities);
        self.expires_at = self.next_expires_at.take();
        self.smime_ciphers = Map::default();
        self.smime_oaep = false;
        self.smime_signed_at = None;
        self.clear_next_key();
        true
    }

    fn replacement_due(&self, now: u64) -> bool {
        self.next_key.is_some()
            && !self.pinned
            && self
                .expires_at
                .is_some_and(|expires_at| expires_at.timestamp() as u64 <= now)
    }

    fn block_fingerprint(&mut self, fingerprint: &str) {
        if !self.blocked_fingerprints.iter().any(|b| b == fingerprint) {
            if self.blocked_fingerprints.len() >= MAX_BLOCKED_FINGERPRINTS {
                self.blocked_fingerprints.inner_mut().remove(0);
            }
            self.blocked_fingerprints.push(fingerprint.to_string());
        }
    }

    fn revoke(&mut self, fingerprints: &[String]) -> bool {
        let mut revoked = false;
        if let Some(fingerprint) = self
            .next_fingerprint
            .clone()
            .filter(|fingerprint| fingerprints.contains(fingerprint))
        {
            self.block_fingerprint(&fingerprint);
            self.clear_next_key();
            revoked = true;
        }
        if let Some(fingerprint) = self
            .fingerprint
            .clone()
            .filter(|fingerprint| fingerprints.contains(fingerprint))
        {
            self.block_fingerprint(&fingerprint);
            if self.pinned || !self.promote_next_key() {
                self.clear_key();
            }
            revoked = true;
        }
        revoked
    }

    fn accept_candidate(
        &mut self,
        candidate: &KeyCandidate,
        fingerprint: String,
        now: u64,
    ) -> KeyChange {
        if self.next_fingerprint.as_deref() == Some(fingerprint.as_str())
            && (self.pinned || !self.source.is_automatic())
        {
            return KeyChange::Unchanged;
        }
        if self.key.is_none() && (!self.pinned || self.blocked_fingerprints.is_empty()) {
            self.set_key(candidate, fingerprint);
            self.first_seen = UTCDateTime::from_timestamp(now as i64);
            self.last_seen = self.first_seen;
            KeyChange::Stored
        } else if candidate.may_replace(self, now) {
            self.set_key(candidate, fingerprint);
            self.last_seen = UTCDateTime::from_timestamp(now as i64);
            KeyChange::Replaced
        } else {
            self.set_next_key(candidate, fingerprint);
            KeyChange::PendingApproval
        }
    }

    fn schedule_next_check(&mut self, gateway: &GatewayConfig, now: u64) {
        let expires_at = self
            .expires_at
            .map(|at| at.timestamp() as u64)
            .filter(|_| self.status != ExternalPublicKeyStatus::Disabled);
        let check_at = match &self.source {
            _ if self.status == ExternalPublicKeyStatus::Disabled => None,
            KeySource::Automatic(_) => {
                let check_at = now + gateway.key_refresh_interval.as_secs();
                Some(
                    expires_at
                        .filter(|expires_at| *expires_at > now)
                        .map_or(check_at, |expires_at| {
                            check_at.min(expires_at.saturating_sub(EXPIRY_MARGIN_SECS))
                        }),
                )
            }
            KeySource::HarvestedSmime if self.trust != KeyTrust::Manual && self.key.is_some() => {
                Some(now - (now % SMIME_RECHECK_SECS) + SMIME_RECHECK_SECS)
            }
            _ => None,
        };
        let promote_at = expires_at.filter(|_| self.next_key.is_some() && !self.pinned);
        let next_check = match (check_at, promote_at) {
            (Some(check_at), Some(promote_at)) => Some(check_at.min(promote_at)),
            (check_at, promote_at) => check_at.or(promote_at),
        };
        self.next_check_at = next_check.map(|at| {
            UTCDateTime::from_timestamp(at.max(now + KEY_CHECK_INTERVAL.as_secs()) as i64)
        });
    }

    fn schedule_retry(&mut self, gateway: &GatewayConfig, now: u64) {
        let confirmed = self
            .last_checked
            .unwrap_or(self.first_seen)
            .timestamp()
            .max(0) as u64;
        let delay = now.saturating_sub(confirmed).clamp(
            KEY_CHECK_INTERVAL.as_secs(),
            gateway
                .key_refresh_interval
                .as_secs()
                .max(KEY_CHECK_INTERVAL.as_secs()),
        );
        let retry_before = self
            .expires_at
            .map(|at| at.timestamp() as u64)
            .filter(|at| *at > now || (self.next_key.is_some() && !self.pinned))
            .map(|at| at.max(now + KEY_CHECK_INTERVAL.as_secs()));
        let retry_at = retry_before.map_or(now + delay, |at| at.min(now + delay));
        self.next_check_at = Some(UTCDateTime::from_timestamp(retry_at as i64));
    }

    fn differs_when_resolved(&self, other: &ExternalPublicKey) -> bool {
        self.key != other.key
            || self.status != other.status
            || self.trust != other.trust
            || self.expires_at != other.expires_at
            || self.last_seen != other.last_seen
            || self.next_fingerprint != other.next_fingerprint
            || self.blocked_fingerprints != other.blocked_fingerprints
            || self.smime_oaep != other.smime_oaep
            || self.smime_ciphers != other.smime_ciphers
            || self.authenticated_encryption != other.authenticated_encryption
    }
}

fn assert_key_written(result: RegistryWriteResult) -> trc::Result<()> {
    match result {
        RegistryWriteResult::Success(_) => Ok(()),
        _ => Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("External public key was not written.")
            .caused_by(trc::location!())),
    }
}

impl KeySourceKind for KeySource {
    fn harvested_kind(&self) -> Option<KeyKind> {
        match self {
            KeySource::HarvestedSmime => Some(KeyKind::Smime),
            KeySource::HarvestedPgp | KeySource::Autocrypt => Some(KeyKind::OpenPgp),
            KeySource::Manual | KeySource::Automatic(_) => None,
        }
    }

    fn is_automatic(&self) -> bool {
        matches!(self, KeySource::Automatic(_))
    }
}

impl RegistryKeyKind for KeyKind {
    fn registry_kind(self) -> PublicKeyKind {
        match self {
            KeyKind::OpenPgp => PublicKeyKind::OpenPgp,
            KeyKind::Smime => PublicKeyKind::Smime,
        }
    }
}

impl KeyCandidate {
    pub fn fingerprint(&self) -> Option<String> {
        match self.parsed.fingerprints.as_slice() {
            [fingerprint] => Some(fingerprint.to_hex()),
            _ => None,
        }
    }

    fn expires_at(&self) -> Option<UTCDateTime> {
        match (self.parsed.expires_at, self.valid_until) {
            (Some(expires_at), Some(valid_until)) => Some(expires_at.min(valid_until)),
            (expires_at, valid_until) => expires_at.or(valid_until),
        }
        .map(|at| UTCDateTime::from_timestamp(at as i64))
    }

    fn outranks_harvested(&self, current: &ExternalPublicKey) -> bool {
        !current.pinned
            && current.source.harvested_kind().is_some()
            && self.trust.rank() > current.trust.rank()
    }

    fn may_replace(&self, current: &ExternalPublicKey, now: u64) -> bool {
        !current.pinned
            && (current.source.is_automatic()
                || (self.trust == KeyTrust::Verified && self.trust.rank() >= current.trust.rank())
                || (current.trust == KeyTrust::Unverified
                    && self.trust.rank() > current.trust.rank())
                || current
                    .expires_at
                    .is_some_and(|expires_at| expires_at.timestamp() as u64 <= now)
                || (self.parsed.kind == KeyKind::OpenPgp
                    && crypto::certifies(
                        &current.key_bytes(),
                        &self.key,
                        &current.email_address,
                        now,
                    )))
    }

    pub fn refreshed(&self, row: &ExternalPublicKey, now: u64) -> Option<ExternalPublicKey> {
        let mut updated = row.clone();
        let mut changed = false;
        if now.saturating_sub(row.last_seen.timestamp() as u64) >= LAST_SEEN_RESOLUTION {
            updated.last_seen = UTCDateTime::from_timestamp(now as i64);
            changed = true;
        }
        let automatic = row.source.is_automatic();
        let authoritative = automatic && self.source == row.source;
        if row.source.harvested_kind().is_some() && self.trust.rank() > row.trust.rank() {
            updated.trust = self.trust;
            updated.source = self.source.clone();
            changed = true;
        }
        if authoritative && row.expires_at != self.expires_at() {
            updated.expires_at = self.expires_at();
            changed = true;
        }
        if !row.pinned
            && ((!automatic && self.extends_expiry(row))
                || (authoritative && self.key != row.key_bytes()))
        {
            updated.key = Some(STANDARD.encode(&self.key));
            updated.key_type = Some(self.parsed.set.key_type());
            updated.capabilities = self.parsed.registry_capabilities();
            updated.expires_at = self.expires_at();
            changed = true;
        }
        if self.apply_capabilities(&mut updated) {
            changed = true;
        }
        changed.then_some(updated)
    }

    fn apply_capabilities(&self, row: &mut ExternalPublicKey) -> bool {
        if let (Some(capabilities), Some(signed_at)) = (&self.capabilities, self.signed_at)
            && signed_at <= now() + MAX_SIGNING_TIME_SKEW
            && row
                .smime_signed_at
                .is_none_or(|known| (known.timestamp() as u64) < signed_at)
        {
            row.smime_ciphers = Self::registry_ciphers(capabilities);
            row.smime_oaep = capabilities.rsaes_oaep;
            row.smime_signed_at = Some(UTCDateTime::from_timestamp(signed_at as i64));
            true
        } else {
            false
        }
    }

    fn extends_expiry(&self, row: &ExternalPublicKey) -> bool {
        match (self.parsed.expires_at, row.expires_at) {
            (None, Some(_)) => true,
            (Some(new), Some(known)) => new > known.timestamp() as u64,
            _ => false,
        }
    }

    fn registry_ciphers(capabilities: &SmimeCapabilities) -> Map<SmimeCipher> {
        let mut ciphers = Map::default();
        for cipher in &capabilities.ciphers {
            ciphers.push(match cipher {
                crypto::SmimeCipher::Aes128Cbc => SmimeCipher::Aes128Cbc,
                crypto::SmimeCipher::Aes192Cbc => SmimeCipher::Aes192Cbc,
                crypto::SmimeCipher::Aes256Cbc => SmimeCipher::Aes256Cbc,
                crypto::SmimeCipher::Aes128Gcm => SmimeCipher::Aes128Gcm,
                crypto::SmimeCipher::Aes192Gcm => SmimeCipher::Aes192Gcm,
                crypto::SmimeCipher::Aes256Gcm => SmimeCipher::Aes256Gcm,
                crypto::SmimeCipher::ChaCha20Poly1305 => SmimeCipher::ChaCha20Poly1305,
            });
        }
        ciphers
    }

    fn into_row(self, fingerprint: String, now: u64) -> ExternalPublicKey {
        let time = UTCDateTime::from_timestamp(now as i64);
        let mut row = ExternalPublicKey {
            email_address: self.address.to_string(),
            first_seen: time,
            last_seen: time,
            last_checked: Some(time),
            ..Default::default()
        };
        row.set_key(&self, fingerprint);
        row
    }
}

impl RegistryKeyCapabilities for ParsedKeys {
    fn registry_capabilities(&self) -> Map<PublicKeyCapability> {
        let mut capabilities = Map::default();
        if self.capabilities.contains(KeyCapability::Aead) {
            capabilities.push(PublicKeyCapability::Aead);
        }
        if self.capabilities.contains(KeyCapability::PostQuantum) {
            capabilities.push(PublicKeyCapability::PostQuantum);
        }
        capabilities
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/gateway/store/tests.rs"]
mod tests;
