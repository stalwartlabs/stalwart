/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::KeyTrustRank,
    store::{ExternalPublicKeyData, ExternalPublicKeyStore},
};
use crate::{Server, storage::encryption::PublicKeyParse};
use crypto::{KeyKind, ParsedKeys, Profile, RecipientSet};
use quick_cache::Equivalent;
use registry::schema::{
    enums::{KeyTrust, SmimeCipher},
    structs::ExternalPublicKey,
};
use smallvec::SmallVec;
use std::{borrow::Cow, sync::Arc};
use store::write::now;
use utils::cache::CacheItemWeight;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyCacheKey {
    pub address: Box<str>,
}

#[derive(Hash)]
struct KeyCacheRef<'x>(&'x str);

#[derive(Debug)]
pub struct ResolvedKey {
    pub recipients: RecipientSet,
    pub kind: KeyKind,
    pub trust: KeyTrust,
    pub fingerprint: Box<str>,
    pub expires_at: Option<u64>,
    pub profile: Profile,
}

#[derive(Debug, Default)]
pub struct KeyEntry {
    pub key: Option<Arc<ResolvedKey>>,
    pub fingerprints: SmallVec<[Box<str>; 2]>,
    pub last_seen: u64,
}

pub struct KeyQuery<'x> {
    pub address: &'x str,
    pub min_trust: KeyTrust,
}

pub enum Resolution {
    Found(Arc<ResolvedKey>),
    NotFound,
}

pub trait KeyResolver: Sync + Send {
    fn resolve_key(
        &self,
        query: &KeyQuery<'_>,
    ) -> impl Future<Output = trc::Result<Resolution>> + Send;

    fn key_entry(
        &self,
        key: &KeyCacheKey,
    ) -> impl Future<Output = trc::Result<Option<Arc<KeyEntry>>>> + Send;
}

impl KeyResolver for Server {
    async fn resolve_key(&self, query: &KeyQuery<'_>) -> trc::Result<Resolution> {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return Ok(Resolution::NotFound);
        };
        let address = KeyCacheKey::normalize(query.address);
        let entry = match self
            .inner
            .cache
            .external_public_keys
            .get(&KeyCacheRef(&address))
        {
            Some(entry) => entry,
            None => {
                self.key_entry(&KeyCacheKey {
                    address: address.into(),
                })
                .await?
            }
        };
        Ok(entry
            .and_then(|entry| {
                entry
                    .select(query, &gateway.methods, now())
                    .cloned()
                    .map(Resolution::Found)
            })
            .unwrap_or(Resolution::NotFound))
    }

    async fn key_entry(&self, key: &KeyCacheKey) -> trc::Result<Option<Arc<KeyEntry>>> {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return Ok(None);
        };
        match self
            .inner
            .cache
            .external_public_keys
            .get_value_or_guard_async(key)
            .await
        {
            Ok(entry) => Ok(entry),
            Err(guard) => {
                let entry = self.load_key_entry(key).await?.map(Arc::new);
                let ttl = if entry.is_some() {
                    gateway.key_refresh_interval
                } else {
                    gateway.negative_ttl
                };
                guard.insert(entry.clone(), ttl);
                Ok(entry)
            }
        }
    }
}

impl ResolvedKey {
    pub fn new(row: &ExternalPublicKey, parsed: ParsedKeys) -> Self {
        let aead_advertised = row.smime_oaep && row.smime_ciphers.contains(&SmimeCipher::Aes256Gcm);
        ResolvedKey {
            profile: parsed
                .set
                .inferred_profile(row.authenticated_encryption || aead_advertised),
            kind: parsed.kind,
            recipients: parsed.set,
            trust: row.trust,
            fingerprint: row.fingerprint.as_deref().unwrap_or_default().into(),
            expires_at: row.expires_at.map(|at| at.timestamp() as u64),
        }
    }
}

impl KeyEntry {
    pub fn select(
        &self,
        query: &KeyQuery<'_>,
        methods: &[KeyKind],
        now: u64,
    ) -> Option<&Arc<ResolvedKey>> {
        self.key.as_ref().filter(|key| {
            methods.contains(&key.kind)
                && key.trust.rank() >= query.min_trust.rank()
                && key.expires_at.is_none_or(|expires_at| expires_at > now)
        })
    }

    pub fn knows(&self, fingerprint: &str) -> bool {
        self.fingerprints
            .iter()
            .any(|known| known.as_ref() == fingerprint)
    }
}

impl KeyCacheKey {
    pub fn new(address: &str) -> Self {
        KeyCacheKey {
            address: Self::normalize(address).into(),
        }
    }

    fn normalize(address: &str) -> Cow<'_, str> {
        if address
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii())
        {
            address.to_lowercase().into()
        } else {
            address.into()
        }
    }

    pub fn address_hash(address: &str) -> u32 {
        xxhash_rust::xxh3::xxh3_64(address.as_bytes()) as u32
    }
}

impl Equivalent<KeyCacheKey> for KeyCacheRef<'_> {
    fn equivalent(&self, key: &KeyCacheKey) -> bool {
        self.0 == key.address.as_ref()
    }
}

impl PublicKeyParse for ExternalPublicKey {
    fn parse_keys(&self, now: u64) -> Result<ParsedKeys, crypto::KeyError> {
        crate::storage::encryption::parse_key_text(self.key_text(), now)
    }
}

impl CacheItemWeight for KeyCacheKey {
    fn weight(&self) -> u64 {
        (size_of::<KeyCacheKey>() + self.address.len()) as u64
    }
}

impl CacheItemWeight for KeyEntry {
    fn weight(&self) -> u64 {
        (size_of::<KeyEntry>()
            + self.key.as_ref().map_or(0, |key| {
                size_of::<ResolvedKey>() + key.recipients.heap_size() + key.fingerprint.len()
            })
            + self
                .fingerprints
                .iter()
                .map(|fingerprint| fingerprint.len())
                .sum::<usize>()) as u64
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/gateway/resolver/tests.rs"]
mod tests;
