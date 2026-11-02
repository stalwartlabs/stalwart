/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod dns;
pub mod keyserver;
pub mod wkd;

use super::{
    store::{
        ExternalPublicKeyData, ExternalPublicKeyRow, ExternalPublicKeyStore, KeyCandidate,
        KeyChange, MAX_STORED_KEY_SIZE, RegistryKeyKind,
    },
    trust::RunTrustAnchors,
};
use crate::Server;
use crypto::KeyKind;
use dns::DnssecKeyLookup;
use futures::{StreamExt, stream::FuturesUnordered};
use keyserver::KeyserverLookup;
use registry::{
    schema::{
        enums::{KeyDiscoverySource, KeyTrust},
        structs::{ExternalPublicKey, KeySource, KeySourceAutomatic},
    },
    types::{EnumImpl, datetime::UTCDateTime},
};
use std::time::Instant;
use store::write::now;
use trc::EncryptionEvent;
use wkd::WkdLookup;

pub const MAX_KEY_RESPONSE: usize = 256 * 1024;
const MAX_CONCURRENT_FETCHES: usize = 16;
const KIND_PREFERENCE: [KeyKind; 2] = [KeyKind::Smime, KeyKind::OpenPgp];

pub enum SourceResult {
    Keys {
        candidates: Vec<KeyCandidate>,
        revoked: Vec<String>,
    },
    NotFound,
    TemporaryFailure,
    Bogus,
}

pub trait KeyDiscovery: Sync + Send {
    fn fetch_external_public_keys(
        &self,
        rows: &[ExternalPublicKeyRow],
        anchors: &RunTrustAnchors,
    ) -> impl Future<Output = ()> + Send;

    fn fetch_external_public_key(
        &self,
        row: &ExternalPublicKeyRow,
        anchors: &RunTrustAnchors,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn lookup_key(
        &self,
        address: &str,
        method: KeyDiscoverySource,
        anchors: &RunTrustAnchors,
    ) -> impl Future<Output = SourceResult> + Send;
}

pub trait DiscoveryMethod {
    fn trust(self) -> KeyTrust;

    fn key_source(self) -> KeySource;
}

trait CandidateSelection {
    fn preferred_candidate(
        &self,
        candidates: Vec<KeyCandidate>,
        methods: &[KeyKind],
    ) -> Option<KeyCandidate>;
}

impl KeyDiscovery for Server {
    async fn fetch_external_public_keys(
        &self,
        rows: &[ExternalPublicKeyRow],
        anchors: &RunTrustAnchors,
    ) {
        let mut rows = rows.iter();
        let mut running = FuturesUnordered::new();
        loop {
            while running.len() < MAX_CONCURRENT_FETCHES
                && let Some(row) = rows.next()
            {
                running.push(self.fetch_external_public_key(row, anchors));
            }
            match running.next().await {
                Some(Ok(())) => {}
                Some(Err(err)) => {
                    trc::error!(err.caused_by(trc::location!()));
                }
                None => return,
            }
        }
    }

    async fn fetch_external_public_key(
        &self,
        row: &ExternalPublicKeyRow,
        anchors: &RunTrustAnchors,
    ) -> trc::Result<()> {
        let Some(gateway) = self.core.email.gateway.as_deref() else {
            return Ok(());
        };
        let KeySource::Automatic(KeySourceAutomatic { method }) = row.key.source else {
            return Ok(());
        };
        let address = row.key.email_address.as_str();
        let started = Instant::now();
        let result = tokio::time::timeout(
            gateway.source_timeout,
            self.lookup_key(address, method, anchors),
        )
        .await
        .unwrap_or(SourceResult::TemporaryFailure);
        trc::event!(
            Encryption(EncryptionEvent::KeyLookup),
            Source = method.as_str(),
            Result = result.as_str(),
            Elapsed = started.elapsed(),
        );

        let time = now();
        let mut updated = row.key.clone();
        match result {
            SourceResult::Keys {
                candidates,
                revoked,
            } => {
                updated.revoke(&revoked);
                updated.last_checked = Some(UTCDateTime::from_timestamp(time as i64));
                if let Some(candidate) = updated.preferred_candidate(candidates, &gateway.methods) {
                    let fingerprint = candidate.fingerprint().unwrap_or_default();
                    if updated.fingerprint.as_deref() == Some(fingerprint.as_str()) {
                        if let Some(refreshed) = candidate.refreshed(&updated, time) {
                            updated = refreshed;
                        }
                    } else if updated.accept_candidate(&candidate, fingerprint, time)
                        == KeyChange::PendingApproval
                    {
                        trc::event!(
                            Encryption(EncryptionEvent::KeyChange),
                            To = address.to_string(),
                        );
                    }
                }
                updated.schedule_next_check(gateway, time);
            }
            SourceResult::NotFound => {
                updated.last_checked = Some(UTCDateTime::from_timestamp(time as i64));
                if method == KeyDiscoverySource::Dnssec && !updated.pinned {
                    updated.clear_next_key();
                    updated.clear_key();
                }
                updated.schedule_next_check(gateway, time);
            }
            SourceResult::Bogus => {
                trc::event!(
                    Encryption(EncryptionEvent::DnssecBogus),
                    To = address.to_string(),
                );
                updated.schedule_retry(gateway, time);
            }
            SourceResult::TemporaryFailure => updated.schedule_retry(gateway, time),
        }
        self.update_external_public_key(row, updated).await
    }

    async fn lookup_key(
        &self,
        address: &str,
        method: KeyDiscoverySource,
        anchors: &RunTrustAnchors,
    ) -> SourceResult {
        match method {
            KeyDiscoverySource::Dnssec => self.lookup_dnssec_keys(address, anchors).await,
            KeyDiscoverySource::Wkd => self.lookup_wkd(address).await,
            KeyDiscoverySource::Vks => self.lookup_vks(address).await,
            KeyDiscoverySource::Hkp => self.lookup_hkp(address).await,
        }
    }
}

impl DiscoveryMethod for KeyDiscoverySource {
    fn trust(self) -> KeyTrust {
        match self {
            KeyDiscoverySource::Dnssec => KeyTrust::Verified,
            KeyDiscoverySource::Wkd | KeyDiscoverySource::Vks => KeyTrust::Discovered,
            KeyDiscoverySource::Hkp => KeyTrust::Unverified,
        }
    }

    fn key_source(self) -> KeySource {
        KeySource::Automatic(KeySourceAutomatic { method: self })
    }
}

impl CandidateSelection for ExternalPublicKey {
    fn preferred_candidate(
        &self,
        mut candidates: Vec<KeyCandidate>,
        methods: &[KeyKind],
    ) -> Option<KeyCandidate> {
        candidates.retain(|candidate| {
            candidate.key.len() <= MAX_STORED_KEY_SIZE
                && candidate.fingerprint().is_some_and(|fingerprint| {
                    !self
                        .blocked_fingerprints
                        .iter()
                        .any(|blocked| *blocked == fingerprint)
                })
                && self
                    .kind
                    .is_none_or(|kind| kind == candidate.parsed.kind.registry_kind())
        });
        let known = [
            self.fingerprint.as_deref(),
            self.next_fingerprint.as_deref(),
        ];
        let idx = known
            .into_iter()
            .flatten()
            .find_map(|known| {
                candidates
                    .iter()
                    .position(|candidate| candidate.fingerprint().as_deref() == Some(known))
            })
            .or_else(|| {
                KIND_PREFERENCE
                    .iter()
                    .filter(|kind| methods.contains(kind))
                    .find_map(|kind| {
                        candidates
                            .iter()
                            .position(|candidate| candidate.parsed.kind == *kind)
                    })
            })?;
        Some(candidates.swap_remove(idx))
    }
}

impl SourceResult {
    pub fn from_openpgp(
        input: &[u8],
        address: &str,
        method: KeyDiscoverySource,
        valid_until: Option<u64>,
    ) -> Self {
        let time = now();
        let revoked: Vec<String> = crypto::revoked_fingerprints(input, time)
            .iter()
            .map(|fingerprint| fingerprint.to_hex())
            .collect();
        let candidates: Vec<KeyCandidate> = crypto::parse_public_keys_for(input, address, time)
            .map(|keys| {
                keys.into_iter()
                    .map(|key| KeyCandidate {
                        address: address.into(),
                        key: key.key,
                        parsed: key.parsed,
                        source: method.key_source(),
                        trust: method.trust(),
                        valid_until,
                        capabilities: None,
                        signed_at: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        if candidates.is_empty() && revoked.is_empty() {
            SourceResult::NotFound
        } else {
            SourceResult::Keys {
                candidates,
                revoked,
            }
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SourceResult::Keys { .. } => "found",
            SourceResult::NotFound => "notFound",
            SourceResult::TemporaryFailure => "temporaryFailure",
            SourceResult::Bogus => "bogus",
        }
    }
}
