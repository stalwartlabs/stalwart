/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::SourceResult;
use crate::{
    Server,
    gateway::{
        discovery::DiscoveryMethod,
        store::KeyCandidate,
        trust::{RunTrustAnchors, SmimeTrust},
    },
};
use crypto::ChainStatus;
use mail_auth::hickory_resolver::{
    net::{DnsError, NetError},
    proto::{
        dnssec::Proof,
        rr::{
            Name, RData, RecordType,
            rdata::tlsa::{CertUsage, Matching, Selector},
        },
    },
};
use registry::schema::enums::KeyDiscoverySource;
use sha2::{Digest, Sha256};
use std::{fmt::Write, time::Instant};
use store::write::now;

const OWNER_HASH_LEN: usize = 28;

pub trait DnssecKeyLookup: Sync + Send {
    fn lookup_dnssec_keys(
        &self,
        address: &str,
        anchors: &RunTrustAnchors,
    ) -> impl Future<Output = SourceResult> + Send;
}

enum KeyRecords {
    Found(Vec<KeyRecord>, u64),
    Missing,
    Failed,
    Bogus,
}

struct KeyRecord {
    data: Vec<u8>,
    needs_chain: bool,
}

impl DnssecKeyLookup for Server {
    async fn lookup_dnssec_keys(&self, address: &str, anchors: &RunTrustAnchors) -> SourceResult {
        let resolvers = &self.core.smtp.resolvers;
        if !resolvers.dnssec_available {
            return SourceResult::TemporaryFailure;
        }
        let Some((local_part, domain)) = address.rsplit_once('@') else {
            return SourceResult::NotFound;
        };
        let Some(label) = Sha256::digest(local_part.as_bytes())
            .get(..OWNER_HASH_LEN)
            .map(|hash| {
                hash.iter()
                    .fold(String::with_capacity(56), |mut label, byte| {
                        let _ = write!(label, "{byte:02x}");
                        label
                    })
            })
        else {
            return SourceResult::NotFound;
        };

        let (pgp, smime) = tokio::join!(
            self.key_records(
                format!("{label}._openpgpkey.{domain}."),
                RecordType::OPENPGPKEY
            ),
            self.key_records(format!("{label}._smimecert.{domain}."), RecordType::SMIMEA),
        );

        let mut candidates = Vec::new();
        let mut revoked = Vec::new();
        let mut failed = false;
        for (records, is_pgp) in [(pgp, true), (smime, false)] {
            match records {
                KeyRecords::Found(records, ttl) => {
                    let time = now();
                    let valid_until = time + ttl;
                    for record in records {
                        if is_pgp {
                            if let SourceResult::Keys {
                                candidates: keys,
                                revoked: fingerprints,
                            } = SourceResult::from_openpgp(
                                &record.data,
                                address,
                                KeyDiscoverySource::Dnssec,
                                Some(valid_until),
                            ) {
                                candidates.extend(keys);
                                revoked.extend(fingerprints);
                            }
                        } else if let Ok(parsed) = crypto::parse_public_keys(&record.data, time)
                            && parsed
                                .addresses
                                .iter()
                                .any(|bound| bound.eq_ignore_ascii_case(address))
                        {
                            if record.needs_chain {
                                match self.pkix_chain_valid(&record.data, anchors, time).await {
                                    Some(true) => {}
                                    Some(false) => continue,
                                    None => {
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            candidates.push(KeyCandidate {
                                address: address.into(),
                                key: record.data,
                                parsed,
                                source: KeyDiscoverySource::Dnssec.key_source(),
                                trust: KeyDiscoverySource::Dnssec.trust(),
                                valid_until: Some(valid_until),
                                capabilities: None,
                                signed_at: None,
                            });
                        }
                    }
                }
                KeyRecords::Bogus => return SourceResult::Bogus,
                KeyRecords::Failed => failed = true,
                KeyRecords::Missing => {}
            }
        }

        if !candidates.is_empty() || !revoked.is_empty() {
            SourceResult::Keys {
                candidates,
                revoked,
            }
        } else if failed {
            SourceResult::TemporaryFailure
        } else {
            SourceResult::NotFound
        }
    }
}

trait KeyRecordLookup {
    fn pkix_chain_valid(
        &self,
        certificate: &[u8],
        anchors: &RunTrustAnchors,
        now: u64,
    ) -> impl Future<Output = Option<bool>> + Send;

    fn key_records(
        &self,
        name: String,
        record_type: RecordType,
    ) -> impl Future<Output = KeyRecords> + Send;
}

impl KeyRecordLookup for Server {
    async fn pkix_chain_valid(
        &self,
        certificate: &[u8],
        anchors: &RunTrustAnchors,
        now: u64,
    ) -> Option<bool> {
        let anchors = self.run_trust_anchors(anchors).await.ok()?;
        let verdict = self
            .verify_certificate_chain(&[certificate.to_vec()], anchors, &[], now)
            .await?;
        match verdict.status {
            ChainStatus::Valid | ChainStatus::RevocationUnknown => Some(true),
            ChainStatus::Untrusted if !verdict.issuer_urls.is_empty() => None,
            _ => Some(false),
        }
    }

    async fn key_records(&self, name: String, record_type: RecordType) -> KeyRecords {
        #[cfg(stalwart_tests)]
        if let Some(records) = test_records(&name) {
            return records;
        }

        let Ok(name) = Name::from_str_relaxed(name.as_str()) else {
            return KeyRecords::Missing;
        };
        let lookup = match self
            .core
            .smtp
            .resolvers
            .dnssec
            .resolver
            .lookup(name, record_type)
            .await
        {
            Ok(lookup) => lookup,
            Err(err) => return KeyRecords::from_error(&err),
        };

        let ttl = lookup
            .valid_until()
            .saturating_duration_since(Instant::now())
            .as_secs();
        let mut records = Vec::new();
        for record in lookup.answers() {
            let found = match &record.data {
                RData::OPENPGPKEY(key) => KeyRecord {
                    data: key.public_key.to_vec(),
                    needs_chain: false,
                },
                RData::SMIMEA(smimea)
                    if matches!(smimea.cert_usage, CertUsage::PkixEe | CertUsage::DaneEe)
                        && smimea.selector == Selector::Full
                        && smimea.matching == Matching::Raw =>
                {
                    KeyRecord {
                        data: smimea.cert_data.clone(),
                        needs_chain: smimea.cert_usage == CertUsage::PkixEe,
                    }
                }
                _ => continue,
            };
            match record.proof {
                Proof::Secure => records.push(found),
                Proof::Insecure => return KeyRecords::Missing,
                Proof::Bogus | Proof::Indeterminate => return KeyRecords::Bogus,
            }
        }

        if records.is_empty() {
            KeyRecords::Missing
        } else {
            KeyRecords::Found(records, ttl)
        }
    }
}

impl KeyRecords {
    fn from_error(err: &NetError) -> Self {
        match err {
            NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                if no_records.authorities.as_deref().is_some_and(|records| {
                    records.iter().any(|record| {
                        matches!(record.proof, Proof::Bogus | Proof::Indeterminate)
                            && matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3)
                    })
                }) {
                    KeyRecords::Bogus
                } else {
                    KeyRecords::Missing
                }
            }
            NetError::Dns(DnsError::DnssecBogus) => KeyRecords::Bogus,
            NetError::Dns(DnsError::Nsec {
                proof: Proof::Bogus | Proof::Indeterminate,
                ..
            }) => KeyRecords::Bogus,
            NetError::Dns(DnsError::Nsec { .. }) => KeyRecords::Missing,
            _ => KeyRecords::Failed,
        }
    }
}

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/gateway/discovery/dns/test_support.rs"]
pub mod test_support;

#[cfg(stalwart_tests)]
use test_support::test_records;
