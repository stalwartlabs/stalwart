/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::smtp::resolver::{Tlsa, TlsaEntry, TlsaMatching},
};
pub use mail_auth::DnssecStatus;
use mail_auth::{
    MX, RecordSet,
    common::resolver::ToFqdn,
    hickory_resolver::{
        net::{DnsError, NetError},
        proto::{
            dnssec::Proof,
            op::ResponseCode,
            rr::{
                Name, RData, Record, RecordType,
                rdata::tlsa::{CertUsage, Matching, Selector},
            },
        },
    },
};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

pub trait TlsaLookup: Sync + Send {
    fn mx_lookup(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<RecordSet<MX>>> + Send;

    fn tlsa_lookup(
        &self,
        key: impl ToFqdn + Sync + Send,
    ) -> impl Future<Output = mail_auth::Result<TlsaResult>> + Send;
}

pub enum TlsaResult {
    Secure(Arc<Tlsa>),
    Bogus,
    Missing,
}

impl TlsaLookup for Server {
    async fn mx_lookup(&self, key: impl ToFqdn + Sync + Send) -> mail_auth::Result<RecordSet<MX>> {
        if !self.core.smtp.resolvers.dnssec_available {
            return self
                .core
                .smtp
                .resolvers
                .dns
                .mx_lookup(key, Some(&self.inner.cache.dns_mx))
                .await;
        }

        let key = key.to_fqdn();
        if let Some(value) = self.inner.cache.dns_mx.get::<str>(key.as_ref())
            && value.dnssec_status != DnssecStatus::Indeterminate
        {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let mx_lookup = match self
            .core
            .smtp
            .resolvers
            .dnssec
            .resolver
            .mx_lookup(Name::from_str_relaxed::<&str>(key.as_ref())?)
            .await
        {
            Ok(mx_lookup) => mx_lookup,
            Err(err) => {
                if let Some(denial) = NegativeAnswer::from_error(&err)
                    && denial.response_code == ResponseCode::NoError
                {
                    let records = RecordSet {
                        rrset: Arc::new([]),
                        dnssec_status: denial.dnssec_status,
                    };
                    if let Some(valid_until) = denial.valid_until {
                        self.inner.cache.dns_mx.insert_with_expiry(
                            key,
                            records.clone(),
                            valid_until,
                        );
                    }
                    return Ok(records);
                }
                return Err(err.into());
            }
        };
        let mx_records = mx_lookup.answers();
        let mut dnssec_status: Option<DnssecStatus> = None;
        let mut records: Vec<(u16, Vec<Box<str>>)> = Vec::with_capacity(mx_records.len());
        for mx_record in mx_records {
            if let RData::MX(mx) = &mx_record.data {
                dnssec_status = Some(match dnssec_status {
                    Some(status) => least_secure(status, proof_to_dnssec_status(mx_record.proof)),
                    None => proof_to_dnssec_status(mx_record.proof),
                });

                let preference = mx.preference;
                let exchange = mx.exchange.to_lowercase().to_string().into_boxed_str();

                if let Some(record) = records.iter_mut().find(|r| r.0 == preference) {
                    record.1.push(exchange);
                } else {
                    records.push((preference, vec![exchange]));
                }
            }
        }

        records.sort_unstable_by_key(|a| a.0);
        let rrset: Arc<[MX]> = records
            .into_iter()
            .map(|(preference, exchanges)| MX {
                preference,
                exchanges: exchanges.into_boxed_slice(),
            })
            .collect::<Arc<[MX]>>();
        let records = RecordSet {
            rrset,
            dnssec_status: dnssec_status.unwrap_or(DnssecStatus::Indeterminate),
        };

        self.inner
            .cache
            .dns_mx
            .insert_with_expiry(key, records.clone(), mx_lookup.valid_until());

        Ok(records)
    }

    async fn tlsa_lookup(&self, key: impl ToFqdn + Sync + Send) -> mail_auth::Result<TlsaResult> {
        let key = key.to_fqdn();
        if let Some(value) = self.inner.cache.dns_tlsa.get(key.as_ref()) {
            return Ok(TlsaResult::Secure(value));
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            if key.as_ref().contains("_dnssec_bogus.") {
                return Ok(TlsaResult::Bogus);
            }
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let tlsa_lookup = match self
            .core
            .smtp
            .resolvers
            .dnssec
            .resolver
            .tlsa_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await
        {
            Ok(tlsa_lookup) => tlsa_lookup,
            Err(err) => {
                if let Some(denial) = NegativeAnswer::from_error(&err) {
                    return Ok(if denial.dnssec_status == DnssecStatus::Bogus {
                        TlsaResult::Bogus
                    } else {
                        TlsaResult::Missing
                    });
                }
                return Err(err.into());
            }
        };

        let mut entries = Vec::new();
        let mut has_end_entities = false;
        let mut has_intermediates = false;
        let mut dnssec_status: Option<DnssecStatus> = None;

        for record in tlsa_lookup.answers() {
            if let RData::TLSA(tlsa) = &record.data {
                dnssec_status = Some(match dnssec_status {
                    Some(status) => least_secure(status, proof_to_dnssec_status(record.proof)),
                    None => proof_to_dnssec_status(record.proof),
                });

                if !record.proof.is_secure() {
                    continue;
                }

                let is_end_entity = match tlsa.cert_usage {
                    CertUsage::DaneEe => true,
                    CertUsage::DaneTa => false,
                    _ => continue,
                };
                let matching = match tlsa.matching {
                    Matching::Raw => TlsaMatching::Full,
                    Matching::Sha256 => TlsaMatching::Sha256,
                    Matching::Sha512 => TlsaMatching::Sha512,
                    _ => continue,
                };
                let is_spki = match tlsa.selector {
                    Selector::Spki => true,
                    Selector::Full => false,
                    _ => continue,
                };
                if is_end_entity {
                    has_end_entities = true;
                } else {
                    has_intermediates = true;
                }
                entries.push(TlsaEntry {
                    is_end_entity,
                    is_spki,
                    matching,
                    data: tlsa.cert_data.clone(),
                });
            }
        }

        match dnssec_status {
            Some(DnssecStatus::Bogus) => Ok(TlsaResult::Bogus),
            Some(DnssecStatus::Secure) => {
                let tlsa = Arc::new(Tlsa {
                    entries,
                    has_end_entities,
                    has_intermediates,
                });

                self.inner.cache.dns_tlsa.insert_with_expiry(
                    key,
                    tlsa.clone(),
                    tlsa_lookup.valid_until(),
                );

                Ok(TlsaResult::Secure(tlsa))
            }
            _ => Ok(TlsaResult::Missing),
        }
    }
}

struct NegativeAnswer {
    response_code: ResponseCode,
    dnssec_status: DnssecStatus,
    valid_until: Option<Instant>,
}

impl NegativeAnswer {
    fn from_error(err: &NetError) -> Option<Self> {
        let NetError::Dns(dns_error) = err else {
            return None;
        };

        match dns_error {
            DnsError::NoRecordsFound(no_records) => Some(NegativeAnswer {
                response_code: no_records.response_code,
                dnssec_status: no_records
                    .authorities
                    .as_deref()
                    .map(denial_dnssec_status)
                    .unwrap_or(DnssecStatus::Indeterminate),
                valid_until: no_records
                    .negative_ttl
                    .map(|ttl| Instant::now() + Duration::from_secs(ttl as u64)),
            }),
            DnsError::Nsec {
                response, proof, ..
            } => Some(NegativeAnswer {
                response_code: response.response_code,
                dnssec_status: proof_to_dnssec_status(*proof),
                valid_until: None,
            }),
            _ => None,
        }
    }
}

fn denial_dnssec_status(authorities: &[Record]) -> DnssecStatus {
    authorities
        .iter()
        .filter(|record| matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3))
        .map(|record| proof_to_dnssec_status(record.proof))
        .reduce(least_secure)
        .unwrap_or(DnssecStatus::Indeterminate)
}

fn proof_to_dnssec_status(proof: Proof) -> DnssecStatus {
    match proof {
        Proof::Secure => DnssecStatus::Secure,
        Proof::Insecure => DnssecStatus::Insecure,
        Proof::Bogus => DnssecStatus::Bogus,
        Proof::Indeterminate => DnssecStatus::Indeterminate,
    }
}

fn least_secure(a: DnssecStatus, b: DnssecStatus) -> DnssecStatus {
    fn rank(status: DnssecStatus) -> u8 {
        match status {
            DnssecStatus::Bogus => 0,
            DnssecStatus::Indeterminate => 1,
            DnssecStatus::Insecure => 2,
            DnssecStatus::Secure => 3,
        }
    }

    if rank(a) <= rank(b) { a } else { b }
}
