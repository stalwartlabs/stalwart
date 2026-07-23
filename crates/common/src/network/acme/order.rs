/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use crate::network::acme::directory::AcmeRequestBuilder;
use crate::network::acme::{
    AcmeDnsParameters, AcmeError, AcmeResult, AuthStatus, ChallengeType, Identifier, OrderStatus,
    ParsedCert, PemCert,
};
use crate::{KV_ACME, Server};
use chrono::{TimeZone, Utc};
use dns_update::DnsRecord;
use futures::future::try_join_all;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use store::dispatch::lookup::KeyValue;
use trc::AcmeEvent;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{GeneralName, ParsedExtension};

const HOSTNAMES: &[&str] = &["mta-sts", "ua-auto-config", "autoconfig", "autodiscover"];

impl AcmeRequestBuilder {
    pub fn build_domains(
        &self,
        server: &Server,
        domain: &str,
        hostnames: &[String],
    ) -> Vec<String> {
        if hostnames.is_empty() {
            if matches!(
                self.challenge,
                ChallengeType::Dns01 | ChallengeType::DnsPersist01
            ) {
                vec![format!("*.{domain}"), domain.to_string()]
            } else {
                let server_name = server.core.network.server_name.as_str();
                let domain_suffix = format!(".{domain}");
                let matches_zone = |name: &str| name == domain || name.ends_with(&domain_suffix);

                // Add technical domains
                let mut domains = HOSTNAMES
                    .iter()
                    .map(|hostname| format!("{hostname}.{domain}"))
                    .collect::<BTreeSet<_>>();

                // Add server name if it matches the domain (including the apex itself)
                if matches_zone(server_name) {
                    domains.insert(server_name.to_string());
                }

                // Add mail exchangers
                for exchanger in &server.core.network.info.mxs {
                    if let Some(exchanger) = &exchanger.hostname
                        && matches_zone(exchanger)
                    {
                        domains.insert(exchanger.to_string());
                    }
                }

                // Add service hosts
                for (_, service) in &server.core.network.info.services {
                    if let Some(service) = &service.hostname
                        && matches_zone(service)
                    {
                        domains.insert(service.to_string());
                    }
                }

                domains.into_iter().collect()
            }
        } else {
            hostnames
                .iter()
                .map(|h| {
                    if h.contains('.') {
                        h.clone()
                    } else {
                        format!("{h}.{domain}")
                    }
                })
                .collect()
        }
    }

    pub async fn renew(
        &self,
        server: &Server,
        domains: Vec<String>,
        reuse_key_pem: Option<String>,
        dns_parameters: Option<AcmeDnsParameters>,
    ) -> AcmeResult<PemCert> {
        let mut params = CertificateParams::new(domains.clone()).map_err(|err| {
            AcmeError::Crypto(format!("Failed to create certificate params: {}", err))
        })?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = match reuse_key_pem {
            Some(pem) => KeyPair::from_pem(&pem).map_err(|err| {
                AcmeError::Crypto(format!("Failed to load private key for reuse: {}", err))
            })?,
            None => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|err| {
                AcmeError::Crypto(format!("Failed to generate key pair: {}", err))
            })?,
        };
        let response = self.new_order(domains.clone()).await?;
        let order_url = response.location;
        let mut order = response.body;
        let mut retry_after = None;

        loop {
            match order.status {
                OrderStatus::Pending => {
                    if matches!(self.challenge, ChallengeType::Dns01) {
                        for url in &order.authorizations {
                            self.authorize(server, url, dns_parameters.as_ref()).await?;
                        }
                    } else {
                        let auth_futures = order
                            .authorizations
                            .iter()
                            .map(|url| self.authorize(server, url, dns_parameters.as_ref()));
                        try_join_all(auth_futures).await?;
                    }
                    trc::event!(
                        Acme(AcmeEvent::AuthCompleted),
                        Url = self.directory.new_order.to_string(),
                        Hostname = domains.as_slice(),
                    );
                    let response = self.order(&order_url).await?;
                    order = response.body;
                    retry_after = response.retry_after;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        trc::event!(
                            Acme(AcmeEvent::OrderProcessing),
                            Url = self.directory.new_order.to_string(),
                            Hostname = domains.as_slice(),
                            Total = i,
                        );

                        tokio::time::sleep(
                            retry_after.unwrap_or_else(|| Duration::from_secs(1u64 << i)),
                        )
                        .await;
                        let response = self
                            .order(&order_url)
                            .await?
                            .assert_reasonable_retry_after(self.max_retries)?;
                        order = response.body;
                        retry_after = response.retry_after;
                        if order.status != OrderStatus::Processing {
                            break;
                        }
                    }
                    if order.status == OrderStatus::Processing {
                        return Err(AcmeError::OrderTimeout {
                            max_retries: self.max_retries,
                        });
                    }
                }
                OrderStatus::Ready => {
                    trc::event!(
                        Acme(AcmeEvent::OrderReady),
                        Url = self.directory.new_order.to_string(),
                        Hostname = domains.as_slice(),
                    );

                    let csr = params.serialize_request(&key_pair).map_err(|err| {
                        AcmeError::Crypto(format!("Failed to serialize CSR: {}", err))
                    })?;
                    let csr = csr.der().to_vec();
                    order = self.finalize(order.finalize, csr).await?.body;
                }
                OrderStatus::Valid { certificate } => {
                    trc::event!(
                        Acme(AcmeEvent::OrderValid),
                        Url = self.directory.new_order.to_string(),
                        Hostname = domains.as_slice(),
                    );

                    let certificate = self.select_certificate(&domains, certificate).await?;

                    return Ok(PemCert {
                        certificate,
                        private_key: key_pair.serialize_pem(),
                    });
                }
                OrderStatus::Invalid => {
                    let reason = if let Some(reason) = order.error {
                        reason.to_string()
                    } else {
                        "Unknown reason".to_string()
                    };

                    return Err(AcmeError::OrderInvalid(reason));
                }
            }
        }
    }

    async fn authorize(
        &self,
        server: &Server,
        url: &String,
        dns_parameters: Option<&AcmeDnsParameters>,
    ) -> AcmeResult<()> {
        let response = self
            .auth(url)
            .await?
            .assert_reasonable_retry_after(self.max_retries)?;
        let mut retry_after = response.retry_after;
        let auth = response.body;

        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;

                trc::event!(
                    Acme(AcmeEvent::AuthStart),
                    Hostname = domain.to_string(),
                    Type = self.challenge.as_str(),
                    Url = self.directory.new_order.to_string(),
                );

                let challenge = auth
                    .challenges
                    .iter()
                    .find(|c| c.typ == self.challenge)
                    .ok_or(AcmeError::ChallengeNotSupported {
                        requested: self.challenge,
                        supported: auth.challenges.clone(),
                    })?;

                match &self.challenge {
                    ChallengeType::TlsAlpn01 => {
                        server
                            .in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_ACME,
                                    &domain,
                                    self.tls_alpn_key(challenge, domain.clone())?,
                                )
                                .expires(3600),
                            )
                            .await?;
                    }
                    ChallengeType::Http01 => {
                        server
                            .in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_ACME,
                                    challenge.token.as_deref().ok_or_else(|| {
                                        AcmeError::Invalid(
                                            "Missing http-01 challenge token in response"
                                                .to_string(),
                                        )
                                    })?,
                                    self.http_proof(challenge)?,
                                )
                                .expires(3600),
                            )
                            .await?;
                    }
                    ChallengeType::Dns01 => {
                        let dns_parameters = dns_parameters.unwrap();
                        let domain = domain.strip_prefix("*.").unwrap_or(&domain);

                        let zone = dns_parameters
                            .origin
                            .as_deref()
                            .or_else(|| psl::domain_str(domain))
                            .unwrap_or(domain);

                        let proof = self.dns_proof(challenge)?;
                        let challenge_name = format!("_acme-challenge.{}", domain);
                        dns_parameters
                            .updater
                            .set_rrset(
                                zone,
                                &challenge_name,
                                dns_update::DnsRecordType::TXT,
                                vec![DnsRecord::TXT(proof.clone())],
                            )
                            .await
                            .map_err(AcmeError::Dns)?;
                        dns_parameters
                            .updater
                            .wait_for_txt_propagation(&challenge_name, zone, &proof)
                            .await;
                    }
                    ChallengeType::DnsPersist01 => {}
                    ChallengeType::Unknown => unreachable!(),
                }

                self.challenge(&challenge.url).await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => {
                return Err(AcmeError::AuthInvalid(auth.into_error()));
            }
        };

        for i in 0u64..5 {
            tokio::time::sleep(retry_after.unwrap_or_else(|| Duration::from_secs(1u64 << i))).await;
            let response = self
                .auth(url)
                .await?
                .assert_reasonable_retry_after(self.max_retries)?;
            retry_after = response.retry_after;

            match response.body.status {
                AuthStatus::Pending => {
                    trc::event!(
                        Acme(AcmeEvent::AuthPending),
                        Hostname = domain.to_string(),
                        Url = self.directory.new_order.to_string(),
                        Total = i,
                    );

                    self.challenge(&challenge_url).await?
                }
                AuthStatus::Valid => {
                    trc::event!(
                        Acme(AcmeEvent::AuthValid),
                        Hostname = domain.to_string(),
                        Url = self.directory.new_order.to_string(),
                    );

                    return Ok(());
                }
                _ => {
                    return Err(AcmeError::AuthInvalid(response.body.into_error()));
                }
            }
        }

        Err(AcmeError::AuthTimeout {
            max_retries: self.max_retries,
        })
    }

    async fn select_certificate(&self, domains: &[String], url: String) -> AcmeResult<String> {
        let response = self.certificate(url).await?;
        let Some(preferred) = self.preferred_chain.as_deref() else {
            return Ok(response.body);
        };

        if chain_matches(&response.body, preferred) {
            return Ok(response.body);
        }

        for alternate in &response.alternates {
            match self.certificate(alternate).await {
                Ok(alternate) if chain_matches(&alternate.body, preferred) => {
                    return Ok(alternate.body);
                }
                Ok(_) => {}
                Err(err) => {
                    trc::event!(
                        Acme(AcmeEvent::ProcessCert),
                        Url = alternate.to_string(),
                        Hostname = domains,
                        Reason = err.to_string(),
                    );
                }
            }
        }

        trc::event!(
            Acme(AcmeEvent::ProcessCert),
            Hostname = domains,
            Reason = format!(
                "Preferred certificate chain '{preferred}' not offered by the CA; using the default chain",
            ),
        );

        Ok(response.body)
    }
}

fn chain_matches(pem_chain: &str, preferred: &str) -> bool {
    let Ok(blocks) = pem::parse_many(pem_chain) else {
        return false;
    };
    let Some(top) = blocks.last() else {
        return false;
    };
    let Ok((_, cert)) = parse_x509_certificate(top.contents()) else {
        return false;
    };
    cert.issuer()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .any(|cn| cn == preferred)
}

impl ParsedCert {
    pub fn parse(certificate: impl AsRef<[u8]>) -> AcmeResult<ParsedCert> {
        let der = pem::parse_many(certificate)
            .map_err(|err| AcmeError::Crypto(format!("Failed to parse PEM: {}", err)))?
            .into_iter()
            .next()
            .ok_or_else(|| AcmeError::Crypto("No certificates found in PEM".to_string()))?;
        Self::parse_der(der.contents())
    }

    pub fn parse_der(der: &[u8]) -> AcmeResult<ParsedCert> {
        parse_x509_certificate(der)
            .map_err(|err| AcmeError::Crypto(format!("Failed to parse X.509 certificate: {}", err)))
            .and_then(|(_, cert)| {
                // Add CNs and SANs to the list of names
                let mut names: BTreeSet<String> = BTreeSet::new();
                for name in cert.subject().iter_common_name() {
                    if let Ok(name) = name.as_str() {
                        names.insert(name.into());
                    }
                }
                for ext in cert.extensions() {
                    if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                        for name in &san.general_names {
                            let name = match name {
                                GeneralName::DNSName(name) => (*name).into(),
                                GeneralName::IPAddress(ip) => match ip.len() {
                                    4 => Ipv4Addr::from(<[u8; 4]>::try_from(*ip).unwrap())
                                        .to_string(),
                                    16 => Ipv6Addr::from(<[u8; 16]>::try_from(*ip).unwrap())
                                        .to_string(),
                                    _ => continue,
                                },
                                _ => {
                                    continue;
                                }
                            };
                            names.insert(name);
                        }
                    }
                }

                Ok(ParsedCert {
                    sans: names.into_iter().collect(),
                    issuer: cert.tbs_certificate.issuer().to_string(),
                    valid_not_before: Utc
                        .timestamp_opt(cert.tbs_certificate.validity().not_before.timestamp(), 0)
                        .single()
                        .ok_or_else(|| {
                            AcmeError::Crypto(
                                "Certificate not_before time is out of range".to_string(),
                            )
                        })?,
                    valid_not_after: Utc
                        .timestamp_opt(cert.tbs_certificate.validity().not_after.timestamp(), 0)
                        .single()
                        .ok_or_else(|| {
                            AcmeError::Crypto(
                                "Certificate not_after time is out of range".to_string(),
                            )
                        })?,
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::chain_matches;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

    fn self_signed_pem(common_name: &str) -> String {
        let mut params = CertificateParams::new(vec!["host.example".to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        params.self_signed(&key_pair).unwrap().pem()
    }

    #[test]
    fn matches_top_certificate_issuer() {
        let chain = self_signed_pem("ISRG Root X1");
        assert!(chain_matches(&chain, "ISRG Root X1"));
    }

    #[test]
    fn match_is_case_sensitive() {
        let chain = self_signed_pem("ISRG Root X1");
        assert!(!chain_matches(&chain, "isrg root x1"));
    }

    #[test]
    fn match_is_exact_not_substring() {
        let chain = self_signed_pem("ISRG Root X10");
        assert!(!chain_matches(&chain, "ISRG Root X1"));
    }

    #[test]
    fn does_not_match_unrelated_issuer() {
        let chain = self_signed_pem("ISRG Root X2");
        assert!(!chain_matches(&chain, "ISRG Root X1"));
    }

    #[test]
    fn uses_topmost_certificate_not_leaf() {
        let leaf = self_signed_pem("Leaf Issuer");
        let top = self_signed_pem("ISRG Root X1");
        let chain = format!("{leaf}{top}");
        assert!(chain_matches(&chain, "ISRG Root X1"));
        assert!(!chain_matches(&chain, "Leaf Issuer"));
    }

    #[test]
    fn rejects_unparseable_chain() {
        assert!(!chain_matches("not a pem", "ISRG Root X1"));
    }
}
