/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, config::network::Pacc, network::dkim::generate_dkim_dns_record};
use ahash::{AHashMap, AHashSet};
use base64::{Engine, engine::general_purpose};
use dns_update::{
    CAARecord, DnsRecord, KeyValue, MXRecord, NamedDnsRecord, SRVRecord, TLSARecord, TlsaCertUsage,
    TlsaMatching, TlsaSelector, bind::BindSerializer,
};
use registry::schema::{
    enums::{DnsRecordType, ServiceProtocol},
    prelude::{ObjectType, Property},
    structs::{AcmeProvider, CertificateManagement, DkimSignature, DnsManagement, Domain},
};
use reqwest::Url;
use sha2::{Digest, Sha256};
use store::registry::RegistryQuery;
use trc::AddContext;
use types::id::Id;
use x509_parser::parse_x509_certificate;

impl Server {
    pub async fn build_dns_records(
        &self,
        domain_id: Id,
        domain: &Domain,
        record_types: &[DnsRecordType],
    ) -> trc::Result<Vec<NamedDnsRecord>> {
        let mut records = Vec::new();
        let network = &self.core.network;
        let default_host = network.server_name.as_str();
        let domain_name = domain.name.as_str();
        let domain_name_suffix = format!(".{domain_name}");

        for record_type in record_types {
            match record_type {
                DnsRecordType::Dkim => {
                    let signature_ids = self
                        .registry()
                        .query::<Vec<Id>>(
                            RegistryQuery::new(ObjectType::DkimSignature)
                                .equal(Property::DomainId, domain_id.document_id()),
                        )
                        .await?;

                    for id in signature_ids {
                        let Some(key) = self.registry().object::<DkimSignature>(id).await? else {
                            continue;
                        };
                        records.push(generate_dkim_dns_record(&key, domain_name).await?);
                    }
                }
                DnsRecordType::Mx => {
                    for mx in &network.info.mxs {
                        records.push(NamedDnsRecord {
                            name: format!("{domain_name}."),
                            record: DnsRecord::MX(MXRecord {
                                exchange: mx
                                    .hostname
                                    .as_deref()
                                    .unwrap_or(default_host)
                                    .to_string(),
                                priority: mx.priority as u16,
                            }),
                        });
                    }
                }
                DnsRecordType::Spf => {
                    let mxs = network
                        .info
                        .mxs
                        .iter()
                        .map(|mx| mx.hostname.as_deref().unwrap_or(default_host))
                        .collect::<AHashSet<_>>();

                    for mx in mxs {
                        if mx.ends_with(&domain_name_suffix) {
                            records.push(NamedDnsRecord {
                                name: format!("{mx}."),
                                record: DnsRecord::TXT("v=spf1 a -all".to_string()),
                            });
                        }
                    }

                    records.push(NamedDnsRecord {
                        name: format!("{domain_name}."),
                        record: DnsRecord::TXT("v=spf1 mx -all".to_string()),
                    });
                }
                DnsRecordType::Dmarc => {
                    if let Some(uri) = &domain.report_address_uri {
                        let contents = if uri.starts_with("mailto:") && !uri.contains('@') {
                            format!("v=DMARC1; p=reject; rua={uri}@{domain_name}",)
                        } else {
                            format!("v=DMARC1; p=reject; rua={uri}",)
                        };

                        records.push(NamedDnsRecord {
                            name: format!("_dmarc.{domain_name}."),
                            record: DnsRecord::TXT(contents),
                        });
                    }
                }
                DnsRecordType::TlsRpt => {
                    if let Some(uri) = &domain.report_address_uri {
                        let contents = if uri.starts_with("mailto:") && !uri.contains('@') {
                            format!("v=TLSRPTv1; rua={uri}@{domain_name}",)
                        } else {
                            format!("v=TLSRPTv1; rua={uri}",)
                        };

                        records.push(NamedDnsRecord {
                            name: format!("_smtp._tls.{domain_name}."),
                            record: DnsRecord::TXT(contents),
                        });
                    }
                }
                DnsRecordType::MtaSts => {
                    if let Some(policy) = &self.core.smtp.session.mta_sts_policy {
                        records.push(NamedDnsRecord {
                            name: format!("mta-sts.{domain_name}."),
                            record: DnsRecord::CNAME(format!("{default_host}.")),
                        });

                        records.push(NamedDnsRecord {
                            name: format!("_mta-sts.{domain_name}."),
                            record: DnsRecord::TXT(format!("v=STSv1; id={}", policy.id)),
                        });
                    }
                }
                DnsRecordType::AutoConfig => {
                    let pacc_digest = Sha256::digest(&self.get_pacc_for_domain(domain_name).await?);
                    let pacc_digest_encoded = general_purpose::STANDARD.encode(pacc_digest);

                    records.push(NamedDnsRecord {
                        name: format!("ua-auto-config.{domain_name}."),
                        record: DnsRecord::CNAME(format!("{default_host}.")),
                    });
                    records.push(NamedDnsRecord {
                        name: format!("_ua-auto-config.{domain_name}."),
                        record: DnsRecord::TXT(format!(
                            "v=UAAC1; a=sha256; d={pacc_digest_encoded}"
                        )),
                    });
                }
                DnsRecordType::AutoConfigLegacy => {
                    records.push(NamedDnsRecord {
                        name: format!("autoconfig.{domain_name}."),
                        record: DnsRecord::CNAME(format!("{default_host}.")),
                    });
                }
                DnsRecordType::AutoDiscover => {
                    records.push(NamedDnsRecord {
                        name: format!("autodiscover.{domain_name}."),
                        record: DnsRecord::CNAME(format!("{default_host}.")),
                    });
                }
                DnsRecordType::Srv => {
                    for (protocol, service) in &network.info.services {
                        let target =
                            format!("{}.", service.hostname.as_deref().unwrap_or(default_host));
                        let services = match protocol {
                            ServiceProtocol::Jmap
                            | ServiceProtocol::Caldav
                            | ServiceProtocol::Carddav => {
                                let name = match protocol {
                                    ServiceProtocol::Jmap => "jmap",
                                    ServiceProtocol::Caldav => "caldavs",
                                    ServiceProtocol::Carddav => "carddavs",
                                    _ => unreachable!(),
                                };

                                records.push(NamedDnsRecord {
                                    name: format!("_{name}._tcp.{domain_name}."),
                                    record: DnsRecord::SRV(SRVRecord {
                                        target: target.clone(),
                                        priority: 0,
                                        weight: 1,
                                        port: 443,
                                    }),
                                });
                                continue;
                            }
                            ServiceProtocol::Webdav | ServiceProtocol::Managesieve => continue,
                            ServiceProtocol::Imap => [("imap", 143), ("imaps", 993)],
                            ServiceProtocol::Pop3 => [("pop3", 110), ("pop3s", 995)],
                            ServiceProtocol::Smtp => [("submission", 587), ("submissions", 465)],
                        };

                        for (is_tls, (service_name, port)) in services.into_iter().enumerate() {
                            if is_tls == 1 || service.cleartext {
                                records.push(NamedDnsRecord {
                                    name: format!("_{service_name}._tcp.{domain_name}."),
                                    record: DnsRecord::SRV(SRVRecord {
                                        target: target.clone(),
                                        priority: 0,
                                        weight: 1,
                                        port,
                                    }),
                                });
                            }
                        }
                    }
                }
                DnsRecordType::Caa => {
                    if let CertificateManagement::Automatic(props) = &domain.certificate_management
                        && let Some(provider) = self
                            .registry()
                            .object::<AcmeProvider>(props.acme_provider_id)
                            .await?
                        && let Ok(provider_url) = Url::parse(&provider.directory)
                        && let Some(provider_name) = provider_domain(&provider_url)
                    {
                        records.push(NamedDnsRecord {
                            name: format!("{domain_name}."),
                            record: DnsRecord::CAA(CAARecord::Issue {
                                issuer_critical: false,
                                name: provider_name.to_string().into(),
                                options: vec![KeyValue {
                                    key: "accounturi".to_string(),
                                    value: provider.account_uri.clone(),
                                }],
                            }),
                        });

                        if let Some(uri) = &domain.report_address_uri
                            && uri.starts_with("mailto:")
                        {
                            let url = if !uri.contains('@') {
                                format!("{uri}@{domain_name}")
                            } else {
                                uri.to_string()
                            };
                            records.push(NamedDnsRecord {
                                name: format!("{domain_name}."),
                                record: DnsRecord::CAA(CAARecord::Iodef {
                                    issuer_critical: false,
                                    url,
                                }),
                            });
                        }

                        // ACME DNS-PERSIST-01 validation record
                        records.push(NamedDnsRecord {
                            name: format!("_validation-persist.{domain_name}."),
                            record: DnsRecord::TXT(format!(
                                "{provider_name}; accounturi={}{}",
                                provider.account_uri,
                                if props.subject_alternative_names.is_empty() {
                                    "; policy=wildcard"
                                } else {
                                    ""
                                }
                            )),
                        });
                    }
                }
                DnsRecordType::Tlsa => {
                    let mut hostnames: AHashMap<String, AHashSet<u16>> = AHashMap::new();

                    for mx in &network.info.mxs {
                        let hostname = mx.hostname.as_deref().unwrap_or(default_host);
                        if hostname.ends_with(&domain_name_suffix) || hostname == domain_name {
                            hostnames
                                .entry(hostname.to_string())
                                .or_default()
                                .insert(25);
                        }
                    }

                    for (protocol, service) in &network.info.services {
                        let hostname = service.hostname.as_deref().unwrap_or(default_host);
                        if hostname.ends_with(&domain_name_suffix) || hostname == domain_name {
                            let port = match protocol {
                                ServiceProtocol::Imap => 993,
                                ServiceProtocol::Pop3 => 995,
                                ServiceProtocol::Smtp => 465,
                                ServiceProtocol::Jmap
                                | ServiceProtocol::Caldav
                                | ServiceProtocol::Carddav
                                | ServiceProtocol::Webdav => 443,
                                ServiceProtocol::Managesieve => continue,
                            };
                            hostnames
                                .entry(hostname.to_string())
                                .or_default()
                                .insert(port);
                        }
                    }

                    for (record_name, record_type) in [
                        ("ua-auto-config", DnsRecordType::AutoConfig),
                        ("autoconfig", DnsRecordType::AutoConfigLegacy),
                        ("autodiscover", DnsRecordType::AutoDiscover),
                        ("mta-sts", DnsRecordType::MtaSts),
                    ] {
                        if matches!(&domain.dns_management, DnsManagement::Automatic(props) if props.publish_records.contains(&record_type))
                            || matches!(domain.dns_management, DnsManagement::Manual)
                        {
                            hostnames
                                .entry(format!("{record_name}.{domain_name}"))
                                .or_default()
                                .insert(443);
                        }
                    }

                    for (hostname, ports) in hostnames {
                        if let Some(key) = self.resolve_certificate(&hostname) {
                            for (cert_num, cert) in key.cert.iter().enumerate() {
                                let parsed_cert = match parse_x509_certificate(cert) {
                                    Ok((_, parsed_cert)) => parsed_cert,
                                    Err(err) => {
                                        trc::error!(
                                            trc::StoreEvent::UnexpectedError
                                                .into_err()
                                                .reason(err)
                                                .caused_by(trc::location!())
                                        );
                                        continue;
                                    }
                                };

                                let cert_usage = if cert_num == 0 {
                                    TlsaCertUsage::DaneEe
                                } else {
                                    TlsaCertUsage::DaneTa
                                };
                                let cert_data = sha2::Sha256::digest(parsed_cert.subject_pki.raw);

                                for port in &ports {
                                    records.push(NamedDnsRecord {
                                        name: format!("_{port}._tcp.{hostname}."),
                                        record: DnsRecord::TLSA(TLSARecord {
                                            cert_usage,
                                            selector: TlsaSelector::Spki,
                                            matching: TlsaMatching::Sha256,
                                            cert_data: cert_data.to_vec(),
                                        }),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(records)
    }

    pub async fn build_bind_dns_records(
        &self,
        domain_id: Id,
        domain: &Domain,
    ) -> trc::Result<String> {
        self.build_dns_records(
            domain_id,
            domain,
            &[
                DnsRecordType::Dkim,
                DnsRecordType::Tlsa,
                DnsRecordType::Spf,
                DnsRecordType::Mx,
                DnsRecordType::Dmarc,
                DnsRecordType::Srv,
                DnsRecordType::MtaSts,
                DnsRecordType::TlsRpt,
                DnsRecordType::Caa,
                DnsRecordType::AutoConfig,
                DnsRecordType::AutoConfigLegacy,
                DnsRecordType::AutoDiscover,
            ],
        )
        .await
        .map(|records| BindSerializer::serialize(&records))
    }

    pub async fn get_pacc_for_domain(&self, domain_name: &str) -> trc::Result<String> {
        self.get_directory_for_domain(domain_name)
            .await
            .caused_by(trc::location!())
            .map(|directory| {
                directory
                    .and_then(|directory| {
                        directory
                            .oidc_discovery_document()
                            .map(|doc| self.core.network.info.pacc.build(&doc.url))
                    })
                    .unwrap_or_else(|| {
                        self.core
                            .network
                            .info
                            .pacc
                            .build(&self.core.network.http.url_https)
                    })
            })
    }
}

impl Pacc {
    pub fn build(&self, endpoint: &str) -> String {
        let mut response =
            String::with_capacity(self.prefix.len() + self.suffix.len() + endpoint.len());
        response.push_str(&self.prefix);
        response.push_str(endpoint);
        response.push_str(&self.suffix);
        response
    }
}

#[inline(always)]
#[allow(unused)]
fn provider_domain(url: &Url) -> Option<&str> {
    #[cfg(feature = "test_mode")]
    {
        Some("pebble.letsencrypt.org")
    }

    #[cfg(not(feature = "test_mode"))]
    {
        url.host_str().and_then(psl::domain_str)
    }
}
