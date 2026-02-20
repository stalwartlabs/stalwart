/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, network::acme::AcmeProvider};
use ahash::{AHashMap, AHashSet};
use dns_update::{
    Algorithm, DnsUpdater, TsigAlgorithm,
    providers::{ovh::OvhEndpoint, rfc2136::DnsAddress},
};
use hickory_proto::rr::dnssec::KeyPair;
use rcgen::generate_simple_self_signed;
use registry::schema::{
    enums,
    structs::{self, Certificate, DnsServer},
};
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};
use rustls::{
    SupportedProtocolVersion,
    crypto::ring::sign::any_supported_type,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};
use rustls_pemfile::{Item, certs, read_one};
use rustls_pki_types::PrivateKeyDer;
use std::{
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use store::registry::bootstrap::Bootstrap;
use trc::AddContext;
use x509_parser::{
    certificate::X509Certificate,
    der_parser::asn1_rs::FromDer,
    extensions::{GeneralName, ParsedExtension},
};

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

impl Server {
    pub async fn build_acme_provider(&self, id: u64) -> trc::Result<AcmeProvider> {
        if let Some(server) = self
            .registry()
            .object::<structs::AcmeProvider>(id.into())
            .await
            .caused_by(trc::location!())?
        {
            Ok(AcmeProvider::new(server))
        } else {
            trc::bail!(
                trc::AcmeEvent::Error
                    .into_err()
                    .id(id.to_string())
                    .details("ACME provider not found")
            )
        }
    }

    pub async fn build_dns_updater(&self, id: u64) -> trc::Result<DnsUpdater> {
        let Some(server) = self
            .registry()
            .object::<DnsServer>(id.into())
            .await
            .caused_by(trc::location!())?
        else {
            trc::bail!(
                trc::DnsEvent::BuildError
                    .into_err()
                    .id(id.to_string())
                    .details("DNS server settings not found")
            );
        };

        match server {
            DnsServer::Tsig(server) => DnsUpdater::new_rfc2136_tsig(
                match server.protocol {
                    enums::IpProtocol::Udp => DnsAddress::Tcp(SocketAddr::new(
                        server.host.into_inner(),
                        server.port as u16,
                    )),
                    enums::IpProtocol::Tcp => DnsAddress::Udp(SocketAddr::new(
                        server.host.into_inner(),
                        server.port as u16,
                    )),
                },
                server.key_name,
                server.key,
                match server.tsig_algorithm {
                    enums::TsigAlgorithm::HmacMd5 => TsigAlgorithm::HmacMd5,
                    enums::TsigAlgorithm::Gss => TsigAlgorithm::Gss,
                    enums::TsigAlgorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
                    enums::TsigAlgorithm::HmacSha224 => TsigAlgorithm::HmacSha224,
                    enums::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
                    enums::TsigAlgorithm::HmacSha256128 => TsigAlgorithm::HmacSha256_128,
                    enums::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
                    enums::TsigAlgorithm::HmacSha384192 => TsigAlgorithm::HmacSha384_192,
                    enums::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
                    enums::TsigAlgorithm::HmacSha512256 => TsigAlgorithm::HmacSha512_256,
                },
            ),
            DnsServer::Sig0(server) => DnsUpdater::new_rfc2136_sig0(
                match server.protocol {
                    enums::IpProtocol::Udp => DnsAddress::Tcp(SocketAddr::new(
                        server.host.into_inner(),
                        server.port as u16,
                    )),
                    enums::IpProtocol::Tcp => DnsAddress::Udp(SocketAddr::new(
                        server.host.into_inner(),
                        server.port as u16,
                    )),
                },
                server.signer_name,
                match server.sig0_algorithm {
                    enums::Sig0Algorithm::EcdsaP256Sha256 => KeyPair::ECDSA(
                        EcdsaKeyPair::from_pkcs8(
                            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                            server.key.as_bytes(),
                            &ring::rand::SystemRandom::new(),
                        )
                        .map_err(|err| {
                            trc::DnsEvent::BuildError
                                .reason(err)
                                .details("Failed to build ECDSA P-256 key pair")
                                .id(id.to_string())
                        })?,
                    ),
                    enums::Sig0Algorithm::EcdsaP384Sha384 => KeyPair::ECDSA(
                        EcdsaKeyPair::from_pkcs8(
                            &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                            server.key.as_bytes(),
                            &ring::rand::SystemRandom::new(),
                        )
                        .map_err(|err| {
                            trc::DnsEvent::BuildError
                                .reason(err)
                                .details("Failed to build ECDSA P-384 key pair")
                                .id(id.to_string())
                        })?,
                    ),
                    enums::Sig0Algorithm::Ed25519 => KeyPair::ED25519(
                        Ed25519KeyPair::from_pkcs8(server.key.as_bytes()).map_err(|err| {
                            trc::DnsEvent::BuildError
                                .reason(err)
                                .details("Failed to build Ed25519 key pair")
                                .id(id.to_string())
                        })?,
                    ),
                },
                server.public_key,
                match server.sig0_algorithm {
                    enums::Sig0Algorithm::EcdsaP256Sha256 => Algorithm::ECDSAP256SHA256,
                    enums::Sig0Algorithm::EcdsaP384Sha384 => Algorithm::ECDSAP384SHA384,
                    enums::Sig0Algorithm::Ed25519 => Algorithm::ED25519,
                },
            ),
            DnsServer::Cloudflare(server) => DnsUpdater::new_cloudflare(
                server.secret,
                server.email,
                server.timeout.into_inner().into(),
            ),
            DnsServer::DigitalOcean(server) => {
                DnsUpdater::new_digitalocean(server.secret, server.timeout.into_inner().into())
            }
            DnsServer::DeSEC(server) => {
                DnsUpdater::new_desec(server.secret, server.timeout.into_inner().into())
            }
            DnsServer::Ovh(server) => DnsUpdater::new_ovh(
                server.application_key,
                server.application_secret,
                server.consumer_key,
                match server.ovh_endpoint {
                    enums::OvhEndpoint::OvhEu => OvhEndpoint::OvhEu,
                    enums::OvhEndpoint::OvhCa => OvhEndpoint::OvhCa,
                    enums::OvhEndpoint::KimsufiEu => OvhEndpoint::KimsufiEu,
                    enums::OvhEndpoint::KimsufiCa => OvhEndpoint::KimsufiCa,
                    enums::OvhEndpoint::SoyoustartEu => OvhEndpoint::SoyoustartEu,
                    enums::OvhEndpoint::SoyoustartCa => OvhEndpoint::SoyoustartCa,
                },
                server.timeout.into_inner().into(),
            ),
        }
        .map_err(|err| {
            trc::DnsEvent::BuildError
                .reason(err)
                .details("Failed to build DNS updater")
                .id(id.to_string())
        })
    }
}

pub(crate) async fn parse_certificates(
    bp: &mut Bootstrap,
    certificates: &mut AHashMap<Box<str>, Arc<CertifiedKey>>,
    subject_names: &mut AHashSet<Box<str>>,
) {
    // Parse certificates
    for cert_obj in bp.list_infallible::<Certificate>().await {
        match build_certified_key(
            cert_obj.object.certificate.into_bytes(),
            cert_obj.object.private_key.into_bytes(),
        ) {
            Ok(cert) => {
                match cert
                    .end_entity_cert()
                    .map_err(|err| format!("Failed to obtain end entity cert: {err}"))
                    .and_then(|cert| {
                        X509Certificate::from_der(cert.as_ref())
                            .map_err(|err| format!("Failed to parse end entity cert: {err}"))
                    }) {
                    Ok((_, parsed)) => {
                        // Add CNs and SANs to the list of names
                        let mut names: AHashSet<Box<str>> = AHashSet::new();
                        for name in parsed.subject().iter_common_name() {
                            if let Ok(name) = name.as_str() {
                                names.insert(name.into());
                            }
                        }
                        for ext in parsed.extensions() {
                            if let ParsedExtension::SubjectAlternativeName(san) =
                                ext.parsed_extension()
                            {
                                for name in &san.general_names {
                                    let name: Box<str> = match name {
                                        GeneralName::DNSName(name) => (*name).into(),
                                        GeneralName::IPAddress(ip) => match ip.len() {
                                            4 => Ipv4Addr::from(<[u8; 4]>::try_from(*ip).unwrap())
                                                .to_string()
                                                .into(),
                                            16 => {
                                                Ipv6Addr::from(<[u8; 16]>::try_from(*ip).unwrap())
                                                    .to_string()
                                                    .into()
                                            }
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

                        // Add custom SNIs
                        names.extend(
                            cert_obj
                                .object
                                .subject_alternative_names
                                .into_iter()
                                .map(Into::into),
                        );

                        // Add domain names
                        subject_names.extend(names.iter().cloned());

                        // Add certificates
                        let cert = Arc::new(cert);
                        for name in names {
                            certificates.insert(
                                name.strip_prefix("*.").map(Into::into).unwrap_or(name),
                                cert.clone(),
                            );
                        }

                        // Add default certificate
                        if cert_obj.object.default {
                            certificates.insert("*".into(), cert.clone());
                        }
                    }
                    Err(err) => {
                        bp.build_error(cert_obj.id, format!("Invalid certificate: {err}"));
                    }
                }
            }
            Err(err) => {
                bp.build_error(cert_obj.id, format!("Invalid certificate: {err}"));
            }
        }
    }
}

pub(crate) fn build_certified_key(cert: Vec<u8>, pk: Vec<u8>) -> Result<CertifiedKey, String> {
    let cert = certs(&mut Cursor::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Failed to read certificates: {err}"))?;
    if cert.is_empty() {
        return Err("No certificates found.".to_string());
    }
    let pk = match read_one(&mut Cursor::new(pk))
        .map_err(|err| format!("Failed to read private keys.: {err}",))?
        .into_iter()
        .next()
    {
        Some(Item::Pkcs8Key(key)) => PrivateKeyDer::Pkcs8(key),
        Some(Item::Pkcs1Key(key)) => PrivateKeyDer::Pkcs1(key),
        Some(Item::Sec1Key(key)) => PrivateKeyDer::Sec1(key),
        Some(_) => return Err("Unsupported private keys found.".to_string()),
        None => return Err("No private keys found.".to_string()),
    };

    Ok(CertifiedKey {
        cert,
        key: any_supported_type(&pk)
            .map_err(|err| format!("Failed to sign certificate: {err}",))?,
        ocsp: None,
    })
}

pub(crate) fn build_self_signed_cert(
    domains: impl Into<Vec<String>>,
) -> Result<CertifiedKey, String> {
    let cert = generate_simple_self_signed(domains)
        .map_err(|err| format!("Failed to generate self-signed certificate: {err}",))?;
    build_certified_key(
        cert.serialize_pem().unwrap().into_bytes(),
        cert.serialize_private_key_pem().into_bytes(),
    )
}
