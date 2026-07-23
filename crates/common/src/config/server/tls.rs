/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::network::acme::ParsedCert;
use ahash::{AHashMap, AHashSet};
use rcgen::generate_simple_self_signed;
use registry::{
    schema::{
        prelude::Object,
        structs::{Certificate, PublicText, SecretText, SystemSettings},
    },
    types::{datetime::UTCDateTime, map::Map},
};
use rustls::{
    SupportedProtocolVersion,
    crypto::aws_lc_rs::sign::any_supported_type,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};
use rustls_pemfile::{Item, certs, read_all};
use rustls_pki_types::PrivateKeyDer;
use std::{io::Cursor, sync::Arc};
use store::{
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
    write::now,
};

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

pub(crate) async fn parse_certificates(
    bp: &mut Bootstrap,
    certificates: &mut AHashMap<Box<str>, Arc<CertifiedKey>>,
    subject_names: &mut AHashSet<Box<str>>,
) {
    let system = bp.setting_infallible::<SystemSettings>().await;

    // Parse certificates
    let now = now() as i64;
    let mut certs_expired = Vec::new();
    let mut certs_expirations = AHashMap::new();
    for cert_obj in bp.list_infallible::<Certificate>().await {
        let obj_id = cert_obj.id;
        let revision = cert_obj.revision;
        let mut cert = cert_obj.object;

        let is_file_backed = matches!(cert.certificate, PublicText::File(_))
            || matches!(cert.private_key, SecretText::File(_));
        let mut public = None;
        let mut refreshed_meta = None;
        if is_file_backed {
            let pem = match cert.certificate.value().await {
                Ok(value) => value.into_owned().into_bytes(),
                Err(err) => {
                    bp.build_error(obj_id, format!("Failed to obtain certificate value: {err}"));
                    continue;
                }
            };
            match ParsedCert::parse(&pem) {
                Ok(parsed) => {
                    let not_valid_after =
                        UTCDateTime::from_timestamp(parsed.valid_not_after.timestamp());
                    let not_valid_before =
                        UTCDateTime::from_timestamp(parsed.valid_not_before.timestamp());
                    let sans = Map::new(parsed.sans);
                    if cert.not_valid_after != not_valid_after
                        || cert.not_valid_before != not_valid_before
                        || cert.issuer != parsed.issuer
                        || cert.subject_alternative_names != sans
                    {
                        refreshed_meta =
                            Some((not_valid_after, not_valid_before, parsed.issuer, sans));
                    }
                    public = Some(pem);
                }
                Err(err) => {
                    bp.build_error(obj_id, format!("Invalid certificate: {err}"));
                    continue;
                }
            }
        }

        let (not_valid_after, not_valid_before) = match refreshed_meta.as_ref() {
            Some((after, before, _, _)) => (after.timestamp(), before.timestamp()),
            None => (
                cert.not_valid_after.timestamp(),
                cert.not_valid_before.timestamp(),
            ),
        };

        if not_valid_after <= now {
            certs_expired.push((
                obj_id,
                cert.subject_alternative_names.clone().into_inner(),
                Object {
                    inner: cert.into(),
                    revision,
                },
            ));
            continue;
        } else if not_valid_before > now {
            continue; // Skip certificates that are not yet valid
        }

        let secret = match cert.private_key.secret().await {
            Ok(secret) => secret.into_owned().into_bytes(),
            Err(err) => {
                bp.build_error(
                    obj_id,
                    format!("Failed to obtain private key secret: {err}"),
                );
                continue;
            }
        };
        let public = match public {
            Some(public) => public,
            None => match cert.certificate.value().await {
                Ok(value) => value.into_owned().into_bytes(),
                Err(err) => {
                    bp.build_error(obj_id, format!("Failed to obtain certificate value: {err}"));
                    continue;
                }
            },
        };

        if let Some((not_valid_after, not_valid_before, issuer, sans)) = refreshed_meta {
            let old = Object {
                inner: cert.clone().into(),
                revision,
            };
            cert.not_valid_after = not_valid_after;
            cert.not_valid_before = not_valid_before;
            cert.issuer = issuer;
            cert.subject_alternative_names = sans;
            let new = Object {
                inner: cert.clone().into(),
                revision,
            };
            if let Err(err) = bp
                .registry
                .write(RegistryWrite::update(obj_id.id(), &new, &old))
                .await
            {
                trc::error!(
                    err.details("Failed to refresh TLS certificate metadata in registry.")
                        .caused_by(trc::location!())
                );
            }
        }

        // Add default certificate
        if system
            .default_certificate_id
            .as_ref()
            .is_some_and(|id| *id == obj_id.id())
        {
            cert.subject_alternative_names
                .push_unchecked("*".to_string());
        }

        // Ensure that the most up-to-date certificate is used
        cert.subject_alternative_names.inner_mut().retain(|name| {
            if certs_expirations
                .get(name)
                .is_none_or(|expires| *expires < not_valid_after)
            {
                certs_expirations.insert(name.clone(), not_valid_after);
                true
            } else {
                false
            }
        });

        match build_certified_key(public, secret) {
            Ok(key) => {
                // Add certificates
                let key = Arc::new(key);
                for name in cert.subject_alternative_names.into_inner() {
                    subject_names.insert(name.as_str().into());
                    certificates.insert(
                        name.strip_prefix("*.")
                            .map(Into::into)
                            .unwrap_or_else(|| name.into_boxed_str()),
                        key.clone(),
                    );
                }
            }
            Err(err) => {
                bp.build_error(obj_id, format!("Invalid certificate: {err}"));
            }
        }
    }

    // Remove expired certificates
    if !certs_expired.is_empty() {
        for (id, sans, object) in certs_expired {
            if let Err(err) = bp
                .registry
                .write(RegistryWrite::delete_object(id, &object))
                .await
            {
                trc::error!(
                    err.details("Failed to delete expired TLS certificate from registry.")
                        .caused_by(trc::location!())
                );
            } else {
                trc::event!(
                    Tls(trc::TlsEvent::ExpiredCertificateRemoved),
                    Details = sans
                );
            }
        }
    }
}

pub(crate) fn build_certified_key(
    cert: Vec<u8>,
    pk_bytes: Vec<u8>,
) -> Result<CertifiedKey, String> {
    let mut pk = None;
    for item in read_all(&mut Cursor::new(pk_bytes)) {
        match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            Item::Pkcs8Key(key) => {
                pk = Some(PrivateKeyDer::Pkcs8(key));
                break;
            }
            Item::Pkcs1Key(key) => {
                pk = Some(PrivateKeyDer::Pkcs1(key));
                break;
            }
            Item::Sec1Key(key) => {
                pk = Some(PrivateKeyDer::Sec1(key));
                break;
            }
            _ => continue, // Skip certificates, DH params, etc.
        }
    }
    let pk = pk.ok_or_else(|| "No private keys found.".to_string())?;
    let cert = certs(&mut Cursor::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Failed to read certificates: {err}"))?;

    if !cert.is_empty() {
        Ok(CertifiedKey {
            cert,
            key: any_supported_type(&pk)
                .map_err(|err| format!("Failed to sign certificate: {err}",))?,
            ocsp: None,
        })
    } else {
        Err("No certificates found.".to_string())
    }
}

pub(crate) fn build_self_signed_cert(
    domains: impl Into<Vec<String>>,
) -> Result<CertifiedKey, String> {
    let domains = domains
        .into()
        .into_iter()
        .map(|domain| {
            if domain.is_ascii() {
                domain
            } else {
                idna::domain_to_ascii(&domain).unwrap_or(domain)
            }
        })
        .collect::<Vec<_>>();
    let rcgen::CertifiedKey { cert, signing_key } = generate_simple_self_signed(domains)
        .map_err(|err| format!("Failed to generate self-signed certificate: {err}",))?;
    build_certified_key(
        cert.pem().into_bytes(),
        signing_key.serialize_pem().into_bytes(),
    )
}
