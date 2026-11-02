/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::smtp::auth::{pem_or_base64_decode, rsa_key_parse};
use dns_update::{DnsRecord, NamedDnsRecord};
use encodify::{base64::STANDARD, pem};
use jiff::{Timestamp, fmt::strtime, tz::TimeZone};
use mail_auth::crypto::{Ed25519Key, MlDsa44Key};
use mail_auth::dkim::generate::DkimKeyPair;
use registry::schema::enums::DkimSignatureType;
use registry::schema::structs::DkimSignature;
use rsa::pkcs1::{DecodeRsaPublicKey, der::Document};
use store::rand::distr::Alphanumeric;
use store::rand::{self, RngExt};

pub async fn generate_dkim_private_key(
    key_type: DkimSignatureType,
) -> trc::Result<Result<String, String>> {
    let private_key = tokio::task::spawn_blocking(move || match key_type {
        DkimSignatureType::Dkim1RsaSha256 | DkimSignatureType::Dkim2RsaSha256 => {
            DkimKeyPair::generate_rsa(2048).map(|key| (key, "RSA PRIVATE KEY"))
        }
        DkimSignatureType::Dkim1Ed25519Sha256 | DkimSignatureType::Dkim2Ed25519Sha256 => {
            DkimKeyPair::generate_ed25519().map(|key| (key, "PRIVATE KEY"))
        }
        DkimSignatureType::Dkim2MlDsa44 => {
            DkimKeyPair::generate_mldsa44().map(|key| (key, "PRIVATE KEY"))
        }
    })
    .await
    .map_err(|err| {
        trc::EventType::Server(trc::ServerEvent::ThreadError)
            .reason(err)
            .caused_by(trc::location!())
    })?;

    Ok(private_key
        .map(|(private_key, pk_type)| pem::STANDARD.encode(pk_type, private_key.private_key()))
        .map_err(|err| err.to_string()))
}

pub async fn generate_dkim_public_key(key: &DkimSignature) -> trc::Result<String> {
    let pem = key
        .private_key()
        .secret()
        .await
        .map_err(|err| trc::DkimEvent::BuildError.reason(err))?;

    match key {
        DkimSignature::Dkim1RsaSha256(_) | DkimSignature::Dkim2RsaSha256(_) => {
            rsa_key_parse(pem.as_bytes())
                .and_then(|pk| {
                    Document::from_pkcs1_der(&pk.public_key()).map_err(|err| {
                        trc::EventType::Dkim(trc::DkimEvent::BuildError)
                            .into_err()
                            .reason(err)
                    })
                })
                .map(|pk| STANDARD.encode(pk.as_bytes()))
        }
        DkimSignature::Dkim1Ed25519Sha256(_) | DkimSignature::Dkim2Ed25519Sha256(_) => {
            Ed25519Key::from_pkcs8_maybe_unchecked_der(&decode_private_key(&pem)?)
                .map(|pk| STANDARD.encode(pk.public_key()))
                .map_err(|err| {
                    trc::EventType::Dkim(trc::DkimEvent::BuildError)
                        .into_err()
                        .reason(err)
                })
        }
        DkimSignature::Dkim2MlDsa44(_) => MlDsa44Key::from_pkcs8_der(&decode_private_key(&pem)?)
            .and_then(|pk| pk.public_key())
            .map(|pk| STANDARD.encode(pk))
            .map_err(|err| {
                trc::EventType::Dkim(trc::DkimEvent::BuildError)
                    .into_err()
                    .reason(err)
            }),
    }
}

fn decode_private_key(pem: &str) -> trc::Result<Vec<u8>> {
    pem_or_base64_decode(pem).map_err(|_| {
        trc::EventType::Dkim(trc::DkimEvent::BuildError)
            .into_err()
            .details("Failed to parse private key PEM")
    })
}

pub async fn generate_dkim_dns_record(
    key: &DkimSignature,
    domain: &str,
) -> trc::Result<NamedDnsRecord> {
    let public_key = generate_dkim_public_key(key).await?;

    let (selector, record) = match key {
        DkimSignature::Dkim1Ed25519Sha256(sign) => (
            &sign.selector,
            format!("v=DKIM1; k=ed25519; h=sha256; p={public_key}"),
        ),
        DkimSignature::Dkim2Ed25519Sha256(sign) => (
            &sign.selector,
            format!("v=DKIM1; k=ed25519; h=sha256; p={public_key}"),
        ),
        DkimSignature::Dkim1RsaSha256(sign) => (
            &sign.selector,
            format!("v=DKIM1; k=rsa; h=sha256; p={public_key}"),
        ),
        DkimSignature::Dkim2RsaSha256(sign) => (
            &sign.selector,
            format!("v=DKIM1; k=rsa; h=sha256; p={public_key}"),
        ),
        DkimSignature::Dkim2MlDsa44(sign) => (
            &sign.selector,
            format!("v=DKIM1; k=mldsa44; p={public_key}"),
        ),
    };

    Ok(NamedDnsRecord {
        name: format!("{selector}._domainkey.{domain}."),
        record: DnsRecord::TXT(record),
    })
}

pub fn generate_dkim_dns_record_name(key: &DkimSignature, domain: &str) -> String {
    format!("{}._domainkey.{domain}.", key.selector())
}

/// Generate a DKIM selector from a template string.
///
/// Supported variables:
/// - `{algorithm}`: signing algorithm in lowercase (`rsa`, `ed25519`, `mldsa44`)
/// - `{hash}`: hash algorithm (`sha256`, or `none` for ML-DSA-44)
/// - `{version}`: DKIM version number (`1`, `2`)
/// - `{date-<fmt>}`: current UTC date formatted with strftime specifiers (e.g. `{date-%Y%m%d}`)
/// - `{epoch}`: current UTC unix timestamp
/// - `{random}`: random 8-character alphanumeric string
///
pub fn generate_dkim_selector(
    template: &str,
    sig_type: DkimSignatureType,
) -> Result<String, String> {
    let now = Timestamp::now().to_zoned(TimeZone::UTC);
    let mut result = Vec::with_capacity(template.len());
    let mut chars = template.as_bytes();

    while !chars.is_empty() {
        // Find next '{' or consume literal text
        let Some(open) = memchr(b'{', chars) else {
            // No more variables: append remaining literal
            // SAFETY: template is valid UTF-8, and we only slice on ASCII boundaries
            result.extend(
                chars
                    .iter()
                    .filter(|&&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_'),
            );
            break;
        };

        // Append literal before '{'
        if open > 0 {
            result.extend(
                chars[..open]
                    .iter()
                    .filter(|&&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_'),
            );
        }

        // Find matching '}'
        let rest = chars.get(open + 1..).unwrap_or_default();
        let Some(close) = memchr(b'}', rest) else {
            return Err("unclosed '{' in template".into());
        };

        let var =
            std::str::from_utf8(&rest[..close]).map_err(|_| "invalid UTF-8 in variable name")?;

        match var {
            "algorithm" => result.extend_from_slice(sig_type.algorithm().as_bytes()),
            "hash" => result.extend_from_slice(sig_type.hash().as_bytes()),
            "version" => result.extend_from_slice(sig_type.version().as_bytes()),
            "epoch" => {
                result.extend_from_slice(now.timestamp().as_second().to_string().as_bytes());
            }
            "random" => {
                let rand_str: String = rand::rng()
                    .sample_iter(Alphanumeric)
                    .take(8)
                    .map(|ch| char::from(ch.to_ascii_lowercase()))
                    .collect::<String>();
                result.extend(rand_str.as_bytes());
            }
            v => {
                if let Some(fmt) = v.strip_prefix("date-") {
                    if fmt.is_empty() {
                        return Err("empty strftime format in {date-}".into());
                    }
                    let formatted = strtime::format(fmt, &now)
                        .map_err(|err| format!("invalid date format '{fmt}': {err}"))?;
                    if formatted.is_empty() {
                        return Err(format!("date format '{fmt}' produced empty output"));
                    }
                    result.extend(formatted.as_bytes().iter().filter(|&&c| {
                        c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_'
                    }));
                } else {
                    return Err(format!("unrecognized variable '{{{var}}}'"));
                }
            }
        }

        chars = rest.get(close + 1..).unwrap_or_default();
    }

    if !result.is_empty() {
        Ok(String::from_utf8(result).unwrap_or_default())
    } else {
        Err("Selector cannot be empty".into())
    }
}

#[inline]
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/network/dkim/tests.rs"]
mod tests;
