/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::smtp::auth::{rsa_key_parse, simple_pem_parse};
use chrono::Utc;
use dns_update::{DnsRecord, NamedDnsRecord};
use mail_auth::common::crypto::Ed25519Key;
use mail_auth::dkim::generate::DkimKeyPair;
use mail_builder::encoders::base64::base64_encode;
use pkcs8::Document;
use registry::schema::enums::DkimSignatureType;
use registry::schema::structs::DkimSignature;
use rsa::pkcs1::DecodeRsaPublicKey;
use store::rand::distr::Alphanumeric;
use store::rand::{self, Rng};

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
    })
    .await
    .map_err(|err| {
        trc::EventType::Server(trc::ServerEvent::ThreadError)
            .reason(err)
            .caused_by(trc::location!())
    })?;

    Ok(private_key
        .map(|(private_key, pk_type)| {
            let mut pem = format!("-----BEGIN {pk_type}-----\n").into_bytes();
            let mut lf_count = 65;
            for ch in base64_encode(private_key.private_key()).unwrap_or_default() {
                pem.push(ch);
                lf_count -= 1;
                if lf_count == 0 {
                    pem.push(b'\n');
                    lf_count = 65;
                }
            }
            if lf_count != 65 {
                pem.push(b'\n');
            }
            pem.extend_from_slice(format!("-----END {pk_type}-----\n").as_bytes());

            String::from_utf8(pem).unwrap_or_default()
        })
        .map_err(|err| err.to_string()))
}

pub async fn generate_dkim_public_key(key: &DkimSignature) -> trc::Result<String> {
    let is_rsa = matches!(
        key,
        DkimSignature::Dkim1RsaSha256(_) | DkimSignature::Dkim2RsaSha256(_)
    );
    let pem = key
        .private_key()
        .secret()
        .await
        .map_err(|err| trc::DkimEvent::BuildError.reason(err))?;

    if is_rsa {
        rsa_key_parse(pem.as_bytes())
            .and_then(|pk| {
                Document::from_pkcs1_der(&pk.public_key()).map_err(|err| {
                    trc::EventType::Dkim(trc::DkimEvent::BuildError)
                        .into_err()
                        .reason(err)
                })
            })
            .map(|pk| {
                String::from_utf8(base64_encode(pk.as_bytes()).unwrap_or_default())
                    .unwrap_or_default()
            })
    } else {
        simple_pem_parse(&pem)
            .ok_or_else(|| {
                trc::EventType::Dkim(trc::DkimEvent::BuildError)
                    .into_err()
                    .details("Failed to parse private key PEM")
            })
            .and_then(|der| {
                Ed25519Key::from_pkcs8_maybe_unchecked_der(&der).map_err(|err| {
                    trc::EventType::Dkim(trc::DkimEvent::BuildError)
                        .into_err()
                        .reason(err)
                })
            })
            .map(|pk| {
                String::from_utf8(base64_encode(&pk.public_key()).unwrap_or_default())
                    .unwrap_or_default()
            })
    }
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
/// - `{algorithm}`: signing algorithm in lowercase (`rsa`, `ed25519`)
/// - `{hash}`: hash algorithm (`sha256`)
/// - `{version}`: DKIM version number (`1`)
/// - `{date-<fmt>}`: current UTC date formatted with chrono strftime (e.g. `{date-%Y%m%d}`)
/// - `{epoch}`: current UTC unix timestamp
/// - `{random}`: random 8-character alphanumeric string
///
pub fn generate_dkim_selector(
    template: &str,
    sig_type: DkimSignatureType,
) -> Result<String, String> {
    let now = Utc::now();
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
                result.extend_from_slice(now.timestamp().to_string().as_bytes());
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
                    let formatted = now.format(fmt).to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_algorithm_date() {
        let sel = generate_dkim_selector(
            "{algorithm}-{date-%Y%m%d}",
            DkimSignatureType::Dkim1RsaSha256,
        )
        .unwrap();
        let today = Utc::now().format("%Y%m%d").to_string();
        assert_eq!(sel, format!("rsa-{today}"));
    }

    #[test]
    fn all_variables() {
        let sel = generate_dkim_selector(
            "v{version}-{algorithm}-{hash}-{epoch}",
            DkimSignatureType::Dkim1Ed25519Sha256,
        )
        .unwrap();
        assert!(sel.starts_with("v1-ed25519-sha256-"));
    }

    #[test]
    fn literal_only() {
        let sel =
            generate_dkim_selector("my-static-selector", DkimSignatureType::default()).unwrap();
        assert_eq!(sel, "my-static-selector");
    }

    #[test]
    fn invalid_chars_stripped() {
        let sel = generate_dkim_selector("{algorithm} {hash}", DkimSignatureType::Dkim1RsaSha256)
            .unwrap();
        assert_eq!(sel, "rsasha256");
    }

    #[test]
    fn unrecognized_variable_errors() {
        let err = generate_dkim_selector("{bogus}", DkimSignatureType::default()).unwrap_err();
        assert!(err.contains("unrecognized variable"));
    }

    #[test]
    fn unclosed_brace_errors() {
        let err = generate_dkim_selector("{algorithm", DkimSignatureType::default()).unwrap_err();
        assert!(err.contains("unclosed"));
    }

    #[test]
    fn empty_after_sanitization_errors() {
        let err = generate_dkim_selector("   ", DkimSignatureType::default()).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn empty_date_format_errors() {
        let err = generate_dkim_selector("{date-}", DkimSignatureType::default()).unwrap_err();
        assert!(err.contains("empty strftime"));
    }

    #[test]
    fn date_month_only() {
        let sel = generate_dkim_selector("{date-%Y%m}", DkimSignatureType::Dkim1RsaSha256).unwrap();
        let expected = Utc::now().format("%Y%m").to_string();
        assert_eq!(sel, expected);
    }
}
