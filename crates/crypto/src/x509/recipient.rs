/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::{
    backend::{
        agree::Curve,
        hash::HashAlgorithm,
        kem::{MlKem, MlKemPublicKey},
        rsa::{MAX_RSA_BITS, MIN_RSA_BITS, OaepHash, RsaPublicKey},
    },
    der::{
        oid,
        reader::Reader,
        tag,
        writer::{tlv_len, write_header, write_tlv},
    },
    error::KeyError,
    pgp::armor::{decode_body, next_block},
    types::{
        Fingerprint, KeyCapabilities, KeyCapability, KeyKind, KeyWarning, ParsedKeys, RecipientSet,
        Recipients, SmimeCapabilities, SmimeCipher,
    },
    x509::cert::{
        AlgorithmId, Certificate, KU_DATA_ENCIPHERMENT, KU_DECIPHER_ONLY, KU_DIGITAL_SIGNATURE,
        KU_ENCIPHER_ONLY, KU_KEY_AGREEMENT, KU_KEY_ENCIPHERMENT, KU_NON_REPUDIATION,
        digest_oid_hash,
    },
};

const WEAK_RSA_BITS: usize = 3072;
const PKCS12_VERSION: u32 = 3;
const PEM_CERTIFICATE: &[u8] = b"CERTIFICATE";
const PEM_PGP_PREFIX: &[u8] = b"PGP ";
const MAX_CERTIFICATES: usize = 64;

pub(crate) enum SmimeKey {
    Rsa {
        key: RsaPublicKey,
        oaep: Option<OaepHash>,
    },
    Ec {
        curve: Curve,
        point: Box<[u8]>,
    },
    X25519([u8; 32]),
    X448([u8; 56]),
    MlKem(MlKemPublicKey),
}

pub(crate) struct SmimeRecipient {
    pub issuer_and_serial: Box<[u8]>,
    pub fingerprint: [u8; 32],
    pub key: SmimeKey,
    pub gcm: bool,
}

impl SmimeKey {
    pub(crate) fn algorithm_name(&self) -> String {
        match self {
            SmimeKey::Rsa { key, .. } => format!("RSA-{}", key.bits()),
            SmimeKey::Ec { curve, .. } => format!("ECDH {}", curve.name()),
            SmimeKey::X25519(_) => "X25519".to_string(),
            SmimeKey::X448(_) => "X448".to_string(),
            SmimeKey::MlKem(key) => key.kem().name().to_string(),
        }
    }
}

impl SmimeRecipient {
    pub(crate) fn heap_size(&self) -> usize {
        self.issuer_and_serial.len()
            + match &self.key {
                SmimeKey::Rsa { key, .. } => key.heap_size(),
                SmimeKey::Ec { point, .. } => point.len(),
                SmimeKey::X25519(_) | SmimeKey::X448(_) => 0,
                SmimeKey::MlKem(key) => key.heap_size(),
            }
    }
}

pub(crate) fn decode_certificates(input: &[u8]) -> Result<Vec<u8>, KeyError> {
    let trimmed = input.trim_ascii_start();
    if !trimmed.starts_with(b"-----BEGIN ") {
        return Ok(input.to_vec());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut rest = trimmed;
    while let Some((block, next)) = next_block(rest)? {
        match block.raw_label {
            PEM_CERTIFICATE | b"X509 CERTIFICATE" | b"TRUSTED CERTIFICATE" => {
                decode_body(block.body, &mut out)?
            }
            label if label.ends_with(b"PRIVATE KEY") => return Err(KeyError::PrivateKey),
            label if label.starts_with(PEM_PGP_PREFIX) => return Err(KeyError::MixedKeyKinds),
            b"PKCS12" => return Err(KeyError::Pkcs12),
            _ => {}
        }
        rest = next;
    }
    Ok(out)
}

pub(crate) fn split_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>, KeyError> {
    let der = decode_certificates(input)?;
    let parsed = certificates(&der).collect::<Result<Vec<_>, _>>()?;
    let leaves = parsed.iter().filter(|cert| !cert.is_ca());
    let authorities = parsed.iter().filter(|cert| cert.is_ca());
    Ok(leaves
        .chain(authorities)
        .map(|cert| cert.raw.to_vec())
        .collect())
}

pub(crate) fn certificates(der: &[u8]) -> impl Iterator<Item = Result<Certificate<'_>, KeyError>> {
    Reader::new(der).take(MAX_CERTIFICATES).map(|tlv| {
        let tlv = tlv?.expect(tag::SEQUENCE)?;
        if let Some(Ok(first)) = tlv.reader().next()
            && first.tag == tag::INTEGER
        {
            let version = first.content.last().copied().unwrap_or(0);
            return Err(if u32::from(version) == PKCS12_VERSION {
                KeyError::Pkcs12
            } else {
                KeyError::PrivateKey
            });
        }
        Certificate::parse_tlv(tlv).map_err(KeyError::from)
    })
}

fn oaep_params(algorithm: &AlgorithmId<'_>) -> Result<OaepHash, KeyError> {
    let Some(params) = algorithm.params.filter(|p| p.tag == tag::SEQUENCE) else {
        return Ok(OaepHash::Sha1);
    };
    let mut reader = params.reader();
    let hash = match reader.read_optional(tag::context_constructed(0))? {
        Some(t) => digest_oid_hash(AlgorithmId::parse(t.reader().read()?)?.oid),
        None => Some(HashAlgorithm::Sha1),
    };
    let mgf_hash = match reader.read_optional(tag::context_constructed(1))? {
        Some(t) => {
            let mgf = AlgorithmId::parse(t.reader().read()?)?;
            if mgf.oid != oid::MGF1 {
                return Err(KeyError::UnsupportedKeyAlgorithm);
            }
            let inner = mgf.params.ok_or(KeyError::MalformedCertificate)?;
            digest_oid_hash(AlgorithmId::parse(inner)?.oid)
        }
        None => Some(HashAlgorithm::Sha1),
    };
    if reader.read_optional(tag::context_constructed(2))?.is_some() || hash != mgf_hash {
        return Err(KeyError::UnsupportedKeyAlgorithm);
    }
    match hash {
        Some(HashAlgorithm::Sha1) => Ok(OaepHash::Sha1),
        Some(HashAlgorithm::Sha256) => Ok(OaepHash::Sha256),
        Some(HashAlgorithm::Sha384) => Ok(OaepHash::Sha384),
        Some(HashAlgorithm::Sha512) => Ok(OaepHash::Sha512),
        _ => Err(KeyError::UnsupportedKeyAlgorithm),
    }
}

enum Usage {
    Encipherment,
    OaepEncipherment,
    Agreement,
}

fn classify(cert: &Certificate<'_>) -> Result<(SmimeKey, Usage, bool), KeyError> {
    let spki = &cert.spki;
    Ok(match spki.algorithm.oid {
        oid::RSA_ENCRYPTION | oid::RSAES_OAEP => {
            let oaep = if spki.algorithm.oid == oid::RSAES_OAEP {
                Some(oaep_params(&spki.algorithm)?)
            } else {
                None
            };
            let mut rsa = Reader::new(spki.key).read_sequence()?;
            let n = rsa.read_content(tag::INTEGER)?;
            let e = rsa.read_content(tag::INTEGER)?;
            let key = RsaPublicKey::from_components(n, e).map_err(|_| KeyError::WeakRsa)?;
            let bits = key.bits();
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
                return Err(KeyError::WeakRsa);
            }
            let usage = if oaep.is_some() {
                Usage::OaepEncipherment
            } else {
                Usage::Encipherment
            };
            (SmimeKey::Rsa { key, oaep }, usage, bits < WEAK_RSA_BITS)
        }
        oid::EC_PUBLIC_KEY => {
            let params = spki
                .algorithm
                .params
                .ok_or(KeyError::MalformedCertificate)?;
            let curve = match params.content {
                oid::P256 => Curve::P256,
                oid::P384 => Curve::P384,
                oid::P521 => Curve::P521,
                other if other.starts_with(oid::BRAINPOOL_PREFIX) => {
                    return Err(KeyError::Brainpool);
                }
                _ => return Err(KeyError::UnsupportedKeyAlgorithm),
            };
            curve
                .validate_public(spki.key)
                .map_err(|_| KeyError::InvalidPublicKey)?;
            (
                SmimeKey::Ec {
                    curve,
                    point: spki.key.into(),
                },
                Usage::Agreement,
                false,
            )
        }
        oid::X25519 => (
            SmimeKey::X25519(
                spki.key
                    .try_into()
                    .map_err(|_| KeyError::InvalidPublicKey)?,
            ),
            Usage::Agreement,
            false,
        ),
        oid::X448 => (
            SmimeKey::X448(
                spki.key
                    .try_into()
                    .map_err(|_| KeyError::InvalidPublicKey)?,
            ),
            Usage::Agreement,
            false,
        ),
        oid::ML_KEM_512 | oid::ML_KEM_768 | oid::ML_KEM_1024 => {
            let kem = match spki.algorithm.oid {
                oid::ML_KEM_512 => MlKem::MlKem512,
                oid::ML_KEM_768 => MlKem::MlKem768,
                _ => MlKem::MlKem1024,
            };
            (
                SmimeKey::MlKem(
                    MlKemPublicKey::new(kem, spki.key).map_err(|_| KeyError::InvalidPublicKey)?,
                ),
                Usage::Encipherment,
                false,
            )
        }
        _ => return Err(KeyError::UnsupportedKeyAlgorithm),
    })
}

fn check_key_usage(cert: &Certificate<'_>, usage: &Usage) -> Result<(), KeyError> {
    let Some(bits) = cert.extensions.key_usage else {
        return Ok(());
    };
    let allowed = match usage {
        Usage::Encipherment => bits & KU_KEY_ENCIPHERMENT != 0,
        Usage::OaepEncipherment => bits & (KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT) != 0,
        Usage::Agreement => {
            if bits & KU_KEY_AGREEMENT != 0
                && bits & KU_ENCIPHER_ONLY != 0
                && bits & KU_DECIPHER_ONLY == 0
            {
                return Err(KeyError::EncipherOnlyCertificate);
            }
            bits & KU_KEY_AGREEMENT != 0
        }
    };
    if allowed {
        Ok(())
    } else if bits & (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION) != 0 {
        Err(KeyError::SignatureOnlyCertificate)
    } else {
        Err(KeyError::UnsupportedKeyAlgorithm)
    }
}

pub(crate) fn issuer_and_serial(cert: &Certificate<'_>) -> Box<[u8]> {
    let content = cert.issuer.len() + tlv_len(cert.serial.len());
    let mut out = Vec::with_capacity(tlv_len(content));
    write_header(&mut out, tag::SEQUENCE, content);
    out.extend_from_slice(cert.issuer);
    write_tlv(&mut out, tag::INTEGER, cert.serial);
    out.into_boxed_slice()
}

pub(crate) fn parse_capabilities(content: &[u8]) -> SmimeCapabilities {
    let mut caps = SmimeCapabilities::default();
    for capability in Reader::new(content).map_while(Result::ok) {
        let Ok(id) = capability.reader().read_content(tag::OID) else {
            continue;
        };
        let cipher = match id {
            oid::AES128_CBC => Some(SmimeCipher::Aes128Cbc),
            oid::AES192_CBC => Some(SmimeCipher::Aes192Cbc),
            oid::AES256_CBC => Some(SmimeCipher::Aes256Cbc),
            oid::AES128_GCM => Some(SmimeCipher::Aes128Gcm),
            oid::AES192_GCM => Some(SmimeCipher::Aes192Gcm),
            oid::AES256_GCM => Some(SmimeCipher::Aes256Gcm),
            oid::CHACHA20_POLY1305 => Some(SmimeCipher::ChaCha20Poly1305),
            oid::RSAES_OAEP => {
                caps.rsaes_oaep = true;
                None
            }
            _ => None,
        };
        if let Some(cipher) = cipher
            && !caps.ciphers.contains(&cipher)
        {
            caps.ciphers.push(cipher);
        }
    }
    caps
}

pub(crate) fn lists_gcm(caps: &SmimeCapabilities) -> bool {
    caps.ciphers.iter().any(|c| {
        matches!(
            c,
            SmimeCipher::Aes128Gcm | SmimeCipher::Aes192Gcm | SmimeCipher::Aes256Gcm
        )
    })
}

pub(crate) fn validate_leaf(
    cert: &Certificate<'_>,
    now: u64,
) -> Result<(SmimeRecipient, bool, bool), KeyError> {
    if now < cert.not_before {
        return Err(KeyError::NotYetValid);
    }
    if now > cert.not_after {
        return Err(KeyError::Expired);
    }
    let (key, usage, weak) = classify(cert)?;
    check_key_usage(cert, &usage)?;
    if !cert.has_email_protection() {
        return Err(KeyError::NoEmailProtection);
    }
    let no_known_decryptor = matches!(key, SmimeKey::X25519(_) | SmimeKey::X448(_));
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(HashAlgorithm::Sha256.digest(cert.raw).as_ref());
    let gcm = cert
        .extensions
        .smime_capabilities
        .is_some_and(|c| lists_gcm(&parse_capabilities(c)));
    Ok((
        SmimeRecipient {
            issuer_and_serial: issuer_and_serial(cert),
            fingerprint,
            key,
            gcm,
        },
        weak,
        no_known_decryptor,
    ))
}

pub(crate) fn parse_public_keys(input: &[u8], now: u64) -> Result<ParsedKeys, KeyError> {
    let der = decode_certificates(input)?;
    let mut recipients = Vec::new();
    let mut addresses: Vec<Box<str>> = Vec::new();
    let mut warnings = Vec::new();
    let mut capabilities = KeyCapabilities::default();
    let mut smime_capabilities = None;
    let mut expires_at = 0u64;
    let mut first_error = None;
    let mut all_gcm = true;
    let parsed = certificates(&der).collect::<Result<Vec<_>, _>>()?;
    let only_ca = parsed.iter().all(Certificate::is_ca);
    for cert in parsed.iter().filter(|c| only_ca || !c.is_ca()) {
        match validate_leaf(cert, now) {
            Ok((recipient, weak, no_decryptor)) => {
                if weak && !warnings.contains(&KeyWarning::WeakRsa) {
                    warnings.push(KeyWarning::WeakRsa);
                }
                if no_decryptor && !warnings.contains(&KeyWarning::NoKnownDecryptor) {
                    warnings.push(KeyWarning::NoKnownDecryptor);
                }
                if matches!(recipient.key, SmimeKey::MlKem(_)) {
                    capabilities.insert(KeyCapability::PostQuantum);
                }
                all_gcm &= recipient.gcm;
                if smime_capabilities.is_none() {
                    smime_capabilities = cert.extensions.smime_capabilities.map(parse_capabilities);
                }
                for address in cert.email_addresses() {
                    if !addresses.iter().any(|a| a.eq_ignore_ascii_case(address)) {
                        addresses.push(address.into());
                    }
                }
                expires_at = expires_at.max(cert.not_after);
                recipients.push(recipient);
            }
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    if recipients.is_empty() {
        return Err(first_error.unwrap_or(KeyError::NoEncryptionKey));
    }
    if all_gcm {
        capabilities.insert(KeyCapability::Aead);
    }
    if expires_at <= now + crate::pgp::EXPIRES_SOON_SECS {
        warnings.push(KeyWarning::ExpiresSoon);
    }
    Ok(ParsedKeys {
        kind: KeyKind::Smime,
        fingerprints: recipients
            .iter()
            .map(|r| Fingerprint::X509Sha256(r.fingerprint))
            .collect(),
        set: RecipientSet(Arc::new(Recipients::Smime(recipients.into_boxed_slice()))),
        addresses,
        expires_at: Some(expires_at),
        capabilities,
        warnings,
        smime_capabilities,
    })
}
