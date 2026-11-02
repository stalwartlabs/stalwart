/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::{
        hash::HashAlgorithm,
        verify::{EcCurve, MlDsa, SignatureScheme},
    },
    der::{
        DerError, oid,
        reader::{Reader, Tlv},
        tag,
    },
    x509::{
        names::{GN_OTHER_NAME, GN_RFC822, GN_URI, general_names, smtp_utf8_mailbox, uris},
        time::parse_time,
    },
};

pub(crate) const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
pub(crate) const KU_NON_REPUDIATION: u16 = 1 << 1;
pub(crate) const KU_KEY_ENCIPHERMENT: u16 = 1 << 2;
pub(crate) const KU_DATA_ENCIPHERMENT: u16 = 1 << 3;
pub(crate) const KU_KEY_AGREEMENT: u16 = 1 << 4;
pub(crate) const KU_KEY_CERT_SIGN: u16 = 1 << 5;
pub(crate) const KU_CRL_SIGN: u16 = 1 << 6;
pub(crate) const KU_ENCIPHER_ONLY: u16 = 1 << 7;
pub(crate) const KU_DECIPHER_ONLY: u16 = 1 << 8;

const DP_NAME: u8 = tag::context_constructed(0);
const DP_FULL_NAME: u8 = tag::context_constructed(0);

#[derive(Debug, Clone, Copy)]
pub(crate) struct AlgorithmId<'x> {
    pub oid: &'x [u8],
    pub params: Option<Tlv<'x>>,
    pub raw: &'x [u8],
}

impl<'x> AlgorithmId<'x> {
    pub(crate) fn parse(tlv: Tlv<'x>) -> Result<Self, DerError> {
        let tlv = tlv.expect(tag::SEQUENCE)?;
        let mut reader = tlv.reader();
        let oid = reader.read_content(tag::OID)?;
        let params = if reader.is_empty() {
            None
        } else {
            Some(reader.read()?)
        };
        reader.finish()?;
        Ok(AlgorithmId {
            oid,
            params,
            raw: tlv.raw,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Spki<'x> {
    pub algorithm: AlgorithmId<'x>,
    pub key: &'x [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Extensions<'x> {
    pub key_usage: Option<u16>,
    pub eku: Option<&'x [u8]>,
    pub san: Option<&'x [u8]>,
    pub ski: Option<&'x [u8]>,
    pub aki: Option<&'x [u8]>,
    pub basic_constraints: Option<BasicConstraints>,
    pub aia: Option<&'x [u8]>,
    pub crl_distribution_points: Option<&'x [u8]>,
    pub policies: Option<&'x [u8]>,
    pub name_constraints: Option<&'x [u8]>,
    pub smime_capabilities: Option<&'x [u8]>,
    pub unknown_critical: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Certificate<'x> {
    pub raw: &'x [u8],
    pub tbs: &'x [u8],
    pub signature_algorithm: AlgorithmId<'x>,
    pub signature: &'x [u8],
    pub serial: &'x [u8],
    pub issuer: &'x [u8],
    pub subject: &'x [u8],
    pub not_before: u64,
    pub not_after: u64,
    pub spki: Spki<'x>,
    pub extensions: Extensions<'x>,
}

pub(crate) fn bit_string(tlv: Tlv<'_>) -> Result<&[u8], DerError> {
    match tlv.expect(tag::BIT_STRING)?.content {
        [0, rest @ ..] => Ok(rest),
        _ => Err(DerError::InvalidValue),
    }
}

fn key_usage_bits(content: &[u8]) -> Result<u16, DerError> {
    match content {
        [unused, bytes @ ..] if *unused < 8 => {
            Ok(bytes.iter().take(2).enumerate().fold(0u16, |acc, (i, b)| {
                acc | u16::from(b.reverse_bits()) << (8 * i)
            }))
        }
        _ => Err(DerError::InvalidValue),
    }
}

fn distinguished_name(name: Tlv<'_>) -> Result<&[u8], DerError> {
    for rdn in name.reader() {
        for attribute in rdn?.expect(tag::SET)?.reader() {
            let mut attribute = attribute?.expect(tag::SEQUENCE)?.reader();
            attribute.read_tag(tag::OID)?;
            attribute.read()?;
            attribute.finish()?;
        }
    }
    Ok(name.raw)
}

fn parse_extensions<'x>(tlv: Tlv<'x>) -> Result<Extensions<'x>, DerError> {
    let mut ext = Extensions::default();
    let mut list = tlv.reader().read_sequence()?;
    while !list.is_empty() {
        let mut item = list.read_sequence()?;
        let id = item.read_content(tag::OID)?;
        let critical = item.read_bool_default_false()?;
        let value = item.read_content(tag::OCTET_STRING)?;
        item.finish()?;
        let mut inner = Reader::new(value);
        match id {
            oid::EXT_KEY_USAGE => {
                ext.key_usage = Some(key_usage_bits(inner.read_content(tag::BIT_STRING)?)?)
            }
            oid::EXT_EXTENDED_KEY_USAGE => ext.eku = Some(inner.read_content(tag::SEQUENCE)?),
            oid::EXT_SUBJECT_ALT_NAME => {
                ext.san = Some(general_names(inner.read_content(tag::SEQUENCE)?)?)
            }
            oid::EXT_SUBJECT_KEY_ID => ext.ski = Some(inner.read_content(tag::OCTET_STRING)?),
            oid::EXT_AUTHORITY_KEY_ID => {
                let mut aki = inner.read_sequence()?;
                ext.aki = aki.read_optional(tag::context(0))?.map(|t| t.content);
            }
            oid::EXT_BASIC_CONSTRAINTS => {
                let mut bc = inner.read_sequence()?;
                let ca = bc.read_bool_default_false()?;
                let path_len = if bc.peek_tag() == Some(tag::INTEGER) {
                    Some(bc.read_small_unsigned()?)
                } else {
                    None
                };
                ext.basic_constraints = Some(BasicConstraints { ca, path_len });
            }
            oid::EXT_AUTHORITY_INFO_ACCESS => ext.aia = Some(inner.read_content(tag::SEQUENCE)?),
            oid::EXT_CRL_DISTRIBUTION_POINTS => {
                ext.crl_distribution_points = Some(inner.read_content(tag::SEQUENCE)?)
            }
            oid::EXT_CERTIFICATE_POLICIES => {
                ext.policies = Some(inner.read_content(tag::SEQUENCE)?)
            }
            oid::EXT_NAME_CONSTRAINTS => {
                ext.name_constraints = Some(inner.read_content(tag::SEQUENCE)?)
            }
            oid::SMIME_CAPABILITIES => {
                ext.smime_capabilities = Some(inner.read_content(tag::SEQUENCE)?)
            }
            oid::EXT_POLICY_CONSTRAINTS
            | oid::EXT_INHIBIT_ANY_POLICY
            | oid::EXT_POLICY_MAPPINGS
            | oid::EXT_ISSUER_ALT_NAME => continue,
            _ => {
                ext.unknown_critical |= critical;
                continue;
            }
        }
        inner.finish()?;
    }
    Ok(ext)
}

impl<'x> Certificate<'x> {
    pub(crate) fn parse(der: &'x [u8]) -> Result<Self, DerError> {
        let mut outer = Reader::new(der);
        let cert_tlv = outer.read_tag(tag::SEQUENCE)?;
        outer.finish()?;
        Self::parse_tlv(cert_tlv)
    }

    pub(crate) fn parse_tlv(cert_tlv: Tlv<'x>) -> Result<Self, DerError> {
        let mut cert = cert_tlv.reader();
        let tbs_tlv = cert.read_tag(tag::SEQUENCE)?;
        let signature_algorithm = AlgorithmId::parse(cert.read()?)?;
        let signature = bit_string(cert.read()?)?;
        cert.finish()?;

        let mut tbs = tbs_tlv.reader();
        if let Some(version) = tbs.read_optional(tag::context_constructed(0))? {
            let v = version.reader().read_small_unsigned()?;
            if v > 2 {
                return Err(DerError::InvalidValue);
            }
        }
        let serial = tbs.read_content(tag::INTEGER)?;
        if AlgorithmId::parse(tbs.read()?)?.raw != signature_algorithm.raw {
            return Err(DerError::InvalidValue);
        }
        let issuer = tbs.read_tag(tag::SEQUENCE)?.raw;
        let mut validity = tbs.read_sequence()?;
        let not_before = parse_time(validity.read()?)?;
        let not_after = parse_time(validity.read()?)?;
        validity.finish()?;
        let subject = distinguished_name(tbs.read_tag(tag::SEQUENCE)?)?;
        let spki_tlv = tbs.read_tag(tag::SEQUENCE)?;
        let mut spki_reader = spki_tlv.reader();
        let algorithm = AlgorithmId::parse(spki_reader.read()?)?;
        let key = bit_string(spki_reader.read()?)?;
        spki_reader.finish()?;
        let mut extensions = Extensions::default();
        for tlv in tbs {
            let tlv = tlv?;
            match tlv.tag {
                t if t == tag::context(1) || t == tag::context(2) => {}
                t if t == tag::context_constructed(3) => extensions = parse_extensions(tlv)?,
                _ => return Err(DerError::UnexpectedTag),
            }
        }
        Ok(Certificate {
            raw: cert_tlv.raw,
            tbs: tbs_tlv.raw,
            signature_algorithm,
            signature,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            spki: Spki { algorithm, key },
            extensions,
        })
    }

    pub(crate) fn is_ca(&self) -> bool {
        self.extensions.basic_constraints.is_some_and(|bc| bc.ca)
    }

    pub(crate) fn email_addresses(&self) -> impl Iterator<Item = &'x str> + use<'x> {
        let san = self
            .extensions
            .san
            .into_iter()
            .flat_map(|san| Reader::new(san).map_while(Result::ok))
            .filter_map(|name| match name.tag {
                GN_RFC822 => std::str::from_utf8(name.content).ok(),
                GN_OTHER_NAME => std::str::from_utf8(smtp_utf8_mailbox(name.content)?).ok(),
                _ => None,
            });
        let subject = name_attributes(self.subject)
            .filter(|(id, _)| *id == oid::EMAIL_ADDRESS)
            .filter_map(|(_, value)| std::str::from_utf8(value).ok());
        san.chain(subject)
    }

    pub(crate) fn has_email_protection(&self) -> bool {
        self.extensions.eku.is_none_or(|eku| {
            Reader::new(eku).map_while(Result::ok).any(|id| {
                id.content == oid::EMAIL_PROTECTION || id.content == oid::ANY_EXTENDED_KEY_USAGE
            })
        })
    }

    pub(crate) fn verify_signed_by(&self, issuer_spki: &Spki<'_>) -> bool {
        verify_signature(
            &self.signature_algorithm,
            issuer_spki,
            self.tbs,
            self.signature,
        )
    }

    pub(crate) fn display_name(&self) -> String {
        [oid::COMMON_NAME, oid::ORGANIZATION]
            .into_iter()
            .find_map(|id| {
                name_attributes(self.subject)
                    .find(|(attribute, _)| *attribute == id)
                    .and_then(|(_, value)| std::str::from_utf8(value).ok())
            })
            .or_else(|| {
                name_attributes(self.subject).find_map(|(_, value)| std::str::from_utf8(value).ok())
            })
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    pub(crate) fn is_valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    pub(crate) fn crl_urls(&self) -> impl Iterator<Item = &'x str> + use<'x> {
        self.extensions
            .crl_distribution_points
            .into_iter()
            .flat_map(|points| Reader::new(points).map_while(Result::ok))
            .filter_map(|point| {
                let name = point.reader().read_optional(DP_NAME).ok()??;
                let full = name.reader().read().ok()?;
                (full.tag == DP_FULL_NAME).then_some(full.content)
            })
            .flat_map(uris)
    }

    pub(crate) fn ca_issuer_urls(&self) -> impl Iterator<Item = &'x str> + use<'x> {
        self.extensions
            .aia
            .into_iter()
            .flat_map(|aia| Reader::new(aia).map_while(Result::ok))
            .filter_map(|access| {
                let mut access = access.reader();
                if access.read_content(tag::OID).ok()? != oid::CA_ISSUERS {
                    return None;
                }
                let location = access.read().ok()?;
                (location.tag == GN_URI)
                    .then(|| std::str::from_utf8(location.content).ok())
                    .flatten()
            })
    }
}

pub(crate) fn name_attributes(name: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    Reader::new(name)
        .read_sequence()
        .into_iter()
        .flat_map(|rdns| rdns.map_while(Result::ok))
        .flat_map(|rdn| rdn.reader().map_while(Result::ok))
        .filter_map(|atv| {
            let mut atv = atv.reader();
            let id = atv.read_content(tag::OID).ok()?;
            let value = atv.read().ok()?;
            Some((id, value.content))
        })
}

pub(crate) fn signature_scheme(
    algorithm: &AlgorithmId<'_>,
    spki: &Spki<'_>,
) -> Option<SignatureScheme> {
    let ec_curve = || {
        let params = spki.algorithm.params?;
        match params.content {
            oid::P256 => Some(EcCurve::P256),
            oid::P384 => Some(EcCurve::P384),
            oid::P521 => Some(EcCurve::P521),
            _ => None,
        }
    };
    Some(match algorithm.oid {
        oid::SHA1_WITH_RSA => SignatureScheme::RsaPkcs1(HashAlgorithm::Sha1),
        oid::SHA256_WITH_RSA => SignatureScheme::RsaPkcs1(HashAlgorithm::Sha256),
        oid::SHA384_WITH_RSA => SignatureScheme::RsaPkcs1(HashAlgorithm::Sha384),
        oid::SHA512_WITH_RSA => SignatureScheme::RsaPkcs1(HashAlgorithm::Sha512),
        oid::RSASSA_PSS => SignatureScheme::RsaPss(pss_hash(algorithm)?),
        oid::ECDSA_SHA1 => SignatureScheme::Ecdsa(ec_curve()?, HashAlgorithm::Sha1),
        oid::ECDSA_SHA256 => SignatureScheme::Ecdsa(ec_curve()?, HashAlgorithm::Sha256),
        oid::ECDSA_SHA384 => SignatureScheme::Ecdsa(ec_curve()?, HashAlgorithm::Sha384),
        oid::ECDSA_SHA512 => SignatureScheme::Ecdsa(ec_curve()?, HashAlgorithm::Sha512),
        oid::ED25519 => SignatureScheme::Ed25519,
        oid::ED448 => SignatureScheme::Ed448,
        oid::ML_DSA_44 => SignatureScheme::MlDsa(MlDsa::MlDsa44),
        oid::ML_DSA_65 => SignatureScheme::MlDsa(MlDsa::MlDsa65),
        oid::ML_DSA_87 => SignatureScheme::MlDsa(MlDsa::MlDsa87),
        _ => return None,
    })
}

pub(crate) fn digest_oid_hash(id: &[u8]) -> Option<HashAlgorithm> {
    Some(match id {
        oid::SHA1 => HashAlgorithm::Sha1,
        oid::SHA224 => HashAlgorithm::Sha224,
        oid::SHA256 => HashAlgorithm::Sha256,
        oid::SHA384 => HashAlgorithm::Sha384,
        oid::SHA512 => HashAlgorithm::Sha512,
        _ => return None,
    })
}

fn pss_hash(algorithm: &AlgorithmId<'_>) -> Option<HashAlgorithm> {
    let params = algorithm.params?;
    let mut reader = params.reader();
    let hash = reader.read_optional(tag::context_constructed(0)).ok()??;
    let hash = AlgorithmId::parse(hash.reader().read().ok()?).ok()?;
    digest_oid_hash(hash.oid).filter(|h| {
        matches!(
            h,
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
        )
    })
}

pub(crate) fn signature_hash(algorithm: &AlgorithmId<'_>) -> Option<HashAlgorithm> {
    match algorithm.oid {
        oid::SHA1_WITH_RSA | oid::ECDSA_SHA1 => Some(HashAlgorithm::Sha1),
        oid::SHA256_WITH_RSA | oid::ECDSA_SHA256 => Some(HashAlgorithm::Sha256),
        oid::SHA384_WITH_RSA | oid::ECDSA_SHA384 => Some(HashAlgorithm::Sha384),
        oid::SHA512_WITH_RSA | oid::ECDSA_SHA512 => Some(HashAlgorithm::Sha512),
        oid::RSASSA_PSS => pss_hash(algorithm),
        _ => None,
    }
}

pub(crate) fn verify_prehashed(
    algorithm: &AlgorithmId<'_>,
    spki: &Spki<'_>,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let Some(hash) = signature_hash(algorithm) else {
        return false;
    };
    let Ok(digest) = aws_lc_rs::digest::Digest::import_less_safe(digest, hash.algorithm()) else {
        return false;
    };
    signature_scheme(algorithm, spki)
        .is_some_and(|scheme| scheme.verify_digest(spki.key, &digest, signature).is_ok())
}

pub(crate) fn verify_signature(
    algorithm: &AlgorithmId<'_>,
    spki: &Spki<'_>,
    message: &[u8],
    signature: &[u8],
) -> bool {
    signature_scheme(algorithm, spki)
        .is_some_and(|scheme| scheme.verify(spki.key, message, signature).is_ok())
}
