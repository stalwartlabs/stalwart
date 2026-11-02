/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::digest::Digest;

use crate::{
    backend::{hash::HashAlgorithm, verify::SignatureScheme},
    der::{
        DerError, oid,
        reader::{Encoding, Reader, Tlv},
        tag,
    },
    error::VerifyError,
    mime::{Canonical, Sink},
    x509::{
        cert::{AlgorithmId, Certificate, digest_oid_hash, signature_scheme},
        time::parse_time,
    },
};

const CERTIFICATES: u8 = tag::context_constructed(0);
const CRLS: u8 = tag::context_constructed(1);
const SIGNED_ATTRS: u8 = tag::context_constructed(0);
const UNSIGNED_ATTRS: u8 = tag::context_constructed(1);
const SID_KEY_ID: u8 = tag::context(0);
const ECONTENT: u8 = tag::context_constructed(0);
const CONSTRUCTED_OCTET_STRING: u8 = tag::OCTET_STRING | tag::CONSTRUCTED;
const PREF_ISSUER_SERIAL: u8 = tag::context_constructed(0);
const PREF_SUBJECT_KEY_ID: u8 = tag::context(2);
const MAX_SIGNERS: usize = 8;
const MAX_FUTURE_SKEW: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyPreference<'x> {
    IssuerSerial { issuer: &'x [u8], serial: &'x [u8] },
    SubjectKeyId(&'x [u8]),
}

impl KeyPreference<'_> {
    pub(crate) fn matches(&self, cert: &Certificate<'_>) -> bool {
        match self {
            KeyPreference::IssuerSerial { issuer, serial } => {
                cert.issuer == *issuer && cert.serial == *serial
            }
            KeyPreference::SubjectKeyId(id) => cert.extensions.ski == Some(*id),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedData<'x> {
    pub certificates: &'x [u8],
    pub signer: Option<Certificate<'x>>,
    pub verified: bool,
    pub signing_time: Option<u64>,
    pub capabilities: Option<&'x [u8]>,
    pub preference: Option<KeyPreference<'x>>,
}

fn certificate_set(set: &[u8]) -> impl Iterator<Item = Certificate<'_>> {
    Reader::new(set)
        .map_while(Result::ok)
        .filter(|tlv| tlv.tag == tag::SEQUENCE)
        .filter_map(|tlv| Certificate::parse_tlv(tlv).ok())
}

impl<'x> SignedData<'x> {
    pub(crate) fn certificates(&self) -> impl Iterator<Item = Certificate<'x>> + use<'x> {
        certificate_set(self.certificates)
    }
}

pub(crate) enum Content<'x> {
    Detached(&'x [u8]),
    Encapsulated,
}

#[derive(Default)]
struct Attributes<'x> {
    content_type: Option<&'x [u8]>,
    message_digest: Option<&'x [u8]>,
    signing_time: Option<u64>,
    capabilities: Option<&'x [u8]>,
    preference: Option<KeyPreference<'x>>,
}

struct SignerInfo<'x> {
    sid: Tlv<'x>,
    digest: HashAlgorithm,
    signed_attrs: Option<Tlv<'x>>,
    algorithm: AlgorithmId<'x>,
    signature: &'x [u8],
}

fn hash_econtent(econtent: Tlv<'_>, hasher: &mut impl Sink) -> Result<(), DerError> {
    match econtent.tag {
        tag::OCTET_STRING => {
            hasher.put(econtent.content);
            Ok(())
        }
        CONSTRUCTED_OCTET_STRING => {
            for chunk in econtent.reader() {
                hash_econtent(chunk?, hasher)?;
            }
            Ok(())
        }
        _ => Err(DerError::UnexpectedTag),
    }
}

fn parse_preference(value: Tlv<'_>) -> Option<KeyPreference<'_>> {
    match value.tag {
        PREF_ISSUER_SERIAL | tag::SEQUENCE => {
            let mut reader = value.reader();
            let issuer = reader.read_tag(tag::SEQUENCE).ok()?.raw;
            let serial = reader.read_content(tag::INTEGER).ok()?;
            Some(KeyPreference::IssuerSerial { issuer, serial })
        }
        PREF_SUBJECT_KEY_ID => Some(KeyPreference::SubjectKeyId(value.content)),
        _ => None,
    }
}

fn parse_attributes(signed_attrs: Tlv<'_>) -> Result<Attributes<'_>, DerError> {
    let mut attrs = Attributes::default();
    for attribute in signed_attrs.reader() {
        let mut attribute = attribute?.expect(tag::SEQUENCE)?.reader();
        let id = attribute.read_content(tag::OID)?;
        let mut values = attribute.read_tag(tag::SET)?.reader();
        let value = values.read()?;
        match id {
            oid::CONTENT_TYPE => attrs.content_type = Some(value.expect(tag::OID)?.content),
            oid::MESSAGE_DIGEST => {
                attrs.message_digest = Some(value.expect(tag::OCTET_STRING)?.content)
            }
            oid::SIGNING_TIME => attrs.signing_time = Some(parse_time(value)?),
            oid::SMIME_CAPABILITIES => {
                attrs.capabilities = Some(value.expect(tag::SEQUENCE)?.content)
            }
            oid::ENCRYPTION_KEY_PREFERENCE => attrs.preference = parse_preference(value),
            oid::MS_ENCRYPTION_KEY_PREFERENCE => {
                attrs.preference = attrs.preference.or_else(|| parse_preference(value))
            }
            _ => {}
        }
    }
    Ok(attrs)
}

fn parse_signer_info(tlv: Tlv<'_>) -> Result<SignerInfo<'_>, VerifyError> {
    let mut info = tlv.expect(tag::SEQUENCE)?.reader();
    info.read_small_unsigned()?;
    let sid = info.read()?;
    let digest = AlgorithmId::parse(info.read()?)?;
    let digest = digest_oid_hash(digest.oid)
        .filter(|hash| {
            matches!(
                hash,
                HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
            )
        })
        .ok_or(VerifyError::UnsupportedAlgorithm)?;
    let signed_attrs = info.read_optional(SIGNED_ATTRS)?;
    let algorithm = AlgorithmId::parse(info.read()?)?;
    let signature = info.read_content(tag::OCTET_STRING)?;
    info.read_optional(UNSIGNED_ATTRS)?;
    info.finish()?;
    Ok(SignerInfo {
        sid,
        digest,
        signed_attrs,
        algorithm,
        signature,
    })
}

fn find_signer<'x>(certificates: &'x [u8], sid: &Tlv<'_>) -> Option<Certificate<'x>> {
    let preference = match sid.tag {
        tag::SEQUENCE => parse_preference(*sid)?,
        SID_KEY_ID => KeyPreference::SubjectKeyId(sid.content),
        _ => return None,
    };
    certificate_set(certificates).find(|cert| preference.matches(cert))
}

fn scheme_for(info: &SignerInfo<'_>, signer: &Certificate<'_>) -> Option<SignatureScheme> {
    let scheme = if info.algorithm.oid == oid::RSA_ENCRYPTION {
        SignatureScheme::RsaPkcs1(info.digest)
    } else {
        signature_scheme(&info.algorithm, &signer.spki)?
    };
    match scheme {
        SignatureScheme::RsaPkcs1(HashAlgorithm::Sha1)
        | SignatureScheme::Ecdsa(_, HashAlgorithm::Sha1) => None,
        scheme => Some(scheme),
    }
}

struct DigestCache {
    entries: [Option<(HashAlgorithm, Digest)>; 3],
}

impl DigestCache {
    fn get(
        &mut self,
        hash: HashAlgorithm,
        compute: impl FnOnce(HashAlgorithm) -> Result<Digest, DerError>,
    ) -> Result<Digest, DerError> {
        if let Some((_, digest)) = self.entries.iter().flatten().find(|(h, _)| *h == hash) {
            return Ok(*digest);
        }
        let digest = compute(hash)?;
        if let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((hash, digest));
        }
        Ok(digest)
    }
}

fn verify_signer(
    info: &SignerInfo<'_>,
    signer: &Certificate<'_>,
    attrs: &Attributes<'_>,
    econtent_type: &[u8],
    digest: &Digest,
    now: u64,
) -> bool {
    let Some(scheme) = scheme_for(info, signer) else {
        return false;
    };
    match info.signed_attrs {
        Some(signed_attrs) => {
            if signed_attrs.encoding != Encoding::Definite
                || attrs.content_type != Some(econtent_type)
                || attrs.message_digest != Some(digest.as_ref())
                || attrs
                    .signing_time
                    .is_some_and(|time| time > now + MAX_FUTURE_SKEW)
            {
                return false;
            }
            let mut der = Vec::with_capacity(signed_attrs.raw.len());
            der.push(tag::SET);
            der.extend_from_slice(signed_attrs.raw.get(1..).unwrap_or_default());
            scheme.verify(signer.spki.key, &der, info.signature).is_ok()
        }
        None => scheme
            .verify_digest(signer.spki.key, digest, info.signature)
            .is_ok(),
    }
}

pub(crate) fn verify<'x>(
    der: &'x [u8],
    content: Content<'_>,
    now: u64,
) -> Result<SignedData<'x>, VerifyError> {
    let mut content_info = Reader::new(der).read_sequence()?;
    if content_info.read_content(tag::OID)? != oid::SIGNED_DATA {
        return Err(VerifyError::NotSigned);
    }
    let mut signed = content_info
        .read_tag(tag::context_constructed(0))?
        .reader()
        .read_sequence()?;
    signed.read_small_unsigned()?;
    signed.read_tag(tag::SET)?;
    let mut encap = signed.read_sequence()?;
    let econtent_type = encap.read_content(tag::OID)?;
    let econtent = encap
        .read_optional(ECONTENT)?
        .map(|explicit| explicit.reader().read())
        .transpose()?;
    let certificates = signed
        .read_optional(CERTIFICATES)?
        .map_or(&[][..], |set| set.content);
    signed.read_optional(CRLS)?;
    let signer_infos = signed.read_tag(tag::SET)?;

    let mut cache = DigestCache {
        entries: [None, None, None],
    };
    let compute = |hash: HashAlgorithm| -> Result<Digest, DerError> {
        let mut hasher = hash.hasher();
        match (&content, econtent) {
            (Content::Detached(data), None) => Canonical::new(&mut hasher).put(data),
            (Content::Encapsulated, Some(econtent)) => hash_econtent(econtent, &mut hasher)?,
            _ => return Err(DerError::UnexpectedTag),
        }
        Ok(hasher.finish())
    };

    let mut first = None;
    for info in signer_infos.reader().take(MAX_SIGNERS) {
        let info = parse_signer_info(info?)?;
        let Some(signer) = find_signer(certificates, &info.sid) else {
            continue;
        };
        let attrs = match info.signed_attrs {
            Some(signed_attrs) => parse_attributes(signed_attrs)?,
            None => Attributes::default(),
        };
        let digest = cache.get(info.digest, compute)?;
        let verified = verify_signer(&info, &signer, &attrs, econtent_type, &digest, now);
        let result = SignedData {
            certificates,
            signer: Some(signer),
            verified,
            signing_time: attrs.signing_time,
            capabilities: attrs.capabilities,
            preference: attrs.preference,
        };
        if verified {
            return Ok(result);
        }
        first.get_or_insert(result);
    }
    first.ok_or(VerifyError::UnknownSigner)
}
