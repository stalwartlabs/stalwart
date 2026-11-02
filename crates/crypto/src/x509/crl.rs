/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    backend::hash::HashAlgorithm,
    der::{
        oid,
        reader::{Reader, Tlv},
        tag,
    },
    error::CrlError,
    pgp::armor::{decode_body, next_block},
    x509::{
        cert::{AlgorithmId, Certificate, Spki, bit_string, signature_hash, verify_prehashed},
        names::uris,
        time::parse_time,
    },
};

const MAX_CRL_LEN: usize = 64 << 20;
const MAX_SERIAL_LEN: usize = 20;
const LONG_SERIAL: u8 = 0xFF;
const PEM_CRL: &[u8] = b"X509 CRL";
const IDP_DISTRIBUTION_POINT: u8 = tag::context_constructed(0);
const IDP_FULL_NAME: u8 = tag::context_constructed(0);
const IDP_ONLY_USER: u8 = tag::context(1);
const IDP_ONLY_CA: u8 = tag::context(2);
const IDP_ONLY_SOME_REASONS: u8 = tag::context(3);
const IDP_INDIRECT: u8 = tag::context(4);
const IDP_ONLY_ATTRIBUTE: u8 = tag::context(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SerialKey([u8; MAX_SERIAL_LEN + 1]);

impl SerialKey {
    fn new(serial: &[u8]) -> Self {
        let mut key = [0u8; MAX_SERIAL_LEN + 1];
        let (len, bytes) = key.split_at_mut(1);
        match bytes.get_mut(..serial.len()) {
            Some(slot) => {
                slot.copy_from_slice(serial);
                len[0] = serial.len() as u8;
            }
            None => {
                let digest = HashAlgorithm::Sha1.digest(serial);
                bytes.copy_from_slice(digest.as_ref());
                len[0] = LONG_SERIAL;
            }
        }
        SerialKey(key)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum CertScope {
    #[default]
    All,
    EndEntity,
    Authority,
}

#[derive(Debug, Clone, Default)]
struct Scope {
    certs: CertScope,
    distribution_points: Box<[Box<str>]>,
}

#[derive(Debug, Clone)]
enum SignedPayload {
    Digest(Box<[u8]>),
    Message(Box<[u8]>),
}

#[derive(Debug, Clone)]
pub struct Crl {
    issuer: Box<[u8]>,
    this_update: u64,
    next_update: Option<u64>,
    scope: Scope,
    revoked: Box<[SerialKey]>,
    algorithm: Box<[u8]>,
    payload: SignedPayload,
    signature: Box<[u8]>,
}

impl Crl {
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer
    }

    pub fn this_update(&self) -> u64 {
        self.this_update
    }

    pub fn next_update(&self) -> Option<u64> {
        self.next_update
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    pub(crate) fn is_current(&self, now: u64) -> bool {
        self.this_update <= now && self.next_update.is_some_and(|next| now <= next)
    }

    pub(crate) fn covers(&self, cert: &Certificate<'_>) -> bool {
        if cert.issuer != self.issuer.as_ref() {
            return false;
        }
        let scope_ok = match self.scope.certs {
            CertScope::All => true,
            CertScope::EndEntity => !cert.is_ca(),
            CertScope::Authority => cert.is_ca(),
        };
        scope_ok
            && (self.scope.distribution_points.is_empty()
                || cert.crl_urls().any(|url| {
                    self.scope
                        .distribution_points
                        .iter()
                        .any(|dp| dp.as_bytes() == url.as_bytes())
                }))
    }

    pub(crate) fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked.binary_search(&SerialKey::new(serial)).is_ok()
    }

    pub(crate) fn verify(&self, issuer: &Spki<'_>) -> bool {
        let Ok(algorithm) = Reader::new(&self.algorithm)
            .read()
            .and_then(AlgorithmId::parse)
        else {
            return false;
        };
        match &self.payload {
            SignedPayload::Digest(digest) => {
                verify_prehashed(&algorithm, issuer, digest, &self.signature)
            }
            SignedPayload::Message(message) => {
                crate::x509::cert::verify_signature(&algorithm, issuer, message, &self.signature)
            }
        }
    }
}

pub fn parse_crl(input: &[u8]) -> Result<Crl, CrlError> {
    if input.len() > MAX_CRL_LEN {
        return Err(CrlError::TooLarge);
    }
    let der = pem_or_der(input)?;
    parse_der(&der)
}

fn pem_or_der(input: &[u8]) -> Result<Cow<'_, [u8]>, CrlError> {
    let trimmed = input.trim_ascii_start();
    if !trimmed.starts_with(b"-----BEGIN ") {
        return Ok(Cow::Borrowed(input));
    }
    let (block, _) = next_block(trimmed)
        .ok()
        .flatten()
        .ok_or(CrlError::Malformed)?;
    if block.raw_label != PEM_CRL {
        return Err(CrlError::Malformed);
    }
    let mut out = Vec::with_capacity(block.body.len() / 4 * 3);
    decode_body(block.body, &mut out).map_err(|_| CrlError::Malformed)?;
    Ok(Cow::Owned(out))
}

fn parse_der(der: &[u8]) -> Result<Crl, CrlError> {
    let mut outer = Reader::new(der);
    let list = outer.read_tag(tag::SEQUENCE)?;
    outer.finish()?;
    let mut list = list.reader();
    let tbs_tlv = list.read_tag(tag::SEQUENCE)?;
    let algorithm_tlv = list.read()?;
    let algorithm = AlgorithmId::parse(algorithm_tlv)?;
    let signature = bit_string(list.read()?)?;
    list.finish()?;
    let hash = signature_hash(&algorithm);
    if hash == Some(HashAlgorithm::Sha1) {
        return Err(CrlError::Sha1Signature);
    }

    let mut tbs = tbs_tlv.reader();
    if tbs.peek_tag() == Some(tag::INTEGER) {
        let version = tbs.read_small_unsigned()?;
        if version > 1 {
            return Err(CrlError::Malformed);
        }
    }
    let inner_algorithm = tbs.read()?;
    if inner_algorithm.raw != algorithm_tlv.raw {
        return Err(CrlError::Malformed);
    }
    let issuer = tbs.read_tag(tag::SEQUENCE)?.raw;
    let this_update = parse_time(tbs.read()?)?;
    let next_update = match tbs.peek_tag() {
        Some(tag::UTC_TIME | tag::GENERALIZED_TIME) => Some(parse_time(tbs.read()?)?),
        _ => None,
    };
    let entries = tbs.read_optional(tag::SEQUENCE)?;
    let scope = match tbs.read_optional(tag::context_constructed(0))? {
        Some(extensions) => parse_extensions(extensions)?,
        None => Scope::default(),
    };
    tbs.finish()?;

    let revoked = match entries {
        Some(entries) => parse_entries(entries)?,
        None => Box::default(),
    };
    let payload = match hash {
        Some(hash) => SignedPayload::Digest(hash.digest(tbs_tlv.raw).as_ref().into()),
        None => SignedPayload::Message(tbs_tlv.raw.into()),
    };
    Ok(Crl {
        issuer: issuer.into(),
        this_update,
        next_update,
        scope,
        revoked,
        algorithm: algorithm.raw.into(),
        payload,
        signature: signature.into(),
    })
}

fn parse_entries(entries: Tlv<'_>) -> Result<Box<[SerialKey]>, CrlError> {
    let count = entries
        .reader()
        .try_fold(0usize, |count, entry| entry.map(|_| count + 1))?;
    let mut revoked = Vec::with_capacity(count);
    for entry in entries.reader() {
        let mut entry = entry?.expect(tag::SEQUENCE)?.reader();
        let serial = entry.read_content(tag::INTEGER)?;
        parse_time(entry.read()?)?;
        if let Some(extensions) = entry.read_optional(tag::SEQUENCE)? {
            for extension in extensions.reader() {
                let mut extension = extension?.expect(tag::SEQUENCE)?.reader();
                let id = extension.read_content(tag::OID)?;
                let critical = extension.read_bool_default_false()?;
                if critical && id != oid::EXT_REASON_CODE && id != oid::EXT_INVALIDITY_DATE {
                    return Err(CrlError::UnsupportedCriticalExtension);
                }
            }
        }
        entry.finish()?;
        revoked.push(SerialKey::new(serial));
    }
    revoked.sort_unstable();
    Ok(revoked.into_boxed_slice())
}

fn parse_extensions(extensions: Tlv<'_>) -> Result<Scope, CrlError> {
    let mut scope = Scope::default();
    let mut list = extensions.reader().read_sequence()?;
    while !list.is_empty() {
        let mut extension = list.read_sequence()?;
        let id = extension.read_content(tag::OID)?;
        let critical = extension.read_bool_default_false()?;
        let value = extension.read_content(tag::OCTET_STRING)?;
        extension.finish()?;
        match id {
            oid::EXT_DELTA_CRL_INDICATOR => return Err(CrlError::DeltaCrl),
            oid::EXT_ISSUING_DISTRIBUTION_POINT => {
                scope = parse_idp(value)?;
            }
            oid::EXT_AUTHORITY_KEY_ID
            | oid::EXT_CRL_NUMBER
            | oid::EXT_FRESHEST_CRL
            | oid::EXT_ISSUER_ALT_NAME => {}
            _ if critical => return Err(CrlError::UnsupportedCriticalExtension),
            _ => {}
        }
    }
    Ok(scope)
}

fn parse_idp(value: &[u8]) -> Result<Scope, CrlError> {
    let mut idp = Reader::new(value).read_sequence()?;
    let mut distribution_points = Box::default();
    if let Some(point) = idp.read_optional(IDP_DISTRIBUTION_POINT)? {
        let name = point.reader().read()?;
        if name.tag != IDP_FULL_NAME {
            return Err(CrlError::UnsupportedScope);
        }
        distribution_points = uris(name.content).map(Box::from).collect();
    }
    let flag = |idp: &mut Reader<'_>, tag: u8| -> Result<bool, CrlError> {
        Ok(match idp.read_optional(tag)? {
            Some(tlv) => matches!(tlv.content, [value] if *value != 0),
            None => false,
        })
    };
    let only_user = flag(&mut idp, IDP_ONLY_USER)?;
    let only_ca = flag(&mut idp, IDP_ONLY_CA)?;
    if idp.read_optional(IDP_ONLY_SOME_REASONS)?.is_some()
        || flag(&mut idp, IDP_INDIRECT)?
        || flag(&mut idp, IDP_ONLY_ATTRIBUTE)?
    {
        return Err(CrlError::UnsupportedScope);
    }
    idp.finish()?;
    let certs = match (only_user, only_ca) {
        (false, false) => CertScope::All,
        (true, false) => CertScope::EndEntity,
        (false, true) => CertScope::Authority,
        (true, true) => return Err(CrlError::Malformed),
    };
    Ok(Scope {
        certs,
        distribution_points,
    })
}
