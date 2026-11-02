/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod autocrypt;

use mail_parser::{HeaderName, Message};

use crate::{
    cms::signed::{Content, verify as verify_signed_data},
    error::VerifyError,
    mime::signed::{SignedProtocol, detached_signature, opaque_signed_data},
    pgp::{
        armor::dearmor_public_keys,
        cert::split_certs,
        verify::{PgpVerified, validate_signers, verify_detached},
    },
    types::{Fingerprint, KeyKind, SmimeCapabilities},
    x509::{cert::Certificate, recipient::parse_capabilities},
};

use autocrypt::parse_autocrypt;

const MAX_AUTOCRYPT_HEADERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarvestSource {
    SmimeSignature,
    Autocrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestedKey {
    pub kind: KeyKind,
    pub source: HarvestSource,
    pub key: Box<[u8]>,
    pub addresses: Vec<Box<str>>,
    pub signing_time: Option<u64>,
    pub signature_verified: bool,
    pub smime_capabilities: Option<SmimeCapabilities>,
    pub encryption_key_preference: bool,
    pub certificates: Vec<Box<[u8]>>,
    pub prefer_encrypt: bool,
}

impl HarvestedKey {
    pub fn chain(&self) -> Vec<Vec<u8>> {
        let mut chain = Vec::with_capacity(self.certificates.len() + 1);
        chain.push(self.key.to_vec());
        chain.extend(
            self.certificates
                .iter()
                .filter(|der| {
                    der.as_ref() != self.key.as_ref()
                        && Certificate::parse(der).is_ok_and(|cert| cert.is_ca())
                })
                .map(|der| der.to_vec()),
        );
        chain
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureCheck {
    pub signer: Fingerprint,
    pub signing_time: u64,
}

fn is_excluded(message: &Message<'_>) -> bool {
    message
        .from()
        .is_none_or(|from| from.mailboxes().nth(1).is_some() || from.first().is_none())
        || message.root_part().content_type().is_some_and(|ct| {
            ct.ctype().eq_ignore_ascii_case("multipart")
                && ct
                    .subtype()
                    .is_some_and(|sub| sub.eq_ignore_ascii_case("report"))
        })
}

pub fn harvest(message: &Message<'_>, from: &str, now: u64) -> Vec<HarvestedKey> {
    if is_excluded(message) {
        return Vec::new();
    }
    smime_key(message, from, now)
        .into_iter()
        .chain(autocrypt_key(message, from, now))
        .collect()
}

pub fn verify_pgp_signature(
    message: &Message<'_>,
    cert: &[u8],
    now: u64,
) -> Result<SignatureCheck, VerifyError> {
    let detached = detached_signature(message)
        .filter(|signed| signed.protocol == SignedProtocol::Pgp)
        .ok_or(VerifyError::NotSigned)?;
    let binary = dearmor_public_keys(cert).map_err(VerifyError::InvalidCertificate)?;
    let certs = split_certs(&binary).map_err(VerifyError::InvalidCertificate)?;
    let PgpVerified { signer, created } = verify_detached(
        &validate_signers(&certs, now),
        &detached.signature.decoded(),
        detached.content,
        now,
    )?;
    Ok(SignatureCheck {
        signer,
        signing_time: created,
    })
}

fn bound_to(cert: &Certificate<'_>, from: &str) -> bool {
    cert.email_addresses()
        .any(|address| address.eq_ignore_ascii_case(from))
}

fn smime_key(message: &Message<'_>, from: &str, now: u64) -> Option<HarvestedKey> {
    let (der, content) = match detached_signature(message) {
        Some(signed) if signed.protocol == SignedProtocol::Smime => (
            signed.signature.decoded(),
            Content::Detached(signed.content),
        ),
        Some(_) => return None,
        None => (
            opaque_signed_data(message)?.decoded(),
            Content::Encapsulated,
        ),
    };
    let signed = verify_signed_data(&der, content, now).ok()?;
    let signer = signed.signer?;
    let preferred = signed
        .preference
        .and_then(|preference| signed.certificates().find(|cert| preference.matches(cert)))
        .filter(|cert| bound_to(cert, from));
    let (cert, is_preferred) = match preferred {
        Some(cert) => (cert, true),
        None if bound_to(&signer, from) => (signer, false),
        None => return None,
    };
    let mut addresses: Vec<Box<str>> = Vec::new();
    for address in cert.email_addresses() {
        if !addresses
            .iter()
            .any(|known| known.eq_ignore_ascii_case(address))
        {
            addresses.push(address.into());
        }
    }
    Some(HarvestedKey {
        kind: KeyKind::Smime,
        source: HarvestSource::SmimeSignature,
        key: cert.raw.into(),
        addresses,
        signing_time: signed.signing_time,
        signature_verified: signed.verified,
        smime_capabilities: signed.capabilities.map(parse_capabilities),
        encryption_key_preference: is_preferred,
        certificates: signed.certificates().map(|c| c.raw.into()).collect(),
        prefer_encrypt: false,
    })
}

fn autocrypt_key(message: &Message<'_>, from: &str, now: u64) -> Option<HarvestedKey> {
    let mut found = None;
    for header in message
        .root_part()
        .headers()
        .iter()
        .filter(|header| header.name() == HeaderName::Autocrypt)
        .take(MAX_AUTOCRYPT_HEADERS)
    {
        let Some(parsed) = parse_autocrypt(header.raw_value()) else {
            continue;
        };
        if !parsed.addr.eq_ignore_ascii_case(from.as_bytes()) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(parsed);
    }
    let header = found?;
    let certs = split_certs(&header.keydata).ok()?;
    if certs.len() != 1 {
        return None;
    }
    let mut signers = validate_signers(&certs, now);
    signers.retain(|(_, valid)| {
        !valid.cert.keys.is_empty()
            && valid
                .addresses
                .iter()
                .any(|address| address.eq_ignore_ascii_case(from))
    });
    let (_, first) = signers.first()?;
    let addresses = first.addresses.clone();
    let verified = detached_signature(message)
        .filter(|signed| signed.protocol == SignedProtocol::Pgp)
        .and_then(|signed| {
            verify_detached(&signers, &signed.signature.decoded(), signed.content, now).ok()
        });
    Some(HarvestedKey {
        kind: KeyKind::OpenPgp,
        source: HarvestSource::Autocrypt,
        key: header.keydata.into_boxed_slice(),
        addresses,
        signing_time: verified.map(|v| v.created),
        signature_verified: verified.is_some(),
        smime_capabilities: None,
        encryption_key_preference: false,
        certificates: Vec::new(),
        prefer_encrypt: header.prefer_encrypt,
    })
}
