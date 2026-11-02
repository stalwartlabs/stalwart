/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    error::VerifyError,
    mime::{Canonical, Sink},
    pgp::{
        armor::{ArmorLabel, decode_body, is_armored, next_block},
        cert::{Purpose, RawCert, ValidCert},
        packet::{Packet, PacketReader, TAG_SIGNATURE},
        signature::{SIG_BINARY, SIG_TEXT, Signature},
    },
    types::Fingerprint,
};

const MAX_SIGNATURES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PgpVerified {
    pub signer: Fingerprint,
    pub created: u64,
}

fn dearmor_signature(input: &[u8]) -> Result<Cow<'_, [u8]>, VerifyError> {
    if !is_armored(input) {
        return Ok(Cow::Borrowed(input));
    }
    let (block, _) = next_block(input)
        .ok()
        .flatten()
        .ok_or(VerifyError::Malformed)?;
    if block.label != ArmorLabel::Signature {
        return Err(VerifyError::Malformed);
    }
    let mut out = Vec::with_capacity(block.body.len() / 4 * 3);
    decode_body(block.body, &mut out).map_err(|_| VerifyError::Malformed)?;
    Ok(Cow::Owned(out))
}

pub(crate) fn validate_signers<'c, 'x>(
    certs: &'c [RawCert<'x>],
    now: u64,
) -> Vec<(&'c RawCert<'x>, ValidCert)> {
    let primaries: Vec<_> = certs.iter().filter_map(RawCert::primary).collect();
    certs
        .iter()
        .filter_map(|cert| {
            cert.validate(&primaries, now, Purpose::Verify)
                .ok()
                .map(|valid| (cert, valid))
        })
        .collect()
}

pub(crate) fn verify_detached(
    signers: &[(&RawCert<'_>, ValidCert)],
    signature: &[u8],
    content: &[u8],
    now: u64,
) -> Result<PgpVerified, VerifyError> {
    if signers.is_empty() {
        return Err(VerifyError::InvalidCertificate(
            crate::error::KeyError::NoValidSelfSignature,
        ));
    }
    let signature = dearmor_signature(signature)?;
    let mut error = VerifyError::UnknownSigner;
    for packet in PacketReader::new(&signature).take(MAX_SIGNATURES) {
        let Packet { tag, body } = packet.map_err(|_| VerifyError::Malformed)?;
        if tag != TAG_SIGNATURE {
            continue;
        }
        let Ok(sig) = Signature::parse(body) else {
            continue;
        };
        if !matches!(sig.sig_type, SIG_BINARY | SIG_TEXT) {
            continue;
        }
        for (cert, valid) in signers {
            for fingerprint in valid.signing.iter().flatten() {
                let Some(key) = cert.key(fingerprint).filter(|key| sig.is_issued_by(key)) else {
                    continue;
                };
                match sig.verify(key, |h| Canonical::new(h).put(content), now) {
                    Ok(()) => {
                        return Ok(PgpVerified {
                            signer: *fingerprint,
                            created: u64::from(sig.info.created.unwrap_or_default()),
                        });
                    }
                    Err(_) => error = VerifyError::BadSignature,
                }
            }
        }
    }
    Err(error)
}
