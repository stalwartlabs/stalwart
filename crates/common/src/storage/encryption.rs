/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::EncryptionKeys;
use mail_parser::decoders::base64::base64_decode;
use registry::schema::structs::PublicKey;
use sequoia_openpgp::{Cert, parse::Parse, policy::StandardPolicy, types::KeyFlags};
use std::borrow::Cow;

const P: StandardPolicy<'static> = StandardPolicy::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
}

pub struct EncryptionParams {
    pub certs: EncryptionKeys,
    pub method: EncryptionMethod,
}

#[allow(clippy::type_complexity)]
pub fn parse_public_key(pk: &PublicKey) -> Result<Option<EncryptionParams>, Cow<'static, str>> {
    let bytes_ = pk.key.as_bytes();
    let mut bytes = bytes_.iter().enumerate();
    let mut buf = vec![];
    let mut method = None;
    let mut certs: Vec<Box<[u8]>> = vec![];

    loop {
        // Find start of PEM block
        let mut start_pos = 0;
        for (pos, &ch) in bytes.by_ref() {
            if ch.is_ascii_whitespace() {
                continue;
            } else if ch == b'-' {
                start_pos = pos;
                break;
            } else {
                return Ok(None);
            }
        }

        // Find block type
        for (_, &ch) in bytes.by_ref() {
            match ch {
                b'-' => (),
                b'\n' => break,
                _ => {
                    if ch.is_ascii() {
                        buf.push(ch.to_ascii_uppercase());
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
        if buf.is_empty() {
            break;
        }

        // Find type
        let tag = std::str::from_utf8(&buf).unwrap();
        if tag.contains("CERTIFICATE") {
            if method.is_some_and(|m| m == EncryptionMethod::PGP) {
                return Err("Cannot mix OpenPGP and S/MIME certificates".into());
            } else {
                method = Some(EncryptionMethod::SMIME);
            }
        } else if tag.contains("PGP") {
            if method.is_some_and(|m| m == EncryptionMethod::SMIME) {
                return Err("Cannot mix OpenPGP and S/MIME certificates".into());
            } else {
                method = Some(EncryptionMethod::PGP);
            }
        } else {
            // Ignore block
            let mut found_end = false;
            for (_, &ch) in bytes.by_ref() {
                if ch == b'-' {
                    found_end = true;
                } else if ch == b'\n' && found_end {
                    break;
                }
            }
            buf.clear();
            continue;
        }

        // Collect base64
        buf.clear();
        let mut found_end = false;
        let mut end_pos = 0;
        for (pos, &ch) in bytes.by_ref() {
            match ch {
                b'-' => {
                    found_end = true;
                }
                b'\n' => {
                    if found_end {
                        end_pos = pos;
                        break;
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        buf.push(ch);
                    }
                }
            }
        }

        // Decode base64
        let cert = base64_decode(&buf)
            .ok_or_else(|| Cow::from("Failed to decode base64 certificate."))?
            .into_boxed_slice();
        match method.unwrap() {
            EncryptionMethod::PGP => match Cert::from_bytes(bytes_) {
                Ok(cert) => {
                    if !has_pgp_keys(cert) {
                        return Err("Could not find any suitable keys in OpenPGP public key".into());
                    }
                    certs.push(
                        bytes_
                            .get(start_pos..end_pos + 1)
                            .unwrap_or_default()
                            .into(),
                    );
                }
                Err(err) => {
                    return Err(format!("Failed to decode OpenPGP public key: {err}").into());
                }
            },
            EncryptionMethod::SMIME => {
                if let Err(err) = rasn::der::decode::<rasn_pkix::Certificate>(&cert) {
                    return Err(format!("Failed to decode X509 certificate: {err}").into());
                }
                certs.push(cert);
            }
        }
        buf.clear();
    }

    Ok(method.map(|method| EncryptionParams {
        method,
        certs: certs.into_boxed_slice(),
    }))
}

fn has_pgp_keys(cert: Cert) -> bool {
    cert.keys()
        .with_policy(&P, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(KeyFlags::empty().set_transport_encryption())
        .next()
        .is_some()
}
