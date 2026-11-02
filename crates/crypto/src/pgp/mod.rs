/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod armor;
pub(crate) mod cert;
pub(crate) mod encrypt;
pub(crate) mod key;
pub(crate) mod packet;
pub(crate) mod signature;
pub(crate) mod verify;

use std::sync::Arc;

use crate::{
    error::KeyError,
    pgp::packet::{
        Packet, PacketReader, TAG_MARKER, TAG_PADDING, TAG_PUBLIC_KEY, TAG_SIGNATURE, TAG_TRUST,
        TAG_USER_ATTRIBUTE, TAG_USER_ID,
    },
    types::{
        AddressKey, KeyCapabilities, KeyCapability, KeyKind, KeyWarning, ParsedKeys, RecipientSet,
        Recipients,
    },
};

pub const EXPIRES_SOON_SECS: u64 = 14 * 86_400;
const MAX_ADDRESS_KEYS: usize = 5;

pub(crate) fn parse_public_keys_for(
    input: &[u8],
    address: &str,
    now: u64,
) -> Result<Vec<AddressKey>, KeyError> {
    let binary = armor::dearmor_public_keys(input)?;
    let mut keys = Vec::new();
    let mut first_error = None;
    let mut current = Vec::new();
    let mut keep_signatures = false;
    let mut has_user_id = false;
    let mut reader = PacketReader::new(&binary);
    loop {
        let packet = if reader.is_empty() {
            None
        } else {
            Some(reader.read_raw()?)
        };
        if matches!(
            packet,
            None | Some((
                Packet {
                    tag: TAG_PUBLIC_KEY,
                    ..
                },
                _
            ))
        ) {
            if has_user_id && keys.len() < MAX_ADDRESS_KEYS {
                match parse_public_keys(&current, now) {
                    Ok(parsed) => keys.push(AddressKey {
                        parsed,
                        key: std::mem::take(&mut current),
                    }),
                    Err(err) => {
                        first_error.get_or_insert(err);
                    }
                }
            }
            current.clear();
            keep_signatures = true;
            has_user_id = false;
        }
        let Some((Packet { tag, body }, raw)) = packet else {
            break;
        };
        match tag {
            TAG_USER_ID => {
                keep_signatures = cert::email_address(body)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(address));
                has_user_id |= keep_signatures;
                if keep_signatures {
                    current.extend_from_slice(raw);
                }
            }
            TAG_USER_ATTRIBUTE => keep_signatures = false,
            TAG_SIGNATURE => {
                if keep_signatures {
                    current.extend_from_slice(raw);
                }
            }
            TAG_MARKER | TAG_PADDING | TAG_TRUST => {}
            _ => {
                keep_signatures = true;
                current.extend_from_slice(raw);
            }
        }
    }
    if keys.is_empty() {
        Err(first_error.unwrap_or(KeyError::NoEncryptionKey))
    } else {
        Ok(keys)
    }
}

pub(crate) fn certifies(old_key: &[u8], new_key: &[u8], address: &str, now: u64) -> bool {
    let (Ok(old_key), Ok(new_key)) = (
        armor::dearmor_public_keys(old_key),
        armor::dearmor_public_keys(new_key),
    ) else {
        return false;
    };
    let (Ok(old_certs), Ok(new_certs)) = (cert::split_certs(&old_key), cert::split_certs(&new_key))
    else {
        return false;
    };
    let signers: Vec<_> = old_certs
        .iter()
        .filter_map(cert::RawCert::primary)
        .collect();
    new_certs
        .iter()
        .any(|cert| cert.certified_by(&signers, address, now))
}

pub(crate) fn revoked_fingerprints(input: &[u8], now: u64) -> Vec<crate::Fingerprint> {
    let Ok(binary) = armor::dearmor_public_keys(input) else {
        return Vec::new();
    };
    let Ok(raw) = cert::split_certs(&binary) else {
        return Vec::new();
    };
    let primaries: Vec<_> = raw.iter().filter_map(cert::RawCert::primary).collect();
    raw.iter()
        .filter(|cert| {
            matches!(
                cert.validate(&primaries, now, cert::Purpose::Encrypt),
                Err(KeyError::Revoked)
            )
        })
        .filter_map(|cert| cert.primary().map(|primary| primary.fingerprint))
        .collect()
}

pub(crate) fn parse_public_keys(input: &[u8], now: u64) -> Result<ParsedKeys, KeyError> {
    let binary = armor::dearmor_public_keys(input)?;
    let raw = cert::split_certs(&binary)?;
    let primaries: Vec<_> = raw.iter().filter_map(cert::RawCert::primary).collect();
    let mut certs = Vec::with_capacity(raw.len());
    let mut addresses = Vec::new();
    let mut warnings = Vec::new();
    let mut first_error = None;
    for raw_cert in &raw {
        match raw_cert.validate(&primaries, now, cert::Purpose::Encrypt) {
            Ok(valid) => {
                if valid.weak_rsa && !warnings.contains(&KeyWarning::WeakRsa) {
                    warnings.push(KeyWarning::WeakRsa);
                }
                for address in valid.addresses {
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                certs.push(valid.cert);
            }
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    if certs.is_empty() {
        return Err(first_error.unwrap_or(KeyError::NoEncryptionKey));
    }
    let keys = certs.iter().flat_map(|c| c.keys.iter());
    let mut capabilities = KeyCapabilities::default();
    if keys.clone().all(|k| k.seipd_v2) {
        capabilities.insert(KeyCapability::Aead);
    }
    if keys.clone().any(|k| k.is_post_quantum()) {
        capabilities.insert(KeyCapability::PostQuantum);
    }
    if certs
        .iter()
        .any(|c| c.keys.iter().all(cert::PgpKey::is_post_quantum))
    {
        warnings.push(KeyWarning::PostQuantumOnly);
    }
    let expires_at = keys
        .clone()
        .map(|k| k.expires_at)
        .try_fold(0u64, |acc, exp| exp.map(|e| acc.max(e)));
    if expires_at.is_some_and(|exp| exp <= now + EXPIRES_SOON_SECS) {
        warnings.push(KeyWarning::ExpiresSoon);
    }
    Ok(ParsedKeys {
        kind: KeyKind::OpenPgp,
        fingerprints: certs.iter().map(|c| c.fingerprint).collect(),
        set: RecipientSet(Arc::new(Recipients::OpenPgp(certs.into_boxed_slice()))),
        addresses,
        expires_at,
        capabilities,
        warnings,
        smime_capabilities: None,
    })
}
