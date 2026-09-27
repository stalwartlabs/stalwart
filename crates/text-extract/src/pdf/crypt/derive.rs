/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::key::FileKey;
use super::legacy::{Legacy, OwnerHash, PADDED_LEN};
use super::modern::{ENTRY_LEN, Modern};
use super::{CryptError, EncryptDict};

const DEFAULT_KEY_LEN: usize = 5;
const FULL_KEY_LEN: usize = 16;
const MIN_KEY_BITS: i64 = 40;
const MAX_KEY_BITS: i64 = 128;
const MIN_KEY_BYTES: i64 = 5;
const MAX_KEY_BYTES: i64 = 16;
const MIN_U_LEN_R2: usize = 32;
const MIN_U_LEN_R3: usize = 16;
const R5: i64 = 5;
const R6: i64 = 6;

pub(crate) fn legacy_key(dict: &EncryptDict<'_>, password: &[u8]) -> Result<FileKey, CryptError> {
    let min_u_len = if dict.r == 2 {
        MIN_U_LEN_R2
    } else {
        MIN_U_LEN_R3
    };
    let o = dict.o.get(..PADDED_LEN).ok_or(CryptError::Malformed)?;
    if dict.u.len() < min_u_len {
        return Err(CryptError::Malformed);
    }
    let base = Legacy {
        revision: dict.r,
        o,
        u: dict.u,
        p: dict.p as u32,
        id0: dict.id0,
        encrypt_metadata: dict.encrypt_metadata,
    };
    let metadata_flags = [
        Some(dict.encrypt_metadata),
        (dict.r >= 4).then_some(!dict.encrypt_metadata),
    ];
    let lengths = KeyLengths::new(dict);
    let variants = || {
        lengths.iter().flat_map(move |key_len| {
            metadata_flags
                .into_iter()
                .flatten()
                .map(move |encrypt_metadata| {
                    (
                        key_len,
                        Legacy {
                            encrypt_metadata,
                            ..base
                        },
                    )
                })
        })
    };
    variants()
        .find_map(|(key_len, legacy)| legacy.user_key(password, key_len))
        .or_else(|| {
            variants().find_map(|(key_len, legacy)| {
                legacy
                    .owner_key(password, key_len, OwnerHash::KeyLength)
                    .or_else(|| {
                        (key_len < FULL_KEY_LEN)
                            .then(|| legacy.owner_key(password, key_len, OwnerHash::FullDigest))
                            .flatten()
                    })
            })
        })
        .ok_or(if lengths.has_invalid {
            CryptError::Malformed
        } else {
            CryptError::PasswordRequired
        })
}

pub(crate) fn modern_key(dict: &EncryptDict<'_>, password: &[u8]) -> Result<FileKey, CryptError> {
    let o = dict
        .o
        .first_chunk::<ENTRY_LEN>()
        .ok_or(CryptError::Malformed)?;
    let u = dict
        .u
        .first_chunk::<ENTRY_LEN>()
        .ok_or(CryptError::Malformed)?;
    let alternate = if dict.r == R6 { R5 } else { R6 };
    let mut scratch = Vec::new();
    for revision in [dict.r, alternate] {
        let modern = Modern {
            revision,
            o,
            u,
            oe: dict.oe,
            ue: dict.ue,
        };
        if let Some(key) = modern.user_key(password, &mut scratch)? {
            return Ok(key);
        }
        if let Some(key) = modern.owner_key(password, &mut scratch)? {
            return Ok(key);
        }
    }
    Err(CryptError::PasswordRequired)
}

struct KeyLengths {
    candidates: [Option<usize>; 3],
    has_invalid: bool,
}

impl KeyLengths {
    fn new(dict: &EncryptDict<'_>) -> Self {
        if dict.v == 1 {
            return KeyLengths {
                candidates: [Some(DEFAULT_KEY_LEN), None, None],
                has_invalid: false,
            };
        }
        let length = dict.length.and_then(key_len_from_entry);
        let filter_length = dict.crypt_filter_length.and_then(key_len_from_entry);
        let declared = if dict.v >= 4 {
            filter_length.or(length)
        } else {
            length.or(filter_length)
        };
        let has_invalid =
            declared.is_none() && (dict.length.is_some() || dict.crypt_filter_length.is_some());
        KeyLengths {
            candidates: [declared, Some(DEFAULT_KEY_LEN), Some(FULL_KEY_LEN)],
            has_invalid,
        }
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.candidates
            .iter()
            .enumerate()
            .filter_map(move |(pos, candidate)| {
                let len = (*candidate)?;
                (!self
                    .candidates
                    .iter()
                    .take(pos)
                    .any(|seen| *seen == Some(len)))
                .then_some(len)
            })
    }
}

fn key_len_from_entry(value: i64) -> Option<usize> {
    let bytes = if (MIN_KEY_BITS..=MAX_KEY_BITS).contains(&value) && value % 8 == 0 {
        value / 8
    } else if (MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&value) {
        value
    } else {
        return None;
    };
    usize::try_from(bytes).ok()
}
