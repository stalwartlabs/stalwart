/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::digest::{self, Algorithm, Context, SHA256, SHA384, SHA512};

use super::CryptError;
use super::aes::{self, AesKind, BLOCK_LEN};
use super::key::{FileKey, MAX_KEY_LEN};

pub(crate) const ENTRY_LEN: usize = 48;
pub(crate) const MAX_PASSWORD_LEN: usize = 127;
const HASH_LEN: usize = 32;
const SALT_LEN: usize = 8;
const MAX_DIGEST_LEN: usize = 64;
const R6_REPEAT: usize = 64;
const R6_MIN_ROUNDS: u32 = 64;
const R6_ROUND_SLACK: u32 = 32;

pub(crate) struct Modern<'a> {
    pub(crate) revision: i64,
    pub(crate) o: &'a [u8; ENTRY_LEN],
    pub(crate) u: &'a [u8; ENTRY_LEN],
    pub(crate) oe: &'a [u8],
    pub(crate) ue: &'a [u8],
}

struct Entry<'a> {
    hash: &'a [u8; HASH_LEN],
    validation_salt: &'a [u8; SALT_LEN],
    key_salt: &'a [u8; SALT_LEN],
}

impl<'a> Entry<'a> {
    fn split(entry: &'a [u8; ENTRY_LEN]) -> Option<Self> {
        let (hash, salts) = entry.split_first_chunk::<HASH_LEN>()?;
        let (validation_salt, key_salt) = salts.split_first_chunk::<SALT_LEN>()?;
        Some(Entry {
            hash,
            validation_salt,
            key_salt: key_salt.first_chunk::<SALT_LEN>()?,
        })
    }
}

impl Modern<'_> {
    pub(crate) fn user_key(
        &self,
        password: &[u8],
        scratch: &mut Vec<u8>,
    ) -> Result<Option<FileKey>, CryptError> {
        let password = password.get(..MAX_PASSWORD_LEN).unwrap_or(password);
        let entry = Entry::split(self.u).ok_or(CryptError::Malformed)?;
        if self.hash(password, entry.validation_salt, &[], scratch)? != *entry.hash {
            return Ok(None);
        }
        let intermediate = self.hash(password, entry.key_salt, &[], scratch)?;
        unwrap_file_key(&intermediate, self.ue).map(Some)
    }

    pub(crate) fn owner_key(
        &self,
        password: &[u8],
        scratch: &mut Vec<u8>,
    ) -> Result<Option<FileKey>, CryptError> {
        let password = password.get(..MAX_PASSWORD_LEN).unwrap_or(password);
        let entry = Entry::split(self.o).ok_or(CryptError::Malformed)?;
        if self.hash(password, entry.validation_salt, self.u, scratch)? != *entry.hash {
            return Ok(None);
        }
        let intermediate = self.hash(password, entry.key_salt, self.u, scratch)?;
        unwrap_file_key(&intermediate, self.oe).map(Some)
    }

    fn hash(
        &self,
        password: &[u8],
        salt: &[u8; SALT_LEN],
        user_entry: &[u8],
        scratch: &mut Vec<u8>,
    ) -> Result<[u8; HASH_LEN], CryptError> {
        let initial = concat_digest(&SHA256, password, salt, user_entry);
        let initial = initial
            .as_ref()
            .first_chunk::<HASH_LEN>()
            .ok_or(CryptError::Malformed)?;
        if self.revision >= 6 {
            hardened_hash(password, initial, user_entry, scratch).ok_or(CryptError::Malformed)
        } else {
            Ok(*initial)
        }
    }
}

fn concat_digest(algorithm: &'static Algorithm, a: &[u8], b: &[u8], c: &[u8]) -> digest::Digest {
    let mut context = Context::new(algorithm);
    context.update(a);
    context.update(b);
    context.update(c);
    context.finish()
}

fn hardened_hash(
    password: &[u8],
    initial: &[u8; HASH_LEN],
    user_entry: &[u8],
    scratch: &mut Vec<u8>,
) -> Option<[u8; HASH_LEN]> {
    let mut k = [0u8; MAX_DIGEST_LEN];
    k.get_mut(..HASH_LEN)?.copy_from_slice(initial);
    let mut k_len = HASH_LEN;
    scratch.clear();
    scratch.reserve(R6_REPEAT * (password.len() + MAX_DIGEST_LEN + user_entry.len()));
    let mut round = 0u32;
    loop {
        let current = k.get(..k_len)?;
        scratch.clear();
        for _ in 0..R6_REPEAT {
            scratch.extend_from_slice(password);
            scratch.extend_from_slice(current);
            scratch.extend_from_slice(user_entry);
        }
        let (aes_key, rest) = current.split_first_chunk::<BLOCK_LEN>()?;
        aes::encrypt_aes128_cbc(aes_key, rest.first_chunk::<BLOCK_LEN>()?, scratch)?;
        let selector = scratch
            .iter()
            .take(BLOCK_LEN)
            .map(|byte| u32::from(*byte))
            .sum::<u32>()
            % 3;
        let algorithm = match selector {
            0 => &SHA256,
            1 => &SHA384,
            _ => &SHA512,
        };
        let next = digest::digest(algorithm, scratch);
        k_len = next.as_ref().len();
        k.get_mut(..k_len)?.copy_from_slice(next.as_ref());
        round += 1;
        let last = u32::from(*scratch.last()?);
        if round >= R6_MIN_ROUNDS && last + R6_ROUND_SLACK <= round {
            break;
        }
    }
    k.first_chunk::<HASH_LEN>().copied()
}

fn unwrap_file_key(intermediate: &[u8; HASH_LEN], wrapped: &[u8]) -> Result<FileKey, CryptError> {
    let mut key = *wrapped
        .first_chunk::<MAX_KEY_LEN>()
        .ok_or(CryptError::Malformed)?;
    aes::decrypt_zero_iv(AesKind::Aes256, intermediate, &mut key).ok_or(CryptError::Malformed)?;
    FileKey::from_slice(&key).ok_or(CryptError::Malformed)
}
