/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::key::FileKey;
use super::rc4::Rc4;

pub(crate) const PADDED_LEN: usize = 32;
const PASSWORD_PAD: [u8; PADDED_LEN] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];
const U_CHECK_LEN: usize = 16;
const MD5_ROUNDS: usize = 50;
const RC4_ROUNDS: u8 = 20;
const METADATA_MARKER: [u8; 4] = [0xff; 4];

#[derive(Clone, Copy)]
pub(crate) enum OwnerHash {
    KeyLength,
    FullDigest,
}

#[derive(Clone, Copy)]
pub(crate) struct Legacy<'a> {
    pub(crate) revision: i64,
    pub(crate) o: &'a [u8],
    pub(crate) u: &'a [u8],
    pub(crate) p: u32,
    pub(crate) id0: &'a [u8],
    pub(crate) encrypt_metadata: bool,
}

impl Legacy<'_> {
    pub(crate) fn user_key(&self, password: &[u8], key_len: usize) -> Option<FileKey> {
        let key = self.file_key(&pad_password(password), key_len)?;
        self.matches_u(&key).then_some(key)
    }

    pub(crate) fn owner_key(
        &self,
        password: &[u8],
        key_len: usize,
        owner_hash: OwnerHash,
    ) -> Option<FileKey> {
        let mut hash = md5::compute(pad_password(password)).0;
        if self.revision >= 3 {
            let rehashed_len = match owner_hash {
                OwnerHash::KeyLength => key_len,
                OwnerHash::FullDigest => hash.len(),
            };
            for _ in 0..MD5_ROUNDS {
                hash = md5::compute(hash.get(..rehashed_len)?).0;
            }
        }
        let owner_key = FileKey::from_slice(hash.get(..key_len)?)?;
        let mut user_password = pad_password(self.o);
        if self.revision >= 3 {
            for round in (0..RC4_ROUNDS).rev() {
                Rc4::new(owner_key.xor(round).as_slice()).apply_in_place(&mut user_password);
            }
        } else {
            Rc4::new(owner_key.as_slice()).apply_in_place(&mut user_password);
        }
        self.user_key(&user_password, key_len)
    }

    fn file_key(&self, padded_password: &[u8; PADDED_LEN], key_len: usize) -> Option<FileKey> {
        let mut context = md5::Context::new();
        context.consume(padded_password);
        context.consume(self.o);
        context.consume(self.p.to_le_bytes());
        context.consume(self.id0);
        if self.revision >= 4 && !self.encrypt_metadata {
            context.consume(METADATA_MARKER);
        }
        let mut hash = context.finalize().0;
        if self.revision >= 3 {
            for _ in 0..MD5_ROUNDS {
                hash = md5::compute(hash.get(..key_len)?).0;
            }
        }
        FileKey::from_slice(hash.get(..key_len)?)
    }

    fn matches_u(&self, key: &FileKey) -> bool {
        if self.revision >= 3 {
            let mut context = md5::Context::new();
            context.consume(PASSWORD_PAD);
            context.consume(self.id0);
            let mut check = context.finalize().0;
            Rc4::new(key.as_slice()).apply_in_place(&mut check);
            for round in 1..RC4_ROUNDS {
                Rc4::new(key.xor(round).as_slice()).apply_in_place(&mut check);
            }
            self.u.get(..U_CHECK_LEN) == Some(check.as_slice())
        } else {
            let mut check = PASSWORD_PAD;
            Rc4::new(key.as_slice()).apply_in_place(&mut check);
            self.u.get(..PADDED_LEN) == Some(check.as_slice())
        }
    }
}

fn pad_password(password: &[u8]) -> [u8; PADDED_LEN] {
    let mut padded = [0u8; PADDED_LEN];
    for (slot, byte) in padded
        .iter_mut()
        .zip(password.iter().chain(PASSWORD_PAD.iter()))
    {
        *slot = *byte;
    }
    padded
}
