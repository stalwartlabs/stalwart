/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::cipher::{
    AES_128, AES_256, Algorithm, DecryptingKey, DecryptionContext, EncryptingKey,
    EncryptionContext, UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;

pub(crate) const BLOCK_LEN: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum AesKind {
    Aes128,
    Aes256,
}

impl AesKind {
    fn algorithm(self) -> &'static Algorithm {
        match self {
            AesKind::Aes128 => &AES_128,
            AesKind::Aes256 => &AES_256,
        }
    }

    pub(crate) fn decrypting_key(self, key: &[u8]) -> Option<DecryptingKey> {
        UnboundCipherKey::new(self.algorithm(), key)
            .and_then(DecryptingKey::cbc)
            .ok()
    }
}

pub(crate) fn decrypt_with_iv(cipher: &DecryptingKey, data: &[u8], out: &mut Vec<u8>) {
    let Some((iv, body)) = data.split_first_chunk::<BLOCK_LEN>() else {
        return;
    };
    let whole_blocks = body.len() - body.len() % BLOCK_LEN;
    let Some(body) = body.get(..whole_blocks).filter(|body| !body.is_empty()) else {
        return;
    };
    let start = out.len();
    out.extend_from_slice(body);
    let plain_len = out
        .get_mut(start..)
        .and_then(|buf| {
            cipher
                .decrypt(buf, DecryptionContext::Iv128(FixedLength::from(iv)))
                .ok()
        })
        .map(|plain| plain.len() - valid_padding(plain));
    match plain_len {
        Some(len) => out.truncate(start + len),
        None => out.truncate(start),
    }
}

fn valid_padding(plain: &[u8]) -> usize {
    let Some(&last) = plain.last() else {
        return 0;
    };
    let pad = usize::from(last);
    if (1..=BLOCK_LEN).contains(&pad)
        && plain.len() >= pad
        && plain.iter().rev().take(pad).all(|byte| *byte == last)
    {
        pad
    } else {
        0
    }
}

pub(crate) fn decrypt_zero_iv(kind: AesKind, key: &[u8], data: &mut [u8]) -> Option<()> {
    kind.decrypting_key(key)?
        .decrypt(
            data,
            DecryptionContext::Iv128(FixedLength::from([0u8; BLOCK_LEN])),
        )
        .ok()
        .map(|_| ())
}

pub(crate) fn encrypt_aes128_cbc(key: &[u8], iv: &[u8; BLOCK_LEN], data: &mut [u8]) -> Option<()> {
    UnboundCipherKey::new(&AES_128, key)
        .and_then(EncryptingKey::cbc)
        .and_then(|cipher| {
            cipher.less_safe_encrypt(data, EncryptionContext::Iv128(FixedLength::from(iv)))
        })
        .ok()
        .map(|_| ())
}
