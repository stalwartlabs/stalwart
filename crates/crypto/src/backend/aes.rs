/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};
use aws_lc_rs::{
    cipher::{AES_128, AES_192, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey},
    iv::FixedLength,
};

use super::PrimitiveError;

pub(crate) const BLOCK_LEN: usize = 16;
pub(crate) const KEY_WRAP_OVERHEAD: usize = 8;
const KEY_WRAP_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;
const KEY_WRAP_ROUNDS: u64 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl AesKeySize {
    pub const fn key_len(self) -> usize {
        match self {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes192 => 24,
            AesKeySize::Aes256 => 32,
        }
    }

    fn aws_algorithm(self) -> &'static aws_lc_rs::cipher::Algorithm {
        match self {
            AesKeySize::Aes128 => &AES_128,
            AesKeySize::Aes192 => &AES_192,
            AesKeySize::Aes256 => &AES_256,
        }
    }

    pub(crate) const fn from_key_len(len: usize) -> Option<Self> {
        match len {
            16 => Some(AesKeySize::Aes128),
            24 => Some(AesKeySize::Aes192),
            32 => Some(AesKeySize::Aes256),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(crate) enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

macro_rules! with_cipher {
    ($self:expr, $c:ident => $body:expr) => {
        match $self {
            AesCipher::Aes128($c) => $body,
            AesCipher::Aes192($c) => $body,
            AesCipher::Aes256($c) => $body,
        }
    };
}

impl AesCipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self, PrimitiveError> {
        match AesKeySize::from_key_len(key.len()) {
            Some(AesKeySize::Aes128) => Aes128::new_from_slice(key).map(AesCipher::Aes128),
            Some(AesKeySize::Aes192) => Aes192::new_from_slice(key).map(AesCipher::Aes192),
            Some(AesKeySize::Aes256) => Aes256::new_from_slice(key).map(AesCipher::Aes256),
            None => return Err(PrimitiveError::InvalidKeyLength),
        }
        .map_err(|_| PrimitiveError::InvalidKeyLength)
    }

    pub(crate) fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        with_cipher!(self, c => c.encrypt_block(block.into()))
    }

    pub(crate) fn encrypt_blocks(&self, data: &mut [u8]) {
        let (blocks, _) = Array::slice_as_chunks_mut(data);
        with_cipher!(self, c => c.encrypt_blocks(blocks))
    }

    pub(crate) fn wrap_len(input_len: usize) -> usize {
        input_len + KEY_WRAP_OVERHEAD
    }

    pub(crate) fn wrap(&self, input: &[u8], out: &mut [u8]) -> Result<(), PrimitiveError> {
        if input.len() < 16
            || !input.len().is_multiple_of(8)
            || out.len() != Self::wrap_len(input.len())
        {
            return Err(PrimitiveError::InvalidLength);
        }
        let (a_out, r) = out.split_at_mut(KEY_WRAP_OVERHEAD);
        r.copy_from_slice(input);
        let (r, _) = r.as_chunks_mut::<8>();
        let n = r.len() as u64;
        let mut a = KEY_WRAP_IV;
        for j in 0..KEY_WRAP_ROUNDS {
            for (i, r) in (1..).zip(r.iter_mut()) {
                let mut block =
                    ((u128::from(a) << 64) | u128::from(u64::from_be_bytes(*r))).to_be_bytes();
                self.encrypt_block(&mut block);
                let b = u128::from_be_bytes(block);
                a = ((b >> 64) as u64) ^ (n * j + i);
                *r = (b as u64).to_be_bytes();
            }
        }
        a_out.copy_from_slice(&a.to_be_bytes());
        Ok(())
    }
}

fn unbound_key(key: &[u8]) -> Result<UnboundCipherKey, PrimitiveError> {
    let size = AesKeySize::from_key_len(key.len()).ok_or(PrimitiveError::InvalidKeyLength)?;
    UnboundCipherKey::new(size.aws_algorithm(), key).map_err(|_| PrimitiveError::InvalidKeyLength)
}

pub(crate) fn cfb_encrypt_zero_iv(key: &[u8], data: &mut [u8]) -> Result<(), PrimitiveError> {
    EncryptingKey::cfb128(unbound_key(key)?)
        .and_then(|key| {
            key.less_safe_encrypt(
                data,
                EncryptionContext::Iv128(FixedLength::from([0u8; BLOCK_LEN])),
            )
        })
        .map(|_| ())
        .map_err(|_| PrimitiveError::Encryption)
}
