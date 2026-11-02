/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::{
    aead::{AES_128_GCM, AES_192_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    cipher::{AES_128, AES_192, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey},
    iv::FixedLength,
};

use super::{PrimitiveError, aes::BLOCK_LEN};

pub(crate) const GCM_NONCE_LEN: usize = 12;
pub(crate) const GCM_TAG_LEN: usize = 16;

pub(crate) struct GcmKey(LessSafeKey);

impl GcmKey {
    pub(crate) fn new(key: &[u8]) -> Result<Self, PrimitiveError> {
        let alg = match key.len() {
            16 => &AES_128_GCM,
            24 => &AES_192_GCM,
            32 => &AES_256_GCM,
            _ => return Err(PrimitiveError::InvalidKeyLength),
        };
        UnboundKey::new(alg, key)
            .map(|key| GcmKey(LessSafeKey::new(key)))
            .map_err(|_| PrimitiveError::InvalidKeyLength)
    }

    pub(crate) fn seal_in_place(
        &self,
        nonce: [u8; GCM_NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; GCM_TAG_LEN], PrimitiveError> {
        let tag = self
            .0
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(ad), data)
            .map_err(|_| PrimitiveError::Encryption)?;
        tag.as_ref()
            .try_into()
            .map_err(|_| PrimitiveError::Encryption)
    }
}

pub(crate) fn cbc_pkcs7_padded_len(len: usize) -> usize {
    (len / BLOCK_LEN + 1) * BLOCK_LEN
}

pub(crate) fn write_pkcs7_padding(out: &mut Vec<u8>, plaintext_len: usize) {
    let pad = cbc_pkcs7_padded_len(plaintext_len) - plaintext_len;
    out.resize(out.len() + pad, pad as u8);
}

pub(crate) fn cbc_encrypt_padded_in_place(
    key: &[u8],
    iv: [u8; BLOCK_LEN],
    data: &mut [u8],
) -> Result<(), PrimitiveError> {
    let alg = match key.len() {
        16 => &AES_128,
        24 => &AES_192,
        32 => &AES_256,
        _ => return Err(PrimitiveError::InvalidKeyLength),
    };
    if !data.len().is_multiple_of(BLOCK_LEN) {
        return Err(PrimitiveError::InvalidLength);
    }
    let key = UnboundCipherKey::new(alg, key)
        .and_then(EncryptingKey::cbc)
        .map_err(|_| PrimitiveError::InvalidKeyLength)?;
    key.less_safe_encrypt(data, EncryptionContext::Iv128(FixedLength::from(iv)))
        .map(|_| ())
        .map_err(|_| PrimitiveError::Encryption)
}
