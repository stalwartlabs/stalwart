/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aes_gcm_siv::{
    Aes256GcmSiv, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use store::blake3;

pub struct SymmetricEncrypt {
    aes: Aes256GcmSiv,
}

impl SymmetricEncrypt {
    pub const ENCRYPT_TAG_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;

    pub fn new(key: &[u8], context: &str) -> Self {
        SymmetricEncrypt {
            aes: Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&blake3::derive_key(
                context, key,
            ))),
        }
    }

    pub fn encrypt_with_aad(
        &self,
        bytes: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.aes
            .encrypt(Nonce::from_slice(nonce), Payload { msg: bytes, aad })
            .map_err(|e| e.to_string())
    }

    pub fn decrypt_with_aad(
        &self,
        bytes: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.aes
            .decrypt(Nonce::from_slice(nonce), Payload { msg: bytes, aad })
            .map_err(|e| e.to_string())
    }
}
