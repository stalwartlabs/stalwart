/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::{
    aead::{
        AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey,
    },
    hkdf::{HKDF_SHA256, KeyType, Prk, Salt},
};
use registry::schema::enums::SymmetricCipher;
use std::sync::Arc;
use tinyvec::TinyVec;
use utils::HexEncode;

pub const BLOB_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const KEY_ID_LEN: usize = 4;

const EXTRACT_SALT: &[u8] = b"stalwart-blob-v1";
const FINGERPRINT_INFO: &[u8] = b"stalwart-blob-fingerprint";
const FINGERPRINT_LEN: usize = 16;
const DERIVED_LEN: usize = BLOB_KEY_LEN + NONCE_LEN;
const AAD_INLINE_LEN: usize = 64;

pub struct BlobKey {
    id: u32,
    cipher: SymmetricCipher,
    prk: Prk,
}

#[derive(Clone, Default)]
pub struct BlobKeyring(Arc<[Arc<BlobKey>]>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKeyError {
    InvalidEncoding,
    InvalidLength,
}

struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl BlobKey {
    pub fn new(id: u32, cipher: SymmetricCipher, secret: &[u8; BLOB_KEY_LEN]) -> Self {
        BlobKey {
            id,
            cipher,
            prk: Salt::new(HKDF_SHA256, EXTRACT_SALT).extract(secret),
        }
    }

    pub fn from_base64(
        id: u32,
        cipher: SymmetricCipher,
        encoded: &str,
    ) -> Result<Self, BlobKeyError> {
        let decoded = encodify::base64::STANDARD
            .decode(encoded.trim().as_bytes())
            .map_err(|_| BlobKeyError::InvalidEncoding)?;
        let secret = <&[u8; BLOB_KEY_LEN]>::try_from(decoded.as_slice())
            .map_err(|_| BlobKeyError::InvalidLength)?;
        Ok(BlobKey::new(id, cipher, secret))
    }

    #[inline(always)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[inline(always)]
    pub fn cipher(&self) -> SymmetricCipher {
        self.cipher
    }

    pub fn fingerprint(&self) -> String {
        let mut out = [0u8; FINGERPRINT_LEN];
        self.prk
            .expand(
                &[FINGERPRINT_INFO, &[self.cipher_tag()]],
                OkmLen(FINGERPRINT_LEN),
            )
            .and_then(|okm| okm.fill(&mut out))
            .map(|_| out.hex_encode())
            .unwrap_or_default()
    }

    pub(super) fn seal(&self, buf: &mut Vec<u8>, storage_key: &[u8], flags: u8) -> trc::Result<()> {
        let salt: [u8; SALT_LEN] = rand::random();
        let header = self.header(flags);
        let (key, nonce) = self.derive(&salt)?;
        let tag = key
            .seal_in_place_separate_tag(nonce, BlobKey::aad(&header, storage_key), buf)
            .map_err(|_| BlobKey::crypto_error("seal"))?;
        buf.reserve(TAG_LEN + SALT_LEN + header.len());
        buf.extend_from_slice(tag.as_ref());
        buf.extend_from_slice(&salt);
        buf.extend_from_slice(&header);
        Ok(())
    }

    pub(super) fn open(
        &self,
        body: &mut [u8],
        tag: &[u8; TAG_LEN],
        salt: &[u8; SALT_LEN],
        storage_key: &[u8],
        flags: u8,
    ) -> trc::Result<()> {
        let header = self.header(flags);
        let (key, nonce) = self.derive(salt)?;
        key.open_in_place_separate_tag(nonce, BlobKey::aad(&header, storage_key), tag, body)
            .map(|_| ())
            .map_err(|_| {
                trc::StoreEvent::DecryptError
                    .into_err()
                    .ctx(trc::Key::Id, self.id)
                    .ctx(trc::Key::Key, storage_key)
                    .details("Authentication failed")
            })
    }

    fn header(&self, flags: u8) -> [u8; KEY_ID_LEN + 1] {
        let [a, b, c, d] = self.id.to_le_bytes();
        [a, b, c, d, flags]
    }

    fn derive(&self, salt: &[u8; SALT_LEN]) -> trc::Result<(LessSafeKey, Nonce)> {
        let mut okm = [0u8; DERIVED_LEN];
        self.prk
            .expand(&[&[self.cipher_tag()], salt], OkmLen(DERIVED_LEN))
            .and_then(|derived| derived.fill(&mut okm))
            .map_err(|_| BlobKey::crypto_error("derive"))?;
        let (key, nonce) = okm.split_at(BLOB_KEY_LEN);
        let nonce =
            <[u8; NONCE_LEN]>::try_from(nonce).map_err(|_| BlobKey::crypto_error("nonce"))?;
        let key =
            UnboundKey::new(self.algorithm(), key).map_err(|_| BlobKey::crypto_error("key"))?;
        Ok((LessSafeKey::new(key), Nonce::assume_unique_for_key(nonce)))
    }

    fn algorithm(&self) -> &'static Algorithm {
        match self.cipher {
            SymmetricCipher::Aes256Gcm => &AES_256_GCM,
            SymmetricCipher::Chacha20Poly1305 => &CHACHA20_POLY1305,
        }
    }

    fn cipher_tag(&self) -> u8 {
        match self.cipher {
            SymmetricCipher::Aes256Gcm => 0,
            SymmetricCipher::Chacha20Poly1305 => 1,
        }
    }

    fn aad(
        header: &[u8; KEY_ID_LEN + 1],
        storage_key: &[u8],
    ) -> Aad<TinyVec<[u8; AAD_INLINE_LEN]>> {
        let mut aad = TinyVec::with_capacity(header.len() + storage_key.len());
        aad.extend_from_slice(header);
        aad.extend_from_slice(storage_key);
        Aad::from(aad)
    }

    #[cold]
    fn crypto_error(step: &'static str) -> trc::Error {
        trc::StoreEvent::CryptoError
            .into_err()
            .details(step)
            .caused_by(trc::location!())
    }
}

impl BlobKeyError {
    pub fn message(self) -> &'static str {
        match self {
            BlobKeyError::InvalidEncoding => "Symmetric key is not valid base64",
            BlobKeyError::InvalidLength => "Symmetric key must decode to exactly 32 bytes",
        }
    }
}

impl BlobKeyring {
    pub fn new(mut keys: Vec<Arc<BlobKey>>) -> Self {
        keys.sort_unstable_by_key(|key| key.id);
        keys.dedup_by_key(|key| key.id);
        BlobKeyring(keys.into())
    }

    pub fn get(&self, id: u32) -> Option<&Arc<BlobKey>> {
        self.0
            .binary_search_by_key(&id, |key| key.id)
            .ok()
            .and_then(|idx| self.0.get(idx))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
