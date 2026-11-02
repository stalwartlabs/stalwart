/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::rsa::{
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
    OaepAlgorithm, OaepPublicEncryptingKey, Pkcs1PublicEncryptingKey, PublicEncryptingKey,
};

use super::PrimitiveError;
use crate::der::{
    oid, tag,
    writer::{
        bit_string_len, rsa_public_key_len, tlv_len, write_bit_string_header, write_header,
        write_rsa_public_key, write_tlv,
    },
};

pub(crate) const MIN_RSA_BITS: usize = 2048;
pub(crate) const MAX_RSA_BITS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OaepHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl OaepHash {
    fn algorithm(self) -> &'static OaepAlgorithm {
        match self {
            OaepHash::Sha1 => &OAEP_SHA1_MGF1SHA1,
            OaepHash::Sha256 => &OAEP_SHA256_MGF1SHA256,
            OaepHash::Sha384 => &OAEP_SHA384_MGF1SHA384,
            OaepHash::Sha512 => &OAEP_SHA512_MGF1SHA512,
        }
    }
}

#[derive(Clone)]
pub(crate) struct RsaPublicKey(PublicEncryptingKey);

impl RsaPublicKey {
    pub(crate) fn from_spki(spki: &[u8]) -> Result<Self, PrimitiveError> {
        PublicEncryptingKey::from_der(spki)
            .map(RsaPublicKey)
            .map_err(|_| PrimitiveError::InvalidPublicKey)
    }

    pub(crate) fn from_components(n: &[u8], e: &[u8]) -> Result<Self, PrimitiveError> {
        let key_len = rsa_public_key_len(n, e);
        let algorithm_len = tlv_len(tlv_len(oid::RSA_ENCRYPTION.len()) + tlv_len(0));
        let spki_content_len = algorithm_len + bit_string_len(key_len);
        let mut spki = Vec::with_capacity(tlv_len(spki_content_len));
        write_header(&mut spki, tag::SEQUENCE, spki_content_len);
        write_header(&mut spki, tag::SEQUENCE, algorithm_len - 2);
        write_tlv(&mut spki, tag::OID, oid::RSA_ENCRYPTION);
        write_tlv(&mut spki, tag::NULL, &[]);
        write_bit_string_header(&mut spki, key_len);
        write_rsa_public_key(&mut spki, n, e);
        Self::from_spki(&spki)
    }

    pub(crate) fn bits(&self) -> usize {
        self.0.key_size_bits()
    }

    pub(crate) fn ciphertext_len(&self) -> usize {
        self.0.key_size_bytes()
    }

    pub(crate) fn heap_size(&self) -> usize {
        super::NATIVE_KEY_OVERHEAD + 3 * self.0.key_size_bytes()
    }

    pub(crate) fn encrypt_pkcs1(
        &self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), PrimitiveError> {
        let key = Pkcs1PublicEncryptingKey::new(self.0.clone())
            .map_err(|_| PrimitiveError::InvalidPublicKey)?;
        let written = key
            .encrypt(plaintext, out)
            .map_err(|_| PrimitiveError::Encryption)?
            .len();
        if written == out.len() {
            Ok(())
        } else {
            Err(PrimitiveError::Encryption)
        }
    }

    pub(crate) fn encrypt_oaep(
        &self,
        hash: OaepHash,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), PrimitiveError> {
        let key = OaepPublicEncryptingKey::new(self.0.clone())
            .map_err(|_| PrimitiveError::InvalidPublicKey)?;
        let written = key
            .encrypt(hash.algorithm(), plaintext, out, None)
            .map_err(|_| PrimitiveError::Encryption)?
            .len();
        if written == out.len() {
            Ok(())
        } else {
            Err(PrimitiveError::Encryption)
        }
    }
}
