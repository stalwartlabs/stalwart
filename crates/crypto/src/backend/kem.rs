/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::kem::{Ciphertext, EncapsulationKey, ML_KEM_512, ML_KEM_768, ML_KEM_1024};
use zeroize::Zeroizing;

use super::PrimitiveError;

pub(crate) const ML_KEM_SHARED_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlKem {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKem {
    pub(crate) fn name(self) -> &'static str {
        match self {
            MlKem::MlKem512 => "ML-KEM-512",
            MlKem::MlKem768 => "ML-KEM-768",
            MlKem::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub const fn public_len(self) -> usize {
        match self {
            MlKem::MlKem512 => 800,
            MlKem::MlKem768 => 1184,
            MlKem::MlKem1024 => 1568,
        }
    }

    pub const fn ciphertext_len(self) -> usize {
        match self {
            MlKem::MlKem512 => 768,
            MlKem::MlKem768 => 1088,
            MlKem::MlKem1024 => 1568,
        }
    }
}

pub(crate) struct MlKemPublicKey {
    kem: MlKem,
    key: EncapsulationKey,
}

pub(crate) struct Encapsulation {
    ciphertext: Ciphertext<'static>,
    shared: Zeroizing<[u8; ML_KEM_SHARED_LEN]>,
}

impl Encapsulation {
    pub(crate) fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_ref()
    }

    pub(crate) fn shared(&self) -> &[u8; ML_KEM_SHARED_LEN] {
        &self.shared
    }
}

impl MlKemPublicKey {
    pub(crate) fn new(kem: MlKem, bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let alg = match kem {
            MlKem::MlKem512 => &ML_KEM_512,
            MlKem::MlKem768 => &ML_KEM_768,
            MlKem::MlKem1024 => &ML_KEM_1024,
        };
        EncapsulationKey::new(alg, bytes)
            .map(|key| MlKemPublicKey { kem, key })
            .map_err(|_| PrimitiveError::InvalidPublicKey)
    }

    pub(crate) fn kem(&self) -> MlKem {
        self.kem
    }

    pub(crate) fn heap_size(&self) -> usize {
        super::NATIVE_KEY_OVERHEAD + 2 * self.kem.public_len()
    }

    pub(crate) fn encapsulate(&self) -> Result<Encapsulation, PrimitiveError> {
        let (ciphertext, secret) = self
            .key
            .encapsulate()
            .map_err(|_| PrimitiveError::Encryption)?;
        let mut shared = Zeroizing::new([0u8; ML_KEM_SHARED_LEN]);
        if secret.as_ref().len() != ML_KEM_SHARED_LEN
            || ciphertext.as_ref().len() != self.kem.ciphertext_len()
        {
            return Err(PrimitiveError::Encryption);
        }
        shared.copy_from_slice(secret.as_ref());
        Ok(Encapsulation { ciphertext, shared })
    }
}
