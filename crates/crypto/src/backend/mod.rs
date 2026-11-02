/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod aes;
pub(crate) mod agree;
pub(crate) mod base64;
pub(crate) mod crc24;
pub(crate) mod ed448;
pub(crate) mod hash;
pub(crate) mod kdf;
pub(crate) mod kem;
pub(crate) mod ocb;
pub(crate) mod rng;
pub(crate) mod rsa;
pub(crate) mod symmetric;
pub(crate) mod verify;

pub(crate) const NATIVE_KEY_OVERHEAD: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveError {
    Random,
    InvalidKeyLength,
    InvalidLength,
    InvalidPublicKey,
    KeyAgreement,
    Encryption,
    UnsupportedAlgorithm,
    BadSignature,
}
