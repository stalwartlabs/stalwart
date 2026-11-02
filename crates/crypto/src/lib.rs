/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![deny(rust_2018_idioms)]

pub(crate) mod backend;
pub(crate) mod cms;
pub(crate) mod der;
pub mod error;
pub mod harvest;
pub mod mime;
pub(crate) mod pgp;
pub mod types;
pub mod x509;

use mail_parser::Message;

pub use error::{ChainError, CrlError, EncryptError, KeyError, ProfileError, VerifyError};
pub use harvest::{
    HarvestSource, HarvestedKey, SignatureCheck,
    autocrypt::{AutocryptHeader, parse_autocrypt},
    harvest, verify_pgp_signature,
};
pub use mime::protection::{Protection, is_ciphertext, is_encrypted_media, protection};
pub use types::{
    AddressKey, EcdhWrapParameters, EncryptOptions, EncryptWarning, Encrypted, Fingerprint,
    HeaderProtection, KeyCapabilities, KeyCapability, KeyKind, KeyWarning, ParsedKeys, Profile,
    RecipientIds, RecipientSet, SmimeCapabilities, SmimeCipher,
};

pub use pgp::EXPIRES_SOON_SECS;
pub use x509::{
    chain::{ChainStatus, ChainVerdict, TrustContext, verify_smime_chain},
    crl::{Crl, parse_crl},
    trust::{TrustAnchor, TrustAnchors},
};

use backend::rng::{Rng, SystemRng};
use mime::entity::Entity;
use types::Recipients;

pub fn parse_public_keys(input: &[u8], now: u64) -> Result<ParsedKeys, KeyError> {
    let trimmed = input.trim_ascii();
    match trimmed.first() {
        None => Err(KeyError::Empty),
        Some(b'-') if !trimmed.starts_with(b"-----BEGIN PGP ") => {
            x509::recipient::parse_public_keys(input, now)
        }
        Some(0x30) => x509::recipient::parse_public_keys(input, now),
        Some(_) => pgp::parse_public_keys(input, now),
    }
}

pub fn check_profile(set: &RecipientSet, profile: Profile) -> Result<(), ProfileError> {
    match set.0.as_ref() {
        Recipients::OpenPgp(certs) => pgp::encrypt::check_profile(certs, profile),
        Recipients::Smime(recipients) => cms::envelope::check_profile(recipients, profile),
    }
}

pub fn split_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>, KeyError> {
    x509::recipient::split_certificates(input)
}

pub fn parse_public_keys_for(
    input: &[u8],
    address: &str,
    now: u64,
) -> Result<Vec<AddressKey>, KeyError> {
    pgp::parse_public_keys_for(input, address, now)
}

pub fn revoked_fingerprints(input: &[u8], now: u64) -> Vec<Fingerprint> {
    pgp::revoked_fingerprints(input, now)
}

pub fn certifies(old_key: &[u8], new_key: &[u8], address: &str, now: u64) -> bool {
    pgp::certifies(old_key, new_key, address, now)
}

impl RecipientSet {
    pub fn encrypt(
        &self,
        message: &Message<'_>,
        options: &EncryptOptions,
    ) -> Result<Encrypted, EncryptError> {
        encrypt_with(message, self, options, &mut SystemRng::new())
    }
}

pub(crate) fn encrypt_with(
    message: &Message<'_>,
    recipients: &RecipientSet,
    options: &EncryptOptions,
    rng: &mut impl Rng,
) -> Result<Encrypted, EncryptError> {
    let entity = Entity::new(message, options.header_protection)?;
    let (message, warning) = match recipients.0.as_ref() {
        Recipients::OpenPgp(certs) => (pgp::encrypt::encrypt(&entity, certs, options, rng)?, None),
        Recipients::Smime(recipients) => cms::envelope::encrypt(&entity, recipients, options, rng)?,
    };
    Ok(Encrypted { message, warning })
}

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/crypto/src/test_support.rs"]
pub mod test_support;
