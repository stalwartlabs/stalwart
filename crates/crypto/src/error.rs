/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use crate::{backend::PrimitiveError, der::DerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Empty,
    MalformedArmor,
    MalformedPacket,
    MalformedCertificate,
    MixedKeyKinds,
    SecretKey,
    PrivateKey,
    Pkcs12,
    UnsupportedKeyVersion,
    UnsupportedPrimaryAlgorithm,
    UnsupportedKeyAlgorithm,
    Elgamal,
    Brainpool,
    WeakRsa,
    NoValidSelfSignature,
    Revoked,
    Expired,
    NotYetValid,
    NoEncryptionKey,
    SignatureOnlyCertificate,
    EncipherOnlyCertificate,
    NoEmailProtection,
    InvalidPublicKey,
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    NoPostQuantumKey,
    IncompatibleRecipientVersions,
    NoAeadSupport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptError {
    NoRecipients,
    Profile(ProfileError),
    Primitive(PrimitiveError),
    MessageTooLarge,
    MalformedMessage,
}

impl From<PrimitiveError> for EncryptError {
    fn from(err: PrimitiveError) -> Self {
        EncryptError::Primitive(err)
    }
}

impl From<ProfileError> for EncryptError {
    fn from(err: ProfileError) -> Self {
        EncryptError::Profile(err)
    }
}

impl From<DerError> for KeyError {
    fn from(_: DerError) -> Self {
        KeyError::MalformedCertificate
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlError {
    Malformed,
    TooLarge,
    DeltaCrl,
    UnsupportedScope,
    UnsupportedCriticalExtension,
    Sha1Signature,
}

impl From<DerError> for CrlError {
    fn from(_: DerError) -> Self {
        CrlError::Malformed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    MalformedCertificate,
    UnsupportedCriticalExtension,
    NoEmailProtection,
    TooManyAnchors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    NotSigned,
    Malformed,
    UnknownSigner,
    UnsupportedAlgorithm,
    BadSignature,
    InvalidCertificate(KeyError),
}

impl From<DerError> for VerifyError {
    fn from(_: DerError) -> Self {
        VerifyError::Malformed
    }
}

macro_rules! unit_variant_names {
    ($ty:ty { $($variant:ident),* $(,)? }) => {
        impl $ty {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant),)*
                }
            }
        }
    };
}

unit_variant_names!(KeyError {
    Empty,
    MalformedArmor,
    MalformedPacket,
    MalformedCertificate,
    MixedKeyKinds,
    SecretKey,
    PrivateKey,
    Pkcs12,
    UnsupportedKeyVersion,
    UnsupportedPrimaryAlgorithm,
    UnsupportedKeyAlgorithm,
    Elgamal,
    Brainpool,
    WeakRsa,
    NoValidSelfSignature,
    Revoked,
    Expired,
    NotYetValid,
    NoEncryptionKey,
    SignatureOnlyCertificate,
    EncipherOnlyCertificate,
    NoEmailProtection,
    InvalidPublicKey,
    TooLarge,
});

unit_variant_names!(ProfileError {
    NoPostQuantumKey,
    IncompatibleRecipientVersions,
    NoAeadSupport,
});

unit_variant_names!(PrimitiveError {
    Random,
    InvalidKeyLength,
    InvalidLength,
    InvalidPublicKey,
    KeyAgreement,
    Encryption,
    UnsupportedAlgorithm,
    BadSignature,
});

impl EncryptError {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptError::NoRecipients => "NoRecipients",
            EncryptError::Profile(err) => err.as_str(),
            EncryptError::Primitive(err) => err.as_str(),
            EncryptError::MessageTooLarge => "MessageTooLarge",
            EncryptError::MalformedMessage => "MalformedMessage",
        }
    }
}

impl KeyError {
    pub fn description(&self) -> &'static str {
        match self {
            KeyError::Empty => "No valid public key found.",
            KeyError::MalformedArmor => "The ASCII armor or PEM encoding is malformed.",
            KeyError::MalformedPacket => "The OpenPGP key data is malformed.",
            KeyError::MalformedCertificate => "The X.509 certificate is malformed.",
            KeyError::MixedKeyKinds => "Cannot mix OpenPGP keys and S/MIME certificates.",
            KeyError::SecretKey | KeyError::PrivateKey | KeyError::Pkcs12 => {
                "Secret key material is not accepted, upload the public key only."
            }
            KeyError::UnsupportedKeyVersion => {
                "Unsupported OpenPGP key version, only v4 and v6 keys are supported."
            }
            KeyError::UnsupportedPrimaryAlgorithm => "The primary key algorithm is not supported.",
            KeyError::UnsupportedKeyAlgorithm => "The encryption key algorithm is not supported.",
            KeyError::Elgamal => "ElGamal keys are not supported.",
            KeyError::Brainpool => "Brainpool curves are not supported.",
            KeyError::WeakRsa => "RSA keys must be between 2048 and 8192 bits long.",
            KeyError::NoValidSelfSignature => "The key has no valid self-signature.",
            KeyError::Revoked => "The key or certificate has been revoked.",
            KeyError::Expired => "The key or certificate has expired.",
            KeyError::NotYetValid => "The certificate is not valid yet.",
            KeyError::NoEncryptionKey => "The key contains no key usable for encryption.",
            KeyError::SignatureOnlyCertificate => {
                "Signature-only certificate cannot be used for encryption."
            }
            KeyError::EncipherOnlyCertificate => {
                "Encipher-only certificates cannot be used for encryption."
            }
            KeyError::NoEmailProtection => {
                "The certificate is not valid for email protection (extended key usage)."
            }
            KeyError::InvalidPublicKey => "The public key is invalid.",
            KeyError::TooLarge => "The key is too large.",
        }
    }
}

impl ProfileError {
    pub fn description(&self) -> &'static str {
        match self {
            ProfileError::NoPostQuantumKey => {
                "The post-quantum profile requires a key with a post-quantum (ML-KEM) encryption key."
            }
            ProfileError::IncompatibleRecipientVersions => {
                "The key mixes OpenPGP key versions that cannot be used together with this profile."
            }
            ProfileError::NoAeadSupport => {
                "The key does not support the authenticated encryption this profile requires."
            }
        }
    }
}

macro_rules! display_as_debug {
    ($($ty:ty),*) => {
        $(impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(self, f)
            }
        }

        impl std::error::Error for $ty {})*
    };
}

display_as_debug!(
    KeyError,
    ProfileError,
    EncryptError,
    CrlError,
    ChainError,
    VerifyError
);
