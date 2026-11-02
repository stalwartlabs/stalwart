/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::{
    pgp::{cert::PgpCert, key::KeyVersion},
    x509::recipient::SmimeRecipient,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    OpenPgp,
    Smime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    V4([u8; 20]),
    V6([u8; 32]),
    X509Sha256([u8; 32]),
}

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Fingerprint::V4(fp) => fp,
            Fingerprint::V6(fp) | Fingerprint::X509Sha256(fp) => fp,
        }
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let bytes = self.as_bytes();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push(char::from(HEX[usize::from(byte >> 4)]));
            hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        hex
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyCapability {
    Aead,
    PostQuantum,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct KeyCapabilities(u8);

impl KeyCapabilities {
    const fn bit(capability: KeyCapability) -> u8 {
        match capability {
            KeyCapability::Aead => 1,
            KeyCapability::PostQuantum => 2,
        }
    }

    pub fn contains(self, capability: KeyCapability) -> bool {
        self.0 & Self::bit(capability) != 0
    }

    pub(crate) fn insert(&mut self, capability: KeyCapability) {
        self.0 |= Self::bit(capability);
    }

    pub fn iter(self) -> impl Iterator<Item = KeyCapability> {
        [KeyCapability::Aead, KeyCapability::PostQuantum]
            .into_iter()
            .filter(move |c| self.contains(*c))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyWarning {
    WeakRsa,
    NoKnownDecryptor,
    PostQuantumOnly,
    ExpiresSoon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmimeCipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmimeCapabilities {
    pub ciphers: Vec<SmimeCipher>,
    pub rsaes_oaep: bool,
}

#[derive(Debug, Clone)]
pub struct AddressKey {
    pub parsed: ParsedKeys,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedKeys {
    pub kind: KeyKind,
    pub set: RecipientSet,
    pub addresses: Vec<Box<str>>,
    pub expires_at: Option<u64>,
    pub fingerprints: Vec<Fingerprint>,
    pub capabilities: KeyCapabilities,
    pub warnings: Vec<KeyWarning>,
    pub smime_capabilities: Option<SmimeCapabilities>,
}

#[derive(Clone)]
pub struct RecipientSet(pub(crate) Arc<Recipients>);

pub(crate) enum Recipients {
    OpenPgp(Box<[PgpCert]>),
    Smime(Box<[SmimeRecipient]>),
}

impl RecipientSet {
    pub fn kind(&self) -> KeyKind {
        match self.0.as_ref() {
            Recipients::OpenPgp(_) => KeyKind::OpenPgp,
            Recipients::Smime(_) => KeyKind::Smime,
        }
    }

    pub fn inferred_profile(&self, authenticated_encryption: bool) -> Profile {
        if crate::check_profile(self, Profile::PostQuantum).is_ok() {
            Profile::PostQuantum
        } else if authenticated_encryption && self.kind() == KeyKind::Smime {
            Profile::Modern
        } else {
            Profile::Compatible
        }
    }

    pub fn key_type(&self) -> String {
        let (prefix, algorithms): (&str, Vec<String>) = match self.0.as_ref() {
            Recipients::OpenPgp(certs) => (
                match certs
                    .first()
                    .and_then(|cert| cert.keys.first())
                    .map(|key| key.version)
                {
                    Some(KeyVersion::V6) => "OpenPGP v6",
                    _ => "OpenPGP v4",
                },
                certs
                    .iter()
                    .flat_map(|cert| cert.keys.iter())
                    .map(|key| key.algorithm_name())
                    .collect(),
            ),
            Recipients::Smime(recipients) => (
                "S/MIME",
                recipients
                    .iter()
                    .map(|recipient| recipient.key.algorithm_name())
                    .collect(),
            ),
        };
        let mut key_type = String::with_capacity(32);
        key_type.push_str(prefix);
        key_type.push_str(": ");
        for (idx, algorithm) in algorithms.iter().enumerate() {
            if !algorithms[..idx].contains(algorithm) {
                if !key_type.ends_with(": ") {
                    key_type.push_str(", ");
                }
                key_type.push_str(algorithm);
            }
        }
        key_type
    }

    pub fn heap_size(&self) -> usize {
        size_of::<Recipients>()
            + match self.0.as_ref() {
                Recipients::OpenPgp(certs) => certs
                    .iter()
                    .map(|cert| size_of::<PgpCert>() + cert.heap_size())
                    .sum::<usize>(),
                Recipients::Smime(recipients) => recipients
                    .iter()
                    .map(|recipient| size_of::<SmimeRecipient>() + recipient.heap_size())
                    .sum::<usize>(),
            }
    }
}

impl std::fmt::Debug for RecipientSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = match self.0.as_ref() {
            Recipients::OpenPgp(certs) => certs.len(),
            Recipients::Smime(certs) => certs.len(),
        };
        f.debug_struct("RecipientSet")
            .field("kind", &self.kind())
            .field("certificates", &count)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Profile {
    #[default]
    Compatible,
    Modern,
    PostQuantum,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum HeaderProtection {
    #[default]
    None,
    Full,
    Baseline,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum EcdhWrapParameters {
    #[default]
    Absent,
    Null,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum RecipientIds {
    #[default]
    Real,
    Anonymous,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EncryptOptions {
    pub profile: Profile,
    pub header_protection: HeaderProtection,
    pub ecdh_wrap_parameters: EcdhWrapParameters,
    pub recipient_ids: RecipientIds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptWarning {
    ExceedsNssLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub message: Vec<u8>,
    pub warning: Option<EncryptWarning>,
}
