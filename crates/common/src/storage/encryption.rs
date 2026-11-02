/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crypto::{
    EcdhWrapParameters, EncryptError, EncryptOptions, Encrypted, HeaderProtection, KeyError,
    ParsedKeys, RecipientSet,
};
use encodify::base64::LENIENT;
use mail_parser::Message;
use registry::schema::{
    enums::HeaderProtection as RegistryHeaderProtection,
    structs::{EncryptionSettings, PublicKey},
};
use tokio::runtime::{Handle, RuntimeFlavor};
use utils::cache::CacheItemWeight;

const ENCRYPT_INLINE_MAX: usize = 512 * 1024;

#[derive(Debug)]
pub struct AccountEncryption {
    pub keys: EncryptionKeys,
    pub options: EncryptOptions,
    pub train_spam: bool,
    pub encrypt_on_append: bool,
}

#[derive(Debug)]
pub enum EncryptionKeys {
    Usable {
        recipients: RecipientSet,
        expires_at: Option<u64>,
    },
    Unusable(UnusableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnusableReason {
    KeyNotFound,
    Invalid(KeyError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Expired,
    Unusable(UnusableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptFailure {
    Skipped(SkipReason),
    Error(EncryptError),
}

pub trait RecipientEncrypt {
    fn encrypt_on_runtime(
        &self,
        message: &Message<'_>,
        options: &EncryptOptions,
    ) -> Result<Encrypted, EncryptError>;
}

pub trait PublicKeyParse {
    fn parse_keys(&self, now: u64) -> Result<ParsedKeys, KeyError>;
}

pub trait ToCrypto {
    type Output;

    fn to_crypto(self) -> Self::Output;
}

impl AccountEncryption {
    pub fn build(settings: &EncryptionSettings, public_key: Option<&PublicKey>, now: u64) -> Self {
        let mut options = EncryptOptions {
            header_protection: settings.header_protection.to_crypto(),
            ..Default::default()
        };
        let keys = match public_key {
            Some(public_key) => match public_key.parse_keys(now).map_err(UnusableReason::Invalid) {
                Ok(parsed) => {
                    options.profile = parsed
                        .set
                        .inferred_profile(public_key.authenticated_encryption);
                    if !public_key.strict_key_wrap_encoding {
                        options.ecdh_wrap_parameters = EcdhWrapParameters::Null;
                    }
                    EncryptionKeys::Usable {
                        recipients: parsed.set,
                        expires_at: parsed.expires_at,
                    }
                }
                Err(reason) => EncryptionKeys::Unusable(reason),
            },
            None => EncryptionKeys::Unusable(UnusableReason::KeyNotFound),
        };
        AccountEncryption {
            keys,
            options,
            train_spam: settings.allow_spam_training,
            encrypt_on_append: settings.encrypt_on_append,
        }
    }

    pub fn recipients(&self, now: u64) -> Result<&RecipientSet, SkipReason> {
        match &self.keys {
            EncryptionKeys::Usable {
                recipients,
                expires_at,
            } => {
                if expires_at.is_none_or(|expires_at| expires_at > now) {
                    Ok(recipients)
                } else {
                    Err(SkipReason::Expired)
                }
            }
            EncryptionKeys::Unusable(UnusableReason::Invalid(KeyError::Expired)) => {
                Err(SkipReason::Expired)
            }
            EncryptionKeys::Unusable(reason) => Err(SkipReason::Unusable(*reason)),
        }
    }

    pub fn encrypt(&self, message: &Message<'_>, now: u64) -> Result<Encrypted, EncryptFailure> {
        self.recipients(now)
            .map_err(EncryptFailure::Skipped)?
            .encrypt_on_runtime(message, &self.options)
            .map_err(EncryptFailure::Error)
    }
}

impl RecipientEncrypt for RecipientSet {
    fn encrypt_on_runtime(
        &self,
        message: &Message<'_>,
        options: &EncryptOptions,
    ) -> Result<Encrypted, EncryptError> {
        if message.raw().len() >= ENCRYPT_INLINE_MAX
            && matches!(
                Handle::try_current().map(|handle| handle.runtime_flavor()),
                Ok(RuntimeFlavor::MultiThread)
            )
        {
            tokio::task::block_in_place(|| self.encrypt(message, options))
        } else {
            self.encrypt(message, options)
        }
    }
}

impl UnusableReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            UnusableReason::KeyNotFound => "KeyNotFound",
            UnusableReason::Invalid(err) => err.as_str(),
        }
    }
}

impl SkipReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            SkipReason::Expired => "Expired",
            SkipReason::Unusable(reason) => reason.as_str(),
        }
    }
}

impl CacheItemWeight for AccountEncryption {
    fn weight(&self) -> u64 {
        (size_of::<AccountEncryption>()
            + match &self.keys {
                EncryptionKeys::Usable { recipients, .. } => recipients.heap_size(),
                EncryptionKeys::Unusable(_) => 0,
            }) as u64
    }
}

impl PublicKeyParse for PublicKey {
    fn parse_keys(&self, now: u64) -> Result<ParsedKeys, KeyError> {
        parse_key_text(&self.key, now)
    }
}

pub(crate) fn parse_key_text(key: &str, now: u64) -> Result<ParsedKeys, KeyError> {
    let key = key.trim_ascii();
    if !key.starts_with("-----")
        && let Ok(binary) = LENIENT.decode(key.as_bytes())
        && !binary.is_empty()
    {
        crypto::parse_public_keys(&binary, now)
    } else {
        crypto::parse_public_keys(key.as_bytes(), now)
    }
}

impl ToCrypto for RegistryHeaderProtection {
    type Output = HeaderProtection;

    fn to_crypto(self) -> HeaderProtection {
        match self {
            RegistryHeaderProtection::None => HeaderProtection::None,
            RegistryHeaderProtection::NoConfidentiality | RegistryHeaderProtection::Baseline => {
                HeaderProtection::Full
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/storage/encryption/tests.rs"]
mod tests;
