/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod aes;
mod derive;
mod key;
mod legacy;
mod modern;
mod rc4;

#[cfg(test)]
mod tests;

use aws_lc_rs::cipher::DecryptingKey;

use self::aes::AesKind;
use self::key::FileKey;
use self::rc4::Rc4;

const STANDARD_FILTER: &[u8] = b"Standard";
const AES_SALT: &[u8] = b"sAlT";
const AES128_KEY_LEN: usize = 16;
const OBJECT_KEY_MAX_LEN: usize = 16;
const OBJECT_KEY_EXTRA: usize = 5;
const UNPUBLISHED_V3: i64 = 3;
const MODERN_V: i64 = 5;
const PADDED_KEY_V: i64 = 4;
const PADDED_KEY_R: i64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptMethod {
    Identity,
    Rc4,
    AesV2,
    AesV3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    String,
    Stream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptError {
    UnsupportedHandler,
    PasswordRequired,
    Malformed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EncryptDict<'a> {
    pub(crate) filter: &'a [u8],
    pub(crate) v: i64,
    pub(crate) r: i64,
    pub(crate) length: Option<i64>,
    pub(crate) o: &'a [u8],
    pub(crate) u: &'a [u8],
    pub(crate) oe: &'a [u8],
    pub(crate) ue: &'a [u8],
    pub(crate) p: i64,
    pub(crate) encrypt_metadata: bool,
    pub(crate) stream_method: Option<CryptMethod>,
    pub(crate) string_method: Option<CryptMethod>,
    pub(crate) crypt_filter_length: Option<i64>,
    pub(crate) id0: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct Decryptor {
    key: FileKey,
    aes256: Option<DecryptingKey>,
    stream_method: CryptMethod,
    string_method: CryptMethod,
    #[cfg(test)]
    encrypt_metadata: bool,
}

impl Decryptor {
    pub(crate) fn new(dict: &EncryptDict<'_>) -> Result<Self, CryptError> {
        Self::with_password(dict, &[])
    }

    pub(crate) fn with_password(
        dict: &EncryptDict<'_>,
        password: &[u8],
    ) -> Result<Self, CryptError> {
        if dict.filter != STANDARD_FILTER || dict.v == UNPUBLISHED_V3 {
            return Err(CryptError::UnsupportedHandler);
        }
        let version = match (dict.v, dict.r) {
            (1 | 2 | 4, 2..=4) => dict.v,
            (1 | 2 | 4 | 5, 5 | 6) => MODERN_V,
            _ => return Err(CryptError::Malformed),
        };
        let (string_method, stream_method) = resolve_methods(version, dict)?;
        if string_method == CryptMethod::Identity && stream_method == CryptMethod::Identity {
            return Ok(Decryptor {
                key: FileKey::default(),
                aes256: None,
                stream_method,
                string_method,
                #[cfg(test)]
                encrypt_metadata: dict.encrypt_metadata,
            });
        }
        let mut key = if version == MODERN_V {
            derive::modern_key(dict, password)?
        } else {
            derive::legacy_key(dict, password)?
        };
        if dict.v == PADDED_KEY_V || dict.r == PADDED_KEY_R {
            key.zero_extend(AES128_KEY_LEN);
        }
        let aes256 = (string_method == CryptMethod::AesV3 || stream_method == CryptMethod::AesV3)
            .then(|| AesKind::Aes256.decrypting_key(key.as_slice()))
            .flatten();
        Ok(Decryptor {
            key,
            aes256,
            stream_method,
            string_method,
            #[cfg(test)]
            encrypt_metadata: dict.encrypt_metadata || version < PADDED_KEY_V,
        })
    }

    #[cfg(test)]
    pub(crate) fn encrypts_metadata(&self) -> bool {
        self.encrypt_metadata
    }

    pub(crate) fn method(&self, target: Target) -> CryptMethod {
        match target {
            Target::String => self.string_method,
            Target::Stream => self.stream_method,
        }
    }

    pub(crate) fn decrypt(
        &self,
        target: Target,
        object: u32,
        generation: u16,
        data: &[u8],
        out: &mut Vec<u8>,
    ) {
        match self.method(target) {
            CryptMethod::Identity => out.extend_from_slice(data),
            CryptMethod::Rc4 => {
                let key = self.object_key(object, generation, false);
                Rc4::new(key.as_slice()).apply_into(data, out);
            }
            CryptMethod::AesV2 => {
                let key = self.object_key(object, generation, true);
                if let Some(cipher) = AesKind::Aes128.decrypting_key(key.as_slice()) {
                    aes::decrypt_with_iv(&cipher, data, out);
                }
            }
            CryptMethod::AesV3 => {
                if let Some(cipher) = &self.aes256 {
                    aes::decrypt_with_iv(cipher, data, out);
                }
            }
        }
    }

    fn object_key(&self, object: u32, generation: u16, aes: bool) -> FileKey {
        let mut context = md5::Context::new();
        context.consume(self.key.as_slice());
        context.consume(object.to_le_bytes().get(..3).unwrap_or_default());
        context.consume(generation.to_le_bytes());
        if aes {
            context.consume(AES_SALT);
        }
        let hash = context.finalize().0;
        let len = (self.key.len() + OBJECT_KEY_EXTRA).min(OBJECT_KEY_MAX_LEN);
        hash.get(..len)
            .and_then(FileKey::from_slice)
            .unwrap_or_default()
    }
}

fn resolve_methods(
    version: i64,
    dict: &EncryptDict<'_>,
) -> Result<(CryptMethod, CryptMethod), CryptError> {
    match version {
        1 | 2 => Ok((CryptMethod::Rc4, CryptMethod::Rc4)),
        4 => {
            let resolve = |method: Option<CryptMethod>| match method {
                Some(CryptMethod::AesV3) => Err(CryptError::Malformed),
                method => Ok(method.unwrap_or(CryptMethod::Identity)),
            };
            Ok((resolve(dict.string_method)?, resolve(dict.stream_method)?))
        }
        5 => {
            let resolve = |method: Option<CryptMethod>| match method {
                None | Some(CryptMethod::Identity) => CryptMethod::Identity,
                Some(_) => CryptMethod::AesV3,
            };
            Ok((resolve(dict.string_method), resolve(dict.stream_method)))
        }
        _ => Err(CryptError::Malformed),
    }
}
