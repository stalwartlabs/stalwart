/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordHasher;
use argon2::PasswordVerifier as _;
use compact_str::CompactString;
use encodify::base64::{Base64, LENIENT, Padding, STANDARD};
use pbkdf2::Pbkdf2;
use pwhash::{bcrypt, bsdi_crypt, md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};
use registry::schema::enums::PasswordHashAlgorithm;
use scrypt::Scrypt;
use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;
use totp_rs::Totp;

use super::verifier::PasswordVerifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVerificationResult {
    Valid,
    Invalid,
    MissingMfaToken,
}

pub async fn verify_mfa_secret_hash(
    verifier: &PasswordVerifier,
    totp_uri: Option<&str>,
    totp_token: Option<&str>,
    hashed_secret: &str,
    secret: &str,
) -> trc::Result<SecretVerificationResult> {
    if let Some(totp_uri) = totp_uri {
        if let Some(totp_token) = totp_token {
            let result = verify_secret_hash(verifier, hashed_secret, secret.as_bytes()).await?
                && Totp::from_url(totp_uri)
                    .map_err(|err| trc::AuthEvent::Error.reason(err))?
                    .check_current(totp_token)
                    .is_some();
            Ok(if result {
                SecretVerificationResult::Valid
            } else {
                SecretVerificationResult::Invalid
            })
        } else if !hashed_secret.is_empty()
            && !secret.is_empty()
            && verify_secret_hash(verifier, hashed_secret, secret.as_bytes()).await?
        {
            // Only let the client know if the TOTP code is missing
            // if the password is correct

            Ok(SecretVerificationResult::MissingMfaToken)
        } else {
            Ok(SecretVerificationResult::Invalid)
        }
    } else if !hashed_secret.is_empty() && !secret.is_empty() {
        if verify_secret_hash(verifier, hashed_secret, secret.as_bytes()).await? {
            Ok(SecretVerificationResult::Valid)
        } else {
            Ok(SecretVerificationResult::Invalid)
        }
    } else {
        Ok(SecretVerificationResult::Invalid)
    }
}

#[derive(Debug, Clone, Copy)]
enum CryptScheme {
    Argon2,
    Pbkdf2,
    Scrypt,
    Bcrypt,
    Sha512Crypt,
    Sha256Crypt,
    Sha1Crypt,
    Md5Crypt,
    BsdiCrypt,
    UnixCrypt,
}

impl CryptScheme {
    fn from_prefix(hashed_secret: &str) -> Option<Self> {
        if hashed_secret.starts_with("$argon2") {
            Some(CryptScheme::Argon2)
        } else if hashed_secret.starts_with("$pbkdf2") {
            Some(CryptScheme::Pbkdf2)
        } else if hashed_secret.starts_with("$scrypt") {
            Some(CryptScheme::Scrypt)
        } else if hashed_secret.starts_with("$2") {
            Some(CryptScheme::Bcrypt)
        } else if hashed_secret.starts_with("$6$") {
            Some(CryptScheme::Sha512Crypt)
        } else if hashed_secret.starts_with("$5$") {
            Some(CryptScheme::Sha256Crypt)
        } else if hashed_secret.starts_with("$sha1") {
            Some(CryptScheme::Sha1Crypt)
        } else if hashed_secret.starts_with("$1") {
            Some(CryptScheme::Md5Crypt)
        } else {
            None
        }
    }

    fn verify(self, hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
        match self {
            CryptScheme::Argon2 | CryptScheme::Pbkdf2 | CryptScheme::Scrypt => {
                let hash = PasswordHash::new(hashed_secret)
                    .map_err(|err| trc::AuthEvent::Error.reason(err))?;
                Ok(match self {
                    CryptScheme::Argon2 => Argon2::default().verify_password(secret, &hash),
                    CryptScheme::Pbkdf2 => Pbkdf2::default().verify_password(secret, &hash),
                    _ => Scrypt::default().verify_password(secret, &hash),
                }
                .is_ok())
            }
            CryptScheme::Bcrypt => Ok(bcrypt::verify(secret, hashed_secret)),
            CryptScheme::Sha512Crypt => Ok(sha512_crypt::verify(secret, hashed_secret)),
            CryptScheme::Sha256Crypt => Ok(sha256_crypt::verify(secret, hashed_secret)),
            CryptScheme::Sha1Crypt => Ok(sha1_crypt::verify(secret, hashed_secret)),
            CryptScheme::Md5Crypt => Ok(md5_crypt::verify(secret, hashed_secret)),
            CryptScheme::BsdiCrypt => Ok(bsdi_crypt::verify(secret, hashed_secret)),
            CryptScheme::UnixCrypt => Ok(unix_crypt::verify(secret, hashed_secret)),
        }
    }

    async fn verify_blocking(
        self,
        verifier: &PasswordVerifier,
        hashed_secret: &str,
        secret: &[u8],
    ) -> trc::Result<bool> {
        let secret = secret.to_vec();
        let hashed_secret = hashed_secret.to_string();

        verifier
            .run_blocking(move || self.verify(&hashed_secret, &secret))
            .await?
    }
}

async fn verify_hash_prefix(
    verifier: &PasswordVerifier,
    hashed_secret: &str,
    secret: &[u8],
) -> trc::Result<bool> {
    match CryptScheme::from_prefix(hashed_secret) {
        Some(scheme) => {
            scheme
                .verify_blocking(verifier, hashed_secret, secret)
                .await
        }
        None => Err(unrecognized_hash_format()),
    }
}

#[cold]
fn unrecognized_hash_format() -> trc::Error {
    trc::AuthEvent::Error
        .into_err()
        .reason("Unrecognized password hash format")
}

fn digest_matches(digest: &[u8], encoded: &str) -> bool {
    let mut buf = [0u8; MAX_ENCODED_DIGEST_LEN];
    STANDARD
        .encode_slice(digest, &mut buf)
        .ok()
        .and_then(|len| buf.get(..len))
        .is_some_and(|expected| expected == encoded.as_bytes())
}

const MAX_ENCODED_DIGEST_LEN: usize = STANDARD.encoded_len(64);

const MAX_SECRET_LEN: usize = 1024;

pub async fn verify_secret_hash(
    verifier: &PasswordVerifier,
    hashed_secret: &str,
    secret: &[u8],
) -> trc::Result<bool> {
    if secret.len() > MAX_SECRET_LEN {
        Ok(false)
    } else if hashed_secret.starts_with('$') {
        verify_hash_prefix(verifier, hashed_secret, secret).await
    } else if hashed_secret.starts_with('_') {
        CryptScheme::BsdiCrypt
            .verify_blocking(verifier, hashed_secret, secret)
            .await
    } else if let Some(hashed_secret) = hashed_secret.strip_prefix('{') {
        if let Some((algo, hashed_secret)) = hashed_secret.split_once('}') {
            hashify::fnc_map_ignore_case!(algo.as_bytes(),
                "ARGON2" => {
                    verify_hash_prefix(verifier, hashed_secret, secret).await
                },
                "ARGON2I" => {
                    verify_hash_prefix(verifier, hashed_secret, secret).await
                },
                "ARGON2ID" => {
                    verify_hash_prefix(verifier, hashed_secret, secret).await
                },
                "PBKDF2" => {
                    verify_hash_prefix(verifier, hashed_secret, secret).await
                },
                "SHA" => {
                    let mut hasher = Sha1::new();
                    hasher.update(secret);
                    Ok(digest_matches(&hasher.finalize(), hashed_secret))
                },
                "SSHA" => {
                    let decoded = LENIENT.decode(hashed_secret).unwrap_or_default();
                    let hash = decoded.get(..20).unwrap_or_default();
                    let salt = decoded.get(20..).unwrap_or_default();
                    let mut hasher = Sha1::new();
                    hasher.update(secret);
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                },
                "SHA256" => {
                    let mut hasher = Sha256::new();
                    hasher.update(secret);
                    Ok(digest_matches(&hasher.finalize(), hashed_secret))
                },
                "SSHA256" => {
                    let decoded = LENIENT.decode(hashed_secret).unwrap_or_default();
                    let hash = decoded.get(..32).unwrap_or_default();
                    let salt = decoded.get(32..).unwrap_or_default();
                    let mut hasher = Sha256::new();
                    hasher.update(secret);
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                },
                "SHA512" => {
                    let mut hasher = Sha512::new();
                    hasher.update(secret);
                    Ok(digest_matches(&hasher.finalize(), hashed_secret))
                },
                "SSHA512" => {
                    let decoded = LENIENT.decode(hashed_secret).unwrap_or_default();
                    let hash = decoded.get(..64).unwrap_or_default();
                    let salt = decoded.get(64..).unwrap_or_default();
                    let mut hasher = Sha512::new();
                    hasher.update(secret);
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                },
                "MD5" => {
                    Ok(digest_matches(&md5::compute(secret)[..], hashed_secret))
                },
                "CRYPT" => {
                    if hashed_secret.starts_with('$') {
                        verify_hash_prefix(verifier, hashed_secret, secret).await
                    } else {
                        CryptScheme::UnixCrypt
                            .verify_blocking(verifier, hashed_secret, secret)
                            .await
                    }
                },
                "PLAIN" => {
                    Ok(hashed_secret.as_bytes() == secret)
                },
                "CLEAR" => {
                    Ok(hashed_secret.as_bytes() == secret)
                },
                _ => {
                    Err(trc::AuthEvent::Error
                        .ctx(trc::Key::Reason, "Unsupported password hash algorithm")
                        .ctx(trc::Key::Name, CompactString::from(algo)))
                }
            )
        } else {
            Err(unrecognized_hash_format())
        }
    } else if !hashed_secret.is_empty() {
        Ok(hashed_secret.as_bytes() == secret)
    } else {
        Ok(false)
    }
}

pub async fn hash_secret(
    verifier: &PasswordVerifier,
    algorithm: PasswordHashAlgorithm,
    secret: Vec<u8>,
) -> trc::Result<String> {
    verifier
        .run_blocking(move || {
            let result = match algorithm {
                PasswordHashAlgorithm::Argon2id => {
                    let hasher = Argon2::default();
                    hasher
                        .hash_password(secret.as_slice())
                        .map(|h| h.to_string())
                }
                PasswordHashAlgorithm::Bcrypt => {
                    return bcrypt::hash(secret.as_slice()).map_err(|err| {
                        trc::AuthEvent::Error
                            .reason(err)
                            .details("Bcrypt hash failed")
                    });
                }
                PasswordHashAlgorithm::Scrypt => Scrypt::default()
                    .hash_password(secret.as_slice())
                    .map(|h| h.to_string()),
                PasswordHashAlgorithm::Pbkdf2 => Pbkdf2::default()
                    .hash_password(secret.as_slice())
                    .map(|h| h.to_string()),
            };

            result.map_err(|err| {
                trc::AuthEvent::Error
                    .reason(err)
                    .details("Password hash failed")
            })
        })
        .await?
}

pub fn is_password_hash(s: &str) -> bool {
    if s.starts_with("$argon2") || s.starts_with("$pbkdf2") || s.starts_with("$scrypt") {
        is_complete_phc(s)
    } else if s.starts_with("$2") {
        is_bcrypt_format(s)
    } else if let Some(body) = s.strip_prefix("$1$") {
        is_md5_crypt(body)
    } else if let Some(body) = s.strip_prefix("$5$") {
        is_sha_crypt(body, 43)
    } else if let Some(body) = s.strip_prefix("$6$") {
        is_sha_crypt(body, 86)
    } else if let Some(body) = s.strip_prefix("$sha1$") {
        is_sha1_crypt(body)
    } else if s.starts_with('_') {
        is_unix_des_crypt(s)
    } else if let Some(rest) = s.strip_prefix('{') {
        rest.split_once('}')
            .map(|(scheme, body)| is_ldap_hash(scheme, body))
            .unwrap_or(false)
    } else {
        false
    }
}

fn is_complete_phc(s: &str) -> bool {
    PasswordHash::new(s)
        .map(|h| h.hash.is_some() && h.salt.is_some())
        .unwrap_or(false)
}

fn is_crypt_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'/'
}

fn all_crypt_b64(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_crypt_b64)
}

fn is_bcrypt_format(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 60
        || !matches!(bytes[2], b'a' | b'b' | b'x' | b'y')
        || bytes[3] != b'$'
        || !bytes[4].is_ascii_digit()
        || !bytes[5].is_ascii_digit()
        || bytes[6] != b'$'
    {
        false
    } else {
        bytes[7..].iter().copied().all(is_crypt_b64)
    }
}

fn is_md5_crypt(body: &str) -> bool {
    let Some((salt, hash)) = body.split_once('$') else {
        return false;
    };
    !salt.is_empty()
        && salt.len() <= 8
        && all_crypt_b64(salt)
        && hash.len() == 22
        && all_crypt_b64(hash)
}

fn is_sha_crypt(body: &str, hash_len: usize) -> bool {
    let remainder = if let Some(after) = body.strip_prefix("rounds=") {
        let Some((rounds, rest)) = after.split_once('$') else {
            return false;
        };
        if rounds.is_empty() || !rounds.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        rest
    } else {
        body
    };
    let Some((salt, hash)) = remainder.split_once('$') else {
        return false;
    };
    !salt.is_empty()
        && salt.len() <= 16
        && all_crypt_b64(salt)
        && hash.len() == hash_len
        && all_crypt_b64(hash)
}

fn is_sha1_crypt(body: &str) -> bool {
    let mut parts = body.splitn(3, '$');
    let Some(rounds) = parts.next() else {
        return false;
    };
    let Some(salt) = parts.next() else {
        return false;
    };
    let Some(hash) = parts.next() else {
        return false;
    };
    if rounds.is_empty()
        || !rounds.bytes().all(|b| b.is_ascii_digit())
        || salt.is_empty()
        || salt.len() > 64
        || !all_crypt_b64(salt)
    {
        false
    } else {
        hash.len() == 28 && all_crypt_b64(hash)
    }
}

fn is_ldap_hash(scheme: &str, body: &str) -> bool {
    hashify::fnc_map_ignore_case!(scheme.as_bytes(),
        "SHA" => b64_decoded_len_eq(body, 20),
        "SSHA" => b64_decoded_len_ge(body, 21),
        "SHA256" => b64_decoded_len_eq(body, 32),
        "SSHA256" => b64_decoded_len_ge(body, 33),
        "SHA512" => b64_decoded_len_eq(body, 64),
        "SSHA512" => b64_decoded_len_ge(body, 65),
        "MD5" => b64_decoded_len_eq(body, 16),
        "ARGON2" => is_complete_phc(body),
        "ARGON2I" => is_complete_phc(body),
        "ARGON2ID" => is_complete_phc(body),
        "PBKDF2" => is_complete_phc(body),
        "CRYPT" => is_password_hash(body) || is_unix_des_crypt(body),
        _ => false
    )
}

fn is_unix_des_crypt(s: &str) -> bool {
    let bytes = s.as_bytes();
    (bytes.len() == 13 && bytes.iter().copied().all(is_crypt_b64))
        || (bytes.len() == 20 && bytes[0] == b'_' && bytes[1..].iter().copied().all(is_crypt_b64))
}

const STANDARD_OPTIONAL_PAD: Base64 = STANDARD.with_padding(Padding::Optional);

fn b64_decoded_len_eq(body: &str, len: usize) -> bool {
    STANDARD_OPTIONAL_PAD.decoded_len(body) == Ok(len)
}

fn b64_decoded_len_ge(body: &str, min: usize) -> bool {
    STANDARD_OPTIONAL_PAD
        .decoded_len(body)
        .is_ok_and(|len| len >= min)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/directory/src/core/secret/tests.rs"]
mod tests;
