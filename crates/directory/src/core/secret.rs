/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use argon2::Argon2;
use argon2::PasswordHasher;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use password_hash::PasswordHash;
use password_hash::SaltString;
use password_hash::rand_core::OsRng;
use pbkdf2::Pbkdf2;
use pwhash::{bcrypt, bsdi_crypt, md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};
use registry::schema::enums::PasswordHashAlgorithm;
use scrypt::Scrypt;
use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;
use tokio::sync::oneshot;
use totp_rs::TOTP;

pub async fn verify_mfa_secret_hash(
    otp_auth: Option<&str>,
    hashed_secret: &str,
    secret: &str,
) -> trc::Result<bool> {
    if let Some(otp_auth) = otp_auth {
        if let Some((code, totp_token)) = secret.rsplit_once('$').filter(|(c, t)| {
            !c.is_empty()
                && (6..=8).contains(&t.len())
                && t.as_bytes().iter().all(|b| b.is_ascii_digit())
        }) {
            let result = verify_secret_hash(hashed_secret, code.as_bytes()).await?
                && TOTP::from_url(otp_auth)
                    .map_err(|err| {
                        trc::AuthEvent::Error
                            .reason(err)
                            .details(otp_auth.to_string())
                    })?
                    .check_current(totp_token)
                    .unwrap_or(false);
            Ok(result)
        } else if !hashed_secret.is_empty()
            && !secret.is_empty()
            && verify_secret_hash(hashed_secret, secret.as_bytes()).await?
        {
            // Only let the client know if the TOTP code is missing
            // if the password is correct

            Err(trc::AuthEvent::MissingTotp.into_err())
        } else {
            Ok(false)
        }
    } else if !hashed_secret.is_empty() && !secret.is_empty() {
        verify_secret_hash(hashed_secret, secret.as_bytes()).await
    } else {
        Ok(false)
    }
}

async fn verify_hash_prefix(hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
    if hashed_secret.starts_with("$argon2")
        || hashed_secret.starts_with("$pbkdf2")
        || hashed_secret.starts_with("$scrypt")
    {
        let (tx, rx) = oneshot::channel();
        let secret = secret.to_vec();
        let hashed_secret = hashed_secret.to_string();

        tokio::task::spawn_blocking(move || match PasswordHash::new(&hashed_secret) {
            Ok(hash) => {
                tx.send(Ok(hash
                    .verify_password(&[&Argon2::default(), &Pbkdf2, &Scrypt], &secret)
                    .is_ok()))
                    .ok();
            }
            Err(err) => {
                tx.send(Err(trc::AuthEvent::Error
                    .reason(err)
                    .details(hashed_secret)))
                    .ok();
            }
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
                .caused_by(trc::location!())
                .reason(err)),
        }
    } else if hashed_secret.starts_with("$2") {
        // Blowfish crypt
        Ok(bcrypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$6$") {
        // SHA-512 crypt
        Ok(sha512_crypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$5$") {
        // SHA-256 crypt
        Ok(sha256_crypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$sha1") {
        // SHA-1 crypt
        Ok(sha1_crypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$1") {
        // MD5 based hash
        Ok(md5_crypt::verify(secret, hashed_secret))
    } else {
        Err(trc::AuthEvent::Error
            .into_err()
            .details(hashed_secret.to_string()))
    }
}

pub async fn verify_secret_hash(hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
    if hashed_secret.starts_with('$') {
        verify_hash_prefix(hashed_secret, secret).await
    } else if hashed_secret.starts_with('_') {
        // Enhanced DES-based hash
        Ok(bsdi_crypt::verify(secret, hashed_secret))
    } else if let Some(hashed_secret) = hashed_secret.strip_prefix('{') {
        if let Some((algo, hashed_secret)) = hashed_secret.split_once('}') {
            match algo {
                "ARGON2" | "ARGON2I" | "ARGON2ID" | "PBKDF2" => {
                    verify_hash_prefix(hashed_secret, secret).await
                }
                "SHA" => {
                    // SHA-1
                    let mut hasher = Sha1::new();
                    hasher.update(secret);
                    Ok(
                        String::from_utf8(
                            base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                        )
                        .unwrap()
                            == hashed_secret,
                    )
                }
                "SSHA" => {
                    // Salted SHA-1
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..20).unwrap_or_default();
                    let salt = decoded.get(20..).unwrap_or_default();
                    let mut hasher = Sha1::new();
                    hasher.update(secret);
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                }
                "SHA256" => {
                    // Verify hash
                    let mut hasher = Sha256::new();
                    hasher.update(secret);
                    Ok(
                        String::from_utf8(
                            base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                        )
                        .unwrap()
                            == hashed_secret,
                    )
                }
                "SSHA256" => {
                    // Salted SHA-256
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..32).unwrap_or_default();
                    let salt = decoded.get(32..).unwrap_or_default();
                    let mut hasher = Sha256::new();
                    hasher.update(secret);
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                }
                "SHA512" => {
                    // SHA-512
                    let mut hasher = Sha512::new();
                    hasher.update(secret);
                    Ok(
                        String::from_utf8(
                            base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                        )
                        .unwrap()
                            == hashed_secret,
                    )
                }
                "SSHA512" => {
                    // Salted SHA-512
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..64).unwrap_or_default();
                    let salt = decoded.get(64..).unwrap_or_default();
                    let mut hasher = Sha512::new();
                    hasher.update(secret);
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                }
                "MD5" => {
                    // MD5
                    let digest = md5::compute(secret);
                    Ok(
                        String::from_utf8(base64_encode(&digest[..]).unwrap_or_default()).unwrap()
                            == hashed_secret,
                    )
                }
                "CRYPT" | "crypt" => {
                    if hashed_secret.starts_with('$') {
                        verify_hash_prefix(hashed_secret, secret).await
                    } else {
                        // Unix crypt
                        Ok(unix_crypt::verify(secret, hashed_secret))
                    }
                }
                "PLAIN" | "plain" | "CLEAR" | "clear" => Ok(hashed_secret.as_bytes() == secret),
                _ => Err(trc::AuthEvent::Error
                    .ctx(trc::Key::Reason, "Unsupported algorithm")
                    .details(hashed_secret.to_string())),
            }
        } else {
            Err(trc::AuthEvent::Error
                .into_err()
                .details(hashed_secret.to_string()))
        }
    } else if !hashed_secret.is_empty() {
        Ok(hashed_secret.as_bytes() == secret)
    } else {
        Ok(false)
    }
}

pub async fn hash_secret(algorithm: PasswordHashAlgorithm, secret: String) -> trc::Result<String> {
    let (tx, rx) = oneshot::channel();

    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);

        let result = match algorithm {
            PasswordHashAlgorithm::Argon2id => {
                let hasher = Argon2::default();
                hasher
                    .hash_password(secret.as_bytes(), &salt)
                    .map(|h| h.to_string())
            }
            PasswordHashAlgorithm::Bcrypt => {
                return tx
                    .send(bcrypt::hash(secret.as_bytes()).map_err(|err| {
                        trc::AuthEvent::Error
                            .reason(err)
                            .details("Bcrypt hash failed")
                    }))
                    .ok()
                    .unwrap_or(());
            }
            PasswordHashAlgorithm::Scrypt => Scrypt
                .hash_password(secret.as_bytes(), &salt)
                .map(|h| h.to_string()),
            PasswordHashAlgorithm::Pbkdf2 => Pbkdf2
                .hash_password(secret.as_bytes(), &salt)
                .map(|h| h.to_string()),
        };

        tx.send(result.map_err(|err| {
            trc::AuthEvent::Error
                .reason(err)
                .details("Password hash failed")
        }))
        .ok();
    });

    match rx.await {
        Ok(result) => result,
        Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
            .caused_by(trc::location!())
            .reason(err)),
    }
}
