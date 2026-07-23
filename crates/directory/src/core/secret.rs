/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVerificationResult {
    Valid,
    Invalid,
    MissingMfaToken,
}

pub async fn verify_mfa_secret_hash(
    totp_uri: Option<&str>,
    totp_token: Option<&str>,
    hashed_secret: &str,
    secret: &str,
) -> trc::Result<SecretVerificationResult> {
    if let Some(totp_uri) = totp_uri {
        if let Some(totp_token) = totp_token {
            let result = verify_secret_hash(hashed_secret, secret.as_bytes()).await?
                && TOTP::from_url(totp_uri)
                    .map_err(|err| {
                        trc::AuthEvent::Error
                            .reason(err)
                            .details(totp_uri.to_string())
                    })?
                    .check_current(totp_token)
                    .unwrap_or(false);
            Ok(if result {
                SecretVerificationResult::Valid
            } else {
                SecretVerificationResult::Invalid
            })
        } else if !hashed_secret.is_empty()
            && !secret.is_empty()
            && verify_secret_hash(hashed_secret, secret.as_bytes()).await?
        {
            // Only let the client know if the TOTP code is missing
            // if the password is correct

            Ok(SecretVerificationResult::MissingMfaToken)
        } else {
            Ok(SecretVerificationResult::Invalid)
        }
    } else if !hashed_secret.is_empty() && !secret.is_empty() {
        if verify_secret_hash(hashed_secret, secret.as_bytes()).await? {
            Ok(SecretVerificationResult::Valid)
        } else {
            Ok(SecretVerificationResult::Invalid)
        }
    } else {
        Ok(SecretVerificationResult::Invalid)
    }
}

async fn verify_hash_prefix(hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
    let is_argon = hashed_secret.starts_with("$argon2");
    let is_pbkdf2 = !is_argon && hashed_secret.starts_with("$pbkdf2");
    let is_scrypt = !is_argon && !is_pbkdf2 && hashed_secret.starts_with("$scrypt");

    if is_argon || is_pbkdf2 || is_scrypt {
        let (tx, rx) = oneshot::channel();
        let secret = secret.to_vec();
        let hashed_secret = hashed_secret.to_string();

        tokio::task::spawn_blocking(move || match PasswordHash::new(&hashed_secret) {
            Ok(hash) => {
                let result = if is_argon {
                    Argon2::default().verify_password(&secret, &hash)
                } else if is_pbkdf2 {
                    Pbkdf2.verify_password(&secret, &hash)
                } else {
                    Scrypt.verify_password(&secret, &hash)
                };

                tx.send(Ok(result.is_ok())).ok();
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
            match algo.to_ascii_uppercase().as_str() {
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
                "CRYPT" => {
                    if hashed_secret.starts_with('$') {
                        verify_hash_prefix(hashed_secret, secret).await
                    } else {
                        // Unix crypt
                        Ok(unix_crypt::verify(secret, hashed_secret))
                    }
                }
                "PLAIN" | "CLEAR" => Ok(hashed_secret.as_bytes() == secret),
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

pub async fn hash_secret(algorithm: PasswordHashAlgorithm, secret: Vec<u8>) -> trc::Result<String> {
    let (tx, rx) = oneshot::channel();

    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);

        let result = match algorithm {
            PasswordHashAlgorithm::Argon2id => {
                let hasher = Argon2::default();
                hasher
                    .hash_password(secret.as_slice(), &salt)
                    .map(|h| h.to_string())
            }
            PasswordHashAlgorithm::Bcrypt => {
                return tx
                    .send(bcrypt::hash(secret.as_slice()).map_err(|err| {
                        trc::AuthEvent::Error
                            .reason(err)
                            .details("Bcrypt hash failed")
                    }))
                    .ok()
                    .unwrap_or(());
            }
            PasswordHashAlgorithm::Scrypt => Scrypt
                .hash_password(secret.as_slice(), &salt)
                .map(|h| h.to_string()),
            PasswordHashAlgorithm::Pbkdf2 => Pbkdf2
                .hash_password(secret.as_slice(), &salt)
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
    match scheme.to_ascii_uppercase().as_str() {
        "SHA" => b64_decoded_len_eq(body, 20),
        "SSHA" => b64_decoded_len_ge(body, 21),
        "SHA256" => b64_decoded_len_eq(body, 32),
        "SSHA256" => b64_decoded_len_ge(body, 33),
        "SHA512" => b64_decoded_len_eq(body, 64),
        "SSHA512" => b64_decoded_len_ge(body, 65),
        "MD5" => b64_decoded_len_eq(body, 16),
        "ARGON2" | "ARGON2I" | "ARGON2ID" | "PBKDF2" => is_complete_phc(body),
        "CRYPT" => is_password_hash(body) || is_unix_des_crypt(body),
        _ => false,
    }
}

fn is_unix_des_crypt(s: &str) -> bool {
    let bytes = s.as_bytes();
    (bytes.len() == 13 && bytes.iter().copied().all(is_crypt_b64))
        || (bytes.len() == 20 && bytes[0] == b'_' && bytes[1..].iter().copied().all(is_crypt_b64))
}

fn b64_decoded_len_eq(body: &str, len: usize) -> bool {
    b64_decode_loose(body)
        .map(|d| d.len() == len)
        .unwrap_or(false)
}

fn b64_decoded_len_ge(body: &str, min: usize) -> bool {
    b64_decode_loose(body)
        .map(|d| d.len() >= min)
        .unwrap_or(false)
}

fn b64_decode_loose(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        String::from_utf8(base64_encode(bytes).unwrap()).unwrap()
    }

    #[test]
    fn is_password_hash_detects_phc_strings() {
        let salt = SaltString::generate(&mut OsRng);

        let argon = Argon2::default()
            .hash_password(b"hello", &salt)
            .unwrap()
            .to_string();
        assert!(is_password_hash(&argon), "argon2 not detected: {argon}");

        let pbkdf = Pbkdf2.hash_password(b"hello", &salt).unwrap().to_string();
        assert!(is_password_hash(&pbkdf), "pbkdf2 not detected: {pbkdf}");

        let scr = Scrypt.hash_password(b"hello", &salt).unwrap().to_string();
        assert!(is_password_hash(&scr), "scrypt not detected: {scr}");
    }

    #[test]
    fn is_password_hash_detects_crypt_variants() {
        let bc = bcrypt::hash("hello").unwrap();
        assert!(is_password_hash(&bc), "bcrypt not detected: {bc}");
        assert!(bcrypt::verify("hello", &bc));

        let md5 = "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0";
        assert!(is_password_hash(md5));
        assert!(md5_crypt::verify("password", md5));

        let sha256 = "$5$WH1ABM5sKhxbkgCK$sOnTVjQn1Y3EWibd8gWqqJqjH.KaFrxJE5rijqxcPp7";
        assert!(is_password_hash(sha256));
        assert!(sha256_crypt::verify("test", sha256));

        let sha256_rounds =
            "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1";
        assert!(is_password_hash(sha256_rounds));
        assert!(sha256_crypt::verify("test", sha256_rounds));

        let s512 = sha512_crypt::hash("hello").unwrap();
        assert!(is_password_hash(&s512), "sha512_crypt not detected: {s512}");
        assert!(sha512_crypt::verify("hello", &s512));

        let s1 = sha1_crypt::hash("hello").unwrap();
        assert!(is_password_hash(&s1), "sha1_crypt not detected: {s1}");
        assert!(sha1_crypt::verify("hello", &s1));

        let bsdi = "_J9..K0AyUubDkQmPLeM";
        assert!(is_password_hash(bsdi), "bsdi_crypt not detected: {bsdi}");
    }

    #[test]
    fn is_password_hash_detects_ldap_schemes() {
        let mut h = Sha1::new();
        h.update(b"hello");
        let sha = b64(&h.finalize()[..]);
        assert!(is_password_hash(&format!("{{SHA}}{sha}")));

        let mut h = Sha1::new();
        h.update(b"hello");
        h.update(b"saltbytes");
        let mut buf = h.finalize().to_vec();
        buf.extend_from_slice(b"saltbytes");
        let ssha = b64(&buf);
        assert!(is_password_hash(&format!("{{SSHA}}{ssha}")));

        let mut h = Sha256::new();
        h.update(b"hello");
        let sha256 = b64(&h.finalize()[..]);
        assert!(is_password_hash(&format!("{{SHA256}}{sha256}")));

        let mut h = Sha256::new();
        h.update(b"hello");
        h.update(b"saltbytes");
        let mut buf = h.finalize().to_vec();
        buf.extend_from_slice(b"saltbytes");
        let ssha256 = b64(&buf);
        assert!(is_password_hash(&format!("{{SSHA256}}{ssha256}")));

        let mut h = Sha512::new();
        h.update(b"hello");
        let sha512 = b64(&h.finalize()[..]);
        assert!(is_password_hash(&format!("{{SHA512}}{sha512}")));

        let mut h = Sha512::new();
        h.update(b"hello");
        h.update(b"saltbytes");
        let mut buf = h.finalize().to_vec();
        buf.extend_from_slice(b"saltbytes");
        let ssha512 = b64(&buf);
        assert!(is_password_hash(&format!("{{SSHA512}}{ssha512}")));

        let digest = md5::compute(b"hello");
        let md5b = b64(&digest[..]);
        assert!(is_password_hash(&format!("{{MD5}}{md5b}")));

        let inner = sha512_crypt::hash("hello").unwrap();
        assert!(is_password_hash(&format!("{{CRYPT}}{inner}")));
        assert!(is_password_hash(&format!("{{crypt}}{inner}")));

        assert!(is_password_hash(
            "{CRYPT}$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0"
        ));
        assert!(is_password_hash("{CRYPT}abcdefghij012"));
        assert!(is_password_hash("{CRYPT}_J9..K0AyUubDkQmPLeM"));

        let salt = SaltString::generate(&mut OsRng);
        let a = Argon2::default()
            .hash_password(b"hello", &salt)
            .unwrap()
            .to_string();
        assert!(is_password_hash(&format!("{{ARGON2ID}}{a}")));
        assert!(is_password_hash(&format!("{{ARGON2}}{a}")));
        assert!(is_password_hash(&format!("{{ARGON2I}}{a}")));

        let p = Pbkdf2.hash_password(b"hello", &salt).unwrap().to_string();
        assert!(is_password_hash(&format!("{{PBKDF2}}{p}")));

        let mut h = Sha1::new();
        h.update(b"hello");
        let sha_lc = b64(&h.finalize()[..]);
        assert!(is_password_hash(&format!("{{sha}}{sha_lc}")));

        let mut h = Sha256::new();
        h.update(b"hello");
        h.update(b"saltbytes");
        let mut buf = h.finalize().to_vec();
        buf.extend_from_slice(b"saltbytes");
        let ssha256_lc = b64(&buf);
        assert!(is_password_hash(&format!("{{ssha256}}{ssha256_lc}")));

        let digest = md5::compute(b"hello");
        let md5_mc = b64(&digest[..]);
        assert!(is_password_hash(&format!("{{Md5}}{md5_mc}")));
    }

    #[test]
    fn is_password_hash_rejects_passwords() {
        let not_hashes = [
            "",
            "hello",
            "p@ssw0rd!",
            "password123",
            "correct horse battery staple",
            "$myPassword",
            "$1incomplete",
            "$1$",
            "$1$short",
            "$1$abc$tooshorthash",
            "$5$",
            "$5$nohashpart$",
            "$5$saltonly$alsotooshort",
            "$6$",
            "$$$",
            "$$argon2$",
            "$argon2id$broken",
            "$argon2id$v=19$bad",
            "$2",
            "$2y$",
            "$2y$10$short",
            "$2z$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
            "$sha1$",
            "$sha1$notdigits$salt$hash",
            "{",
            "{}",
            "{}foo",
            "{SHA}",
            "{SHA}not!valid!base!64",
            "{SHA}aGVsbG8=",
            "{MD5}",
            "{MD5}aGVsbG8=",
            "{SHA256}aGVsbG8=",
            "{SHA512}aGVsbG8=",
            "{SSHA}aGVsbG8=",
            "{UNKNOWN}whatever",
            "{PLAIN}stillplain",
            "{plain}stillplain",
            "{CLEAR}stillplain",
            "{clear}stillplain",
            "{CRYPT}plainpw",
            "{CRYPT}",
            "{CRYPT}toolongtobeunixcryptbutshortbsdi",
            "{ARGON2ID}notaphcstring",
            "_short",
            "_notvalidbsdi",
            "regular_password",
            "1234567890123",
            "abcdefghij012",
            "$5$rounds=$saltvalue$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK",
        ];
        for p in not_hashes {
            assert!(!is_password_hash(p), "false positive: {p:?}");
        }
    }
}
