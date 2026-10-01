/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
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
                && Totp::from_url(totp_uri)
                    .map_err(|err| {
                        trc::AuthEvent::Error
                            .reason(err)
                            .details(CompactString::from(totp_uri))
                    })?
                    .check_current(totp_token)
                    .is_some();
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
                let hash = PasswordHash::new(hashed_secret).map_err(|err| {
                    trc::AuthEvent::Error
                        .reason(err)
                        .details(hashed_secret.to_string())
                })?;
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

    async fn verify_blocking(self, hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
        let secret = secret.to_vec();
        let hashed_secret = hashed_secret.to_string();

        tokio::task::spawn_blocking(move || self.verify(&hashed_secret, &secret))
            .await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .caused_by(trc::location!())
                    .reason(err)
            })?
    }
}

async fn verify_hash_prefix(hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
    match CryptScheme::from_prefix(hashed_secret) {
        Some(scheme) => scheme.verify_blocking(hashed_secret, secret).await,
        None => Err(trc::AuthEvent::Error
            .into_err()
            .details(CompactString::from(hashed_secret))),
    }
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

pub async fn verify_secret_hash(hashed_secret: &str, secret: &[u8]) -> trc::Result<bool> {
    if hashed_secret.starts_with('$') {
        verify_hash_prefix(hashed_secret, secret).await
    } else if hashed_secret.starts_with('_') {
        CryptScheme::BsdiCrypt
            .verify_blocking(hashed_secret, secret)
            .await
    } else if let Some(hashed_secret) = hashed_secret.strip_prefix('{') {
        if let Some((algo, hashed_secret)) = hashed_secret.split_once('}') {
            hashify::fnc_map_ignore_case!(algo.as_bytes(),
                "ARGON2" => {
                    verify_hash_prefix(hashed_secret, secret).await
                },
                "ARGON2I" => {
                    verify_hash_prefix(hashed_secret, secret).await
                },
                "ARGON2ID" => {
                    verify_hash_prefix(hashed_secret, secret).await
                },
                "PBKDF2" => {
                    verify_hash_prefix(hashed_secret, secret).await
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
                        verify_hash_prefix(hashed_secret, secret).await
                    } else {
                        CryptScheme::UnixCrypt
                            .verify_blocking(hashed_secret, secret)
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
                        .ctx(trc::Key::Reason, "Unsupported algorithm")
                        .details(CompactString::from(hashed_secret)))
                }
            )
        } else {
            Err(trc::AuthEvent::Error
                .into_err()
                .details(CompactString::from(hashed_secret)))
        }
    } else if !hashed_secret.is_empty() {
        Ok(hashed_secret.as_bytes() == secret)
    } else {
        Ok(false)
    }
}

pub async fn hash_secret(algorithm: PasswordHashAlgorithm, secret: Vec<u8>) -> trc::Result<String> {
    let result = tokio::task::spawn_blocking(move || {
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
    .await;

    match result {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    #[test]
    fn is_password_hash_detects_phc_strings() {
        let argon = Argon2::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();
        assert!(is_password_hash(&argon), "argon2 not detected: {argon}");

        let pbkdf = Pbkdf2::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();
        assert!(is_password_hash(&pbkdf), "pbkdf2 not detected: {pbkdf}");

        let scr = Scrypt::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();
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

        let a = Argon2::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();
        assert!(is_password_hash(&format!("{{ARGON2ID}}{a}")));
        assert!(is_password_hash(&format!("{{ARGON2}}{a}")));
        assert!(is_password_hash(&format!("{{ARGON2I}}{a}")));

        let p = Pbkdf2::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();
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

    #[tokio::test]
    #[allow(deprecated)]
    async fn verify_secret_hash_all_schemes() {
        let mut sha1 = Sha1::new();
        sha1.update(b"hello");
        let sha1 = b64(&sha1.finalize()[..]);
        let mut sha256 = Sha256::new();
        sha256.update(b"hello");
        let sha256 = b64(&sha256.finalize()[..]);
        let mut sha512 = Sha512::new();
        sha512.update(b"hello");
        let sha512 = b64(&sha512.finalize()[..]);
        let mut ssha = Sha1::new();
        ssha.update(b"hello");
        ssha.update(b"saltbytes");
        let mut ssha = ssha.finalize().to_vec();
        ssha.extend_from_slice(b"saltbytes");
        let ssha = b64(&ssha);
        let md5 = b64(&md5::compute(b"hello")[..]);
        let argon = Argon2::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();
        let pbkdf = Pbkdf2::default()
            .hash_password(b"hello")
            .unwrap()
            .to_string();

        let hashes = [
            argon.clone(),
            pbkdf.clone(),
            format!("{{ARGON2ID}}{argon}"),
            format!("{{argon2}}{argon}"),
            format!("{{PBKDF2}}{pbkdf}"),
            bcrypt::hash("hello").unwrap(),
            sha512_crypt::hash("hello").unwrap(),
            sha256_crypt::hash("hello").unwrap(),
            sha1_crypt::hash("hello").unwrap(),
            md5_crypt::hash("hello").unwrap(),
            bsdi_crypt::hash("hello").unwrap(),
            format!("{{CRYPT}}{}", unix_crypt::hash("hello").unwrap()),
            format!("{{crypt}}{}", sha512_crypt::hash("hello").unwrap()),
            format!("{{SHA}}{sha1}"),
            format!("{{sha}}{sha1}"),
            format!("{{SHA256}}{sha256}"),
            format!("{{Sha512}}{sha512}"),
            format!("{{SSHA}}{ssha}"),
            format!("{{MD5}}{md5}"),
            "{PLAIN}hello".to_string(),
            "{clear}hello".to_string(),
            "hello".to_string(),
        ];

        for hash in &hashes {
            assert!(
                verify_secret_hash(hash, b"hello").await.unwrap(),
                "valid secret rejected for {hash}"
            );
            assert!(
                !verify_secret_hash(hash, b"hellO").await.unwrap(),
                "invalid secret accepted for {hash}"
            );
        }

        for hash in ["{SHA}", "{SHA256}short", "{MD5}aGVsbG8="] {
            assert!(!verify_secret_hash(hash, b"hello").await.unwrap(), "{hash}");
        }
        for hash in ["{UNKNOWN}abc", "$unknown$abc", "{SHA"] {
            assert!(verify_secret_hash(hash, b"hello").await.is_err(), "{hash}");
        }
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
