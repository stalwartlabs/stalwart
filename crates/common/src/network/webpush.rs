/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use encodify::base64::URL_SAFE_NO_PAD;
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, PrivateKeyInfo, der::SecretDocument},
};
use parking_lot::Mutex;
use reqwest::{Url, header::HeaderValue};
use std::sync::Arc;

const VAPID_TOKEN_TTL: u64 = 12 * 60 * 60;
const VAPID_PREFIX: &str = "vapid t=";
const VAPID_JWT_HEADER: &[u8] = br#"{"typ":"JWT","alg":"ES256"}"#;
const VAPID_TOKEN_REFRESH: u64 = VAPID_TOKEN_TTL / 2;

#[derive(Clone)]
pub struct Vapid {
    key: VapidKey,
    contact: Option<String>,
    tokens: Arc<Mutex<AHashMap<String, VapidToken>>>,
}

struct VapidToken {
    authorization: HeaderValue,
    issued_at: u64,
}

impl Vapid {
    pub fn new(key: VapidKey, contact: Option<String>) -> Self {
        Self {
            key,
            contact,
            tokens: Arc::default(),
        }
    }

    pub fn public_key(&self) -> &str {
        self.key.public_key()
    }

    pub fn authorization(&self, endpoint: &str, now: u64) -> Option<HeaderValue> {
        let origin = endpoint_origin(endpoint)?;
        if let Some(token) = self
            .tokens
            .lock()
            .get(&origin)
            .filter(|token| token.is_fresh(now))
        {
            return Some(token.authorization.clone());
        }

        let authorization = HeaderValue::try_from(self.key.authorization_for_origin(
            &origin,
            self.contact.as_deref(),
            now,
        )?)
        .ok()?;
        let mut tokens = self.tokens.lock();
        tokens.retain(|_, token| token.is_fresh(now));
        tokens.insert(
            origin,
            VapidToken {
                authorization: authorization.clone(),
                issued_at: now,
            },
        );
        Some(authorization)
    }
}

impl VapidToken {
    fn is_fresh(&self, now: u64) -> bool {
        now.checked_sub(self.issued_at)
            .is_some_and(|age| age < VAPID_TOKEN_REFRESH)
    }
}

#[derive(Clone)]
pub struct VapidKey {
    signing_key: SigningKey,
    public_key: String,
}

impl VapidKey {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, String> {
        let pem = pem.trim_start_matches('\u{feff}').trim();

        if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::from_signing_key(key));
        }
        if let Ok(secret) = SecretKey::from_sec1_pem(pem) {
            return Ok(Self::from_signing_key(secret.into()));
        }
        if let Some(secret) = secret_key_from_explicit_params(pem) {
            return Ok(Self::from_signing_key(secret.into()));
        }

        Err(SigningKey::from_pkcs8_pem(pem)
            .err()
            .map(|err| {
                format!(
                    "{err}. Re-encode the key as named-curve PKCS#8, \
                     e.g. `openssl pkey -in key.pem -out key_pkcs8.pem`."
                )
            })
            .unwrap_or_else(|| "unsupported VAPID key encoding".to_string()))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        Self {
            signing_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn authorization(&self, endpoint: &str, contact: Option<&str>, now: u64) -> Option<String> {
        self.authorization_for_origin(&endpoint_origin(endpoint)?, contact, now)
    }

    fn authorization_for_origin(
        &self,
        origin: &str,
        contact: Option<&str>,
        now: u64,
    ) -> Option<String> {
        let mut claims = serde_json::Map::new();
        claims.insert("aud".into(), origin.into());
        claims.insert("exp".into(), (now + VAPID_TOKEN_TTL).into());
        if let Some(sub) = contact {
            claims.insert("sub".into(), sub.into());
        }

        let mut authorization = String::from(VAPID_PREFIX);
        URL_SAFE_NO_PAD.encode_append(VAPID_JWT_HEADER, &mut authorization);
        authorization.push('.');
        URL_SAFE_NO_PAD.encode_append(serde_json::to_vec(&claims).ok()?, &mut authorization);
        let signature: Signature = self
            .signing_key
            .sign(authorization.get(VAPID_PREFIX.len()..)?.as_bytes());
        authorization.push('.');
        URL_SAFE_NO_PAD.encode_append(signature.to_bytes(), &mut authorization);
        authorization.push_str(", k=");
        authorization.push_str(&self.public_key);

        Some(authorization)
    }
}

fn endpoint_origin(url: &str) -> Option<String> {
    let origin = Url::parse(url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

pub fn normalize_contact(contact: &str) -> Option<String> {
    let contact = contact.trim();

    match contact.split_once(':') {
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("mailto") => Some(contact.to_string()),
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => Some(contact.to_string()),
        Some(_) => None,
        None if contact.contains('@') => Some(format!("mailto:{contact}")),
        None => None,
    }
}

pub fn generate_pkcs8_pem() -> Result<String, String> {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    SigningKey::random(&mut OsRng)
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|err| err.to_string())
}

fn secret_key_from_explicit_params(pem: &str) -> Option<SecretKey> {
    let (_, document) = SecretDocument::from_pem(pem).ok()?;
    let private_key_info = PrivateKeyInfo::try_from(document.as_bytes()).ok()?;
    SecretKey::from_sec1_der(private_key_info.private_key).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    fn test_key() -> VapidKey {
        VapidKey::from_pkcs8_pem(&generate_pkcs8_pem().unwrap()).unwrap()
    }

    #[test]
    fn generated_key_round_trips_through_pkcs8_pem() {
        let pem = generate_pkcs8_pem().unwrap();
        assert_eq!(
            VapidKey::from_pkcs8_pem(&pem).unwrap().public_key(),
            VapidKey::from_pkcs8_pem(&pem).unwrap().public_key()
        );
    }

    #[test]
    fn endpoint_origin_normalizes() {
        assert_eq!(
            endpoint_origin("HTTPS://Push.Example.COM:443/push?x=1").unwrap(),
            "https://push.example.com"
        );
        assert_eq!(
            endpoint_origin("https://127.0.0.1:19000/push").unwrap(),
            "https://127.0.0.1:19000"
        );
        assert_eq!(
            endpoint_origin("https://user:pass@fcm.googleapis.com/fcm/send/x").unwrap(),
            "https://fcm.googleapis.com"
        );
        assert_eq!(
            endpoint_origin("http://[2001:DB8::1]:80/p").unwrap(),
            "http://[2001:db8::1]"
        );
        assert_eq!(
            endpoint_origin("https://attacker.example\\@fcm.googleapis.com/fcm/send/x").unwrap(),
            "https://attacker.example"
        );
        assert!(endpoint_origin("not-a-url").is_none());
        assert!(endpoint_origin("mailto:admin@example.org").is_none());
    }

    #[test]
    fn authorization_signs_a_verifiable_es256_token() {
        let key = test_key();
        let now = 1_700_000_000;
        let header = key
            .authorization(
                "https://push.example.com/push/abc?token=1",
                Some("mailto:admin@example.org"),
                now,
            )
            .unwrap();

        let (token, advertised_key) = header
            .strip_prefix("vapid ")
            .and_then(|rest| rest.split_once(", "))
            .unwrap();
        let jwt = token.strip_prefix("t=").unwrap();
        assert_eq!(advertised_key.strip_prefix("k=").unwrap(), key.public_key());

        let parts = jwt.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);

        let verifying_key =
            VerifyingKey::from_sec1_bytes(&URL_SAFE_NO_PAD.decode(key.public_key()).unwrap())
                .unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        verifying_key
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();

        assert_eq!(
            URL_SAFE_NO_PAD.decode(parts[0]).unwrap(),
            br#"{"typ":"JWT","alg":"ES256"}"#
        );
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://push.example.com");
        assert_eq!(claims["sub"], "mailto:admin@example.org");
        assert_eq!(claims["exp"], now + VAPID_TOKEN_TTL);
    }

    const SEC1_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP4Zv7be5hDH0x4ur6ditW+whzyZBXK1Vyjn6aIDo0jhoAoGCCqGSM49
AwEHoUQDQgAEVc4PXr+z61s9/dIas44+S0Nza3gm1UW/avddp99dUsEi3JV0H4Yk
1yfqVJ/O9KPvQ69uMAY0t3A5lx/GvOOZfg==
-----END EC PRIVATE KEY-----";

    const PKCS8_NAMED_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/hm/tt7mEMfTHi6v
p2K1b7CHPJkFcrVXKOfpogOjSOGhRANCAARVzg9ev7PrWz390hqzjj5LQ3NreCbV
Rb9q912n311SwSLclXQfhiTXJ+pUn870o+9Dr24wBjS3cDmXH8a845l+
-----END PRIVATE KEY-----";

    const PKCS8_EXPLICIT_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB
AAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA
///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV
AMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg
9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A
AAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQg/hm/tt7mEMfT
Hi6vp2K1b7CHPJkFcrVXKOfpogOjSOGhRANCAARVzg9ev7PrWz390hqzjj5LQ3Nr
eCbVRb9q912n311SwSLclXQfhiTXJ+pUn870o+9Dr24wBjS3cDmXH8a845l+
-----END PRIVATE KEY-----";

    const PKCS8_P384_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCUx+yT22yGHP9q+Y1y
UedDkevSvPaUuSPH8Q4FJBdYKKLqX4a5VdBIOonKPC4Yj7yhZANiAAQPRBsMOJy/
B4yDfR2rGOd2H6Kv3fQNHPj9Nu5Tks8QYMLzrX8ONCNoFnNUQl9S0r0QS6phVqD0
1kt0wbEvKr7mPM/R8XS8dX0xYC58CXHqBsTM0piQN2R7kqWDJ5i4OjE=
-----END PRIVATE KEY-----";

    #[test]
    fn accepts_equivalent_p256_encodings() {
        let named = VapidKey::from_pkcs8_pem(PKCS8_NAMED_PEM).unwrap();
        let sec1 = VapidKey::from_pkcs8_pem(SEC1_PEM).unwrap();
        let explicit = VapidKey::from_pkcs8_pem(PKCS8_EXPLICIT_PEM).unwrap();

        assert_eq!(named.public_key(), sec1.public_key());
        assert_eq!(named.public_key(), explicit.public_key());
    }

    #[test]
    fn accepts_pem_with_leading_bom_and_whitespace() {
        let dirty = format!("\u{feff}  \n{PKCS8_NAMED_PEM}\n  ");
        assert_eq!(
            VapidKey::from_pkcs8_pem(&dirty).unwrap().public_key(),
            VapidKey::from_pkcs8_pem(PKCS8_NAMED_PEM)
                .unwrap()
                .public_key()
        );
    }

    #[test]
    fn rejects_wrong_curve_key() {
        assert!(VapidKey::from_pkcs8_pem(PKCS8_P384_PEM).is_err());
    }

    #[test]
    fn rejects_garbage_with_actionable_error() {
        let err = VapidKey::from_pkcs8_pem("not a key").err().unwrap();
        assert!(err.contains("openssl pkey"), "{err}");
    }

    #[test]
    fn contact_is_normalized_to_a_uri() {
        for (input, expected) in [
            ("hello@stalw.art", Some("mailto:hello@stalw.art")),
            ("  hello@stalw.art  ", Some("mailto:hello@stalw.art")),
            ("mailto:hello@stalw.art", Some("mailto:hello@stalw.art")),
            ("MAILTO:hello@stalw.art", Some("MAILTO:hello@stalw.art")),
            (
                "https://stalw.art/contact",
                Some("https://stalw.art/contact"),
            ),
            ("stalw.art", None),
            ("http://stalw.art", None),
            ("tel:+123456789", None),
            ("", None),
        ] {
            assert_eq!(
                normalize_contact(input).as_deref(),
                expected,
                "unexpected normalization of {input:?}"
            );
        }
    }

    #[test]
    fn authorization_is_never_reused_across_origins_sharing_a_prefix() {
        let vapid = Vapid::new(test_key(), None);
        let now = 1_700_000_000;
        let fcm = vapid
            .authorization("https:////fcm.googleapis.com/fcm/send/x", now)
            .unwrap();
        let other = vapid
            .authorization("https:////attacker.example/x", now)
            .unwrap();

        assert_ne!(fcm, other);
        assert_eq!(
            vapid
                .authorization("https://fcm.googleapis.com/fcm/send/y", now)
                .unwrap(),
            fcm
        );
    }

    #[test]
    fn authorization_is_reused_per_endpoint_prefix() {
        let vapid = Vapid::new(test_key(), None);
        let now = 1_700_000_000;
        let token = vapid
            .authorization("https://push.example.com/push/a", now)
            .unwrap();

        assert_eq!(
            vapid
                .authorization("https://push.example.com/push/b?x=1", now + 60)
                .unwrap(),
            token
        );
        assert_ne!(
            vapid
                .authorization("https://other.example.com/push/a", now)
                .unwrap(),
            token
        );
        assert_ne!(
            vapid
                .authorization("https://push.example.com/push/a", now - 1)
                .unwrap(),
            token
        );
        let refreshed = vapid
            .authorization("https://push.example.com/push/a", now + VAPID_TOKEN_REFRESH)
            .unwrap();
        assert_ne!(refreshed, token);
        assert_eq!(
            vapid
                .authorization(
                    "https://push.example.com/push/c",
                    now + VAPID_TOKEN_REFRESH + 1
                )
                .unwrap(),
            refreshed
        );
    }

    #[test]
    fn authorization_omits_subject_when_no_contact() {
        let key = test_key();
        let header = key
            .authorization("https://fcm.googleapis.com/fcm/send/xyz", None, 0)
            .unwrap();
        let payload = header.split('.').nth(1).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert!(claims.get("sub").is_none());
    }
}
