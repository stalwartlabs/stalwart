/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, PrivateKeyInfo, der::SecretDocument},
};

const VAPID_TOKEN_TTL: u64 = 12 * 60 * 60;

pub fn generate_pkcs8_pem() -> Result<String, String> {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    SigningKey::random(&mut OsRng)
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|err| err.to_string())
}

#[derive(Clone)]
pub struct Vapid {
    key: VapidKey,
    contact: Option<String>,
}

impl Vapid {
    pub fn new(key: VapidKey, contact: Option<String>) -> Self {
        Self { key, contact }
    }

    pub fn public_key(&self) -> &str {
        self.key.public_key()
    }

    pub fn authorization(&self, endpoint: &str, now: u64) -> Option<String> {
        self.key
            .authorization(endpoint, self.contact.as_deref(), now)
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
        let mut claims = serde_json::Map::new();
        claims.insert("aud".into(), endpoint_origin(endpoint)?.into());
        claims.insert("exp".into(), (now + VAPID_TOKEN_TTL).into());
        if let Some(sub) = contact {
            claims.insert("sub".into(), sub.into());
        }

        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).ok()?);
        let signing_input = format!("{header}.{payload}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());

        Some(format!(
            "vapid t={signing_input}.{}, k={}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            self.public_key
        ))
    }
}

fn endpoint_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        (
            format!("[{}]", addr.to_ascii_lowercase()),
            tail.strip_prefix(':').filter(|port| !port.is_empty()),
        )
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (
            host.to_ascii_lowercase(),
            Some(port).filter(|p| !p.is_empty()),
        )
    } else {
        (authority.to_ascii_lowercase(), None)
    };

    match port {
        Some(port)
            if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) =>
        {
            Some(format!("{scheme}://{host}:{port}"))
        }
        _ => Some(format!("{scheme}://{host}")),
    }
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
        assert!(endpoint_origin("not-a-url").is_none());
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
