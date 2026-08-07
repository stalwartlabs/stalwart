/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Cursor;

use self::{mailstore::jmap::JmapConfig, smtp::SmtpConfig, storage::Storage};
use crate::{
    Core, Network,
    auth::oauth::config::OAuthConfig,
    config::mailstore::{
        email::EmailConfig, imap::ImapConfig, scripts::Scripting, spamfilter::SpamFilterConfig,
    },
};
use arc_swap::ArcSwap;
use groupware::GroupwareConfig;
use hyper::HeaderMap;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::EncodePrivateKey;
use rsa::{
    RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs8::DecodePrivateKey as _,
    traits::PublicKeyParts,
};
use store::registry::bootstrap::Bootstrap;
use telemetry::Metrics;

pub mod groupware;
pub mod inner;
pub mod mailstore;
pub mod network;
pub mod server;
pub mod smtp;
pub mod storage;
pub mod telemetry;

impl Core {
    pub async fn parse(bp: &mut Bootstrap, mut storage: Storage) -> Self {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let enterprise = {
            let enterprise = crate::enterprise::Enterprise::parse(bp).await;
            if enterprise.is_none() && !bp.registry.is_recovery_mode() {
                use registry::schema::prelude::ObjectType;
                use store::Store;

                if storage.data.is_enterprise() {
                    bp.build_error(
                        ObjectType::DataStore.singleton(),
                        "Disabling enterprise-only data store.",
                    );
                    storage.data = storage.data.downgrade_store();
                }
                if storage.blob.is_enterprise() {
                    bp.build_error(
                        ObjectType::BlobStore.singleton(),
                        "Disabling enterprise-only blob store.",
                    );
                    storage.blob = storage.blob.downgrade_store();
                }
                if storage.memory.is_enterprise() {
                    bp.build_error(
                        ObjectType::InMemoryStore.singleton(),
                        "Disabling enterprise-only in-memory store.",
                    );
                    storage.memory = storage.memory.downgrade_store();
                }
                storage.metrics = Store::None;
                storage.tracing = Store::None;
                storage.directories.clear();
            }
            enterprise
        };
        // SPDX-SnippetEnd

        Self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            enterprise,
            // SPDX-SnippetEnd
            sieve: Scripting::parse(bp).await,
            network: Network::parse(bp).await,
            smtp: Box::pin(SmtpConfig::parse(bp)).await,
            jmap: JmapConfig::parse(bp).await,
            imap: ImapConfig::parse(bp).await,
            oauth: OAuthConfig::parse(bp).await,
            metrics: Metrics::parse(bp).await,
            spam: SpamFilterConfig::parse(bp).await,
            email: EmailConfig::parse(bp).await,
            groupware: GroupwareConfig::parse(bp).await,
            storage,
        }
    }

    pub fn into_shared(self) -> ArcSwap<Self> {
        ArcSwap::from_pointee(self)
    }
}

const RSA_MIN_MODULUS_BITS: usize = 2048;
const RSA_MAX_MODULUS_BITS: usize = 8192;

fn no_key_found(pem: &str, expected: &str) -> String {
    if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
        format!(
            "No usable {expected} private key found in PEM: the key is password-protected, \
             which is not supported. Decrypt it first with 'openssl pkcs8 -topk8 -nocrypt'."
        )
    } else {
        format!("No usable {expected} private key found in PEM")
    }
}

pub struct RsaSigningKey {
    pub pkcs1_der: Vec<u8>,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

pub fn build_rsa_keypair(pem: &str) -> Result<RsaSigningKey, String> {
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        let key = match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            rustls_pemfile::Item::Pkcs1Key(key) => {
                RsaPrivateKey::from_pkcs1_der(key.secret_pkcs1_der())
                    .map_err(|err| format!("Failed to parse PKCS1 RSA key: {err}"))?
            }
            rustls_pemfile::Item::Pkcs8Key(key) => {
                RsaPrivateKey::from_pkcs8_der(key.secret_pkcs8_der())
                    .map_err(|err| format!("Failed to parse PKCS8 RSA key: {err}"))?
            }
            _ => continue,
        };

        let bits = key.n().bits();
        if !(RSA_MIN_MODULUS_BITS..=RSA_MAX_MODULUS_BITS).contains(&bits) {
            return Err(format!(
                "RSA key modulus is {bits} bits, expected between {RSA_MIN_MODULUS_BITS} and {RSA_MAX_MODULUS_BITS}"
            ));
        }

        let pkcs1_der = key
            .to_pkcs1_der()
            .map_err(|err| format!("Failed to encode RSA key as PKCS1: {err}"))?;

        return Ok(RsaSigningKey {
            pkcs1_der: pkcs1_der.as_bytes().to_vec(),
            modulus: key.n().to_bytes_be(),
            exponent: key.e().to_bytes_be(),
        });
    }

    Err(no_key_found(pem, "RSA"))
}

#[derive(Clone, Copy)]
pub enum EcKeyCurve {
    P256,
    P384,
}

pub struct EcdsaSigningKey {
    pub pkcs8_der: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub fn build_ecdsa_pem(curve: EcKeyCurve, pem: &str) -> Result<EcdsaSigningKey, String> {
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        let pkcs8 = match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            rustls_pemfile::Item::Pkcs8Key(key) => key.secret_pkcs8_der().to_vec(),
            rustls_pemfile::Item::Sec1Key(key) => curve
                .sec1_to_pkcs8(key.secret_sec1_der())?
                .as_bytes()
                .to_vec(),
            _ => continue,
        };

        let (x, y) = curve.public_coordinates(&pkcs8)?;

        return Ok(EcdsaSigningKey {
            pkcs8_der: pkcs8,
            x,
            y,
        });
    }

    Err(no_key_found(pem, "ECDSA"))
}

impl EcKeyCurve {
    fn sec1_to_pkcs8(self, der: &[u8]) -> Result<pkcs8::SecretDocument, String> {
        match self {
            EcKeyCurve::P256 => p256::SecretKey::from_sec1_der(der)
                .map_err(|err| format!("Failed to parse SEC1 ECDSA key: {err}"))?
                .to_pkcs8_der()
                .map_err(|err| format!("Failed to convert SEC1 ECDSA key to PKCS8: {err}")),
            EcKeyCurve::P384 => p384::SecretKey::from_sec1_der(der)
                .map_err(|err| format!("Failed to parse SEC1 ECDSA key: {err}"))?
                .to_pkcs8_der()
                .map_err(|err| format!("Failed to convert SEC1 ECDSA key to PKCS8: {err}")),
        }
    }

    fn public_coordinates(self, pkcs8: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        use pkcs8::DecodePrivateKey;

        match self {
            EcKeyCurve::P256 => {
                let point = p256::SecretKey::from_pkcs8_der(pkcs8)
                    .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}"))?
                    .public_key()
                    .to_encoded_point(false);
                Ok((
                    point.x().map(|x| x.to_vec()).unwrap_or_default(),
                    point.y().map(|y| y.to_vec()).unwrap_or_default(),
                ))
            }
            EcKeyCurve::P384 => {
                let point = p384::SecretKey::from_pkcs8_der(pkcs8)
                    .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}"))?
                    .public_key()
                    .to_encoded_point(false);
                Ok((
                    point.x().map(|x| x.to_vec()).unwrap_or_default(),
                    point.y().map(|y| y.to_vec()).unwrap_or_default(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EcKeyCurve, build_ecdsa_pem, build_rsa_keypair};

    const P256_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ9a6n/cu7XaQez5ZX8z8jDFkkfsMB1P9Vbqzbaes2zOoAoGCCqGSM49
AwEHoUQDQgAEPCbID7bo+8Nk1vIsTFhVKwRWvb9GWTzzwS75Dd8iZuFl23Twn6Sp
V2ZO1FC0WyXxcVOMZN2sJFlCjtaQS+p5Zg==
-----END EC PRIVATE KEY-----";

    const P256_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn1rqf9y7tdpB7Pll
fzPyMMWSR+wwHU/1VurNtp6zbM6hRANCAAQ8JsgPtuj7w2TW8ixMWFUrBFa9v0ZZ
PPPBLvkN3yJm4WXbdPCfpKlXZk7UULRbJfFxU4xk3awkWUKO1pBL6nlm
-----END PRIVATE KEY-----";

    const P384_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAeecJf8ju/70Nf5nbI4DeRo/+Z3VWXUvB+GwuUczew7fyMbyc6B3EE
BskOIqvqu6egBwYFK4EEACKhZANiAAQQjDW03Xn2h9ZmmCMRx+uRaLLfg4o2XITE
pwACH9EY4IjTe9LNNp5CTjERd+RlpWxkYopmDS5Trzycz9sDxxSzzXmq90vomJqt
fTnNHPFHuR2SAiwuzUf26rcPwa7DCWk=
-----END EC PRIVATE KEY-----";

    const P384_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAeecJf8ju/70Nf5nbI
4DeRo/+Z3VWXUvB+GwuUczew7fyMbyc6B3EEBskOIqvqu6ehZANiAAQQjDW03Xn2
h9ZmmCMRx+uRaLLfg4o2XITEpwACH9EY4IjTe9LNNp5CTjERd+RlpWxkYopmDS5T
rzycz9sDxxSzzXmq90vomJqtfTnNHPFHuR2SAiwuzUf26rcPwa7DCWk=
-----END PRIVATE KEY-----";

    #[test]
    fn ecdsa_pem_accepts_sec1_and_pkcs8() {
        let sec1 =
            build_ecdsa_pem(EcKeyCurve::P256, P256_SEC1).expect("P-256 SEC1 key should parse");
        let pkcs8 =
            build_ecdsa_pem(EcKeyCurve::P256, P256_PKCS8).expect("P-256 PKCS8 key should parse");
        assert_eq!((&sec1.x, &sec1.y), (&pkcs8.x, &pkcs8.y));
        assert_eq!(sec1.x.len(), 32);

        let sec1 =
            build_ecdsa_pem(EcKeyCurve::P384, P384_SEC1).expect("P-384 SEC1 key should parse");
        let pkcs8 =
            build_ecdsa_pem(EcKeyCurve::P384, P384_PKCS8).expect("P-384 PKCS8 key should parse");
        assert_eq!((&sec1.x, &sec1.y), (&pkcs8.x, &pkcs8.y));
        assert_eq!(sec1.x.len(), 48);
    }

    const RSA_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAt5Kp7o945bxbnvviI9Kzbjcwi6B5cStu4dBbNhe/ld0Js4tQ\n8Uq9qYaFBlocYzWkEd3e2IG0+uIVB37ewUe0xjq25u6G4ZWeK+SZgzXB4jHinXvh\nuhHW+KzbmO+aYO115451Cu6ymJ8DLVaR6zxT9CJsiS4lMsYZ5JHcLY3az1A5z0df\nF+chjR+sLxdc0ggKqnX6fT/sVXHIlVk6riyeFV929k/v1f0pmRQ2nNu0NMSOK7Mk\nqsvHiAb1e/41LIwlbmbzd5ASHitYYXKP+2YR29SRr2D+52S1M29h4/XbUcP6Zo2U\np5mKgQ0kFZ8pHFhbruamzRp87+yhu98IbZ9ksQIDAQABAoIBAAu2+BGxhbNReR5U\n8Co9krZEntw2NjHG5glSkNOLoe4IIEudJyHy1VYpb7lHTFr3bBw4xrUV1+0PuuxS\nyBfZAdwJmKz1iVWBhQnDiZliN5h9+vp2UqIba9bMPypMFhO766OGh4kWUP7k3ODK\njr7Oh4QDo14AvB54nmPj/ANLM2y50/Upy5s7FK0tm0ntzxSscwQFSZAJ9B0ne6Qe\nu1/PXgiXW4JKNOgrCTrRB2BcOi/Ke6OA/kg54sD+Z9PZivO/qHTx9xXzqivmbg9a\nGmoivaWH/pKwAywFogJnWH/iTe+r//fKdlEDeK+s/iCr0ht//c0w+GxPvPF//wz0\n+1u9+n0CgYEA5M7jzpT8rCYWdORvvRP1BC4+A5jb83zXW4FS+rZRSmq775zDPAif\npm653vAlNHIphEvqSdVw64+36nJFtjuBI17BHCQi0j3iNVjrLC7lbfqIobnNDdmR\n9VeqZ6qwPYt2oi4iBY2dAnPdYVTDMomHSC4vW/SER0l9A9bxt3Co1a0CgYEAzWOQ\n490s6K186CyUMFrNrUmIWEJNd7b6JGI+oCioZLtPZzxO4ebc+bHEPbpbSqx7lJRJ\nt5u6zw/RwUc+6YXXImekvMfZpZMH9v1wjp3djnxGQO4ucmvmu6H25qcYup8tRtlo\n2AVLd1jg3yka1yr7O26M3bhVfm5LOUQfoLuCA5UCgYEA3Iw7882SfFE+RjBHMIcD\nHqOALTFzmhDU+SQAGyAP3V5ihwWg/sYFNYT3btgl1JbSQ+51B/RQIw9mJPs/DPfw\nc2qLU5fVZLg3ylpKXU1a4xaiCtmwuM/mLAnzfHd/5+L9WDiFnLqzBEEwu/fbK2R7\nXOz/w3A+7QP+F+xhFAPpCgUCgYEAsnZOIkA/UlnUi6SYir+LsYOQLihGSbw687xN\n8DoDv6sl3mz/mbhQz8GP45b21hazNrH2r8xn8J0tRATU/HIoMaPe942rZvwv0oP6\n9mDjb3g6TxbmUtPA485iy53rldTTsZkdSX6oSSZ4FlAQG2AkdkqjqdAOsVHCmRrB\nZJco7FUCgYBwk7tQt3YS5b0wi8fH3BIfAH31vJ2VGlAin860H8FXjAj8EZ7Ff9Iq\n5dQIyPbp89TOSxIVxPGniI2ruLy4DZQM7xa42oyxyRir4UeHN2P5D2yEAHaVSwSd\nO6yiiOBj62OATapI8BqeFJZGRFltDsj6XbwC/Z9S2tRKCuE/zp+FLg==\n-----END RSA PRIVATE KEY-----";

    const RSA_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3kqnuj3jlvFue\n++Ij0rNuNzCLoHlxK27h0Fs2F7+V3Qmzi1DxSr2phoUGWhxjNaQR3d7YgbT64hUH\nft7BR7TGOrbm7obhlZ4r5JmDNcHiMeKde+G6Edb4rNuY75pg7XXnjnUK7rKYnwMt\nVpHrPFP0ImyJLiUyxhnkkdwtjdrPUDnPR18X5yGNH6wvF1zSCAqqdfp9P+xVcciV\nWTquLJ4VX3b2T+/V/SmZFDac27Q0xI4rsySqy8eIBvV7/jUsjCVuZvN3kBIeK1hh\nco/7ZhHb1JGvYP7nZLUzb2Hj9dtRw/pmjZSnmYqBDSQVnykcWFuu5qbNGnzv7KG7\n3whtn2SxAgMBAAECggEAC7b4EbGFs1F5HlTwKj2StkSe3DY2McbmCVKQ04uh7ggg\nS50nIfLVVilvuUdMWvdsHDjGtRXX7Q+67FLIF9kB3AmYrPWJVYGFCcOJmWI3mH36\n+nZSohtr1sw/KkwWE7vro4aHiRZQ/uTc4MqOvs6HhAOjXgC8HnieY+P8A0szbLnT\n9SnLmzsUrS2bSe3PFKxzBAVJkAn0HSd7pB67X89eCJdbgko06CsJOtEHYFw6L8p7\no4D+SDniwP5n09mK87+odPH3FfOqK+ZuD1oaaiK9pYf+krADLAWiAmdYf+JN76v/\n98p2UQN4r6z+IKvSG3/9zTD4bE+88X//DPT7W736fQKBgQDkzuPOlPysJhZ05G+9\nE/UELj4DmNvzfNdbgVL6tlFKarvvnMM8CJ+mbrne8CU0cimES+pJ1XDrj7fqckW2\nO4EjXsEcJCLSPeI1WOssLuVt+oihuc0N2ZH1V6pnqrA9i3aiLiIFjZ0Cc91hVMMy\niYdILi9b9IRHSX0D1vG3cKjVrQKBgQDNY5Dj3SzorXzoLJQwWs2tSYhYQk13tvok\nYj6gKKhku09nPE7h5tz5scQ9ultKrHuUlEm3m7rPD9HBRz7phdciZ6S8x9mlkwf2\n/XCOnd2OfEZA7i5ya+a7ofbmpxi6ny1G2WjYBUt3WODfKRrXKvs7bozduFV+bks5\nRB+gu4IDlQKBgQDcjDvzzZJ8UT5GMEcwhwMeo4AtMXOaENT5JAAbIA/dXmKHBaD+\nxgU1hPdu2CXUltJD7nUH9FAjD2Yk+z8M9/BzaotTl9VkuDfKWkpdTVrjFqIK2bC4\nz+YsCfN8d3/n4v1YOIWcurMEQTC799srZHtc7P/DcD7tA/4X7GEUA+kKBQKBgQCy\ndk4iQD9SWdSLpJiKv4uxg5AuKEZJvDrzvE3wOgO/qyXebP+ZuFDPwY/jlvbWFrM2\nsfavzGfwnS1EBNT8cigxo973jatm/C/Sg/r2YONveDpPFuZS08DjzmLLneuV1NOx\nmR1JfqhJJngWUBAbYCR2SqOp0A6xUcKZGsFklyjsVQKBgHCTu1C3dhLlvTCLx8fc\nEh8AffW8nZUaUCKfzrQfwVeMCPwRnsV/0irl1AjI9unz1M5LEhXE8aeIjau4vLgN\nlAzvFrjajLHJGKvhR4c3Y/kPbIQAdpVLBJ07rKKI4GPrY4BNqkjwGp4UlkZEWW0O\nyPpdvAL9n1La1EoK4T/On4Uu\n-----END PRIVATE KEY-----";

    #[test]
    fn rsa_pem_accepts_pkcs1_and_pkcs8() {
        let a = build_rsa_keypair(RSA_PKCS1).expect("PKCS1 RSA key should parse");
        let b = build_rsa_keypair(RSA_PKCS8).expect("PKCS8 RSA key should parse");
        assert_eq!(a.modulus, b.modulus);
        assert_eq!(a.exponent, b.exponent);
        assert_eq!(a.pkcs1_der, b.pkcs1_der);
        assert_eq!(a.modulus.len(), 256);
    }

    #[test]
    fn signing_keys_are_accepted_by_jsonwebtoken() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct Claims {
            sub: &'static str,
        }

        let claims = Claims { sub: "test" };

        for (curve, pem, alg) in [
            (EcKeyCurve::P256, P256_SEC1, Algorithm::ES256),
            (EcKeyCurve::P256, P256_PKCS8, Algorithm::ES256),
            (EcKeyCurve::P384, P384_SEC1, Algorithm::ES384),
            (EcKeyCurve::P384, P384_PKCS8, Algorithm::ES384),
        ] {
            let key = build_ecdsa_pem(curve, pem).expect("key should parse");
            jsonwebtoken::encode(
                &Header::new(alg),
                &claims,
                &EncodingKey::from_ec_der(&key.pkcs8_der),
            )
            .unwrap_or_else(|err| panic!("{alg:?} signing failed: {err}"));
        }

        for pem in [RSA_PKCS1, RSA_PKCS8] {
            let key = build_rsa_keypair(pem).expect("key should parse");
            for alg in [Algorithm::RS256, Algorithm::PS512] {
                jsonwebtoken::encode(
                    &Header::new(alg),
                    &claims,
                    &EncodingKey::from_rsa_der(&key.pkcs1_der),
                )
                .unwrap_or_else(|err| panic!("{alg:?} signing failed: {err}"));
            }
        }
    }

    #[test]
    fn ecdsa_pem_rejects_keyless_pem() {
        let err = match build_ecdsa_pem(
            EcKeyCurve::P256,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        ) {
            Ok(_) => panic!("expected a certificate-only PEM to be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("No usable ECDSA private key"), "{err}");
    }

    const P256_ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCoW4qsep9YbFLRW2u4\nk8ljAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQZYoEYHqh+y9uqT70\n6521jwSBkA9dcdq6hT/7Fzqcu0wX3QVr+8g1Kxc6tCV9dLShi8VU2ax8jG3zZt3h\nBp1CLyX8UfT98SujtoH36PEXPDDTralcP6vWViqGx5AagT4DRFjcI8yucTUXkLoD\n9ZIRBVPviTeznEHt3OvCCMuO76rsyu/gxNC7D46TBtq8JX1OFcaXPctpN8l5GKqH\nh4gA6av3og==\n-----END ENCRYPTED PRIVATE KEY-----";

    #[test]
    fn ecdsa_pem_reports_password_protected_key() {
        let err = match build_ecdsa_pem(EcKeyCurve::P256, P256_ENCRYPTED) {
            Ok(_) => panic!("expected an encrypted key to be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("password-protected"), "{err}");
    }

    #[test]
    fn rsa_pem_rejects_undersized_modulus() {
        const RSA_1024: &str = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz6gcAg0f+2/HFrudtMfRSylyzI8W/lNmPQZhUpz+R6D/7/+4/
HFKsUcZIi+nzdOnrzW/kw19nVOKk2ylAUNV9d2TR75HqrPBYsu0LCDRidb9XOyhY
bQJII1KuFlaWNjfxG28Tlg//FdVPPkn/oTQwnhvMcWCK3Hatho6cx9uzWwIDAQAB
AoGBAIPvjwr1OwrOyFIrnVMaWw2LkMdd6FpCEflYJRmPPLMHGkT2vgRSBN6RaVMy
J3J9vj1J/lBIZeIlAb/baDjeDnAj5GBzCB319oxnBuZSmpyYntW1DEsdhbK0Yeu+
7v05oXBXfzdZvGBWYrwlj5ipoHQo0R+WN4NVXqJFwiagaGBBAkEA6qwv5Pww54za
fHNUD1M6MKRBk5m0Y/GJ58sWmnmFJI6I3sHBIfcy5lylm5KecduzSKoVtAUUbNWf
KOKoZcKHMwJBAMRD2WDEd5+8q5ZxzYG0x5sEdz1lhJkt+YSbudNgfE1kPDDrCE0V
8+hgNdp6Mj1hfihwB0hTCcnaPsXLl9AyAzkCQDVU+HWD0uFso2LRGvN4qKrRSY3v
yo1EIWEqSHLG1zldo0FsqyW69jhgKcrXYWbi1TXYYaJN3Tx2t/skt7yYnv0CQDtD
NYdHq8tbAADcei5ZNRB058BtP/206SwGjbTq5H3F73rh7U7BezXGn1xKG5N3Nc3m
DfzjvgfqU5wMHtopz9kCQBw3AAiRCY8Y0UgejUtu8tXIK76qebaNcMCabBnFrAqV
A4Oj1c5BcOHVtww9W6NeiiRMJpUNN71gmyjsnOyT3cY=
-----END RSA PRIVATE KEY-----";

        let err = match build_rsa_keypair(RSA_1024) {
            Ok(_) => panic!("expected a 1024-bit RSA key to be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("1024 bits"), "{err}");
    }
}
