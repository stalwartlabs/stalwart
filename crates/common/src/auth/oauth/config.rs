/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{crypto::SymmetricEncrypt, token::TOKEN_KEY_CONTEXT};
use crate::{
    config::{EcKeyCurve, build_ecdsa_pem, build_rsa_keypair},
    manager::application::Resource,
};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use encodify::base64::URL_SAFE_NO_PAD;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, RSAKeyParameters,
        RSAKeyType,
    },
};
use registry::schema::{
    enums::{JwtSignatureAlgorithm, OAuthClientMetadataPolicy},
    prelude::ObjectType,
    structs::OidcProvider,
};
use std::borrow::Cow;
use store::{
    blake3,
    rand::{RngExt, distr::Alphanumeric, rng},
    registry::bootstrap::Bootstrap,
};

const REFRESH_NONCE_KEY_CONTEXT: &str = "stalwart-oauth-refresh-nonce-sw1";

#[derive(Clone)]
pub struct OAuthConfig {
    pub oauth_key: String,
    pub token_cipher: SymmetricEncrypt,
    pub refresh_nonce_key: [u8; 32],
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub client_metadata_documents: OAuthClientMetadataPolicy,

    pub oidc_expiry_id_token: u64,
    pub oidc_signing_secret: Option<EncodingKey>,
    pub oidc_verifying_key: Option<DecodingKey>,
    pub oidc_signature_algorithm: Algorithm,
    pub oidc_signature_algorithm_name: &'static str,
    pub oidc_jwks: Resource<Vec<u8>>,
}

impl OAuthConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let auth = bp.setting_infallible::<OidcProvider>().await;

        let (mut oidc_signature_algorithm, mut oidc_signature_algorithm_name) =
            match auth.signature_algorithm {
                JwtSignatureAlgorithm::Es256 => (Algorithm::ES256, "ES256"),
                JwtSignatureAlgorithm::Es384 => (Algorithm::ES384, "ES384"),
                JwtSignatureAlgorithm::Ps256 => (Algorithm::PS256, "PS256"),
                JwtSignatureAlgorithm::Ps384 => (Algorithm::PS384, "PS384"),
                JwtSignatureAlgorithm::Ps512 => (Algorithm::PS512, "PS512"),
                JwtSignatureAlgorithm::Rs256 => (Algorithm::RS256, "RS256"),
                JwtSignatureAlgorithm::Rs384 => (Algorithm::RS384, "RS384"),
                JwtSignatureAlgorithm::Rs512 => (Algorithm::RS512, "RS512"),
                JwtSignatureAlgorithm::Hs256 => (Algorithm::HS256, "HS256"),
                JwtSignatureAlgorithm::Hs384 => (Algorithm::HS384, "HS384"),
                JwtSignatureAlgorithm::Hs512 => (Algorithm::HS512, "HS512"),
            };

        let is_recovery_mode = bp.registry.is_recovery_mode();
        let is_hmac = matches!(
            oidc_signature_algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        );
        let mut signature_key = match auth.signature_key.secret().await {
            Ok(key) if !key.is_empty() => key,
            Ok(_) => {
                if is_hmac && !is_recovery_mode {
                    bp.build_error(
                        ObjectType::OidcProvider.singleton(),
                        "OIDC signature key is empty, using a random key",
                    );
                }
                Cow::Owned(random_secret())
            }
            Err(err) => {
                bp.build_error(ObjectType::OidcProvider.singleton(), err);
                Cow::Owned(random_secret())
            }
        };

        let asymmetric_key = match oidc_signature_algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => None,
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => Some(parse_rsa_key(&auth).await),
            Algorithm::ES256 | Algorithm::ES384 => {
                Some(parse_ecdsa_key(&auth, oidc_signature_algorithm).await)
            }
            _ => Some(Err(format!(
                "Unsupported OIDC signature algorithm {oidc_signature_algorithm:?}"
            ))),
        };

        let (oidc_signing_secret, algorithm) = match asymmetric_key {
            None => (
                EncodingKey::from_secret(signature_key.as_bytes()).ok(),
                None,
            ),
            Some(Ok((secret, params))) => (Some(secret), Some(params)),
            Some(Err(err)) => match ephemeral_ecdsa_key() {
                Ok((secret, params)) => {
                    bp.build_error(
                        ObjectType::OidcProvider.singleton(),
                        format!("{err}; using a temporary ES256 signing key"),
                    );
                    oidc_signature_algorithm = Algorithm::ES256;
                    oidc_signature_algorithm_name = "ES256";
                    (Some(secret), Some(params))
                }
                Err(ephemeral_err) => {
                    bp.build_error(
                        ObjectType::OidcProvider.singleton(),
                        format!(
                            "{err}; failed to generate a temporary signing key ({ephemeral_err}), using a random HS256 key"
                        ),
                    );
                    oidc_signature_algorithm = Algorithm::HS256;
                    oidc_signature_algorithm_name = "HS256";
                    signature_key = Cow::Owned(random_secret());
                    (
                        EncodingKey::from_secret(signature_key.as_bytes()).ok(),
                        None,
                    )
                }
            },
        };

        let oidc_verifying_key = match &algorithm {
            Some(params) => DecodingKey::from_jwk(&Jwk {
                common: CommonParameters::default(),
                algorithm: params.clone(),
            })
            .ok(),
            None => DecodingKey::from_secret(signature_key.as_bytes()).ok(),
        };

        let oidc_jwks = Resource {
            content_type: "application/json".into(),
            contents: serde_json::to_string(&JwkSet {
                keys: algorithm
                    .into_iter()
                    .map(|algorithm| Jwk {
                        common: CommonParameters {
                            public_key_use: PublicKeyUse::Signature.into(),
                            key_algorithm: KeyAlgorithm::from(oidc_signature_algorithm).into(),
                            key_id: "default".to_string().into(),
                            ..Default::default()
                        },
                        algorithm,
                    })
                    .collect(),
            })
            .unwrap_or_default()
            .into_bytes(),
        };

        let oauth_key = match auth.encryption_key.secret().await {
            Ok(key) if !key.is_empty() => key.into_owned(),
            Ok(_) => {
                if !is_recovery_mode {
                    bp.build_error(
                        ObjectType::OidcProvider.singleton(),
                        "OAuth encryption key is empty, using a random key",
                    );
                }
                random_secret()
            }
            Err(err) => {
                bp.build_error(ObjectType::OidcProvider.singleton(), err);
                random_secret()
            }
        };

        OAuthConfig {
            token_cipher: SymmetricEncrypt::new(oauth_key.as_bytes(), TOKEN_KEY_CONTEXT),
            refresh_nonce_key: blake3::derive_key(REFRESH_NONCE_KEY_CONTEXT, oauth_key.as_bytes()),
            oauth_key,
            oauth_expiry_user_code: auth.user_code_expiry.as_secs(),
            oauth_expiry_auth_code: auth.auth_code_expiry.as_secs(),
            oauth_expiry_token: auth.access_token_expiry.as_secs(),
            oauth_expiry_refresh_token: auth.refresh_token_expiry.as_secs(),
            client_metadata_documents: auth.client_metadata_documents,
            oidc_expiry_id_token: auth.id_token_expiry.as_secs(),
            oidc_signing_secret,
            oidc_verifying_key,
            oidc_signature_algorithm,
            oidc_signature_algorithm_name,
            oidc_jwks,
        }
    }
}

async fn parse_rsa_key(auth: &OidcProvider) -> Result<(EncodingKey, AlgorithmParameters), String> {
    let rsa_key = build_rsa_keypair(auth.signature_key.secret().await?.as_ref())?;

    let rsa_key_params = RSAKeyParameters {
        key_type: RSAKeyType::RSA,
        n: URL_SAFE_NO_PAD.encode(&rsa_key.modulus),
        e: URL_SAFE_NO_PAD.encode(&rsa_key.exponent),
    };

    Ok((
        EncodingKey::from_rsa_der(&rsa_key.pkcs1_der),
        AlgorithmParameters::RSA(rsa_key_params),
    ))
}

async fn parse_ecdsa_key(
    auth: &OidcProvider,
    oidc_signature_algorithm: Algorithm,
) -> Result<(EncodingKey, AlgorithmParameters), String> {
    let (curve, ec_curve) = match oidc_signature_algorithm {
        Algorithm::ES256 => (EllipticCurve::P256, EcKeyCurve::P256),
        Algorithm::ES384 => (EllipticCurve::P384, EcKeyCurve::P384),
        _ => unreachable!(),
    };

    ecdsa_key(curve, ec_curve, auth.signature_key.secret().await?.as_ref())
}

fn ephemeral_ecdsa_key() -> Result<(EncodingKey, AlgorithmParameters), String> {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map_err(|err| format!("Failed to generate ECDSA key: {err}"))?;
    ecdsa_key(
        EllipticCurve::P256,
        EcKeyCurve::P256,
        &pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref())),
    )
}

fn ecdsa_key(
    curve: EllipticCurve,
    ec_curve: EcKeyCurve,
    pem: &str,
) -> Result<(EncodingKey, AlgorithmParameters), String> {
    let ecdsa_key = build_ecdsa_pem(ec_curve, pem)?;

    let ecdsa_key_params = EllipticCurveKeyParameters {
        key_type: EllipticCurveKeyType::EC,
        curve,
        x: URL_SAFE_NO_PAD.encode(&ecdsa_key.x),
        y: URL_SAFE_NO_PAD.encode(&ecdsa_key.y),
    };

    Ok((
        EncodingKey::from_ec_der(&ecdsa_key.pkcs8_der),
        AlgorithmParameters::EllipticCurve(ecdsa_key_params),
    ))
}

fn random_secret() -> String {
    rng()
        .sample_iter(Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/config/tests.rs"]
mod tests;
