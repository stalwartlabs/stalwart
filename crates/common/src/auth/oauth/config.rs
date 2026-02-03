/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    config::{build_ecdsa_pem, build_rsa_keypair},
    manager::webadmin::Resource,
};
use biscuit::{
    jwa::{Algorithm, SignatureAlgorithm},
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, JWK, JWKSet, OctetKeyParameters, OctetKeyType, PublicKeyUse,
        RSAKeyParameters, RSAKeyType,
    },
    jws::Secret,
};
use registry::schema::{enums::JwtSignatureAlgorithm, prelude::Object, structs::Authentication};
use ring::signature::{self, KeyPair};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts};
use store::{
    rand::{Rng, distr::Alphanumeric, rng},
    registry::bootstrap::Bootstrap,
};
use x509_parser::num_bigint::BigUint;

#[derive(Clone)]
pub struct OAuthConfig {
    pub oauth_key: String,
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub oauth_expiry_refresh_token_renew: u64,
    pub oauth_max_auth_attempts: u32,

    pub allow_anonymous_client_registration: bool,
    pub require_client_authentication: bool,

    pub oidc_expiry_id_token: u64,
    pub oidc_signing_secret: Secret,
    pub oidc_signature_algorithm: SignatureAlgorithm,
    pub oidc_jwks: Resource<Vec<u8>>,
}

impl OAuthConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let auth = bp.setting_infallible::<Authentication>().await;

        let oidc_signature_algorithm = match auth.signature_algorithm {
            JwtSignatureAlgorithm::Es256 => SignatureAlgorithm::ES256,
            JwtSignatureAlgorithm::Es384 => SignatureAlgorithm::ES384,
            JwtSignatureAlgorithm::Ps256 => SignatureAlgorithm::PS256,
            JwtSignatureAlgorithm::Ps384 => SignatureAlgorithm::PS384,
            JwtSignatureAlgorithm::Ps512 => SignatureAlgorithm::PS512,
            JwtSignatureAlgorithm::Rs256 => SignatureAlgorithm::RS256,
            JwtSignatureAlgorithm::Rs384 => SignatureAlgorithm::RS384,
            JwtSignatureAlgorithm::Rs512 => SignatureAlgorithm::RS512,
            JwtSignatureAlgorithm::Hs256 => SignatureAlgorithm::HS256,
            JwtSignatureAlgorithm::Hs384 => SignatureAlgorithm::HS384,
            JwtSignatureAlgorithm::Hs512 => SignatureAlgorithm::HS512,
        };

        let rand_key = rng()
            .sample_iter(Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>()
            .into_bytes();

        let (oidc_signing_secret, algorithm) = match oidc_signature_algorithm {
            SignatureAlgorithm::None
            | SignatureAlgorithm::HS256
            | SignatureAlgorithm::HS384
            | SignatureAlgorithm::HS512 => (
                Secret::Bytes(auth.signature_key.as_bytes().to_vec()),
                AlgorithmParameters::OctetKey(OctetKeyParameters {
                    key_type: OctetKeyType::Octet,
                    value: auth.signature_key.as_bytes().to_vec(),
                }),
            ),
            SignatureAlgorithm::RS256
            | SignatureAlgorithm::RS384
            | SignatureAlgorithm::RS512
            | SignatureAlgorithm::PS256
            | SignatureAlgorithm::PS384
            | SignatureAlgorithm::PS512 => parse_rsa_key(&auth)
                .map_err(|err| {
                    bp.build_error(Object::Authentication.singleton(), err);
                })
                .unwrap_or_else(|_| {
                    (
                        Secret::Bytes(rand_key.clone()),
                        AlgorithmParameters::OctetKey(OctetKeyParameters {
                            key_type: OctetKeyType::Octet,
                            value: rand_key,
                        }),
                    )
                }),
            SignatureAlgorithm::ES256 | SignatureAlgorithm::ES384 | SignatureAlgorithm::ES512 => {
                parse_ecdsa_key(&auth, oidc_signature_algorithm)
                    .map_err(|err| {
                        bp.build_error(Object::Authentication.singleton(), err);
                    })
                    .unwrap_or_else(|_| {
                        (
                            Secret::Bytes(rand_key.clone()),
                            AlgorithmParameters::OctetKey(OctetKeyParameters {
                                key_type: OctetKeyType::Octet,
                                value: rand_key,
                            }),
                        )
                    })
            }
        };

        let oidc_jwks = Resource {
            content_type: "application/json".into(),
            contents: serde_json::to_string(&JWKSet {
                keys: vec![JWK {
                    common: CommonParameters {
                        public_key_use: PublicKeyUse::Signature.into(),
                        algorithm: Algorithm::Signature(oidc_signature_algorithm).into(),
                        key_id: "default".to_string().into(),
                        ..Default::default()
                    },
                    algorithm,
                    additional: (),
                }],
            })
            .unwrap_or_default()
            .into_bytes(),
        };

        OAuthConfig {
            oauth_key: auth.encryption_key,
            oauth_expiry_user_code: auth.user_code_expiry.as_secs(),
            oauth_expiry_auth_code: auth.auth_code_expiry.as_secs(),
            oauth_expiry_token: auth.access_token_expiry.as_secs(),
            oauth_expiry_refresh_token: auth.refresh_token_expiry.as_secs(),
            oauth_expiry_refresh_token_renew: auth.refresh_token_renewal.as_secs(),
            oauth_max_auth_attempts: auth.auth_code_max_attempts as u32,
            oidc_expiry_id_token: auth.id_token_expiry.as_secs(),
            allow_anonymous_client_registration: auth.anonymous_client_registration,
            require_client_authentication: auth.require_client_registration,
            oidc_signing_secret,
            oidc_signature_algorithm,
            oidc_jwks,
        }
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            oauth_key: Default::default(),
            oauth_expiry_user_code: Default::default(),
            oauth_expiry_auth_code: Default::default(),
            oauth_expiry_token: Default::default(),
            oauth_expiry_refresh_token: Default::default(),
            oauth_expiry_refresh_token_renew: Default::default(),
            oauth_max_auth_attempts: Default::default(),
            oidc_expiry_id_token: Default::default(),
            allow_anonymous_client_registration: Default::default(),
            require_client_authentication: Default::default(),
            oidc_signing_secret: Secret::Bytes("secret".to_string().into_bytes()),
            oidc_signature_algorithm: SignatureAlgorithm::HS256,
            oidc_jwks: Resource {
                content_type: "application/json".into(),
                contents: serde_json::to_string(&JWKSet::<()> { keys: vec![] })
                    .unwrap_or_default()
                    .into_bytes(),
            },
        }
    }
}

fn parse_rsa_key(auth: &Authentication) -> Result<(Secret, AlgorithmParameters), String> {
    let rsa_key_pair = build_rsa_keypair(&auth.signature_key)?;

    let rsa_public_key = match RsaPublicKey::from_pkcs1_der(rsa_key_pair.public_key().as_ref()) {
        Ok(key) => key,
        Err(err) => {
            return Err(format!("Failed to obtain RSA public key: {}", err));
        }
    };

    let rsa_key_params = RSAKeyParameters {
        key_type: RSAKeyType::RSA,
        n: BigUint::from_bytes_be(&rsa_public_key.n().to_bytes_be()),
        e: BigUint::from_bytes_be(&rsa_public_key.e().to_bytes_be()),
        ..Default::default()
    };

    Ok((
        Secret::RsaKeyPair(rsa_key_pair.into()),
        AlgorithmParameters::RSA(rsa_key_params),
    ))
}

fn parse_ecdsa_key(
    auth: &Authentication,
    oidc_signature_algorithm: SignatureAlgorithm,
) -> Result<(Secret, AlgorithmParameters), String> {
    let (alg, curve) = match oidc_signature_algorithm {
        SignatureAlgorithm::ES256 => (
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            EllipticCurve::P256,
        ),
        SignatureAlgorithm::ES384 => (
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            EllipticCurve::P384,
        ),
        _ => unreachable!(),
    };

    let ecdsa_key_pair = build_ecdsa_pem(alg, &auth.signature_key)?;
    let ecdsa_public_key = ecdsa_key_pair.public_key().as_ref();

    let (x, y) = match oidc_signature_algorithm {
        SignatureAlgorithm::ES256 => {
            let points = match p256::EncodedPoint::from_bytes(ecdsa_public_key) {
                Ok(points) => points,
                Err(err) => {
                    return Err(format!("Failed to parse ECDSA key: {}", err));
                }
            };

            (
                points.x().map(|x| x.to_vec()).unwrap_or_default(),
                points.y().map(|y| y.to_vec()).unwrap_or_default(),
            )
        }
        SignatureAlgorithm::ES384 => {
            let points = match p384::EncodedPoint::from_bytes(ecdsa_public_key) {
                Ok(points) => points,
                Err(err) => {
                    return Err(format!("Failed to parse ECDSA key: {}", err));
                }
            };

            (
                points.x().map(|x| x.to_vec()).unwrap_or_default(),
                points.y().map(|y| y.to_vec()).unwrap_or_default(),
            )
        }
        _ => unreachable!(),
    };

    let ecdsa_key_params = EllipticCurveKeyParameters {
        key_type: EllipticCurveKeyType::EC,
        curve,
        x,
        y,
        d: None,
    };

    Ok((
        Secret::EcdsaKeyPair(ecdsa_key_pair.into()),
        AlgorithmParameters::EllipticCurve(ecdsa_key_params),
    ))
}
