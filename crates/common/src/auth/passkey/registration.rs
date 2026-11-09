/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AUTH_DATA_MIN_LEN, CLIENT_DATA_HASH_LEN, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_RS256,
    ClientDataType, ED25519_KEY_LEN, FLAG_AT, FLAG_ED, P256_COORDINATE_LEN,
    PASSKEY_MAX_CREDENTIAL_ID_LEN, PasskeyChallenge, PasskeyError, PasskeyPublicKey, PasskeyRp,
    RP_ID_HASH_LEN, RSA_MAX_EXPONENT_LEN, RSA_MAX_MODULUS_LEN, RSA_MIN_MODULUS_LEN,
    cbor::{CborKey, CborReader, CborValue},
    decode_base64, verify_client_data, verify_flags,
};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use registry::schema::enums::PasskeyAlgorithm;

const MAX_CLIENT_DATA_LEN: usize = 4096;
const MAX_ATTESTATION_OBJECT_LEN: usize = 16384;
const AAGUID_LEN: usize = 16;

const COSE_KEY_KTY: i64 = 1;
const COSE_KEY_ALG: i64 = 3;
const COSE_KEY_PARAM_1: i64 = -1;
const COSE_KEY_PARAM_2: i64 = -2;
const COSE_KEY_PARAM_3: i64 = -3;
const COSE_KTY_OKP: i64 = 1;
const COSE_KTY_EC2: i64 = 2;
const COSE_KTY_RSA: i64 = 3;
const COSE_CRV_P256: i64 = 1;
const COSE_CRV_ED25519: i64 = 6;
const SEC1_UNCOMPRESSED: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredPasskey {
    pub challenge: PasskeyChallenge,
    pub key_id: Vec<u8>,
    pub public_key: PasskeyPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttestationFormat {
    None,
    Packed,
}

struct AttestationObject<'x> {
    fmt: AttestationFormat,
    att_stmt: &'x [u8],
    auth_data: &'x [u8],
}

struct AttestedCredential<'x> {
    key_id: &'x [u8],
    public_key: PasskeyPublicKey,
}

pub fn verify_registration(
    client_data_json: &str,
    attestation_object: &str,
    rp: &PasskeyRp<'_>,
) -> Result<RegisteredPasskey, PasskeyError> {
    let client_data_json = decode_base64(client_data_json, MAX_CLIENT_DATA_LEN)?;
    let attestation_object = decode_base64(attestation_object, MAX_ATTESTATION_OBJECT_LEN)?;
    let client_data = verify_client_data(&client_data_json, ClientDataType::Create, |origin| {
        rp.is_registration_origin(origin)
    })?;
    let attestation = AttestationObject::parse(&attestation_object)?;
    let credential = parse_auth_data(attestation.auth_data, rp)?;
    attestation.verify_statement(&credential.public_key, &client_data.hash)?;

    Ok(RegisteredPasskey {
        challenge: client_data.challenge,
        key_id: credential.key_id.to_vec(),
        public_key: credential.public_key,
    })
}

impl<'x> AttestationObject<'x> {
    fn parse(bytes: &'x [u8]) -> Result<Self, PasskeyError> {
        let mut reader = CborReader::new(bytes);
        let mut fmt = None;
        let mut att_stmt = None;
        let mut auth_data = None;

        for _ in 0..reader.map()? {
            let CborKey::Text(key) = reader.key()? else {
                return Err(PasskeyError::Cbor);
            };
            let is_new = hashify::fnc_map!(key.as_bytes(),
                "fmt" => fmt.replace(AttestationFormat::parse(reader.text()?)?).is_none(),
                "attStmt" => att_stmt.replace(reader.skip()?).is_none(),
                "authData" => auth_data.replace(reader.bytes()?).is_none(),
                _ => {
                    reader.skip()?;
                    true
                }
            );
            if !is_new {
                return Err(PasskeyError::Cbor);
            }
        }

        match (fmt, att_stmt, auth_data) {
            (Some(fmt), Some(att_stmt), Some(auth_data)) if reader.remaining().is_empty() => {
                Ok(AttestationObject {
                    fmt,
                    att_stmt,
                    auth_data,
                })
            }
            _ => Err(PasskeyError::Cbor),
        }
    }

    fn verify_statement(
        &self,
        public_key: &PasskeyPublicKey,
        client_data_hash: &[u8; CLIENT_DATA_HASH_LEN],
    ) -> Result<(), PasskeyError> {
        let mut reader = CborReader::new(self.att_stmt);
        let entries = reader.map()?;
        match self.fmt {
            AttestationFormat::None if entries == 0 => Ok(()),
            AttestationFormat::None => Err(PasskeyError::AttestationFormat),
            AttestationFormat::Packed => {
                let mut alg = None;
                let mut sig = None;
                for _ in 0..entries {
                    let CborKey::Text(key) = reader.key()? else {
                        return Err(PasskeyError::Cbor);
                    };
                    let is_new = hashify::fnc_map!(key.as_bytes(),
                        "alg" => alg.replace(reader.int()?).is_none(),
                        "sig" => sig.replace(reader.bytes()?).is_none(),
                        _ => return Err(PasskeyError::AttestationFormat)
                    );
                    if !is_new {
                        return Err(PasskeyError::Cbor);
                    }
                }
                let (Some(alg), Some(sig)) = (alg, sig) else {
                    return Err(PasskeyError::AttestationFormat);
                };
                if alg != cose_algorithm(public_key.algorithm) {
                    return Err(PasskeyError::AttestationSignature);
                }
                let mut message = Vec::with_capacity(self.auth_data.len() + client_data_hash.len());
                message.extend_from_slice(self.auth_data);
                message.extend_from_slice(client_data_hash);
                if public_key.verify(&message, sig) {
                    Ok(())
                } else {
                    Err(PasskeyError::AttestationSignature)
                }
            }
        }
    }
}

impl AttestationFormat {
    fn parse(fmt: &str) -> Result<Self, PasskeyError> {
        hashify::map!(fmt.as_bytes(), AttestationFormat,
            "none" => AttestationFormat::None,
            "packed" => AttestationFormat::Packed,
        )
        .copied()
        .ok_or(PasskeyError::AttestationFormat)
    }
}

fn parse_auth_data<'x>(
    auth_data: &'x [u8],
    rp: &PasskeyRp<'_>,
) -> Result<AttestedCredential<'x>, PasskeyError> {
    if auth_data.len() < AUTH_DATA_MIN_LEN {
        return Err(PasskeyError::AuthenticatorData);
    }
    let (rp_id_hash, rest) = auth_data
        .split_first_chunk::<RP_ID_HASH_LEN>()
        .ok_or(PasskeyError::AuthenticatorData)?;
    if *rp_id_hash != rp.id_hash() {
        return Err(PasskeyError::RpIdHash);
    }
    let (&flags, rest) = rest.split_first().ok_or(PasskeyError::AuthenticatorData)?;
    verify_flags(flags)?;
    if flags & FLAG_AT == 0 {
        return Err(PasskeyError::AuthenticatorData);
    }
    let (_sign_count, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(PasskeyError::AuthenticatorData)?;
    let (_aaguid, rest) = rest
        .split_first_chunk::<AAGUID_LEN>()
        .ok_or(PasskeyError::AuthenticatorData)?;
    let (key_id_len, rest) = rest
        .split_first_chunk::<2>()
        .ok_or(PasskeyError::AuthenticatorData)?;
    let key_id_len = usize::from(u16::from_be_bytes(*key_id_len));
    if key_id_len == 0 || key_id_len > PASSKEY_MAX_CREDENTIAL_ID_LEN {
        return Err(PasskeyError::AuthenticatorData);
    }
    let (key_id, rest) = rest
        .split_at_checked(key_id_len)
        .ok_or(PasskeyError::AuthenticatorData)?;

    let mut reader = CborReader::new(rest);
    let public_key = parse_cose_key(&mut reader)?;
    if flags & FLAG_ED != 0 {
        for _ in 0..reader.map()? {
            reader.skip()?;
            reader.skip()?;
        }
    }
    if !reader.remaining().is_empty() {
        return Err(PasskeyError::AuthenticatorData);
    }

    Ok(AttestedCredential { key_id, public_key })
}

fn parse_cose_key(reader: &mut CborReader<'_>) -> Result<PasskeyPublicKey, PasskeyError> {
    let mut kty = None;
    let mut alg = None;
    let mut param_1 = None;
    let mut param_2 = None;
    let mut param_3 = None;

    for _ in 0..reader.map()? {
        let is_new = match reader.key()? {
            CborKey::Int(COSE_KEY_KTY) => kty.replace(reader.int()?).is_none(),
            CborKey::Int(COSE_KEY_ALG) => alg.replace(reader.int()?).is_none(),
            CborKey::Int(COSE_KEY_PARAM_1) => param_1.replace(reader.value()?).is_none(),
            CborKey::Int(COSE_KEY_PARAM_2) => param_2.replace(reader.value()?).is_none(),
            CborKey::Int(COSE_KEY_PARAM_3) => param_3.replace(reader.value()?).is_none(),
            CborKey::Int(_) | CborKey::Text(_) => {
                reader.skip()?;
                true
            }
        };
        if !is_new {
            return Err(PasskeyError::Cbor);
        }
    }

    let public_key = match (alg, kty, param_1, param_2, param_3) {
        (
            Some(COSE_ALG_ES256),
            Some(COSE_KTY_EC2),
            Some(CborValue::Int(COSE_CRV_P256)),
            Some(CborValue::Bytes(x)),
            Some(CborValue::Bytes(y)),
        ) if x.len() == P256_COORDINATE_LEN && y.len() == P256_COORDINATE_LEN => {
            let mut key = Vec::with_capacity(1 + P256_COORDINATE_LEN * 2);
            key.push(SEC1_UNCOMPRESSED);
            key.extend_from_slice(x);
            key.extend_from_slice(y);
            PasskeyPublicKey {
                algorithm: PasskeyAlgorithm::Es256,
                key,
            }
        }
        (
            Some(COSE_ALG_EDDSA),
            Some(COSE_KTY_OKP),
            Some(CborValue::Int(COSE_CRV_ED25519)),
            Some(CborValue::Bytes(x)),
            None,
        ) if x.len() == ED25519_KEY_LEN => PasskeyPublicKey {
            algorithm: PasskeyAlgorithm::Ed25519,
            key: x.to_vec(),
        },
        (
            Some(COSE_ALG_RS256),
            Some(COSE_KTY_RSA),
            Some(CborValue::Bytes(n)),
            Some(CborValue::Bytes(e)),
            None,
        ) if (RSA_MIN_MODULUS_LEN..=RSA_MAX_MODULUS_LEN).contains(&n.len())
            && is_valid_rsa_exponent(e) =>
        {
            let mut key = Vec::with_capacity(1 + e.len() + n.len());
            key.push(e.len() as u8);
            key.extend_from_slice(e);
            key.extend_from_slice(n);
            PasskeyPublicKey {
                algorithm: PasskeyAlgorithm::Rs256,
                key,
            }
        }
        (Some(COSE_ALG_ES256 | COSE_ALG_EDDSA | COSE_ALG_RS256), ..) => {
            return Err(PasskeyError::PublicKey);
        }
        _ => return Err(PasskeyError::Algorithm),
    };

    if public_key.is_valid() {
        Ok(public_key)
    } else {
        Err(PasskeyError::PublicKey)
    }
}

impl PasskeyPublicKey {
    fn is_valid(&self) -> bool {
        match self.algorithm {
            PasskeyAlgorithm::Es256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.key)
                .parse()
                .is_ok(),
            PasskeyAlgorithm::Ed25519 => {
                UnparsedPublicKey::new(&ED25519, &self.key).parse().is_ok()
            }
            PasskeyAlgorithm::Rs256 => self.key.split_first().is_some_and(|(&e_len, rest)| {
                rest.split_at_checked(usize::from(e_len))
                    .is_some_and(|(e, n)| {
                        RsaPublicKeyComponents { n, e }
                            .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
                            .is_ok()
                    })
            }),
        }
    }
}

fn is_valid_rsa_exponent(e: &[u8]) -> bool {
    match e {
        [single] => *single >= 3 && single & 1 == 1,
        [first, .., last] => e.len() <= RSA_MAX_EXPONENT_LEN && *first != 0 && last & 1 == 1,
        [] => false,
    }
}

pub fn cose_algorithm(algorithm: PasskeyAlgorithm) -> i64 {
    match algorithm {
        PasskeyAlgorithm::Es256 => COSE_ALG_ES256,
        PasskeyAlgorithm::Ed25519 => COSE_ALG_EDDSA,
        PasskeyAlgorithm::Rs256 => COSE_ALG_RS256,
    }
}
