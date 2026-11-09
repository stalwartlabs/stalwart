/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::KV_OAUTH;
use aws_lc_rs::{
    digest::{SHA256, digest},
    signature::{
        ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
        UnparsedPublicKey,
    },
};
use encodify::base64::URL_SAFE_NO_PAD;
use registry::schema::enums::PasskeyAlgorithm;
use serde::Deserialize;
use std::borrow::Cow;
use store::rand;

pub mod assertion;
mod cbor;
pub mod registration;
pub mod server;

pub const PASSKEY_CHALLENGE_LEN: usize = 32;
pub const PASSKEY_CHALLENGE_TTL: u64 = 300;
pub const PASSKEY_TIMEOUT_MS: u64 = PASSKEY_CHALLENGE_TTL * 1000;
pub const PASSKEY_MAX_CREDENTIAL_ID_LEN: usize = 1023;
pub const PASSKEY_USER_HANDLE_LEN: usize = 4;

pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;
pub const COSE_ALG_RS256: i64 = -257;
pub const PASSKEY_ALGORITHMS: [i64; 3] = [COSE_ALG_ES256, COSE_ALG_EDDSA, COSE_ALG_RS256];

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

const RP_ID_HASH_LEN: usize = 32;
const CLIENT_DATA_HASH_LEN: usize = 32;
const AUTH_DATA_MIN_LEN: usize = RP_ID_HASH_LEN + 1 + 4;
const P256_COORDINATE_LEN: usize = 32;
const ED25519_KEY_LEN: usize = 32;
const RSA_MIN_MODULUS_LEN: usize = 256;
const RSA_MAX_MODULUS_LEN: usize = 1024;
const RSA_MAX_EXPONENT_LEN: usize = 8;
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyError {
    Encoding,
    Cbor,
    ClientDataType,
    Origin,
    CrossOrigin,
    RpIdHash,
    UserPresence,
    UserVerification,
    BackupState,
    AuthenticatorData,
    Algorithm,
    PublicKey,
    AttestationFormat,
    AttestationSignature,
    Signature,
    UserHandle,
}

impl PasskeyError {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasskeyError::Encoding => "Invalid passkey encoding",
            PasskeyError::Cbor => "Invalid CBOR data",
            PasskeyError::ClientDataType => "Unexpected client data type",
            PasskeyError::Origin => "Origin not allowed",
            PasskeyError::CrossOrigin => "Cross-origin ceremony not allowed",
            PasskeyError::RpIdHash => "Relying party ID hash mismatch",
            PasskeyError::UserPresence => "User presence flag not set",
            PasskeyError::UserVerification => "User verification flag not set",
            PasskeyError::BackupState => "Invalid backup state flags",
            PasskeyError::AuthenticatorData => "Invalid authenticator data",
            PasskeyError::Algorithm => "Unsupported public key algorithm",
            PasskeyError::PublicKey => "Invalid credential public key",
            PasskeyError::AttestationFormat => "Unsupported attestation format",
            PasskeyError::AttestationSignature => "Invalid attestation signature",
            PasskeyError::Signature => "Invalid assertion signature",
            PasskeyError::UserHandle => "Invalid user handle",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyPublicKey<B = Vec<u8>> {
    pub algorithm: PasskeyAlgorithm,
    pub key: B,
}

impl<B: AsRef<[u8]>> PasskeyPublicKey<B> {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify_signature(self.algorithm, self.key.as_ref(), message, signature)
    }
}

fn verify_signature(
    algorithm: PasskeyAlgorithm,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        PasskeyAlgorithm::Es256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(message, signature)
            .is_ok(),
        PasskeyAlgorithm::Ed25519 => UnparsedPublicKey::new(&ED25519, key)
            .verify(message, signature)
            .is_ok(),
        PasskeyAlgorithm::Rs256 => key.split_first().is_some_and(|(&e_len, rest)| {
            rest.split_at_checked(usize::from(e_len))
                .is_some_and(|(e, n)| {
                    RsaPublicKeyComponents { n, e }
                        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                        .is_ok()
                })
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyChallenge(pub [u8; PASSKEY_CHALLENGE_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyCeremony {
    SignIn,
    Registration { account_id: u32 },
}

impl PasskeyChallenge {
    pub fn random() -> Self {
        PasskeyChallenge(rand::random())
    }

    pub fn parse(encoded: &str) -> Option<Self> {
        let mut challenge = [0u8; PASSKEY_CHALLENGE_LEN];
        URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut challenge)
            .ok()
            .filter(|&len| len == PASSKEY_CHALLENGE_LEN)
            .map(|_| PasskeyChallenge(challenge))
    }

    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn store_key(&self, ceremony: PasskeyCeremony) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + 1 + 4 + PASSKEY_CHALLENGE_LEN);
        key.push(KV_OAUTH);
        match ceremony {
            PasskeyCeremony::SignIn => key.push(0),
            PasskeyCeremony::Registration { account_id } => {
                key.push(1);
                key.extend_from_slice(&account_id.to_be_bytes());
            }
        }
        key.extend_from_slice(&self.0);
        key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyUserHandle(pub u32);

impl PasskeyUserHandle {
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.to_be_bytes())
    }

    pub fn parse(encoded: &str) -> Option<Self> {
        let mut handle = [0u8; PASSKEY_USER_HANDLE_LEN];
        URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut handle)
            .ok()
            .filter(|&len| len == PASSKEY_USER_HANDLE_LEN)
            .map(|_| PasskeyUserHandle(u32::from_be_bytes(handle)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRp<'x> {
    pub id: Cow<'x, str>,
    pub origin: &'x str,
}

impl<'x> PasskeyRp<'x> {
    pub fn from_issuer(issuer: &'x str) -> Option<Self> {
        let (scheme, rest) = issuer.split_once("://")?;
        let authority = rest
            .split_once('/')
            .map_or(rest, |(authority, _)| authority);
        let origin = issuer.get(..scheme.len() + 3 + authority.len())?;
        let default_port = if scheme.eq_ignore_ascii_case("https") {
            ":443"
        } else {
            ":80"
        };
        let origin = origin.strip_suffix(default_port).unwrap_or(origin);
        let id = match authority.strip_prefix('[') {
            Some(ipv6) => ipv6.split_once(']').map(|(host, _)| host)?,
            None => authority
                .rsplit_once(':')
                .map_or(authority, |(host, _)| host),
        };
        if id.is_empty() {
            None
        } else if id.bytes().any(|ch| ch.is_ascii_uppercase()) {
            Some(PasskeyRp {
                id: Cow::Owned(id.to_ascii_lowercase()),
                origin,
            })
        } else {
            Some(PasskeyRp {
                id: Cow::Borrowed(id),
                origin,
            })
        }
    }

    pub fn id_hash(&self) -> [u8; RP_ID_HASH_LEN] {
        let mut hash = [0u8; RP_ID_HASH_LEN];
        hash.copy_from_slice(digest(&SHA256, self.id.as_bytes()).as_ref());
        hash
    }

    pub fn is_sign_in_origin(&self, origin: &str) -> bool {
        origin.eq_ignore_ascii_case(self.origin)
    }

    pub fn is_registration_origin(&self, origin: &str) -> bool {
        if origin.eq_ignore_ascii_case(self.origin) {
            return true;
        }
        let Some(authority) = origin.strip_prefix("https://") else {
            return false;
        };
        let host = authority
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|ch| ch.is_ascii_digit()))
            .map_or(authority, |(host, _)| host);
        host.eq_ignore_ascii_case(&self.id)
            || host
                .len()
                .checked_sub(self.id.len() + 1)
                .filter(|&split| split > 0)
                .and_then(|split| host.split_at_checked(split))
                .is_some_and(|(_, suffix)| {
                    suffix
                        .strip_prefix('.')
                        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(&self.id))
                })
    }
}

#[derive(Debug, Deserialize)]
struct ClientData<'x> {
    #[serde(rename = "type")]
    typ: &'x str,
    challenge: &'x str,
    #[serde(borrow)]
    origin: Cow<'x, str>,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
    #[serde(rename = "topOrigin", default)]
    top_origin: Option<serde::de::IgnoredAny>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientDataType {
    Create,
    Get,
}

struct VerifiedClientData {
    challenge: PasskeyChallenge,
    hash: [u8; CLIENT_DATA_HASH_LEN],
}

fn verify_client_data(
    client_data_json: &[u8],
    expected_type: ClientDataType,
    is_allowed_origin: impl FnOnce(&str) -> bool,
) -> Result<VerifiedClientData, PasskeyError> {
    let client_data = serde_json::from_slice::<ClientData<'_>>(
        client_data_json
            .strip_prefix(UTF8_BOM)
            .unwrap_or(client_data_json),
    )
    .map_err(|_| PasskeyError::Encoding)?;
    let typ = match expected_type {
        ClientDataType::Create => "webauthn.create",
        ClientDataType::Get => "webauthn.get",
    };
    if client_data.typ != typ {
        return Err(PasskeyError::ClientDataType);
    }
    if client_data.cross_origin || client_data.top_origin.is_some() {
        return Err(PasskeyError::CrossOrigin);
    }
    if !is_allowed_origin(&client_data.origin) {
        return Err(PasskeyError::Origin);
    }
    let challenge = PasskeyChallenge::parse(client_data.challenge).ok_or(PasskeyError::Encoding)?;
    let mut hash = [0u8; CLIENT_DATA_HASH_LEN];
    hash.copy_from_slice(digest(&SHA256, client_data_json).as_ref());
    Ok(VerifiedClientData { challenge, hash })
}

fn verify_flags(flags: u8) -> Result<(), PasskeyError> {
    if flags & FLAG_UP == 0 {
        Err(PasskeyError::UserPresence)
    } else if flags & FLAG_UV == 0 {
        Err(PasskeyError::UserVerification)
    } else if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        Err(PasskeyError::BackupState)
    } else {
        Ok(())
    }
}

fn decode_base64(encoded: &str, max_len: usize) -> Result<Vec<u8>, PasskeyError> {
    decode_base64_with_capacity(encoded, max_len, 0)
}

fn decode_base64_with_capacity(
    encoded: &str,
    max_len: usize,
    extra_capacity: usize,
) -> Result<Vec<u8>, PasskeyError> {
    let len = encoded.len() / 4 * 3 + (encoded.len() % 4).saturating_sub(1);
    if len > max_len {
        return Err(PasskeyError::Encoding);
    }
    let mut decoded = Vec::with_capacity(len + extra_capacity);
    URL_SAFE_NO_PAD
        .decode_append(encoded, &mut decoded)
        .map_err(|_| PasskeyError::Encoding)?;
    Ok(decoded)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/passkey/tests.rs"]
mod tests;
