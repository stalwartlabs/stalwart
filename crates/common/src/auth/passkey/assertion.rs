/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AUTH_DATA_MIN_LEN, CLIENT_DATA_HASH_LEN, ClientDataType, FLAG_AT,
    PASSKEY_MAX_CREDENTIAL_ID_LEN, PasskeyChallenge, PasskeyError, PasskeyPublicKey, PasskeyRp,
    PasskeyUserHandle, RP_ID_HASH_LEN, RSA_MAX_EXPONENT_LEN, RSA_MAX_MODULUS_LEN, decode_base64,
    decode_base64_with_capacity, verify_client_data, verify_flags,
};
use encodify::base64::URL_SAFE_NO_PAD;
use registry::schema::structs::PasskeyCredential;

const MAX_CLIENT_DATA_LEN: usize = 4096;
const MAX_AUTH_DATA_LEN: usize = 4096;
const MAX_SIGNATURE_LEN: usize = RSA_MAX_MODULUS_LEN;
const MAX_STORED_KEY_LEN: usize = 1 + RSA_MAX_EXPONENT_LEN + RSA_MAX_MODULUS_LEN;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAssertion {
    pub raw_id: String,
    pub response: PasskeyAssertionResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PasskeyAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle", default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

#[derive(Debug)]
pub struct ParsedAssertion<'x> {
    pub user_handle: PasskeyUserHandle,
    pub challenge: PasskeyChallenge,
    pub key_id: &'x str,
    signed_data: Vec<u8>,
    signature: Vec<u8>,
}

impl PasskeyAssertion {
    pub fn parse(&self, rp: &PasskeyRp<'_>) -> Result<ParsedAssertion<'_>, PasskeyError> {
        let user_handle = self
            .response
            .user_handle
            .as_deref()
            .and_then(PasskeyUserHandle::parse)
            .ok_or(PasskeyError::UserHandle)?;
        let mut key_id = [0u8; PASSKEY_MAX_CREDENTIAL_ID_LEN];
        if !URL_SAFE_NO_PAD
            .decode_slice(&self.raw_id, &mut key_id)
            .is_ok_and(|len| len > 0)
        {
            return Err(PasskeyError::Encoding);
        }

        let client_data_json = decode_base64(&self.response.client_data_json, MAX_CLIENT_DATA_LEN)?;
        let client_data = verify_client_data(&client_data_json, ClientDataType::Get, |origin| {
            rp.is_sign_in_origin(origin)
        })?;

        let mut signed_data = decode_base64_with_capacity(
            &self.response.authenticator_data,
            MAX_AUTH_DATA_LEN,
            CLIENT_DATA_HASH_LEN,
        )?;
        if signed_data.len() < AUTH_DATA_MIN_LEN {
            return Err(PasskeyError::AuthenticatorData);
        }
        let (rp_id_hash, rest) = signed_data
            .split_first_chunk::<RP_ID_HASH_LEN>()
            .ok_or(PasskeyError::AuthenticatorData)?;
        if *rp_id_hash != rp.id_hash() {
            return Err(PasskeyError::RpIdHash);
        }
        let flags = rest
            .first()
            .copied()
            .ok_or(PasskeyError::AuthenticatorData)?;
        verify_flags(flags)?;
        if flags & FLAG_AT != 0 {
            return Err(PasskeyError::AuthenticatorData);
        }
        signed_data.extend_from_slice(&client_data.hash);

        let signature = decode_base64(&self.response.signature, MAX_SIGNATURE_LEN)?;

        Ok(ParsedAssertion {
            user_handle,
            challenge: client_data.challenge,
            key_id: &self.raw_id,
            signed_data,
            signature,
        })
    }
}

impl ParsedAssertion<'_> {
    pub fn verify_signature(&self, credential: &PasskeyCredential) -> Result<(), PasskeyError> {
        let mut key = [0u8; MAX_STORED_KEY_LEN];
        let key_len = URL_SAFE_NO_PAD
            .decode_slice(&credential.public_key, &mut key)
            .map_err(|_| PasskeyError::PublicKey)?;
        let key = key.get(..key_len).ok_or(PasskeyError::PublicKey)?;
        if (PasskeyPublicKey {
            algorithm: credential.algorithm,
            key,
        })
        .verify(&self.signed_data, &self.signature)
        {
            Ok(())
        } else {
            Err(PasskeyError::Signature)
        }
    }
}
