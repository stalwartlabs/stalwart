/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::request::deserialize::{DeserializeArguments, deserialize_request};
use serde::{Deserialize, Deserializer, Serialize};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct PasskeyRegistrationOptionsRequest {
    pub account_id: Id,
    pub current_secret: Option<String>,
    pub otp_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegistrationOptionsResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "publicKey")]
    pub public_key: PasskeyCreationOptions,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreationOptions {
    pub rp: PasskeyRpEntity,
    pub user: PasskeyUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PasskeyCredentialParameters>,
    pub timeout: u64,
    pub exclude_credentials: Vec<PasskeyCredentialDescriptor>,
    pub authenticator_selection: PasskeyAuthenticatorSelection,
    pub attestation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRpEntity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyCredentialParameters {
    #[serde(rename = "type")]
    pub typ: &'static str,
    pub alg: i64,
}

#[derive(Debug, Serialize)]
pub struct PasskeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub typ: &'static str,
    pub id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticatorSelection {
    pub resident_key: &'static str,
    pub require_resident_key: bool,
    pub user_verification: &'static str,
}

impl<'de> DeserializeArguments<'de> for PasskeyRegistrationOptionsRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = crate::request::deserialize_account_id(map)?;
            },
            b"currentSecret" => {
                self.current_secret = map.next_value()?;
            },
            b"otpCode" => {
                self.otp_code = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for PasskeyRegistrationOptionsRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
