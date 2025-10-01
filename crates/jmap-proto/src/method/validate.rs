/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::SetError,
    object::sieve::SieveProperty,
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct ValidateSieveScriptRequest {
    pub account_id: Id,
    pub blob_id: MaybeInvalid<BlobId>,
}

#[derive(Debug, Serialize)]
pub struct ValidateSieveScriptResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    pub error: Option<SetError<SieveProperty>>,
}

impl<'de> DeserializeArguments<'de> for ValidateSieveScriptRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"blobId" => {
                self.blob_id = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for ValidateSieveScriptRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
