/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::request::{
    MaybeInvalid,
    deserialize::{DeserializeArguments, deserialize_request},
};
use serde::{Deserialize, Deserializer};
use types::{blob::BlobId, id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Default)]
pub struct BlobLookupRequest {
    pub account_id: Id,
    pub type_names: Vec<MaybeInvalid<DataType>>,
    pub ids: Vec<MaybeInvalid<BlobId>>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobLookupResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "list")]
    pub list: Vec<BlobInfo>,

    #[serde(rename = "notFound")]
    pub not_found: Vec<BlobId>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobInfo {
    pub id: BlobId,
    #[serde(rename = "matchedIds")]
    pub matched_ids: VecMap<DataType, Vec<Id>>,
}

impl<'de> DeserializeArguments<'de> for BlobLookupRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"typeNames" => {
                self.type_names = map.next_value()?;
            },
            b"ids" => {
                self.ids = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlobLookupRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
