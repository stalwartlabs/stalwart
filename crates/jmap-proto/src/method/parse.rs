/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::JmapObject,
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::MaybeIdReference,
    },
};
use jmap_tools::Value;
use serde::{Deserialize, Deserializer};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone)]
pub struct ParseRequest<T: JmapObject> {
    pub account_id: Id,
    pub blob_ids: Vec<MaybeIdReference<BlobId>>,
    pub properties: Option<Vec<MaybeInvalid<T::Property>>>,
    pub arguments: T::ParseArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ParseResponse<T: JmapObject> {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "parsed")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub parsed: VecMap<BlobId, Value<'static, T::Property, T::Element>>,

    #[serde(rename = "notParsable")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_parsable: Vec<BlobId>,

    #[serde(rename = "notFound")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<BlobId>,
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for ParseRequest<T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"blobIds" => {
                self.blob_ids = map.next_value()?;
            },
            b"properties" => {
                self.properties = map.next_value()?;
            },
            _ => {
                self.arguments.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T: JmapObject> Deserialize<'de> for ParseRequest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T: JmapObject> Default for ParseRequest<T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            blob_ids: Vec::default(),
            properties: None,
            arguments: T::ParseArguments::default(),
        }
    }
}
