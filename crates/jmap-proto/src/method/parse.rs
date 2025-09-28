/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::email::{EmailProperty, EmailValue},
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
    },
};
use jmap_tools::Value;
use serde::{Deserialize, Deserializer};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Default)]
pub struct ParseEmailRequest {
    pub account_id: Id,
    pub blob_ids: Vec<MaybeInvalid<BlobId>>,
    pub properties: Option<Vec<MaybeInvalid<EmailProperty>>>,
    pub body_properties: Option<Vec<MaybeInvalid<EmailProperty>>>,
    pub fetch_text_body_values: Option<bool>,
    pub fetch_html_body_values: Option<bool>,
    pub fetch_all_body_values: Option<bool>,
    pub max_body_value_bytes: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ParseEmailResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "parsed")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub parsed: VecMap<BlobId, Value<'static, EmailProperty, EmailValue>>,

    #[serde(rename = "notParsable")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_parsable: Vec<BlobId>,

    #[serde(rename = "notFound")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<BlobId>,
}

impl<'de> DeserializeArguments<'de> for ParseEmailRequest {
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
            b"bodyProperties" => {
                self.body_properties = map.next_value()?;
            },
            b"fetchTextBodyValues" => {
                self.fetch_text_body_values = map.next_value()?;
            },
            b"fetchHTMLBodyValues" => {
                self.fetch_html_body_values = map.next_value()?;
            },
            b"fetchAllBodyValues" => {
                self.fetch_all_body_values = map.next_value()?;
            },
            b"maxBodyValueBytes" => {
                self.max_body_value_bytes = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for ParseEmailRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
