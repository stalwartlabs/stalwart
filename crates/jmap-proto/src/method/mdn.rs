/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::SetError,
    object::{
        email::{EmailProperty, EmailValue},
        mdn::{Mdn, MdnProperty},
    },
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::MaybeIdReference,
    },
};
use jmap_tools::Value;
use serde::{Deserialize, Deserializer, Serialize};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Default)]
pub struct MdnSendRequest<'x> {
    pub account_id: Id,
    pub identity_id: Option<MaybeInvalid<Id>>,
    pub send: VecMap<String, Mdn>,
    pub on_success_update_email:
        Option<VecMap<MaybeIdReference<Id>, Value<'x, EmailProperty, EmailValue>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MdnSendResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "sent")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub sent: VecMap<String, Mdn>,

    #[serde(rename = "notSent")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_sent: VecMap<String, SetError<MdnProperty>>,
}

#[derive(Debug, Clone, Default)]
pub struct MdnParseRequest {
    pub account_id: Id,
    pub blob_ids: Vec<MaybeIdReference<BlobId>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MdnParseResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "parsed")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub parsed: VecMap<BlobId, Mdn>,

    #[serde(rename = "notParsable")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_parsable: Vec<BlobId>,

    #[serde(rename = "notFound")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<MaybeInvalid<BlobId>>,
}

impl<'x> DeserializeArguments<'x> for MdnSendRequest<'x> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'x>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = crate::request::deserialize_account_id(map)?;
            },
            b"identityId" => {
                self.identity_id = map.next_value()?;
            },
            b"send" => {
                self.send = map.next_value()?;
            },
            b"onSuccessUpdateEmail" => {
                self.on_success_update_email = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'x> Deserialize<'x> for MdnSendRequest<'x> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'x>,
    {
        deserialize_request(deserializer)
    }
}

impl<'de> DeserializeArguments<'de> for MdnParseRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = crate::request::deserialize_account_id(map)?;
            },
            b"blobIds" => {
                self.blob_ids = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for MdnParseRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
