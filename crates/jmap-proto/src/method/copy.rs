/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::SetError,
    object::{JmapObject, blob::BlobProperty},
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::MaybeIdReference,
    },
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use serde::{Deserialize, Deserializer, Serialize};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone)]
pub struct CopyRequest<'x, T: JmapObject> {
    pub from_account_id: Id,
    pub if_from_in_state: Option<State>,
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub create: VecMap<MaybeIdReference<Id>, Value<'x, T::Property, T::Element>>,
    pub on_success_destroy_original: Option<bool>,
    pub destroy_from_if_in_state: Option<State>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CopyResponse<T: JmapObject> {
    #[serde(rename = "fromAccountId")]
    pub from_account_id: Id,

    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    pub old_state: State,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub created: VecMap<Id, Value<'static, T::Property, T::Element>>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<Id, SetError<T::Property>>,
}

#[derive(Debug, Clone, Default)]
pub struct CopyBlobRequest {
    pub from_account_id: Id,
    pub account_id: Id,
    pub blob_ids: Vec<MaybeInvalid<BlobId>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CopyBlobResponse {
    #[serde(rename = "fromAccountId")]
    pub from_account_id: Id,

    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "copied")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub copied: VecMap<BlobId, BlobId>,

    #[serde(rename = "notCopied")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_copied: VecMap<BlobId, SetError<BlobProperty>>,
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for CopyRequest<'de, T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"ifInState" => {
                self.if_in_state = map.next_value()?;
            },
            b"fromAccountId" => {
                self.from_account_id = map.next_value()?;
            },
            b"ifFromInState" => {
                self.if_from_in_state = map.next_value()?;
            },
            b"create" => {
                self.create = map.next_value()?;
            },
            b"onSuccessDestroyOriginal" => {
                self.on_success_destroy_original = map.next_value()?;
            },
            b"destroyFromIfInState" => {
                self.destroy_from_if_in_state = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for CopyBlobRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"fromAccountId" => {
                self.from_account_id = map.next_value()?;
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

impl<'de, T: JmapObject> Deserialize<'de> for CopyRequest<'de, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<'de> Deserialize<'de> for CopyBlobRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<'de, T: JmapObject> Default for CopyRequest<'de, T> {
    fn default() -> Self {
        CopyRequest {
            from_account_id: Id::default(),
            if_from_in_state: None,
            account_id: Id::default(),
            if_in_state: None,
            create: VecMap::new(),
            on_success_destroy_original: None,
            destroy_from_if_in_state: None,
        }
    }
}

impl<T: JmapObject> CopyResponse<T> {
    pub fn created(&mut self, id: Id, document_id: impl Into<T::Id>) {
        let document_id = document_id.into();
        self.created.append(
            id,
            Value::Object(Map::from(vec![(
                Key::Property(T::ID_PROPERTY),
                Value::Element(document_id.into()),
            )])),
        );
    }
}
