/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::SetError,
    object::{JmapObject, JmapObjectId, blob::BlobProperty},
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
    },
    response::Response,
    types::state::State,
};
use jmap_tools::{Element, Key, Map, ObjectAsVec, Property, Value};
use serde::{Deserialize, Deserializer, Serialize};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone)]
pub struct CopyRequest<'x, T: JmapObject> {
    pub from_account_id: Id,
    pub if_from_in_state: Option<State>,
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub create: VecMap<String, Value<'x, T::Property, T::Element>>,
    pub on_success_destroy_original: Option<bool>,
    pub destroy_from_if_in_state: Option<State>,
    pub arguments: T::CopyArguments,
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
    pub created: VecMap<String, Value<'static, T::Property, T::Element>>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError<T::Property>>,
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
    pub not_copied: VecMap<MaybeInvalid<BlobId>, SetError<BlobProperty>>,
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for CopyRequest<'de, T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = crate::request::deserialize_account_id(map)?;
            },
            b"ifInState" => {
                self.if_in_state = map.next_value()?;
            },
            b"fromAccountId" => {
                self.from_account_id = crate::request::deserialize_account_id(map)?;
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
                self.arguments.deserialize_argument(key, map)?;
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
                self.account_id = crate::request::deserialize_account_id(map)?;
            },
            b"fromAccountId" => {
                self.from_account_id = crate::request::deserialize_account_id(map)?;
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
            arguments: T::CopyArguments::default(),
        }
    }
}

impl<T: JmapObject> CopyResponse<T> {
    pub fn created(&mut self, id: String, document_id: impl Into<T::Id>) {
        self.created_with_properties(id, document_id, []);
    }

    pub fn created_with_properties(
        &mut self,
        id: String,
        document_id: impl Into<T::Id>,
        properties: impl IntoIterator<Item = (T::Property, Value<'static, T::Property, T::Element>)>,
    ) {
        let document_id = document_id.into();
        let mut object = Map::from(vec![(
            Key::Property(T::ID_PROPERTY),
            Value::Element(document_id.into()),
        )]);
        for (property, value) in properties {
            object.insert(property, value);
        }
        self.created.append(id, Value::Object(object));
    }

    pub fn update_created_ids(&self, response: &mut Response) {
        for (create_id, obj) in &self.created {
            if let Value::Object(obj) = obj
                && let Some(Value::Element(id)) = obj.get(&Key::Property(T::ID_PROPERTY))
                && let Some(id) = id.as_any_id()
            {
                response.created_ids.insert(create_id.clone(), id);
            }
        }
    }
}

pub trait CopySourceId<P: Property> {
    fn take_source_id(&mut self, id_property: P) -> Result<Id, SetError<P>>;
}

impl<P: Property, E: Element<Property = P> + JmapObjectId> CopySourceId<P> for Value<'_, P, E> {
    fn take_source_id(&mut self, id_property: P) -> Result<Id, SetError<P>> {
        let key = Key::Property(id_property.clone());
        self.as_object_mut()
            .map(ObjectAsVec::as_mut_vec)
            .and_then(|entries| {
                entries
                    .iter()
                    .position(|(entry, _)| *entry == key)
                    .map(|position| entries.remove(position).1)
            })
            .as_ref()
            .and_then(Value::as_element)
            .and_then(JmapObjectId::as_id)
            .ok_or_else(|| {
                SetError::invalid_properties()
                    .with_property(id_property)
                    .with_description("Missing or invalid \"id\" property.")
            })
    }
}
