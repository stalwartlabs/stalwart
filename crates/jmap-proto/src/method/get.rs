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
        reference::{MaybeIdReference, MaybeResultReference, ResultReference},
    },
    types::state::State,
};
use jmap_tools::Value;
use serde::{Deserialize, Deserializer};
use types::id::Id;

#[derive(Debug, Clone)]
pub struct GetRequest<T: JmapObject> {
    pub account_id: Id,
    pub ids: Option<MaybeResultReference<Vec<MaybeIdReference<T::Id>>>>,
    pub properties: Option<MaybeResultReference<Vec<MaybeInvalid<T::Property>>>>,
    pub arguments: T::GetArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GetResponse<T: JmapObject> {
    #[serde(rename = "accountId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Id>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,

    pub list: Vec<Value<'static, T::Property, T::Element>>,

    #[serde(rename = "notFound")]
    pub not_found: Vec<MaybeInvalid<T::Id>>,
}

impl<T: JmapObject> GetResponse<T> {
    pub fn push_not_found(&mut self, id: T::Id) {
        self.not_found.push(MaybeInvalid::Value(id));
    }
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for GetRequest<T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = crate::request::deserialize_account_id(map)?;
            },
            b"ids" => {
                self.ids = map.next_value::<Option<Vec<MaybeIdReference<T::Id>>>>()?.map(MaybeResultReference::Value);
            },
            b"properties" => {
                self.properties = map.next_value::<Option<Vec<MaybeInvalid<T::Property>>>>()?.map(MaybeResultReference::Value);
            },
            b"#ids" => {
                self.ids = Some(MaybeResultReference::Reference(map.next_value::<ResultReference>()?));
            },
            b"#properties" => {
                self.properties = Some(MaybeResultReference::Reference(map.next_value::<ResultReference>()?));
            },
            _ => {
                self.arguments.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T: JmapObject> Deserialize<'de> for GetRequest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T: JmapObject> Default for GetRequest<T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            ids: None,
            properties: None,
            arguments: T::GetArguments::default(),
        }
    }
}

impl<T: JmapObject> GetRequest<T> {
    pub fn unwrap_properties(&mut self, default: &[T::Property]) -> Vec<T::Property> {
        if let Some(properties_) = self.properties.take().map(|p| p.unwrap()) {
            let mut properties = Vec::with_capacity(properties_.len());
            let id_prop = T::ID_PROPERTY;
            let mut has_id = false;

            for prop in properties_ {
                if let MaybeInvalid::Value(p) = prop {
                    if p == id_prop {
                        has_id = true;
                    }
                    properties.push(p);
                }
            }

            if !has_id {
                properties.push(id_prop);
            }

            properties
        } else {
            default.to_vec()
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn unwrap_ids(
        &mut self,
        max_objects_in_get: usize,
    ) -> trc::Result<(Option<Vec<T::Id>>, Vec<MaybeInvalid<T::Id>>)> {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                let mut valid = Vec::with_capacity(ids.len());
                let mut invalid = Vec::new();
                for id in ids {
                    match id {
                        MaybeIdReference::Id(id) => valid.push(id),
                        MaybeIdReference::Invalid(s) | MaybeIdReference::Reference(s) => {
                            invalid.push(MaybeInvalid::Invalid(s))
                        }
                    }
                }
                Ok((Some(valid), invalid))
            } else {
                Err(trc::JmapEvent::RequestTooLarge.into_err())
            }
        } else {
            Ok((None, Vec::new()))
        }
    }
}
