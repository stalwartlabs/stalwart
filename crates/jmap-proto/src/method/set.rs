/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ahash_is_empty;
use crate::{
    error::set::{InvalidProperty, SetError},
    object::{JmapObject, JmapObjectId},
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::{MaybeResultReference, ResultReference},
    },
    response::Response,
    types::state::State,
};
use ahash::AHashMap;
use jmap_tools::{Key, Map, Value};
use serde::{Deserialize, Deserializer};
use types::id::Id;
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone)]
#[allow(clippy::type_complexity)]
pub struct SetRequest<'x, T: JmapObject> {
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub create: Option<VecMap<String, Value<'x, T::Property, T::Element>>>,
    pub update: Option<VecMap<MaybeInvalid<Id>, Value<'x, T::Property, T::Element>>>,
    pub destroy: Option<MaybeResultReference<Vec<MaybeInvalid<Id>>>>,
    pub arguments: T::SetArguments<'x>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
#[allow(clippy::type_complexity)]
pub struct SetResponse<T: JmapObject> {
    #[serde(rename = "accountId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Id>,

    #[serde(rename = "oldState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<State>,

    #[serde(rename = "newState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_state: Option<State>,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "ahash_is_empty")]
    pub created: AHashMap<String, Value<'static, T::Property, T::Element>>,

    #[serde(rename = "updated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub updated: VecMap<Id, Option<Value<'static, T::Property, T::Element>>>,

    #[serde(rename = "destroyed")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub destroyed: Vec<Id>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError<T::Property>>,

    #[serde(rename = "notUpdated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_updated: VecMap<Id, SetError<T::Property>>,

    #[serde(rename = "notDestroyed")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_destroyed: VecMap<Id, SetError<T::Property>>,
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for SetRequest<'de, T> {
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
            b"create" => {
                self.create = map.next_value()?;
            },
            b"update" => {
                self.update = map.next_value()?;
            },
            b"destroy" => {
                self.destroy = map.next_value::<Option<Vec<MaybeInvalid<Id>>>>()?.map(MaybeResultReference::Value);
            },
            b"#destroy" => {
                self.destroy = Some(MaybeResultReference::Reference(map.next_value::<ResultReference>()?));
            }
            _ => {
                self.arguments.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T: JmapObject> Deserialize<'de> for SetRequest<'de, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<'x, T: JmapObject> Default for SetRequest<'x, T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            if_in_state: None,
            create: None,
            update: None,
            destroy: None,
            arguments: T::SetArguments::default(),
        }
    }
}

impl<'x, T: JmapObject> SetRequest<'x, T> {
    pub fn validate(&self, max_objects_in_set: usize) -> trc::Result<()> {
        if self.create.as_ref().map_or(0, |objs| objs.len())
            + self.update.as_ref().map_or(0, |objs| objs.len())
            + self.destroy.as_ref().map_or(0, |objs| {
                if let MaybeResultReference::Value(ids) = objs {
                    ids.len()
                } else {
                    0
                }
            })
            > max_objects_in_set
        {
            Err(trc::JmapEvent::RequestTooLarge.into_err())
        } else {
            Ok(())
        }
    }

    pub fn has_updates(&self) -> bool {
        self.update.as_ref().is_some_and(|objs| !objs.is_empty())
    }

    pub fn has_creates(&self) -> bool {
        self.create.as_ref().is_some_and(|objs| !objs.is_empty())
    }

    pub fn unwrap_create(&mut self) -> VecMap<String, Value<'x, T::Property, T::Element>> {
        self.create.take().unwrap_or_default()
    }

    pub fn unwrap_update(
        &mut self,
    ) -> VecMap<MaybeInvalid<Id>, Value<'x, T::Property, T::Element>> {
        self.update.take().unwrap_or_default()
    }

    pub fn unwrap_destroy(&mut self) -> Vec<MaybeInvalid<Id>> {
        self.destroy
            .take()
            .map(|ids| ids.unwrap())
            .unwrap_or_default()
    }
}

impl<T: JmapObject> SetResponse<T> {
    pub fn from_request(request: &SetRequest<T>, max_objects: usize) -> trc::Result<Self> {
        let n_create = request.create.as_ref().map_or(0, |objs| objs.len());
        let n_update = request.update.as_ref().map_or(0, |objs| objs.len());
        let n_destroy = request.destroy.as_ref().map_or(0, |objs| {
            if let MaybeResultReference::Value(ids) = objs {
                ids.len()
            } else {
                0
            }
        });
        if n_create + n_update + n_destroy <= max_objects {
            Ok(SetResponse {
                account_id: if request.account_id.is_valid() {
                    request.account_id.into()
                } else {
                    None
                },
                new_state: None,
                old_state: None,
                created: AHashMap::with_capacity(n_create),
                updated: VecMap::with_capacity(n_update),
                destroyed: Vec::with_capacity(n_destroy),
                not_created: VecMap::new(),
                not_updated: VecMap::new(),
                not_destroyed: VecMap::new(),
            })
        } else {
            Err(trc::JmapEvent::RequestTooLarge.into_err())
        }
    }

    pub fn with_state(mut self, state: State) -> Self {
        self.old_state = Some(state.clone());
        self.new_state = Some(state);
        self
    }

    pub fn created(&mut self, id: String, document_id: impl Into<T::Id>) {
        self.created.insert(
            id,
            Value::Object(Map::from(vec![(
                Key::Property(T::ID_PROPERTY),
                Value::Element(document_id.into().into()),
            )])),
        );
    }

    pub fn invalid_property_create(
        &mut self,
        id: String,
        property: impl Into<InvalidProperty<T::Property>>,
    ) {
        self.not_created.append(
            id,
            SetError::invalid_properties()
                .with_property(property)
                .with_description("Invalid property or value.".to_string()),
        );
    }

    pub fn invalid_property_update(
        &mut self,
        id: Id,
        property: impl Into<InvalidProperty<T::Property>>,
    ) {
        self.not_updated.append(
            id,
            SetError::invalid_properties()
                .with_property(property)
                .with_description("Invalid property or value.".to_string()),
        );
    }

    pub fn update_created_ids(&self, response: &mut Response) {
        for (user_id, obj) in &self.created {
            if let Value::Object(obj) = obj
                && let Some(Value::Element(id)) = obj.get(&Key::Property(T::ID_PROPERTY))
                && let Some(id) = id.as_any_id()
            {
                response.created_ids.insert(user_id.clone(), id);
            }
        }
    }

    pub fn get_object_by_id(
        &mut self,
        id: Id,
    ) -> Option<&mut Value<'static, T::Property, T::Element>> {
        if let Some(obj) = self.updated.get_mut(&id) {
            if let Some(obj) = obj {
                return Some(obj);
            } else {
                *obj = Some(Value::Object(Map::with_capacity(1)));
                return obj.as_mut().unwrap().into();
            }
        }

        (&mut self.created)
            .into_iter()
            .map(|(_, obj)| obj)
            .find(|obj| {
                obj.as_object_and_get(&Key::Property(T::ID_PROPERTY))
                    .and_then(|v| v.as_element())
                    .and_then(|v| v.as_id())
                    .is_some_and(|oid| oid == id)
            })
    }

    pub fn has_changes(&self) -> bool {
        !self.created.is_empty() || !self.updated.is_empty() || !self.destroyed.is_empty()
    }
}
