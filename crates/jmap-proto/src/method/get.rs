/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::JmapObject,
    request::{
        IntoValid, MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::{MaybeIdReference, MaybeResultReference, ResultReference},
    },
    types::state::State,
};
use ahash::AHashSet;
use jmap_tools::Value;
use serde::{Deserialize, Deserializer};
use std::hash::Hash;
use types::id::Id;

const LINEAR_DEDUP_LIMIT: usize = 16;

pub fn unique_properties<P: Ord>(properties: impl Iterator<Item = P>) -> Vec<P> {
    let len = properties.size_hint().1.unwrap_or(usize::MAX);
    if len <= LINEAR_DEDUP_LIMIT {
        let mut unique = Vec::with_capacity(len);
        for property in properties {
            if !unique.contains(&property) {
                unique.push(property);
            }
        }
        unique
    } else {
        let mut indexed = properties
            .enumerate()
            .map(|(position, property)| (property, position))
            .collect::<Vec<_>>();
        indexed.sort_unstable();
        indexed.dedup_by(|next, first| next.0 == first.0);
        indexed.sort_unstable_by_key(|(_, position)| *position);
        indexed.into_iter().map(|(property, _)| property).collect()
    }
}

pub fn all_ids<V>(ids: impl Iterator<Item = V>, max_objects_in_get: usize) -> trc::Result<Vec<V>> {
    let ids = ids
        .take(max_objects_in_get.saturating_add(1))
        .collect::<Vec<_>>();
    if ids.len() <= max_objects_in_get {
        Ok(ids)
    } else {
        Err(trc::JmapEvent::RequestTooLarge.into_err())
    }
}

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
        if let Some(properties) = self.properties.take().map(|p| p.unwrap()) {
            let mut properties = unique_properties(properties.into_valid());
            if !properties.contains(&T::ID_PROPERTY) {
                properties.push(T::ID_PROPERTY);
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
    ) -> trc::Result<(Option<Vec<T::Id>>, Vec<MaybeInvalid<T::Id>>)>
    where
        T::Id: Clone + Eq + Hash,
    {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                let mut valid = Vec::with_capacity(ids.len());
                let mut invalid = Vec::new();
                let mut seen =
                    (ids.len() > LINEAR_DEDUP_LIMIT).then(|| AHashSet::with_capacity(ids.len()));
                for id in ids {
                    match id {
                        MaybeIdReference::Id(id) => {
                            let is_new = match &mut seen {
                                Some(seen) => seen.insert(id.clone()),
                                None => !valid.contains(&id),
                            };
                            if is_new {
                                valid.push(id);
                            }
                        }
                        MaybeIdReference::Invalid(s) | MaybeIdReference::Reference(s) => {
                            let id = MaybeInvalid::Invalid(s);
                            if !invalid.contains(&id) {
                                invalid.push(id);
                            }
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/jmap-proto/src/method/get/tests.rs"]
mod tests;
