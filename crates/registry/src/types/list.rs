/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonPatch,
    },
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};
use jmap_tools::{JsonPointerItem, Key, Value};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
};
use std::{
    borrow::Cow,
    fmt::{self, Debug},
    marker::PhantomData,
};
use utils::map::vec_map::{KeyValue, VecMap};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct List<T>(pub VecMap<u32, T>);

impl<T> List<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(VecMap::with_capacity(capacity))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.values_mut()
    }

    pub fn push(&mut self, item: T) {
        let next_index = self.0.last().map(|(k, _)| *k + 1).unwrap_or(0);
        self.0.append(next_index, item);
    }

    pub fn push_unchecked(&mut self, item: T) {
        let next_index = self.0.len() as u32;
        self.0.append(next_index, item);
    }

    pub fn inner_mut(&mut self) -> &mut VecMap<u32, T> {
        &mut self.0
    }
}

impl<T> Pickle for List<T>
where
    T: Pickle,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.0.len() as u32).pickle(out);
        for item in self.0.values() {
            item.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = u32::unpickle(stream)? as usize;
        let mut vec = Self::with_capacity(len);
        for _ in 0..len {
            vec.push_unchecked(T::unpickle(stream)?);
        }
        Some(vec)
    }
}

impl<T: RegistryJsonPatch + Default + Debug> RegistryJsonPatch for List<T> {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (pointer.next(), value) {
            (Some(JsonPointerItem::Number(key)), value) => {
                let key = *key as u32;
                if matches!(value, Value::Null) && !pointer.has_next() {
                    if self.0.remove(&key).is_some() {
                        return Ok(MaybeUnpatched::Patched);
                    }
                } else {
                    let result = self.0.get_mut_or_insert(key).patch(pointer, value);
                    self.0.sort_unstable_by_key();
                    return result;
                }
            }
            (Some(JsonPointerItem::Key(key)), value) => {
                if let Ok(key) = key.to_string().parse::<u32>() {
                    if matches!(value, Value::Null) && !pointer.has_next() {
                        if self.0.remove(&key).is_some() {
                            return Ok(MaybeUnpatched::Patched);
                        }
                    } else {
                        let result = self.0.get_mut_or_insert(key).patch(pointer, value);
                        self.0.sort_unstable_by_key();
                        return result;
                    }
                }
            }
            (None, Value::Object(items)) => {
                self.0.clear();
                for (key, value) in items.into_vec() {
                    if let Ok(key) = key.to_string().parse::<u32>() {
                        let mut inner = T::default();
                        inner.patch(pointer.clone(), value)?;
                        self.0.set(key, inner);
                    } else {
                        return Err(PatchError::new(
                            pointer.clone(),
                            "Invalid key for object property",
                        ));
                    }
                }
                self.0.sort_unstable_by_key();
                return Ok(MaybeUnpatched::Patched);
            }
            _ => {}
        }

        Err(PatchError::new(
            pointer,
            "Invalid value for object property",
        ))
    }
}

impl<V: IntoValue> IntoValue for List<V> {
    fn into_value(self) -> JmapValue<'static> {
        let mut map = jmap_tools::Map::with_capacity(self.0.len());
        for (idx, v) in self.0 {
            map.insert_unchecked(Key::Owned(idx.to_string()), v.into_value());
        }

        JmapValue::Object(map)
    }
}

impl<T: Serialize> Serialize for List<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(&key.to_string(), value)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for List<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ListVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ListVisitor<T> {
            type Value = List<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map of string keys to values")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut items = VecMap::with_capacity(map.size_hint().unwrap_or(0));

                while let Some(key) = map.next_key::<Cow<str>>()? {
                    let id: u32 = key
                        .parse()
                        .map_err(|_| de::Error::custom(format!("invalid integer key: {key}")))?;
                    let value: T = map.next_value()?;
                    items.set(id, value);
                }

                items.sort_unstable_by_key();

                Ok(List(items))
            }
        }

        deserializer.deserialize_map(ListVisitor(PhantomData))
    }
}

impl<T> FromIterator<T> for List<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(VecMap::from_iter(
            iter.into_iter().enumerate().map(|(i, v)| (i as u32, v)),
        ))
    }
}

impl<T> From<Vec<T>> for List<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(VecMap::from_iter(
            vec.into_iter().enumerate().map(|(i, v)| (i as u32, v)),
        ))
    }
}

impl<T> IntoIterator for List<T> {
    type Item = T;
    type IntoIter = std::iter::Map<std::vec::IntoIter<KeyValue<u32, T>>, fn(KeyValue<u32, T>) -> T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.inner.into_iter().map(|kv| kv.value)
    }
}
