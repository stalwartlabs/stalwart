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
    schema::prelude::SocketAddr,
    types::{EnumImpl, error::PatchError, ipaddr::IpAddr, ipmask::IpAddrOrMask},
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
    str::FromStr,
};
use types::id::Id;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Map<T: MapItem>(Vec<T>);

impl<T: MapItem> Map<T> {
    pub fn new(items: Vec<T>) -> Self {
        Self(items)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    #[inline(always)]
    pub fn contains(&self, item: &T) -> bool {
        self.0.contains(item)
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline(always)]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    #[inline(always)]
    pub fn inner_mut(&mut self) -> &mut Vec<T> {
        &mut self.0
    }

    #[inline(always)]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    #[inline(always)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    #[inline(always)]
    pub fn push(&mut self, item: T) {
        if !self.0.contains(&item) {
            self.0.push(item);
        }
    }

    #[inline(always)]
    pub fn push_unchecked(&mut self, item: T) {
        self.0.push(item);
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl<T> Pickle for Map<T>
where
    T: Pickle + MapItem,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.0.len() as u32).pickle(out);
        for item in &self.0 {
            item.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = u32::unpickle(stream)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::unpickle(stream)?);
        }
        Some(Self(vec))
    }
}

impl<V: IntoValue + MapItem> IntoValue for Map<V> {
    fn into_value(self) -> JmapValue<'static> {
        let mut map = jmap_tools::Map::with_capacity(self.0.len());
        for v in self.0 {
            let key = match v.into_string() {
                Cow::Borrowed(s) => Key::Borrowed(s),
                Cow::Owned(s) => Key::Owned(s),
            };
            map.insert_unchecked(key, Value::Bool(true));
        }

        JmapValue::Object(map)
    }
}

impl<T: MapItem + Default> RegistryJsonPatch for Map<T> {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (pointer.next(), value) {
            (Some(JsonPointerItem::Number(idx)), Value::Null | Value::Bool(false)) => {
                let key = T::try_from_integer(*idx);

                if !pointer.has_next()
                    && let Some(key) = key
                {
                    self.0.retain(|item| item != &key);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Key(key)), Value::Null | Value::Bool(false)) => {
                let key = T::try_from_string(key.to_string().as_ref());

                if !pointer.has_next()
                    && let Some(key) = key
                {
                    self.0.retain(|item| item != &key);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Key(key)), Value::Bool(true)) => {
                let key = T::try_from_string(key.to_string().as_ref());

                if !pointer.has_next()
                    && let Some(key) = key
                {
                    if !self.0.contains(&key) {
                        self.0.push(key);
                    }

                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Number(idx)), Value::Bool(true)) => {
                let key = T::try_from_integer(*idx);
                if !pointer.has_next()
                    && let Some(key) = key
                {
                    if !self.0.contains(&key) {
                        self.0.push(key);
                    }

                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (None, Value::Object(items)) => {
                self.0.clear();
                for (key, value) in items.into_vec() {
                    if let (Some(key), Value::Bool(is_set)) =
                        (T::try_from_string(key.to_string().as_ref()), value)
                    {
                        if is_set && !self.0.contains(&key) {
                            self.0.push(key);
                        }
                    } else {
                        return Err(PatchError::new(
                            pointer.clone(),
                            "Invalid key for object property",
                        ));
                    }
                }
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

impl<T: MapItem> Serialize for Map<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for item in &self.0 {
            map.serialize_entry(&item.as_string() as &str, &true)?;
        }
        map.end()
    }
}

impl<'de, T: MapItem> Deserialize<'de> for Map<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MapVisitor<T>(PhantomData<T>);

        impl<'de, T: MapItem> Visitor<'de> for MapVisitor<T> {
            type Value = Map<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map of string keys to booleans or nulls")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut items = Vec::with_capacity(map.size_hint().unwrap_or(0));

                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    let value: Option<bool> = map.next_value()?;

                    if value == Some(true) {
                        let item = T::try_from_string(&key)
                            .ok_or_else(|| de::Error::custom(format!("invalid map key: {key}")))?;
                        if !items.contains(&item) {
                            items.push(item);
                        }
                    }
                }

                Ok(Map(items))
            }
        }

        deserializer.deserialize_map(MapVisitor(PhantomData))
    }
}

pub trait MapItem: Sized + PartialEq + Eq + Debug {
    fn try_from_string(value: &str) -> Option<Self>;
    fn try_from_integer(value: u64) -> Option<Self>;
    fn into_string(self) -> Cow<'static, str>;
    fn as_string(&self) -> Cow<'_, str>;
}

impl MapItem for String {
    fn try_from_string(value: &str) -> Option<Self> {
        let value = value.trim();
        if !value.is_empty() {
            Some(value.to_string())
        } else {
            None
        }
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        Some(value.to_string())
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self)
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl MapItem for Id {
    fn try_from_string(value: &str) -> Option<Self> {
        Id::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.as_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.as_string())
    }
}

impl<T: EnumImpl> MapItem for T {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::parse(value)
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Borrowed(self.as_str())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl MapItem for IpAddr {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl MapItem for IpAddrOrMask {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl MapItem for SocketAddr {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl MapItem for u64 {
    fn try_from_string(value: &str) -> Option<Self> {
        value.parse().ok()
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        Some(value)
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl<T: MapItem> From<Vec<T>> for Map<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T: MapItem> IntoIterator for Map<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
