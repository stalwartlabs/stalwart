/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use jmap_tools::Property;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};
use std::{borrow::Cow, fmt, str::FromStr};

pub mod availability;
pub mod changes;
pub mod copy;
pub mod get;
pub mod import;
pub mod lookup;
pub mod parse;
pub mod query;
pub mod query_changes;
pub mod search_snippet;
pub mod set;
pub mod upload;
pub mod validate;

#[inline(always)]
fn ahash_is_empty<K, V>(map: &AHashMap<K, V>) -> bool {
    map.is_empty()
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct PropertyWrapper<T: Property>(pub T);

impl<T: Property> From<T> for PropertyWrapper<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Property> Serialize for PropertyWrapper<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.to_cow().as_ref())
    }
}

pub(crate) struct JmapDict<T: FromStr>(pub Vec<T>);

struct JmapDictVisitor<'de, T: FromStr> {
    marker: std::marker::PhantomData<&'de T>,
}

impl<'de, T: FromStr> Visitor<'de> for JmapDictVisitor<'de, T> {
    type Value = JmapDict<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut vec = Vec::with_capacity(3);

        while let Some(key) = access.next_key::<Cow<'de, str>>()? {
            let key = T::from_str(&key).map_err(|_| de::Error::custom("invalid dictionary key"))?;
            if access.next_value::<Option<bool>>()?.unwrap_or(false) {
                vec.push(key);
            }
        }

        Ok(JmapDict(vec))
    }
}

impl<'de, T: FromStr + 'static> Deserialize<'de> for JmapDict<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JmapDictVisitor {
            marker: std::marker::PhantomData,
        })
    }
}
