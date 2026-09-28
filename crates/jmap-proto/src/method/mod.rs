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

/// Serialize an empty collection as JSON null rather than omitting it.
///
/// RFC 8620 Section 5.3 types the /set response members "created",
/// "updated", "destroyed", "notCreated", "notUpdated" and "notDestroyed" as
/// "...|null", and Section 5.4 and RFC 8621 Section 4.8 do the same for the
/// /copy and Email/import responses: the member is present, and null when
/// there is nothing to report.
pub(crate) mod null_if_empty {
    use serde::{Serialize, Serializer};
    use utils::map::vec_map::VecMap;

    pub fn vec_map<S, K, V>(map: &VecMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Eq + PartialEq + Serialize,
        V: Serialize,
    {
        if map.is_empty() {
            serializer.serialize_none()
        } else {
            map.serialize(serializer)
        }
    }

    pub fn hash_map<S, K, V>(
        map: &ahash::AHashMap<K, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Serialize + Eq + std::hash::Hash,
        V: Serialize,
    {
        if map.is_empty() {
            serializer.serialize_none()
        } else {
            map.serialize(serializer)
        }
    }

    pub fn vec<S, T>(vec: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        if vec.is_empty() {
            serializer.serialize_none()
        } else {
            vec.serialize(serializer)
        }
    }
}
