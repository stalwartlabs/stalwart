/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{IntoValue, JmapValue},
    schema::prelude::Property,
    types::EnumImpl,
};
use jmap_tools::Key;
use std::fmt::Debug;
use utils::map::vec_map::VecMap;

impl<T: IntoValue> IntoValue for Option<T> {
    fn into_value(self) -> JmapValue<'static> {
        match self {
            Some(value) => value.into_value(),
            None => JmapValue::Null,
        }
    }
}

impl IntoValue for String {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.into())
    }
}

impl IntoValue for bool {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Bool(self)
    }
}

impl IntoValue for u64 {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Number(self.into())
    }
}

impl IntoValue for i64 {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Number(self.into())
    }
}

impl IntoValue for f64 {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Number(self.into())
    }
}

impl<T: EnumImpl> IntoValue for T {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.as_str().into())
    }
}

trait MapKey: Sized + PartialEq + Eq + Debug {
    fn to_key(self) -> Key<'static, Property>;
}

impl MapKey for String {
    fn to_key(self) -> Key<'static, Property> {
        Key::Owned(self)
    }
}

impl MapKey for u32 {
    fn to_key(self) -> Key<'static, Property> {
        Key::Owned(self.to_string())
    }
}

impl<T: EnumImpl> MapKey for T {
    fn to_key(self) -> Key<'static, Property> {
        Key::Borrowed(self.as_str())
    }
}

impl<K: MapKey, V: IntoValue> IntoValue for VecMap<K, V> {
    fn into_value(self) -> JmapValue<'static> {
        let mut map = jmap_tools::Map::with_capacity(self.len());
        for (k, v) in self {
            map.insert_unchecked(k.to_key(), v.into_value());
        }
        JmapValue::Object(map)
    }
}

impl<V: IntoValue> IntoValue for Vec<V> {
    fn into_value(self) -> JmapValue<'static> {
        let mut array = Vec::with_capacity(self.len());
        for v in self {
            array.push(v.into_value());
        }

        JmapValue::Array(array)
    }
}
