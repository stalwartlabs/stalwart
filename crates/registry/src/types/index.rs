/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::prelude::{Object, Property},
    types::{id::Id, ipmask::IpAddrOrMask},
};
use ahash::AHashSet;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub enum IndexType {
    Unique,
    Search,
    TextSearch,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndexValue<'x> {
    Text(Cow<'x, str>),
    Bytes(Vec<u8>),
    U64(u64),
    I64(i64),
    U16(u16),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexKey<'x> {
    pub property: Property,
    pub typ: IndexType,
    pub value: IndexValue<'x>,
    pub value_composite: IndexValue<'x>,
}

#[derive(Debug, Default)]

pub struct IndexBuilder<'x> {
    pub object: Option<Object>,
    pub keys: AHashSet<IndexKey<'x>>,
}

impl<'x> IndexBuilder<'x> {
    pub fn object(&mut self, object: Object) {
        if self.object.is_none() {
            self.object = Some(object);
        }
    }

    pub fn typ(&mut self, typ: u16) {
        self.keys.insert(IndexKey {
            property: Property::Type,
            typ: IndexType::Search,
            value: IndexValue::U16(typ),
            value_composite: IndexValue::None,
        });
    }

    pub fn unique(&mut self, property: Property, value: impl Into<IndexValue<'x>>) {
        self.keys.insert(IndexKey {
            property,
            typ: IndexType::Unique,
            value: value.into(),
            value_composite: IndexValue::None,
        });
    }

    pub fn search(&mut self, property: Property, value: impl Into<IndexValue<'x>>) {
        self.keys.insert(IndexKey {
            property,
            typ: IndexType::Search,
            value: value.into(),
            value_composite: IndexValue::None,
        });
    }

    pub fn text(&mut self, property: Property, value: &'x str) {
        for word in value
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| s.len() > 1)
        {
            if word
                .chars()
                .all(|ch| ch.is_lowercase() || !ch.is_alphabetic())
            {
                self.keys.insert(IndexKey {
                    property,
                    typ: IndexType::TextSearch,
                    value: IndexValue::Text(Cow::Borrowed(word)),
                    value_composite: IndexValue::None,
                });
            } else {
                self.keys.insert(IndexKey {
                    property,
                    typ: IndexType::TextSearch,
                    value: IndexValue::Text(Cow::Owned(word.to_lowercase())),
                    value_composite: IndexValue::Text(Cow::Borrowed(word)),
                });
            }
        }
    }

    pub fn global(&mut self, property: Property, value: impl Into<IndexValue<'x>>) {
        self.keys.insert(IndexKey {
            property,
            typ: IndexType::Global,
            value: value.into(),
            value_composite: IndexValue::None,
        });
    }

    pub fn composite(
        &mut self,
        property: Property,
        value: impl Into<IndexValue<'x>>,
        composite: impl Into<IndexValue<'x>>,
    ) {
        self.keys.insert(IndexKey {
            property,
            typ: IndexType::Global,
            value: value.into(),
            value_composite: composite.into(),
        });
    }
}

impl From<u64> for IndexValue<'_> {
    fn from(value: u64) -> Self {
        IndexValue::U64(value)
    }
}

impl From<&u64> for IndexValue<'_> {
    fn from(value: &u64) -> Self {
        IndexValue::U64(*value)
    }
}

impl From<i64> for IndexValue<'_> {
    fn from(value: i64) -> Self {
        IndexValue::I64(value)
    }
}

impl From<&i64> for IndexValue<'_> {
    fn from(value: &i64) -> Self {
        IndexValue::I64(*value)
    }
}

impl<'x> From<&'x IpAddrOrMask> for IndexValue<'x> {
    fn from(value: &'x IpAddrOrMask) -> Self {
        match value {
            IpAddrOrMask::V4 { addr, mask } => {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&addr.octets());
                bytes.extend_from_slice(&mask.to_be_bytes());
                IndexValue::Bytes(bytes)
            }
            IpAddrOrMask::V6 { addr, mask } => {
                let mut bytes = Vec::with_capacity(24);
                bytes.extend_from_slice(&addr.octets());
                bytes.extend_from_slice(&mask.to_be_bytes());
                IndexValue::Bytes(bytes)
            }
        }
    }
}

impl<'x> From<&'x trc::EventType> for IndexValue<'x> {
    fn from(value: &'x trc::EventType) -> Self {
        IndexValue::U16(value.to_id())
    }
}

impl<'x> From<&'x str> for IndexValue<'x> {
    fn from(value: &'x str) -> Self {
        IndexValue::Text(value.into())
    }
}

impl<'x> From<&'x String> for IndexValue<'x> {
    fn from(value: &'x String) -> Self {
        IndexValue::Text(Cow::Borrowed(value.as_str()))
    }
}

impl<'x> From<&'x Id> for IndexValue<'x> {
    fn from(value: &'x Id) -> Self {
        IndexValue::U64(value.id())
    }
}
