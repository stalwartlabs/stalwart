/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::{id::Id, type_state::DataType};

#[derive(Debug, Clone, Default)]
pub struct Quota;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuotaProperty {
    Id,
    ResourceType,
    Used,
    Name,
    Scope,
    Types,
    HardLimit,
    WarnLimit,
    SoftLimit,
    Description,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuotaValue {
    Id(Id),
    Types(DataType),
}

impl Property for QuotaProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        QuotaProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            QuotaProperty::Description => "description",
            QuotaProperty::Id => "id",
            QuotaProperty::Name => "name",
            QuotaProperty::Types => "types",
            QuotaProperty::ResourceType => "resourceType",
            QuotaProperty::Used => "used",
            QuotaProperty::HardLimit => "hardLimit",
            QuotaProperty::Scope => "scope",
            QuotaProperty::WarnLimit => "warnLimit",
            QuotaProperty::SoftLimit => "softLimit",
        }
        .into()
    }
}

impl QuotaProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => QuotaProperty::Id,
            b"resourceType" => QuotaProperty::ResourceType,
            b"used" => QuotaProperty::Used,
            b"name" => QuotaProperty::Name,
            b"scope" => QuotaProperty::Scope,
            b"types" => QuotaProperty::Types,
            b"hardLimit" => QuotaProperty::HardLimit,
            b"warnLimit" => QuotaProperty::WarnLimit,
            b"softLimit" => QuotaProperty::SoftLimit,
            b"description" => QuotaProperty::Description,
        )
    }
}

impl Element for QuotaValue {
    type Property = QuotaProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                QuotaProperty::Id => Id::from_str(value).ok().map(QuotaValue::Id),
                QuotaProperty::Types => DataType::parse(value).map(QuotaValue::Types),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            QuotaValue::Id(id) => id.to_string().into(),
            QuotaValue::Types(data_type) => data_type.as_str().into(),
        }
    }
}

impl FromStr for QuotaProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        QuotaProperty::parse(s).ok_or(())
    }
}

impl JmapObject for Quota {
    type Property = QuotaProperty;

    type Element = QuotaValue;

    type Id = Id;

    type Filter = QuotaFilter;

    type Comparator = QuotaComparator;

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = QuotaProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaFilter {
    Name(String),
    Type(String),
    Scope(String),
    ResourceType(String),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaComparator {
    Name,
    Type,
    Used,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for QuotaFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"name" => {
                *self = QuotaFilter::Name(map.next_value()?);
            },
            b"type" => {
                *self = QuotaFilter::Type(map.next_value()?);
            },
            b"scope" => {
                *self = QuotaFilter::Scope(map.next_value()?);
            },
            b"resourceType" => {
                *self = QuotaFilter::ResourceType(map.next_value()?);
            },
            _ => {
                *self = QuotaFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for QuotaComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"name" => {
                    *self = QuotaComparator::Name;
                },
                b"type" => {
                    *self = QuotaComparator::Type;
                },
                b"used" => {
                    *self = QuotaComparator::Used;
                },
                _ => {
                    *self = QuotaComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for QuotaFilter {
    fn default() -> Self {
        QuotaFilter::_T("".to_string())
    }
}

impl Default for QuotaComparator {
    fn default() -> Self {
        QuotaComparator::_T("".to_string())
    }
}

impl From<Id> for QuotaValue {
    fn from(id: Id) -> Self {
        QuotaValue::Id(id)
    }
}

impl JmapObjectId for QuotaValue {
    fn as_id(&self) -> Option<Id> {
        if let QuotaValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        self.as_id().map(AnyId::Id)
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = QuotaValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for QuotaProperty {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<AnyId> {
        None
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        false
    }
}
