/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::id::Id;

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};

#[derive(Debug, Clone, Default)]
pub struct Principal;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalProperty {
    Id,
    Type,
    Name,
    Description,
    Email,
    Timezone,
    Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalValue {
    Id(Id),
    Type(PrincipalType),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalType {
    Individual,
    Group,
    Resource,
    Location,
    Other,
}

impl Property for PrincipalProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        PrincipalProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PrincipalProperty::Capabilities => "capabilities",
            PrincipalProperty::Description => "description",
            PrincipalProperty::Email => "email",
            PrincipalProperty::Id => "id",
            PrincipalProperty::Name => "name",
            PrincipalProperty::Timezone => "timezone",
            PrincipalProperty::Type => "type",
        }
        .into()
    }
}

impl Element for PrincipalValue {
    type Property = PrincipalProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                PrincipalProperty::Id => Id::from_str(value).ok().map(PrincipalValue::Id),
                PrincipalProperty::Type => PrincipalType::parse(value).map(PrincipalValue::Type),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PrincipalValue::Id(id) => id.to_string().into(),
            PrincipalValue::Type(t) => t.as_str().into(),
        }
    }
}

impl PrincipalProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => PrincipalProperty::Id,
            b"type" => PrincipalProperty::Type,
            b"name" => PrincipalProperty::Name,
            b"description" => PrincipalProperty::Description,
            b"email" => PrincipalProperty::Email,
            b"timezone" => PrincipalProperty::Timezone,
            b"capabilities" => PrincipalProperty::Capabilities,
        )
    }
}

impl PrincipalType {
    pub fn parse(s: &str) -> Option<Self> {
        hashify::tiny_map!(s.as_bytes(),
            b"individual" => PrincipalType::Individual,
            b"group" => PrincipalType::Group,
            b"resource" => PrincipalType::Resource,
            b"location" => PrincipalType::Location,
            b"other" => PrincipalType::Other,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalType::Individual => "individual",
            PrincipalType::Group => "group",
            PrincipalType::Resource => "resource",
            PrincipalType::Location => "location",
            PrincipalType::Other => "other",
        }
    }
}

impl serde::Serialize for PrincipalProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_cow().as_ref())
    }
}

impl FromStr for PrincipalProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrincipalProperty::parse(s).ok_or(())
    }
}

impl JmapObject for Principal {
    type Property = PrincipalProperty;

    type Element = PrincipalValue;

    type Id = Id;

    type Filter = PrincipalFilter;

    type Comparator = PrincipalComparator;

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    const ID_PROPERTY: Self::Property = PrincipalProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalFilter {
    AccountIds(Vec<Id>),
    Email(String),
    Name(String),
    Text(String),
    Type(PrincipalType),
    Timezone(String),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalComparator {
    Name,
    Email,
    Type,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for PrincipalFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountIds" => {
                *self = PrincipalFilter::AccountIds(map.next_value()?);
            },
            b"email" => {
                *self = PrincipalFilter::Email(map.next_value()?);
            },
            b"name" => {
                *self = PrincipalFilter::Name(map.next_value()?);
            },
            b"text" => {
                *self = PrincipalFilter::Text(map.next_value()?);
            },
            b"type" => {
                *self = PrincipalFilter::Type(map.next_value()?);
            },
            b"timezone" => {
                *self = PrincipalFilter::Timezone(map.next_value()?);
            },
            _ => {
                *self = PrincipalFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for PrincipalComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"name" => {
                    *self = PrincipalComparator::Name;
                },
                b"email" => {
                    *self = PrincipalComparator::Email;
                },
                b"type" => {
                    *self = PrincipalComparator::Type;
                },
                _ => {
                    *self = PrincipalComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for PrincipalFilter {
    fn default() -> Self {
        PrincipalFilter::_T("".to_string())
    }
}

impl Default for PrincipalComparator {
    fn default() -> Self {
        PrincipalComparator::_T("".to_string())
    }
}

impl<'de> serde::Deserialize<'de> for PrincipalType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        PrincipalType::parse(<&str>::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid JMAP PrincipalType"))
    }
}

impl From<Id> for PrincipalValue {
    fn from(id: Id) -> Self {
        PrincipalValue::Id(id)
    }
}

impl JmapObjectId for PrincipalValue {
    fn as_id(&self) -> Option<Id> {
        if let PrincipalValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let PrincipalValue::Id(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }
}

impl TryFrom<AnyId> for PrincipalValue {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        if let AnyId::Id(id) = value {
            Ok(PrincipalValue::Id(id))
        } else {
            Err(())
        }
    }
}

impl Display for PrincipalFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PrincipalFilter::AccountIds(_) => "accountIds",
            PrincipalFilter::Email(_) => "email",
            PrincipalFilter::Name(_) => "name",
            PrincipalFilter::Text(_) => "text",
            PrincipalFilter::Type(_) => "type",
            PrincipalFilter::Timezone(_) => "timezone",
            PrincipalFilter::_T(other) => other,
        })
    }
}
