/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use registry::{jmap::RegistryValue, schema::prelude::Property, types::EnumImpl};
use std::borrow::Cow;
use types::id::Id;

#[derive(Debug)]
pub struct Registry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryFilter {
    Property {
        property: Property,
        operator: RegistryFilterOperator,
        value: serde_json::Value,
    },
    _T(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryFilterOperator {
    Equal,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryComparator {
    Property(Property),
    _T(String),
}

impl JmapObject for Registry {
    type Property = Property;

    type Element = RegistryValue;

    type Id = Id;

    type Filter = RegistryFilter;

    type Comparator = RegistryComparator;

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = Property::Id;
}

impl JmapObjectId for Property {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<super::AnyId> {
        None
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: super::AnyId) -> bool {
        false
    }
}

impl JmapObjectId for RegistryValue {
    fn as_id(&self) -> Option<Id> {
        if let RegistryValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            RegistryValue::Id(id) => Some(AnyId::Id(*id)),
            RegistryValue::BlobId(id) => Some(AnyId::BlobId(id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let RegistryValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        match new_id {
            AnyId::Id(id) => {
                *self = RegistryValue::Id(id);
            }
            AnyId::BlobId(id) => {
                *self = RegistryValue::BlobId(id);
            }
        }
        true
    }
}

impl<'de> DeserializeArguments<'de> for RegistryFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if let Some(property) = Property::parse(key) {
            let value = map.next_value()?;
            *self = RegistryFilter::Property {
                property,
                operator: RegistryFilterOperator::Equal,
                value,
            };
            return Ok(());
        } else if let Some((property, operator)) = key.rsplit_once("Is")
            && let (Some(property), Some(operator)) = (
                Property::parse(property),
                RegistryFilterOperator::parse(operator),
            )
        {
            let value = map.next_value()?;
            *self = RegistryFilter::Property {
                property,
                operator,
                value,
            };
            return Ok(());
        }

        *self = RegistryFilter::_T(key.to_string());
        let _ = map.next_value::<serde::de::IgnoredAny>()?;

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for RegistryComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;

            if let Some(property) = Property::parse(value.as_ref()) {
                *self = RegistryComparator::Property(property);
            } else {
                *self = RegistryComparator::_T(value.into_owned());
            }
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl RegistryFilterOperator {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"GreaterThan" => RegistryFilterOperator::GreaterThan,
            b"GreaterThanOrEqual" => RegistryFilterOperator::GreaterThanOrEqual,
            b"LessThan" => RegistryFilterOperator::LessThan,
            b"LessThanOrEqual" => RegistryFilterOperator::LessThanOrEqual,
        )
    }
}

impl Default for RegistryFilter {
    fn default() -> Self {
        RegistryFilter::_T("".to_string())
    }
}

impl Default for RegistryComparator {
    fn default() -> Self {
        RegistryComparator::_T("".to_string())
    }
}
