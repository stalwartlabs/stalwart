/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId, MaybeReference, parse_ref},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key};
use registry::{
    jmap::RegistryValue,
    schema::prelude::{Object, Property},
};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

#[derive(Debug)]
pub struct Registry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryFilter {
    Type(Object),
    Text(String),
    Id(Vec<Id>),
    Property(Property),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryComparator {
    Id,
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
        hashify::fnc_map!(key.as_bytes(),
            b"text" => {
                *self = RegistryFilter::Text(map.next_value()?);
            },
            b"id" => {
                *self = RegistryFilter::Id(map.next_value()?);
            },
            _ => {
                *self = RegistryFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

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
            hashify::fnc_map!(value.as_bytes(),
                b"id" => {
                    *self = RegistryComparator::Id;
                },
                _ => {
                    *self = RegistryComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
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
