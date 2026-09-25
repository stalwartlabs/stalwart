/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        AnyId, DeserializeArguments, JmapObject, JmapObjectId, MaybeReference,
        metadata::{MetadataFilter, MetadataProperty, MetadataRoot},
        parse_ref,
    },
    request::reference::MaybeIdReference,
};
use jmap_tools::{Element, JsonPointer, Key, PointerDepth, Property};
use serde::{Serialize, Serializer};
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id, text::Text};

#[derive(Debug, Clone, Default)]
pub struct Sieve;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SieveProperty {
    Id,
    Name,
    BlobId,
    IsActive,
    Metadata,
    PrivateMetadata,
    Pointer(JsonPointer<SieveProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SieveValue {
    Id(Id),
    BlobId(BlobId),
    IdReference(String),
}

impl Property for SieveProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        Self::try_parse_nested(key, value, PointerDepth::default())
    }

    fn try_parse_nested(
        key: Option<&Key<'_, Self>>,
        value: &str,
        depth: PointerDepth,
    ) -> Option<Self> {
        match key {
            Some(Key::Property(key)) if key.metadata_root().is_some() => None,
            _ => SieveProperty::parse(value, key.is_none().then_some(depth)),
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.text().to_cow()
    }

    fn key_eq(&self, other: &Self) -> bool {
        if self.has_dynamic_text() || other.has_dynamic_text() {
            self.text().eq_text(other.text())
        } else {
            self == other
        }
    }

    fn key_eq_str(&self, other: &str) -> bool {
        self.text().eq_str(other)
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text().serialize(serializer)
    }
}

impl Element for SieveValue {
    type Property = SieveProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                SieveProperty::Id => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(SieveValue::Id(v)),
                    MaybeReference::Reference(v) => Some(SieveValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                SieveProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(SieveValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(SieveValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.text().to_cow()
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text().serialize(serializer)
    }
}

impl SieveValue {
    pub fn text(&self) -> Text<'_> {
        match self {
            SieveValue::Id(id) => Text::Id(*id),
            SieveValue::BlobId(blob_id) => Text::Display(blob_id),
            SieveValue::IdReference(r) => Text::Reference(r),
        }
    }
}

impl SieveProperty {
    pub fn text(&self) -> Text<'_> {
        Text::Static(match self {
            SieveProperty::BlobId => "blobId",
            SieveProperty::Id => "id",
            SieveProperty::Name => "name",
            SieveProperty::IsActive => "isActive",
            SieveProperty::Metadata => "metadata",
            SieveProperty::PrivateMetadata => "privateMetadata",
            SieveProperty::Pointer(json_pointer) => return Text::Display(json_pointer),
        })
    }

    fn has_dynamic_text(&self) -> bool {
        matches!(self, SieveProperty::Pointer(_))
    }

    fn parse(value: &str, patch_depth: Option<PointerDepth>) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"id" => Some(SieveProperty::Id),
            b"name" => Some(SieveProperty::Name),
            b"blobId" => Some(SieveProperty::BlobId),
            b"isActive" => Some(SieveProperty::IsActive),
            b"metadata" => Some(SieveProperty::Metadata),
            b"privateMetadata" => Some(SieveProperty::PrivateMetadata),
            _ => None,
        )
        .or_else(|| {
            patch_depth
                .filter(|_| value.contains('/'))
                .and_then(|depth| JsonPointer::parse_nested(value, depth))
                .map(SieveProperty::Pointer)
        })
    }
}

impl MetadataProperty for SieveProperty {
    fn as_metadata_root(&self) -> Option<MetadataRoot> {
        match self {
            SieveProperty::Metadata => Some(MetadataRoot::Shared),
            SieveProperty::PrivateMetadata => Some(MetadataRoot::Private),
            _ => None,
        }
    }

    fn as_pointer(&self) -> Option<&JsonPointer<Self>> {
        match self {
            SieveProperty::Pointer(pointer) => Some(pointer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SieveSetArguments {
    pub on_success_activate_script: Option<MaybeIdReference<Id>>,
    pub on_success_deactivate_script: Option<bool>,
}

impl<'de> DeserializeArguments<'de> for SieveSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"onSuccessActivateScript" => {
                self.on_success_activate_script = map.next_value()?;
            },
            b"onSuccessDeactivateScript" => {
                self.on_success_deactivate_script = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for SieveProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SieveProperty::parse(s, None)
            .or_else(|| {
                MetadataRoot::from_selector(s)
                    .map(|_| SieveProperty::Pointer(JsonPointer::parse(s)))
            })
            .ok_or(())
    }
}

impl JmapObject for Sieve {
    type Property = SieveProperty;

    type Element = SieveValue;

    type Id = Id;

    type Filter = SieveFilter;

    type Comparator = SieveComparator;

    type GetArguments = ();

    type SetArguments<'de> = SieveSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = SieveProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveFilter {
    Name(String),
    IsActive(bool),
    Metadata(MetadataFilter),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveComparator {
    Name,
    IsActive,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for SieveFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"name" => {
                *self = SieveFilter::Name(map.next_value()?);
            },
            b"isActive" => {
                *self = SieveFilter::IsActive(map.next_value()?);
            },
            _ => {
                *self = match MetadataFilter::try_deserialize(key, map)? {
                    Some(filter) => SieveFilter::Metadata(filter),
                    None => {
                        let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        SieveFilter::_T(key.to_string())
                    }
                };
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for SieveComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"name" => {
                    *self = SieveComparator::Name;
                },
                b"isActive" => {
                    *self = SieveComparator::IsActive;
                },
                _ => {
                    *self = SieveComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for SieveFilter {
    fn default() -> Self {
        SieveFilter::_T("".to_string())
    }
}

impl Default for SieveComparator {
    fn default() -> Self {
        SieveComparator::_T("".to_string())
    }
}

impl From<Id> for SieveValue {
    fn from(id: Id) -> Self {
        SieveValue::Id(id)
    }
}

impl JmapObjectId for SieveValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            SieveValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            SieveValue::Id(id) => Some(AnyId::Id(*id)),
            SieveValue::BlobId(id) => Some(AnyId::BlobId(id.clone())),
            SieveValue::IdReference(_) => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let SieveValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        match new_id {
            AnyId::Id(id) => {
                *self = SieveValue::Id(id);
            }
            AnyId::BlobId(id) => {
                *self = SieveValue::BlobId(id);
            }
        }
        true
    }
}

impl JmapObjectId for SieveProperty {
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
