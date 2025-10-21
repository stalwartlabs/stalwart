/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        AnyId, JmapObject, JmapObjectId, JmapRight, JmapSharedObject, MaybeReference, parse_ref,
    },
    request::{MaybeInvalid, deserialize::DeserializeArguments},
    types::date::UTCDate,
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{acl::Acl, blob::BlobId, id::Id};
use utils::glob::GlobPattern;

#[derive(Debug, Clone, Default)]
pub struct FileNode;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileNodeProperty {
    Id,
    ParentId,
    BlobId,
    Size,
    Name,
    Type,
    Created,
    Modified,
    Accessed,
    Executable,
    MyRights,
    ShareWith,
    IsSubscribed,

    // Other
    IdValue(Id),
    Rights(FileNodeRight),
    Pointer(JsonPointer<FileNodeProperty>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileNodeRight {
    MayRead,
    MayWrite,
    MayShare,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileNodeValue {
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    IdReference(String),
}

impl Property for FileNodeProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        let allow_patch = key.is_none();
        if let Some(Key::Property(key)) = key {
            match key.patch_or_prop() {
                FileNodeProperty::ShareWith => {
                    Id::from_str(value).ok().map(FileNodeProperty::IdValue)
                }
                _ => FileNodeProperty::parse(value, allow_patch),
            }
        } else {
            FileNodeProperty::parse(value, allow_patch)
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            FileNodeProperty::Id => "id",
            FileNodeProperty::ParentId => "parentId",
            FileNodeProperty::BlobId => "blobId",
            FileNodeProperty::Size => "size",
            FileNodeProperty::Name => "name",
            FileNodeProperty::Type => "type",
            FileNodeProperty::Created => "created",
            FileNodeProperty::Modified => "modified",
            FileNodeProperty::Accessed => "accessed",
            FileNodeProperty::Executable => "executable",
            FileNodeProperty::MyRights => "myRights",
            FileNodeProperty::ShareWith => "shareWith",
            FileNodeProperty::IsSubscribed => "isSubscribed",
            FileNodeProperty::Rights(file_right) => file_right.as_str(),
            FileNodeProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
            FileNodeProperty::IdValue(id) => return id.to_string().into(),
        }
        .into()
    }
}

impl FileNodeRight {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileNodeRight::MayRead => "mayRead",
            FileNodeRight::MayWrite => "mayWrite",
            FileNodeRight::MayShare => "mayShare",
        }
    }
}

impl Element for FileNodeValue {
    type Property = FileNodeProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                FileNodeProperty::Id | FileNodeProperty::ParentId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(FileNodeValue::Id(v)),
                    MaybeReference::Reference(v) => Some(FileNodeValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                FileNodeProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(FileNodeValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(FileNodeValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                FileNodeProperty::Created
                | FileNodeProperty::Modified
                | FileNodeProperty::Accessed => {
                    UTCDate::from_str(value).ok().map(FileNodeValue::Date)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            FileNodeValue::Id(id) => id.to_string().into(),
            FileNodeValue::Date(utcdate) => utcdate.to_string().into(),
            FileNodeValue::BlobId(blob_id) => blob_id.to_string().into(),
            FileNodeValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl FileNodeProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => FileNodeProperty::Id,
            b"parentId" => FileNodeProperty::ParentId,
            b"blobId" => FileNodeProperty::BlobId,
            b"size" => FileNodeProperty::Size,
            b"name" => FileNodeProperty::Name,
            b"type" => FileNodeProperty::Type,
            b"created" => FileNodeProperty::Created,
            b"modified" => FileNodeProperty::Modified,
            b"accessed" => FileNodeProperty::Accessed,
            b"executable" => FileNodeProperty::Executable,
            b"myRights" => FileNodeProperty::MyRights,
            b"shareWith" => FileNodeProperty::ShareWith,
            b"isSubscribed" => FileNodeProperty::IsSubscribed,
            b"mayRead" => FileNodeProperty::Rights(FileNodeRight::MayRead),
            b"mayWrite" => FileNodeProperty::Rights(FileNodeRight::MayWrite),
            b"mayShare" => FileNodeProperty::Rights(FileNodeRight::MayShare),
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                FileNodeProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &FileNodeProperty {
        if let FileNodeProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FileNodeSetArguments {
    pub on_destroy_remove_children: Option<bool>,
}

impl<'x> DeserializeArguments<'x> for FileNodeSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'x>,
    {
        if key == "onDestroyRemoveChildren" {
            self.on_destroy_remove_children = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FileNodeQueryArguments {
    pub depth: Option<u32>,
}

impl<'x> DeserializeArguments<'x> for FileNodeQueryArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'x>,
    {
        if key == "depth" {
            self.depth = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl FromStr for FileNodeProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FileNodeProperty::parse(s, false).ok_or(())
    }
}

impl JmapObject for FileNode {
    type Property = FileNodeProperty;

    type Element = FileNodeValue;

    type Id = Id;

    type Filter = FileNodeFilter;

    type Comparator = FileNodeComparator;

    type GetArguments = ();

    type SetArguments<'de> = FileNodeSetArguments;

    type QueryArguments = FileNodeQueryArguments;

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = FileNodeProperty::Id;
}

impl JmapSharedObject for FileNode {
    type Right = FileNodeRight;

    const SHARE_WITH_PROPERTY: Self::Property = FileNodeProperty::ShareWith;
}

impl From<Id> for FileNodeProperty {
    fn from(id: Id) -> Self {
        FileNodeProperty::IdValue(id)
    }
}

impl JmapRight for FileNodeRight {
    fn to_acl(&self) -> &'static [Acl] {
        match self {
            FileNodeRight::MayShare => &[Acl::Share],
            FileNodeRight::MayRead => &[Acl::Read, Acl::ReadItems],
            FileNodeRight::MayWrite => &[
                Acl::Modify,
                Acl::AddItems,
                Acl::ModifyItems,
                Acl::Delete,
                Acl::RemoveItems,
            ],
        }
    }

    fn all_rights() -> &'static [Self] {
        &[
            FileNodeRight::MayRead,
            FileNodeRight::MayWrite,
            FileNodeRight::MayShare,
        ]
    }
}

impl From<FileNodeRight> for FileNodeProperty {
    fn from(right: FileNodeRight) -> Self {
        FileNodeProperty::Rights(right)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileNodeFilter {
    HasParentId(bool),
    ParentId(MaybeInvalid<Id>),
    AncestorId(MaybeInvalid<Id>),
    HasType(bool),
    BlobId(MaybeInvalid<BlobId>),
    IsExecutable(bool),
    CreatedBefore(UTCDate),
    CreatedAfter(UTCDate),
    ModifiedBefore(UTCDate),
    ModifiedAfter(UTCDate),
    AccessedBefore(UTCDate),
    AccessedAfter(UTCDate),
    MinSize(u64),
    MaxSize(u64),
    Name(String),
    NameMatch(GlobPattern),
    Type(String),
    TypeMatch(GlobPattern),
    Text(String),
    Body(String),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileNodeComparator {
    Name,
    Size,
    Created,
    Modified,
    Type,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for FileNodeFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"hasParentId" => {
                *self = FileNodeFilter::HasParentId(map.next_value()?);
            },
            b"parentId" => {
                *self = FileNodeFilter::ParentId(map.next_value()?);
            },
            b"ancestorId" => {
                *self = FileNodeFilter::AncestorId(map.next_value()?);
            },
            b"hasType" => {
                *self = FileNodeFilter::HasType(map.next_value()?);
            },
            b"blobId" => {
                *self = FileNodeFilter::BlobId(map.next_value()?);
            },
            b"isExecutable" => {
                *self = FileNodeFilter::IsExecutable(map.next_value()?);
            },
            b"createdBefore" => {
                *self = FileNodeFilter::CreatedBefore(map.next_value()?);
            },
            b"createdAfter" => {
                *self = FileNodeFilter::CreatedAfter(map.next_value()?);
            },
            b"modifiedBefore" => {
                *self = FileNodeFilter::ModifiedBefore(map.next_value()?);
            },
            b"modifiedAfter" => {
                *self = FileNodeFilter::ModifiedAfter(map.next_value()?);
            },
            b"accessedBefore" => {
                *self = FileNodeFilter::AccessedBefore(map.next_value()?);
            },
            b"accessedAfter" => {
                *self = FileNodeFilter::AccessedAfter(map.next_value()?);
            },
            b"minSize" => {
                *self = FileNodeFilter::MinSize(map.next_value()?);
            },
            b"maxSize" => {
                *self = FileNodeFilter::MaxSize(map.next_value()?);
            },
            b"name" => {
                *self = FileNodeFilter::Name(map.next_value()?);
            },
            b"nameMatch" => {
                *self = FileNodeFilter::NameMatch(map.next_value()?);
            },
            b"type" => {
                *self = FileNodeFilter::Type(map.next_value()?);
            },
            b"typeMatch" => {
                *self = FileNodeFilter::TypeMatch(map.next_value()?);
            },
            b"body" => {
                *self = FileNodeFilter::Body(map.next_value()?);
            },
            b"text" => {
                *self = FileNodeFilter::Text(map.next_value()?);
            },
            _ => {
                *self = FileNodeFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for FileNodeComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"name" => {
                    *self = FileNodeComparator::Name;
                },
                b"size" => {
                    *self = FileNodeComparator::Size;
                },
                b"created" => {
                    *self = FileNodeComparator::Created;
                },
                b"modified" => {
                    *self = FileNodeComparator::Modified;
                },
                b"type" => {
                    *self = FileNodeComparator::Type;
                },
                _ => {
                    *self = FileNodeComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for FileNodeFilter {
    fn default() -> Self {
        FileNodeFilter::_T("".to_string())
    }
}

impl Default for FileNodeComparator {
    fn default() -> Self {
        FileNodeComparator::_T("".to_string())
    }
}

impl From<Id> for FileNodeValue {
    fn from(id: Id) -> Self {
        FileNodeValue::Id(id)
    }
}

impl JmapObjectId for FileNodeValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            FileNodeValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            FileNodeValue::Id(id) => Some(AnyId::Id(*id)),
            FileNodeValue::BlobId(blob_id) => Some(AnyId::BlobId(blob_id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let FileNodeValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        match new_id {
            AnyId::Id(id) => {
                *self = FileNodeValue::Id(id);
            }
            AnyId::BlobId(blob_id) => {
                *self = FileNodeValue::BlobId(blob_id);
            }
        }
        true
    }
}

impl FileNodeFilter {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            FileNodeFilter::HasParentId(_) => "hasParentId",
            FileNodeFilter::ParentId(_) => "parentId",
            FileNodeFilter::AncestorId(_) => "ancestorId",
            FileNodeFilter::HasType(_) => "hasType",
            FileNodeFilter::BlobId(_) => "blobId",
            FileNodeFilter::IsExecutable(_) => "isExecutable",
            FileNodeFilter::CreatedBefore(_) => "createdBefore",
            FileNodeFilter::CreatedAfter(_) => "createdAfter",
            FileNodeFilter::ModifiedBefore(_) => "modifiedBefore",
            FileNodeFilter::ModifiedAfter(_) => "modifiedAfter",
            FileNodeFilter::AccessedBefore(_) => "accessedBefore",
            FileNodeFilter::AccessedAfter(_) => "accessedAfter",
            FileNodeFilter::MinSize(_) => "minSize",
            FileNodeFilter::MaxSize(_) => "maxSize",
            FileNodeFilter::Name(_) => "name",
            FileNodeFilter::NameMatch(_) => "nameMatch",
            FileNodeFilter::Type(_) => "type",
            FileNodeFilter::TypeMatch(_) => "typeMatch",
            FileNodeFilter::Text(_) => "text",
            FileNodeFilter::Body(_) => "body",
            FileNodeFilter::_T(s) => return s.into(),
        }
        .into()
    }
}

impl FileNodeComparator {
    pub fn as_str(&self) -> &str {
        match self {
            FileNodeComparator::Name => "name",
            FileNodeComparator::Size => "size",
            FileNodeComparator::Created => "created",
            FileNodeComparator::Modified => "modified",
            FileNodeComparator::Type => "type",
            FileNodeComparator::_T(s) => s.as_ref(),
        }
    }

    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            FileNodeComparator::Name => "name",
            FileNodeComparator::Size => "size",
            FileNodeComparator::Created => "created",
            FileNodeComparator::Modified => "modified",
            FileNodeComparator::Type => "type",
            FileNodeComparator::_T(s) => return s.into(),
        }
        .into()
    }
}

impl serde::Serialize for FileNodeComparator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl TryFrom<FileNodeProperty> for Id {
    type Error = ();

    fn try_from(value: FileNodeProperty) -> Result<Self, Self::Error> {
        if let FileNodeProperty::IdValue(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl TryFrom<FileNodeProperty> for FileNodeRight {
    type Error = ();

    fn try_from(value: FileNodeProperty) -> Result<Self, Self::Error> {
        if let FileNodeProperty::Rights(right) = value {
            Ok(right)
        } else {
            Err(())
        }
    }
}

impl JmapObjectId for FileNodeProperty {
    fn as_id(&self) -> Option<Id> {
        if let FileNodeProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let FileNodeProperty::IdValue(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = FileNodeProperty::IdValue(id);
            true
        } else {
            false
        }
    }
}

impl Display for FileNodeProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cow())
    }
}
