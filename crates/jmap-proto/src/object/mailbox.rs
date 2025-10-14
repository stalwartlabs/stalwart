/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        AnyId, JmapObject, JmapObjectId, JmapRight, JmapSharedObject, MaybeReference, parse_ref,
    },
    request::{deserialize::DeserializeArguments, reference::MaybeIdReference},
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::{acl::Acl, id::Id, special_use::SpecialUse};

#[derive(Debug, Clone, Default)]
pub struct Mailbox;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxProperty {
    Id,
    Name,
    ParentId,
    Role,
    SortOrder,
    TotalEmails,
    UnreadEmails,
    TotalThreads,
    UnreadThreads,
    ShareWith,
    MyRights,
    IsSubscribed,

    // Other
    IdValue(Id),
    Rights(MailboxRight),
    Pointer(JsonPointer<MailboxProperty>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxRight {
    MayReadItems,
    MayAddItems,
    MayRemoveItems,
    MaySetSeen,
    MaySetKeywords,
    MayCreateChild,
    MayRename,
    MaySubmit,
    MayDelete,
    MayShare,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxValue {
    Id(Id),
    IdReference(String),
    Role(SpecialUse),
}

impl Property for MailboxProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        let allow_patch = key.is_none();
        if let Some(Key::Property(key)) = key {
            match key.patch_or_prop() {
                MailboxProperty::ShareWith => {
                    Id::from_str(value).ok().map(MailboxProperty::IdValue)
                }
                _ => MailboxProperty::parse(value, allow_patch),
            }
        } else {
            MailboxProperty::parse(value, allow_patch)
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MailboxProperty::Id => "id",
            MailboxProperty::IsSubscribed => "isSubscribed",
            MailboxProperty::MyRights => "myRights",
            MailboxProperty::Name => "name",
            MailboxProperty::ParentId => "parentId",
            MailboxProperty::Role => "role",
            MailboxProperty::SortOrder => "sortOrder",
            MailboxProperty::TotalEmails => "totalEmails",
            MailboxProperty::TotalThreads => "totalThreads",
            MailboxProperty::UnreadEmails => "unreadEmails",
            MailboxProperty::UnreadThreads => "unreadThreads",
            MailboxProperty::ShareWith => "shareWith",
            MailboxProperty::Rights(mailbox_right) => mailbox_right.as_str(),
            MailboxProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
            MailboxProperty::IdValue(id) => return id.to_string().into(),
        }
        .into()
    }
}

impl MailboxRight {
    pub fn as_str(&self) -> &'static str {
        match self {
            MailboxRight::MayReadItems => "mayReadItems",
            MailboxRight::MayAddItems => "mayAddItems",
            MailboxRight::MayRemoveItems => "mayRemoveItems",
            MailboxRight::MaySetSeen => "maySetSeen",
            MailboxRight::MaySetKeywords => "maySetKeywords",
            MailboxRight::MayCreateChild => "mayCreateChild",
            MailboxRight::MayRename => "mayRename",
            MailboxRight::MaySubmit => "maySubmit",
            MailboxRight::MayDelete => "mayDelete",
            MailboxRight::MayShare => "mayShare",
        }
    }
}

impl Element for MailboxValue {
    type Property = MailboxProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                MailboxProperty::Id | MailboxProperty::ParentId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(MailboxValue::Id(v)),
                    MaybeReference::Reference(v) => Some(MailboxValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                MailboxProperty::Role => SpecialUse::parse(value).map(MailboxValue::Role),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MailboxValue::Id(id) => id.to_string().into(),
            MailboxValue::IdReference(r) => format!("#{r}").into(),
            MailboxValue::Role(special_use) => special_use.as_str().unwrap_or_default().into(),
        }
    }
}

impl MailboxProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => MailboxProperty::Id,
            b"name" => MailboxProperty::Name,
            b"parentId" => MailboxProperty::ParentId,
            b"role" => MailboxProperty::Role,
            b"sortOrder" => MailboxProperty::SortOrder,
            b"totalEmails" => MailboxProperty::TotalEmails,
            b"unreadEmails" => MailboxProperty::UnreadEmails,
            b"totalThreads" => MailboxProperty::TotalThreads,
            b"unreadThreads" => MailboxProperty::UnreadThreads,
            b"shareWith" => MailboxProperty::ShareWith,
            b"myRights" => MailboxProperty::MyRights,
            b"mayReadItems" => MailboxProperty::Rights(MailboxRight::MayReadItems),
            b"mayAddItems" => MailboxProperty::Rights(MailboxRight::MayAddItems),
            b"mayRemoveItems" => MailboxProperty::Rights(MailboxRight::MayRemoveItems),
            b"maySetSeen" => MailboxProperty::Rights(MailboxRight::MaySetSeen),
            b"maySetKeywords" => MailboxProperty::Rights(MailboxRight::MaySetKeywords),
            b"mayCreateChild" => MailboxProperty::Rights(MailboxRight::MayCreateChild),
            b"mayRename" => MailboxProperty::Rights(MailboxRight::MayRename),
            b"maySubmit" => MailboxProperty::Rights(MailboxRight::MaySubmit),
            b"mayDelete" => MailboxProperty::Rights(MailboxRight::MayDelete),
            b"mayShare" => MailboxProperty::Rights(MailboxRight::MayShare),
            b"isSubscribed" => MailboxProperty::IsSubscribed,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                MailboxProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &MailboxProperty {
        if let MailboxProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MailboxSetArguments {
    pub on_destroy_remove_emails: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct MailboxQueryArguments {
    pub sort_as_tree: Option<bool>,
    pub filter_as_tree: Option<bool>,
}

impl<'de> DeserializeArguments<'de> for MailboxSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "onDestroyRemoveEmails" {
            self.on_destroy_remove_emails = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for MailboxQueryArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"sortAsTree" => {
                self.sort_as_tree = map.next_value()?;
            },
            b"filterAsTree" => {
                self.filter_as_tree = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for MailboxProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MailboxProperty::parse(s, false).ok_or(())
    }
}

impl JmapObject for Mailbox {
    type Property = MailboxProperty;

    type Element = MailboxValue;

    type Id = Id;

    type Filter = MailboxFilter;

    type Comparator = MailboxComparator;

    type GetArguments = ();

    type SetArguments<'de> = MailboxSetArguments;

    type QueryArguments = MailboxQueryArguments;

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = MailboxProperty::Id;
}

impl JmapSharedObject for Mailbox {
    type Right = MailboxRight;

    const SHARE_WITH_PROPERTY: Self::Property = MailboxProperty::ShareWith;
}

impl From<Id> for MailboxProperty {
    fn from(id: Id) -> Self {
        MailboxProperty::IdValue(id)
    }
}

impl TryFrom<MailboxProperty> for Id {
    type Error = ();

    fn try_from(value: MailboxProperty) -> Result<Self, Self::Error> {
        if let MailboxProperty::IdValue(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl TryFrom<MailboxProperty> for MailboxRight {
    type Error = ();

    fn try_from(value: MailboxProperty) -> Result<Self, Self::Error> {
        if let MailboxProperty::Rights(right) = value {
            Ok(right)
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxFilter {
    Name(String),
    ParentId(Option<MaybeIdReference<Id>>),
    Role(Option<SpecialUse>),
    HasAnyRole(bool),
    IsSubscribed(bool),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxComparator {
    SortOrder,
    Name,
    ParentId,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for MailboxFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"name" => {
                *self = MailboxFilter::Name(map.next_value()?);
            },
            b"parentId" => {
                *self = MailboxFilter::ParentId(map.next_value()?);
            },
            b"role" => {
                *self = MailboxFilter::Role(map.next_value::<Option<RoleWrapper>>()?.map(|r| r.0));
            },
            b"hasAnyRole" => {
                *self = MailboxFilter::HasAnyRole(map.next_value()?);
            },
            b"isSubscribed" => {
                *self = MailboxFilter::IsSubscribed(map.next_value()?);
            },
            _ => {
                *self = MailboxFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for MailboxComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"sortOrder" => {
                    *self = MailboxComparator::SortOrder;
                },
                b"name" => {
                    *self = MailboxComparator::Name;
                },
                b"parentId" => {
                    *self = MailboxComparator::ParentId;
                },
                _ => {
                    *self = MailboxComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for MailboxFilter {
    fn default() -> Self {
        MailboxFilter::_T("".to_string())
    }
}

impl Default for MailboxComparator {
    fn default() -> Self {
        MailboxComparator::_T("".to_string())
    }
}

struct RoleWrapper(SpecialUse);

impl<'de> serde::Deserialize<'de> for RoleWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        SpecialUse::parse(<&str>::deserialize(deserializer)?)
            .map(RoleWrapper)
            .ok_or_else(|| serde::de::Error::custom("invalid JMAP role"))
    }
}

impl From<Id> for MailboxValue {
    fn from(id: Id) -> Self {
        MailboxValue::Id(id)
    }
}

impl JmapObjectId for MailboxValue {
    fn as_id(&self) -> Option<Id> {
        if let MailboxValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let MailboxValue::Id(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let MailboxValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = MailboxValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapRight for MailboxRight {
    fn to_acl(&self) -> &'static [Acl] {
        match self {
            MailboxRight::MayReadItems => &[Acl::Read, Acl::ReadItems],
            MailboxRight::MayAddItems => &[Acl::AddItems],
            MailboxRight::MayRemoveItems => &[Acl::RemoveItems],
            MailboxRight::MaySetSeen => &[Acl::ModifyItems],
            MailboxRight::MaySetKeywords => &[Acl::ModifyItems],
            MailboxRight::MayCreateChild => &[Acl::CreateChild],
            MailboxRight::MayRename => &[Acl::Modify],
            MailboxRight::MaySubmit => &[Acl::Submit],
            MailboxRight::MayDelete => &[Acl::Delete],
            MailboxRight::MayShare => &[Acl::Share],
        }
    }

    fn all_rights() -> &'static [Self] {
        &[
            MailboxRight::MayReadItems,
            MailboxRight::MayAddItems,
            MailboxRight::MayRemoveItems,
            MailboxRight::MaySetSeen,
            MailboxRight::MaySetKeywords,
            MailboxRight::MayCreateChild,
            MailboxRight::MayRename,
            MailboxRight::MaySubmit,
            MailboxRight::MayDelete,
            MailboxRight::MayShare,
        ]
    }
}

impl From<MailboxRight> for MailboxProperty {
    fn from(right: MailboxRight) -> Self {
        MailboxProperty::Rights(right)
    }
}

impl JmapObjectId for MailboxProperty {
    fn as_id(&self) -> Option<Id> {
        if let MailboxProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let MailboxProperty::IdValue(id) = self {
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
            *self = MailboxProperty::IdValue(id);
            true
        } else {
            false
        }
    }
}
