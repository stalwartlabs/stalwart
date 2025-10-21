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
pub struct AddressBook;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressBookProperty {
    Id,
    Name,
    Description,
    SortOrder,
    IsDefault,
    IsSubscribed,
    ShareWith,
    MyRights,

    // Other
    IdValue(Id),
    Rights(AddressBookRight),
    Pointer(JsonPointer<AddressBookProperty>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressBookRight {
    MayRead,
    MayWrite,
    MayShare,
    MayDelete,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressBookValue {
    Id(Id),
    IdReference(String),
    Role(SpecialUse),
}

impl Property for AddressBookProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        let allow_patch = key.is_none();
        if let Some(Key::Property(key)) = key {
            match key.patch_or_prop() {
                AddressBookProperty::ShareWith => {
                    Id::from_str(value).ok().map(AddressBookProperty::IdValue)
                }
                _ => AddressBookProperty::parse(value, allow_patch),
            }
        } else {
            AddressBookProperty::parse(value, allow_patch)
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AddressBookProperty::Id => "id",
            AddressBookProperty::Name => "name",
            AddressBookProperty::Description => "description",
            AddressBookProperty::SortOrder => "sortOrder",
            AddressBookProperty::IsDefault => "isDefault",
            AddressBookProperty::IsSubscribed => "isSubscribed",
            AddressBookProperty::ShareWith => "shareWith",
            AddressBookProperty::MyRights => "myRights",
            AddressBookProperty::Rights(addressbook_right) => addressbook_right.as_str(),
            AddressBookProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
            AddressBookProperty::IdValue(id) => return id.to_string().into(),
        }
        .into()
    }
}

impl AddressBookRight {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressBookRight::MayRead => "mayRead",
            AddressBookRight::MayWrite => "mayWrite",
            AddressBookRight::MayShare => "mayShare",
            AddressBookRight::MayDelete => "mayDelete",
        }
    }
}

impl Element for AddressBookValue {
    type Property = AddressBookProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                AddressBookProperty::Id => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(AddressBookValue::Id(v)),
                    MaybeReference::Reference(v) => Some(AddressBookValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AddressBookValue::Id(id) => id.to_string().into(),
            AddressBookValue::IdReference(r) => format!("#{r}").into(),
            AddressBookValue::Role(special_use) => special_use.as_str().unwrap_or_default().into(),
        }
    }
}

impl AddressBookProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => AddressBookProperty::Id,
            b"name" => AddressBookProperty::Name,
            b"description" => AddressBookProperty::Description,
            b"sortOrder" => AddressBookProperty::SortOrder,
            b"isDefault" => AddressBookProperty::IsDefault,
            b"isSubscribed" => AddressBookProperty::IsSubscribed,
            b"shareWith" => AddressBookProperty::ShareWith,
            b"myRights" => AddressBookProperty::MyRights,
            b"mayRead" => AddressBookProperty::Rights(AddressBookRight::MayRead),
            b"mayWrite" => AddressBookProperty::Rights(AddressBookRight::MayWrite),
            b"mayShare" => AddressBookProperty::Rights(AddressBookRight::MayShare),
            b"mayDelete" => AddressBookProperty::Rights(AddressBookRight::MayDelete)
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                AddressBookProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &AddressBookProperty {
        if let AddressBookProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddressBookSetArguments {
    pub on_destroy_remove_contents: Option<bool>,
    pub on_success_set_is_default: Option<MaybeIdReference<Id>>,
}

impl<'de> DeserializeArguments<'de> for AddressBookSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"onDestroyRemoveContents" => {
                self.on_destroy_remove_contents = map.next_value()?;
            },
            b"onSuccessSetIsDefault" => {
                self.on_success_set_is_default = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for AddressBookProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AddressBookProperty::parse(s, false).ok_or(())
    }
}

impl JmapObject for AddressBook {
    type Property = AddressBookProperty;

    type Element = AddressBookValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = AddressBookSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = AddressBookProperty::Id;
}

impl JmapSharedObject for AddressBook {
    type Right = AddressBookRight;

    const SHARE_WITH_PROPERTY: Self::Property = AddressBookProperty::ShareWith;
}

impl From<Id> for AddressBookProperty {
    fn from(id: Id) -> Self {
        AddressBookProperty::IdValue(id)
    }
}

impl TryFrom<AddressBookProperty> for Id {
    type Error = ();

    fn try_from(value: AddressBookProperty) -> Result<Self, Self::Error> {
        if let AddressBookProperty::IdValue(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl TryFrom<AddressBookProperty> for AddressBookRight {
    type Error = ();

    fn try_from(value: AddressBookProperty) -> Result<Self, Self::Error> {
        if let AddressBookProperty::Rights(right) = value {
            Ok(right)
        } else {
            Err(())
        }
    }
}

impl From<Id> for AddressBookValue {
    fn from(id: Id) -> Self {
        AddressBookValue::Id(id)
    }
}

impl JmapObjectId for AddressBookValue {
    fn as_id(&self) -> Option<Id> {
        if let AddressBookValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let AddressBookValue::Id(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let AddressBookValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(new_id) = new_id {
            *self = AddressBookValue::Id(new_id);
            return true;
        }
        false
    }
}

impl JmapRight for AddressBookRight {
    fn to_acl(&self) -> &'static [Acl] {
        match self {
            AddressBookRight::MayDelete => &[Acl::Delete, Acl::RemoveItems],
            AddressBookRight::MayShare => &[Acl::Share],
            AddressBookRight::MayRead => &[Acl::Read, Acl::ReadItems],
            AddressBookRight::MayWrite => &[Acl::Modify, Acl::AddItems, Acl::ModifyItems],
        }
    }

    fn all_rights() -> &'static [Self] {
        &[
            AddressBookRight::MayRead,
            AddressBookRight::MayWrite,
            AddressBookRight::MayDelete,
            AddressBookRight::MayShare,
        ]
    }
}

impl From<AddressBookRight> for AddressBookProperty {
    fn from(right: AddressBookRight) -> Self {
        AddressBookProperty::Rights(right)
    }
}

impl JmapObjectId for AddressBookProperty {
    fn as_id(&self) -> Option<Id> {
        if let AddressBookProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let AddressBookProperty::IdValue(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(new_id) = new_id {
            *self = AddressBookProperty::IdValue(new_id);
            return true;
        }
        false
    }
}

impl std::fmt::Display for AddressBookProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cow())
    }
}
