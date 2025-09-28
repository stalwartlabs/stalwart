/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

use crate::object::{AnyId, JmapObject, JmapObjectId};

#[derive(Debug, Clone, Default)]
pub struct Identity;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityProperty {
    Id,
    Name,
    Email,
    ReplyTo,
    Bcc,
    TextSignature,
    HtmlSignature,
    MayDelete,

    // Other
    Pointer(JsonPointer<IdentityProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityValue {
    Id(Id),
}

impl Property for IdentityProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        IdentityProperty::parse(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            IdentityProperty::Bcc => "bcc",
            IdentityProperty::Email => "email",
            IdentityProperty::HtmlSignature => "htmlSignature",
            IdentityProperty::Id => "id",
            IdentityProperty::MayDelete => "mayDelete",
            IdentityProperty::Name => "name",
            IdentityProperty::ReplyTo => "replyTo",
            IdentityProperty::TextSignature => "textSignature",
            IdentityProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
        }
        .into()
    }
}

impl Element for IdentityValue {
    type Property = IdentityProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                IdentityProperty::Id => Id::from_str(value).ok().map(IdentityValue::Id),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            IdentityValue::Id(id) => id.to_string().into(),
        }
    }
}

impl IdentityProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => IdentityProperty::Id,
            b"name" => IdentityProperty::Name,
            b"email" => IdentityProperty::Email,
            b"replyTo" => IdentityProperty::ReplyTo,
            b"bcc" => IdentityProperty::Bcc,
            b"textSignature" => IdentityProperty::TextSignature,
            b"htmlSignature" => IdentityProperty::HtmlSignature,
            b"mayDelete" => IdentityProperty::MayDelete,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                IdentityProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &IdentityProperty {
        if let IdentityProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

impl serde::Serialize for IdentityProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_cow().as_ref())
    }
}

impl FromStr for IdentityProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IdentityProperty::parse(s, false).ok_or(())
    }
}

impl JmapObject for Identity {
    type Property = IdentityProperty;

    type Element = IdentityValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    const ID_PROPERTY: Self::Property = IdentityProperty::Id;
}

impl From<Id> for IdentityValue {
    fn from(id: Id) -> Self {
        IdentityValue::Id(id)
    }
}

impl JmapObjectId for IdentityValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            IdentityValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            IdentityValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }
}

impl TryFrom<AnyId> for IdentityValue {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        match value {
            AnyId::Id(id) => Ok(IdentityValue::Id(id)),
            _ => Err(()),
        }
    }
}
