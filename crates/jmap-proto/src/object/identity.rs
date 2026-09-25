/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, PointerDepth, Property};
use serde::{Serialize, Serializer};
use std::{borrow::Cow, str::FromStr};
use types::{id::Id, text::Text};

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
        Self::try_parse_nested(key, value, PointerDepth::default())
    }

    fn try_parse_nested(
        key: Option<&Key<'_, Self>>,
        value: &str,
        depth: PointerDepth,
    ) -> Option<Self> {
        IdentityProperty::parse(value, key.is_none().then_some(depth))
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
        self.text().to_cow()
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text().serialize(serializer)
    }
}

impl IdentityValue {
    pub fn text(&self) -> Text<'_> {
        match self {
            IdentityValue::Id(id) => Text::Id(*id),
        }
    }
}

impl IdentityProperty {
    pub fn text(&self) -> Text<'_> {
        Text::Static(match self {
            IdentityProperty::Bcc => "bcc",
            IdentityProperty::Email => "email",
            IdentityProperty::HtmlSignature => "htmlSignature",
            IdentityProperty::Id => "id",
            IdentityProperty::MayDelete => "mayDelete",
            IdentityProperty::Name => "name",
            IdentityProperty::ReplyTo => "replyTo",
            IdentityProperty::TextSignature => "textSignature",
            IdentityProperty::Pointer(json_pointer) => return Text::Display(json_pointer),
        })
    }

    fn has_dynamic_text(&self) -> bool {
        matches!(self, IdentityProperty::Pointer(_))
    }

    fn parse(value: &str, patch_depth: Option<PointerDepth>) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"id" => Some(IdentityProperty::Id),
            b"name" => Some(IdentityProperty::Name),
            b"email" => Some(IdentityProperty::Email),
            b"replyTo" => Some(IdentityProperty::ReplyTo),
            b"bcc" => Some(IdentityProperty::Bcc),
            b"textSignature" => Some(IdentityProperty::TextSignature),
            b"htmlSignature" => Some(IdentityProperty::HtmlSignature),
            b"mayDelete" => Some(IdentityProperty::MayDelete),
            _ => None,
        )
        .or_else(|| {
            patch_depth
                .filter(|_| value.contains('/'))
                .and_then(|depth| JsonPointer::parse_nested(value, depth))
                .map(IdentityProperty::Pointer)
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

impl FromStr for IdentityProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IdentityProperty::parse(s, None).ok_or(())
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

    type ParseArguments = ();

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

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = IdentityValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for IdentityProperty {
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
