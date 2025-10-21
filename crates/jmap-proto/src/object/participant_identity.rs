/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::{deserialize::DeserializeArguments, reference::MaybeIdReference},
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct ParticipantIdentity;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParticipantIdentityProperty {
    Id,
    Name,
    CalendarAddress,
    IsDefault,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParticipantIdentityValue {
    Id(Id),
}

impl Property for ParticipantIdentityProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        ParticipantIdentityProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ParticipantIdentityProperty::Id => "id",
            ParticipantIdentityProperty::Name => "name",
            ParticipantIdentityProperty::CalendarAddress => "calendarAddress",
            ParticipantIdentityProperty::IsDefault => "isDefault",
        }
        .into()
    }
}

impl Element for ParticipantIdentityValue {
    type Property = ParticipantIdentityProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                ParticipantIdentityProperty::Id => {
                    Id::from_str(value).ok().map(ParticipantIdentityValue::Id)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ParticipantIdentityValue::Id(id) => id.to_string().into(),
        }
    }
}

impl ParticipantIdentityProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ParticipantIdentityProperty::Id,
            b"name" => ParticipantIdentityProperty::Name,
            b"calendarAddress" => ParticipantIdentityProperty::CalendarAddress,
            b"isDefault" => ParticipantIdentityProperty::IsDefault
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            ParticipantIdentityProperty::Id => "id",
            ParticipantIdentityProperty::Name => "name",
            ParticipantIdentityProperty::CalendarAddress => "calendarAddress",
            ParticipantIdentityProperty::IsDefault => "isDefault",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParticipantIdentitySetArguments {
    pub on_success_set_is_default: Option<MaybeIdReference<Id>>,
}

impl<'de> DeserializeArguments<'de> for ParticipantIdentitySetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
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

impl FromStr for ParticipantIdentityProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ParticipantIdentityProperty::parse(s).ok_or(())
    }
}

impl JmapObject for ParticipantIdentity {
    type Property = ParticipantIdentityProperty;

    type Element = ParticipantIdentityValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ParticipantIdentitySetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ParticipantIdentityProperty::Id;
}

impl TryFrom<ParticipantIdentityProperty> for Id {
    type Error = ();

    fn try_from(_: ParticipantIdentityProperty) -> Result<Self, Self::Error> {
        Err(())
    }
}

impl From<Id> for ParticipantIdentityValue {
    fn from(id: Id) -> Self {
        ParticipantIdentityValue::Id(id)
    }
}

impl JmapObjectId for ParticipantIdentityValue {
    fn as_id(&self) -> Option<Id> {
        let ParticipantIdentityValue::Id(id) = self;
        Some(*id)
    }

    fn as_any_id(&self) -> Option<AnyId> {
        let ParticipantIdentityValue::Id(id) = self;
        Some(AnyId::Id(*id))
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(new_id) = new_id {
            *self = ParticipantIdentityValue::Id(new_id);
            return true;
        }
        false
    }
}

impl JmapObjectId for ParticipantIdentityProperty {
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

impl Display for ParticipantIdentityProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}
