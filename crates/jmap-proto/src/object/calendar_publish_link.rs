/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct CalendarPublishLink;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarPublishLinkProperty {
    Id,
    CalendarId,
    Access,
    Visibility,
    Label,
    Url,
    Secret,
    CreatedAt,
    LastUsedAt,
    ExpiresAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarPublishLinkValue {
    Id(Id),
    CalendarId(Id),
    Access(PublishAccess),
    Visibility(PublishVisibility),
    Date(UTCDate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublishAccess {
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublishVisibility {
    Full,
    Busy,
}

impl Property for CalendarPublishLinkProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        CalendarPublishLinkProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CalendarPublishLinkProperty::Id => "id",
            CalendarPublishLinkProperty::CalendarId => "calendarId",
            CalendarPublishLinkProperty::Access => "access",
            CalendarPublishLinkProperty::Visibility => "visibility",
            CalendarPublishLinkProperty::Label => "label",
            CalendarPublishLinkProperty::Url => "url",
            CalendarPublishLinkProperty::Secret => "secret",
            CalendarPublishLinkProperty::CreatedAt => "createdAt",
            CalendarPublishLinkProperty::LastUsedAt => "lastUsedAt",
            CalendarPublishLinkProperty::ExpiresAt => "expiresAt",
        }
        .into()
    }
}

impl Element for CalendarPublishLinkValue {
    type Property = CalendarPublishLinkProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                CalendarPublishLinkProperty::CalendarId => {
                    Id::from_str(value).ok().map(CalendarPublishLinkValue::CalendarId)
                }
                CalendarPublishLinkProperty::Access => match value {
                    "public" => Some(CalendarPublishLinkValue::Access(PublishAccess::Public)),
                    "private" => Some(CalendarPublishLinkValue::Access(PublishAccess::Private)),
                    _ => None,
                },
                CalendarPublishLinkProperty::Visibility => match value {
                    "full" => Some(CalendarPublishLinkValue::Visibility(PublishVisibility::Full)),
                    "busy" => Some(CalendarPublishLinkValue::Visibility(PublishVisibility::Busy)),
                    _ => None,
                },
                CalendarPublishLinkProperty::CreatedAt
                | CalendarPublishLinkProperty::LastUsedAt
                | CalendarPublishLinkProperty::ExpiresAt => UTCDate::from_str(value)
                    .ok()
                    .map(CalendarPublishLinkValue::Date),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CalendarPublishLinkValue::Id(id) => id.as_string().into(),
            CalendarPublishLinkValue::CalendarId(id) => id.to_string().into(),
            CalendarPublishLinkValue::Access(a) => match a {
                PublishAccess::Public => "public",
                PublishAccess::Private => "private",
            }
            .into(),
            CalendarPublishLinkValue::Visibility(v) => match v {
                PublishVisibility::Full => "full",
                PublishVisibility::Busy => "busy",
            }
            .into(),
            CalendarPublishLinkValue::Date(d) => d.to_string().into(),
        }
    }
}

impl CalendarPublishLinkProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => CalendarPublishLinkProperty::Id,
            b"calendarId" => CalendarPublishLinkProperty::CalendarId,
            b"access" => CalendarPublishLinkProperty::Access,
            b"visibility" => CalendarPublishLinkProperty::Visibility,
            b"label" => CalendarPublishLinkProperty::Label,
            b"url" => CalendarPublishLinkProperty::Url,
            b"secret" => CalendarPublishLinkProperty::Secret,
            b"createdAt" => CalendarPublishLinkProperty::CreatedAt,
            b"lastUsedAt" => CalendarPublishLinkProperty::LastUsedAt,
            b"expiresAt" => CalendarPublishLinkProperty::ExpiresAt
        )
    }
}

impl FromStr for CalendarPublishLinkProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CalendarPublishLinkProperty::parse(s).ok_or(())
    }
}

impl JmapObject for CalendarPublishLink {
    type Property = CalendarPublishLinkProperty;
    type Element = CalendarPublishLinkValue;
    type Id = Id;
    type Filter = ();
    type Comparator = ();
    type GetArguments = ();
    type SetArguments<'de> = ();
    type QueryArguments = ();
    type CopyArguments = ();
    type ParseArguments = ();
    const ID_PROPERTY: Self::Property = CalendarPublishLinkProperty::Id;
}

impl From<Id> for CalendarPublishLinkValue {
    fn from(id: Id) -> Self {
        CalendarPublishLinkValue::CalendarId(id)
    }
}

impl From<String> for CalendarPublishLinkValue {
    fn from(_: String) -> Self {
        unreachable!("CalendarPublishLink ids are JMAP Id values")
    }
}

impl JmapObjectId for CalendarPublishLinkValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            CalendarPublishLinkValue::Id(id) => Some(*id),
            CalendarPublishLinkValue::CalendarId(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        self.as_id().map(AnyId::Id)
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, id: AnyId) -> bool {
        let _ = id;
        false
    }
}

impl JmapObjectId for CalendarPublishLinkProperty {
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

impl Display for CalendarPublishLinkProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cow())
    }
}

impl Display for PublishAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PublishAccess::Public => "public",
                PublishAccess::Private => "private",
            }
        )
    }
}

impl Display for PublishVisibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PublishVisibility::Full => "full",
                PublishVisibility::Busy => "busy",
            }
        )
    }
}
