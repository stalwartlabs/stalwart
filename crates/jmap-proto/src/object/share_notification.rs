/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{id::Id, type_state::DataType};

#[derive(Debug, Clone, Default)]
pub struct ShareNotification;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShareNotificationProperty {
    Id,
    Created,
    ChangedBy,
    ChangedByName,
    ChangedByEmail,
    ChangedByPrincipalId,
    ObjectType,
    ObjectAccountId,
    ObjectId,
    OldRights,
    NewRights,
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShareNotificationValue {
    Id(Id),
    Date(UTCDate),
    ObjectType(DataType),
}

impl Property for ShareNotificationProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        ShareNotificationProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ShareNotificationProperty::Id => "id",
            ShareNotificationProperty::Created => "created",
            ShareNotificationProperty::ChangedBy => "changedBy",
            ShareNotificationProperty::ChangedByName => "name",
            ShareNotificationProperty::ChangedByEmail => "email",
            ShareNotificationProperty::ChangedByPrincipalId => "principalId",
            ShareNotificationProperty::ObjectType => "objectType",
            ShareNotificationProperty::ObjectAccountId => "objectAccountId",
            ShareNotificationProperty::ObjectId => "objectId",
            ShareNotificationProperty::OldRights => "oldRights",
            ShareNotificationProperty::NewRights => "newRights",
            ShareNotificationProperty::Name => "name",
        }
        .into()
    }
}

impl Element for ShareNotificationValue {
    type Property = ShareNotificationProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                ShareNotificationProperty::Id
                | ShareNotificationProperty::ChangedByPrincipalId
                | ShareNotificationProperty::ObjectAccountId
                | ShareNotificationProperty::ObjectId => {
                    Id::from_str(value).ok().map(ShareNotificationValue::Id)
                }
                ShareNotificationProperty::Created => UTCDate::from_str(value)
                    .ok()
                    .map(ShareNotificationValue::Date),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ShareNotificationValue::Id(id) => id.to_string().into(),
            ShareNotificationValue::Date(date) => date.to_string().into(),
            ShareNotificationValue::ObjectType(ty) => ty.as_str().into(),
        }
    }
}

impl ShareNotificationProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ShareNotificationProperty::Id,
            b"created" => ShareNotificationProperty::Created,
            b"changedBy" => ShareNotificationProperty::ChangedBy,
            b"name" => ShareNotificationProperty::ChangedByName,
            b"email" => ShareNotificationProperty::ChangedByEmail,
            b"principalId" => ShareNotificationProperty::ChangedByPrincipalId,
            b"objectType" => ShareNotificationProperty::ObjectType,
            b"objectAccountId" => ShareNotificationProperty::ObjectAccountId,
            b"objectId" => ShareNotificationProperty::ObjectId,
            b"oldRights" => ShareNotificationProperty::OldRights,
            b"newRights" => ShareNotificationProperty::NewRights
        )
    }
}

impl FromStr for ShareNotificationProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ShareNotificationProperty::parse(s).ok_or(())
    }
}

impl JmapObject for ShareNotification {
    type Property = ShareNotificationProperty;

    type Element = ShareNotificationValue;

    type Id = Id;

    type Filter = ShareNotificationFilter;

    type Comparator = ShareNotificationComparator;

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ShareNotificationProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareNotificationFilter {
    After(UTCDate),
    Before(UTCDate),
    ObjectType(DataType),
    ObjectAccountId(Id),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareNotificationComparator {
    Created,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for ShareNotificationFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"after" => {
                *self = ShareNotificationFilter::After(map.next_value()?);
            },
            b"before" => {
                *self = ShareNotificationFilter::Before(map.next_value()?);
            },
            b"objectType" => {
                *self = ShareNotificationFilter::ObjectType(map.next_value()?);
            },
            b"objectAccountId" => {
                *self = ShareNotificationFilter::ObjectAccountId(map.next_value()?);
            },
            _ => {
                *self = ShareNotificationFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for ShareNotificationComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"created" => {
                    *self = ShareNotificationComparator::Created;
                },
                _ => {
                    *self = ShareNotificationComparator::_T(value.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl ShareNotificationFilter {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ShareNotificationFilter::After(_) => "after",
            ShareNotificationFilter::Before(_) => "before",
            ShareNotificationFilter::ObjectType(_) => "objectType",
            ShareNotificationFilter::ObjectAccountId(_) => "objectAccountId",
            ShareNotificationFilter::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl ShareNotificationComparator {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ShareNotificationComparator::Created => "created",
            ShareNotificationComparator::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl Default for ShareNotificationFilter {
    fn default() -> Self {
        ShareNotificationFilter::_T(String::new())
    }
}

impl Default for ShareNotificationComparator {
    fn default() -> Self {
        ShareNotificationComparator::_T(String::new())
    }
}

impl TryFrom<ShareNotificationProperty> for Id {
    type Error = ();

    fn try_from(_: ShareNotificationProperty) -> Result<Self, Self::Error> {
        Err(())
    }
}

impl From<Id> for ShareNotificationValue {
    fn from(id: Id) -> Self {
        ShareNotificationValue::Id(id)
    }
}

impl JmapObjectId for ShareNotificationValue {
    fn as_id(&self) -> Option<Id> {
        if let ShareNotificationValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let ShareNotificationValue::Id(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        false
    }
}

impl JmapObjectId for ShareNotificationProperty {
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

impl Display for ShareNotificationProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cow())
    }
}
