/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::{MaybeInvalid, deserialize::DeserializeArguments},
    types::{date::UTCDate, state::State},
};
use calcard::jscalendar::JSCalendar;
use jmap_tools::{Element, Key, Property};
use serde::Serialize;
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct CalendarEventNotification;

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEventNotificationObject {
    pub id: Id,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<UTCDate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<PersonObject>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub notification_type: Option<CalendarEventNotificationType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_event_id: Option<Id>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_draft: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<JSCalendar<'static, Id, BlobId>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_patch: Option<JSCalendar<'static, Id, BlobId>>,
}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PersonObject {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_address: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CalendarEventNotificationGetResponse {
    #[serde(rename = "accountId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Id>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,

    pub list: Vec<CalendarEventNotificationObject>,

    #[serde(rename = "notFound")]
    pub not_found: Vec<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarEventNotificationProperty {
    Id,
    Created,
    ChangedBy,
    Comment,
    Type,
    CalendarEventId,
    IsDraft,
    Event,
    EventPatch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarEventNotificationValue {
    Id(Id),
    Date(UTCDate),
    Type(CalendarEventNotificationType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarEventNotificationType {
    Created,
    Updated,
    Destroyed,
}

impl Property for CalendarEventNotificationProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        CalendarEventNotificationProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CalendarEventNotificationProperty::Id => "id",
            CalendarEventNotificationProperty::Created => "created",
            CalendarEventNotificationProperty::ChangedBy => "changedBy",
            CalendarEventNotificationProperty::Comment => "comment",
            CalendarEventNotificationProperty::Type => "type",
            CalendarEventNotificationProperty::CalendarEventId => "calendarEventId",
            CalendarEventNotificationProperty::IsDraft => "isDraft",
            CalendarEventNotificationProperty::Event => "event",
            CalendarEventNotificationProperty::EventPatch => "eventPatch",
        }
        .into()
    }
}

impl Element for CalendarEventNotificationValue {
    type Property = CalendarEventNotificationProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                CalendarEventNotificationProperty::Id
                | CalendarEventNotificationProperty::CalendarEventId => Id::from_str(value)
                    .ok()
                    .map(CalendarEventNotificationValue::Id),
                CalendarEventNotificationProperty::Created => UTCDate::from_str(value)
                    .ok()
                    .map(CalendarEventNotificationValue::Date),
                CalendarEventNotificationProperty::Type => {
                    CalendarEventNotificationType::parse(value)
                        .map(CalendarEventNotificationValue::Type)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CalendarEventNotificationValue::Id(id) => id.to_string().into(),
            CalendarEventNotificationValue::Date(date) => date.to_string().into(),
            CalendarEventNotificationValue::Type(t) => t.as_str().into(),
        }
    }
}

impl CalendarEventNotificationType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"created" => CalendarEventNotificationType::Created,
            b"updated" => CalendarEventNotificationType::Updated,
            b"destroyed" => CalendarEventNotificationType::Destroyed,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CalendarEventNotificationType::Created => "created",
            CalendarEventNotificationType::Updated => "updated",
            CalendarEventNotificationType::Destroyed => "destroyed",
        }
    }
}

impl CalendarEventNotificationProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => CalendarEventNotificationProperty::Id,
            b"created" => CalendarEventNotificationProperty::Created,
            b"changedBy" => CalendarEventNotificationProperty::ChangedBy,
            b"comment" => CalendarEventNotificationProperty::Comment,
            b"type" => CalendarEventNotificationProperty::Type,
            b"calendarEventId" => CalendarEventNotificationProperty::CalendarEventId,
            b"isDraft" => CalendarEventNotificationProperty::IsDraft,
            b"event" => CalendarEventNotificationProperty::Event,
            b"eventPatch" => CalendarEventNotificationProperty::EventPatch
        )
    }
}

impl FromStr for CalendarEventNotificationProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CalendarEventNotificationProperty::parse(s).ok_or(())
    }
}

impl JmapObject for CalendarEventNotification {
    type Property = CalendarEventNotificationProperty;

    type Element = CalendarEventNotificationValue;

    type Id = Id;

    type Filter = CalendarEventNotificationFilter;

    type Comparator = CalendarEventNotificationComparator;

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = CalendarEventNotificationProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarEventNotificationFilter {
    After(UTCDate),
    Before(UTCDate),
    Type(CalendarEventNotificationType),
    CalendarEventIds(Vec<MaybeInvalid<Id>>),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarEventNotificationComparator {
    Created,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for CalendarEventNotificationFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"after" => {
                *self = CalendarEventNotificationFilter::After(map.next_value()?);
            },
            b"before" => {
                *self = CalendarEventNotificationFilter::Before(map.next_value()?);
            },
            b"type" => {
                *self = CalendarEventNotificationFilter::Type(map.next_value()?);
            },
            b"calendarEventIds" => {
                *self = CalendarEventNotificationFilter::CalendarEventIds(map.next_value()?);
            },
            _ => {
                *self = CalendarEventNotificationFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for CalendarEventNotificationComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"created" => {
                    *self = CalendarEventNotificationComparator::Created;
                },
                _ => {
                    *self = CalendarEventNotificationComparator::_T(value.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for CalendarEventNotificationType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CalendarEventNotificationType::parse(<&str>::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid CalendarEventNotificationType"))
    }
}

impl CalendarEventNotificationFilter {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            CalendarEventNotificationFilter::After(_) => "after",
            CalendarEventNotificationFilter::Before(_) => "before",
            CalendarEventNotificationFilter::Type(_) => "type",
            CalendarEventNotificationFilter::CalendarEventIds(_) => "calendarEventIds",
            CalendarEventNotificationFilter::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl CalendarEventNotificationComparator {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            CalendarEventNotificationComparator::Created => "created",
            CalendarEventNotificationComparator::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl Default for CalendarEventNotificationFilter {
    fn default() -> Self {
        CalendarEventNotificationFilter::_T(String::new())
    }
}

impl Default for CalendarEventNotificationComparator {
    fn default() -> Self {
        CalendarEventNotificationComparator::_T(String::new())
    }
}

impl TryFrom<CalendarEventNotificationProperty> for Id {
    type Error = ();

    fn try_from(_: CalendarEventNotificationProperty) -> Result<Self, Self::Error> {
        Err(())
    }
}

impl From<Id> for CalendarEventNotificationValue {
    fn from(id: Id) -> Self {
        CalendarEventNotificationValue::Id(id)
    }
}

impl JmapObjectId for CalendarEventNotificationValue {
    fn as_id(&self) -> Option<Id> {
        if let CalendarEventNotificationValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let CalendarEventNotificationValue::Id(id) = self {
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

impl JmapObjectId for CalendarEventNotificationProperty {
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

impl serde::Serialize for CalendarEventNotificationType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl Display for CalendarEventNotificationProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cow())
    }
}
