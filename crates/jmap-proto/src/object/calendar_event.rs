/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::{MaybeInvalid, deserialize::DeserializeArguments},
};
use calcard::{
    common::timezone::Tz,
    jscalendar::{JSCalendarDateTime, JSCalendarProperty, JSCalendarValue},
};
use jmap_tools::{JsonPointerItem, Key};
use mail_parser::DateTime;
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct CalendarEvent;

impl JmapObject for CalendarEvent {
    type Property = JSCalendarProperty<Id>;

    type Element = JSCalendarValue<Id, BlobId>;

    type Id = Id;

    type Filter = CalendarEventFilter;

    type Comparator = CalendarEventComparator;

    type GetArguments = CalendarEventGetArguments;

    type SetArguments<'de> = CalendarEventSetArguments;

    type QueryArguments = CalendarEventQueryArguments;

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = JSCalendarProperty::Id;
}

impl JmapObjectId for JSCalendarValue<Id, BlobId> {
    fn as_id(&self) -> Option<Id> {
        if let JSCalendarValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            JSCalendarValue::Id(id) => Some(AnyId::Id(*id)),
            JSCalendarValue::BlobId(blob_id) => Some(AnyId::BlobId(blob_id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        match self {
            JSCalendarValue::IdReference(r) => Some(r),
            _ => None,
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = JSCalendarValue::Id(id);
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarEventFilter {
    InCalendar(MaybeInvalid<Id>),
    After(JSCalendarDateTime),
    Before(JSCalendarDateTime),
    Text(String),
    Title(String),
    Description(String),
    Location(String),
    Owner(String),
    Attendee(String),
    Uid(String),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarEventComparator {
    Start,
    Uid,
    RecurrenceId,
    Created,
    Updated,
    _T(String),
}

#[derive(Debug, Clone, Default)]
pub struct CalendarEventGetArguments {
    pub recurrence_overrides_before: Option<JSCalendarDateTime>,
    pub recurrence_overrides_after: Option<JSCalendarDateTime>,
    pub reduce_participants: Option<bool>,
    pub time_zone: Option<Tz>,
}

#[derive(Debug, Clone, Default)]
pub struct CalendarEventSetArguments {
    pub send_scheduling_messages: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct CalendarEventQueryArguments {
    pub expand_recurrences: Option<bool>,
    pub time_zone: Option<Tz>,
}

impl<'de> DeserializeArguments<'de> for CalendarEventFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"inCalendar" => {
                *self = CalendarEventFilter::InCalendar(map.next_value()?);
            },
            b"after" => {
                *self = CalendarEventFilter::After(map.next_value::<LocalTime>()?.0);
            },
            b"before" => {
                *self = CalendarEventFilter::Before(map.next_value::<LocalTime>()?.0);
            },
            b"text" => {
                *self = CalendarEventFilter::Text(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"title" => {
                *self = CalendarEventFilter::Title(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"description" => {
                *self = CalendarEventFilter::Description(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"location" => {
                *self = CalendarEventFilter::Location(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"owner" => {
                *self = CalendarEventFilter::Owner(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"attendee" => {
                *self = CalendarEventFilter::Attendee(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"uid" => {
                *self = CalendarEventFilter::Uid(map.next_value()?);
            },
            _ => {
                *self = CalendarEventFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for CalendarEventComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"start" => {
                    *self = CalendarEventComparator::Start;
                },
                b"uid" => {
                    *self = CalendarEventComparator::Uid;
                },
                b"recurrenceId" => {
                    *self = CalendarEventComparator::RecurrenceId;
                },
                b"created" => {
                    *self = CalendarEventComparator::Created;
                },
                b"updated" => {
                    *self = CalendarEventComparator::Updated;
                },
                _ => {
                    *self = CalendarEventComparator::_T(value.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for CalendarEventGetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"recurrenceOverridesBefore" => {
                self.recurrence_overrides_before = map.next_value::<Option<LocalTime>>()?.map(|lt| lt.0)
            },
            b"recurrenceOverridesAfter" => {
                self.recurrence_overrides_after = map.next_value::<Option<LocalTime>>()?.map(|lt| lt.0);
            },
            b"reduceParticipants" => {
                self.reduce_participants = map.next_value()?;
            },
            b"timeZone" => {
                self.time_zone = map.next_value::<Option<&str>>()?.and_then(|s| Tz::from_str(s).ok());
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for CalendarEventSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"sendSchedulingMessages" => {
                self.send_scheduling_messages = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for CalendarEventQueryArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"expandRecurrences" => {
                self.expand_recurrences = map.next_value()?;
            },
            b"timeZone" => {
                self.time_zone = map.next_value::<Option<&str>>()?.and_then(|s| Tz::from_str(s).ok());
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl CalendarEventFilter {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            CalendarEventFilter::InCalendar(_) => "inCalendar",
            CalendarEventFilter::After(_) => "after",
            CalendarEventFilter::Before(_) => "before",
            CalendarEventFilter::Text(_) => "text",
            CalendarEventFilter::Title(_) => "title",
            CalendarEventFilter::Description(_) => "description",
            CalendarEventFilter::Location(_) => "location",
            CalendarEventFilter::Owner(_) => "owner",
            CalendarEventFilter::Attendee(_) => "attendee",
            CalendarEventFilter::Uid(_) => "uid",
            CalendarEventFilter::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl CalendarEventComparator {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            CalendarEventComparator::Start => "start",
            CalendarEventComparator::Uid => "uid",
            CalendarEventComparator::RecurrenceId => "recurrenceId",
            CalendarEventComparator::Created => "created",
            CalendarEventComparator::Updated => "updated",
            CalendarEventComparator::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl Default for CalendarEventFilter {
    fn default() -> Self {
        CalendarEventFilter::_T(String::new())
    }
}

impl Default for CalendarEventComparator {
    fn default() -> Self {
        CalendarEventComparator::_T(String::new())
    }
}

struct LocalTime(JSCalendarDateTime);

impl<'de> serde::Deserialize<'de> for LocalTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;

        if let Some(dt) = DateTime::parse_rfc3339(value) {
            Ok(LocalTime(JSCalendarDateTime {
                timestamp: dt.to_timestamp_local(),
                is_local: true,
            }))
        } else {
            Err(serde::de::Error::custom(format!(
                "Invalid datetime: {}",
                value
            )))
        }
    }
}

impl JmapObjectId for JSCalendarProperty<Id> {
    fn as_id(&self) -> Option<Id> {
        if let JSCalendarProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let JSCalendarProperty::IdValue(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        match self {
            JSCalendarProperty::IdReference(r) => Some(r),
            JSCalendarProperty::Pointer(value) => {
                let value = value.as_slice();
                match (value.first(), value.get(1)) {
                    (
                        Some(JsonPointerItem::Key(Key::Property(JSCalendarProperty::CalendarIds))),
                        Some(JsonPointerItem::Key(Key::Property(JSCalendarProperty::IdReference(
                            r,
                        )))),
                    ) => Some(r),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            if let JSCalendarProperty::Pointer(value) = self {
                let value = value.as_mut_slice();
                if let Some(value) = value.get_mut(1) {
                    *value = JsonPointerItem::Key(Key::Property(JSCalendarProperty::IdValue(id)));
                    return true;
                }
            } else {
                *self = JSCalendarProperty::IdValue(id);
                return true;
            }
        }
        false
    }
}
