/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::{JSCalendarProperty, JSCalendarValue};
use common::DavName;
use groupware::calendar::{
    EVENT_DRAFT, EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS, EVENT_INVITE_SELF,
};
use jmap_proto::error::set::SetError;
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventKey<'x> = Key<'x, JSCalendarProperty<Id>>;
type EventError = SetError<JSCalendarProperty<Id>>;

pub(super) trait EventProperty {
    fn is_event_metadata(&self) -> bool;

    fn is_series_property(&self) -> bool;
}

impl EventProperty for JSCalendarProperty<Id> {
    fn is_event_metadata(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::Id
                | JSCalendarProperty::BaseEventId
                | JSCalendarProperty::CalendarIds
                | JSCalendarProperty::IsDraft
                | JSCalendarProperty::IsOrigin
                | JSCalendarProperty::UtcStart
                | JSCalendarProperty::UtcEnd
                | JSCalendarProperty::UseDefaultAlerts
                | JSCalendarProperty::MayInviteSelf
                | JSCalendarProperty::MayInviteOthers
                | JSCalendarProperty::HideAttendees
        )
    }

    fn is_series_property(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::Type
                | JSCalendarProperty::Method
                | JSCalendarProperty::OrganizerCalendarAddress
                | JSCalendarProperty::Privacy
                | JSCalendarProperty::ProdId
                | JSCalendarProperty::RecurrenceId
                | JSCalendarProperty::RecurrenceIdTimeZone
                | JSCalendarProperty::SentBy
                | JSCalendarProperty::Uid
                | JSCalendarProperty::RecurrenceOverrides
                | JSCalendarProperty::RecurrenceRule
        )
    }
}

pub(super) trait OverridePatch {
    fn validate_override_patch(&self) -> Result<(), EventError>;
}

impl OverridePatch for EventValue<'_> {
    fn validate_override_patch(&self) -> Result<(), EventError> {
        match self {
            Value::Object(patch) => patch
                .keys()
                .try_for_each(OverridePatch::validate_override_patch),
            _ => Err(SetError::invalid_properties()
                .with_property(JSCalendarProperty::RecurrenceOverrides)
                .with_description("Expected a patch object.")),
        }
    }
}

impl OverridePatch for EventKey<'_> {
    fn validate_override_patch(&self) -> Result<(), EventError> {
        let rejected = match self {
            Key::Property(JSCalendarProperty::Pointer(pointer)) => {
                pointer.rejected_override_token()
            }
            Key::Property(property)
                if property.is_event_metadata() || property.is_series_property() =>
            {
                Some(property)
            }
            _ => None,
        };

        match rejected {
            Some(property) => Err(SetError::invalid_properties()
                .with_property(JSCalendarProperty::RecurrenceOverrides)
                .with_description(match property {
                    JSCalendarProperty::UtcStart | JSCalendarProperty::UtcEnd => Cow::Borrowed(
                        "utcStart and utcEnd cannot be set inside recurrenceOverrides.",
                    ),
                    property => Cow::Owned(format!(
                        "{} cannot be set inside recurrenceOverrides.",
                        property.to_string()
                    )),
                })),
            None => Ok(()),
        }
    }
}

pub(super) trait OverridePointer {
    fn validate_override_pointer(&self, value: &EventValue<'_>) -> Result<(), EventError>;

    fn rejected_override_token(&self) -> Option<&JSCalendarProperty<Id>>;
}

impl OverridePointer for JsonPointer<JSCalendarProperty<Id>> {
    fn validate_override_pointer(&self, value: &EventValue<'_>) -> Result<(), EventError> {
        match self.as_slice() {
            [_, _] if value.is_null() => Ok(()),
            [_, _] => value.validate_override_patch(),
            [_, _, JsonPointerItem::Key(key), ..] => key.validate_override_patch(),
            _ => Ok(()),
        }
    }

    fn rejected_override_token(&self) -> Option<&JSCalendarProperty<Id>> {
        match self.as_slice() {
            [
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
                _,
                JsonPointerItem::Key(Key::Property(property @ JSCalendarProperty::CalendarAddress)),
            ] => Some(property),
            [JsonPointerItem::Key(Key::Property(property))] if property.is_series_property() => {
                Some(property)
            }
            [JsonPointerItem::Key(Key::Property(property)), ..]
                if property.is_event_metadata()
                    || matches!(
                        property,
                        JSCalendarProperty::RecurrenceOverrides
                            | JSCalendarProperty::RecurrenceRule
                    ) =>
            {
                Some(property)
            }
            _ => None,
        }
    }
}

pub(super) trait BooleanValue {
    fn is_same_boolean(&self, current: bool) -> bool;
}

impl BooleanValue for EventValue<'_> {
    fn is_same_boolean(&self, current: bool) -> bool {
        match self {
            Value::Bool(value) => *value == current,
            Value::Null => !current,
            _ => false,
        }
    }
}

pub(super) trait PropertyName {
    fn is_valid_property_name(&self) -> bool;
}

impl PropertyName for str {
    fn is_valid_property_name(&self) -> bool {
        match self.split_once(':') {
            Some((prefix, name)) => {
                !prefix.is_empty()
                    && prefix.split('.').all(|label| {
                        !label.is_empty()
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || !ch.is_ascii())
                    })
                    && !name.is_empty()
                    && name.chars().all(|ch| {
                        matches!(ch, ' ' | '\t' | '!' | '#'..='.' | '0'..='}') || !ch.is_ascii()
                    })
            }
            None => {
                !self.is_empty()
                    && self
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'@')
            }
        }
    }
}

pub(super) struct InstanceMetadata<'a> {
    pub is_origin: bool,
    pub flags: u16,
    pub calendar_ids: &'a [DavName],
    pub use_default_alerts: bool,
}

pub(super) struct InstanceView<'a, 'x> {
    pub event: &'a EventMap<'x>,
    pub metadata: &'a InstanceMetadata<'a>,
    pub id: Id,
    pub recurrence_ids: [i64; 2],
}

impl InstanceView<'_, '_> {
    pub fn is_override_key(
        &self,
        key: &EventKey<'_>,
        value: &EventValue<'_>,
    ) -> Result<bool, EventError> {
        let property = match key {
            Key::Property(property) => property,
            Key::Borrowed(name) if name.is_valid_property_name() => return Ok(true),
            Key::Owned(name) if name.is_valid_property_name() => return Ok(true),
            key => {
                return Err(SetError::invalid_properties()
                    .with_property(key.to_owned())
                    .with_description("Invalid property."));
            }
        };
        let is_inherited = match property {
            JSCalendarProperty::Id => {
                return if crate::matches_id(value, self.id) {
                    Ok(false)
                } else {
                    Err(SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description("This property is immutable."))
                };
            }
            JSCalendarProperty::BaseEventId => {
                crate::matches_id(value, Id::from(self.id.document_id()))
            }
            JSCalendarProperty::IsOrigin => value.as_bool() == Some(self.metadata.is_origin),
            JSCalendarProperty::CalendarIds => self.is_same_calendar_ids(value),
            JSCalendarProperty::IsDraft => self.is_same_flag(value, EVENT_DRAFT),
            JSCalendarProperty::MayInviteSelf => self.is_same_flag(value, EVENT_INVITE_SELF),
            JSCalendarProperty::MayInviteOthers => self.is_same_flag(value, EVENT_INVITE_OTHERS),
            JSCalendarProperty::HideAttendees => self.is_same_flag(value, EVENT_HIDE_ATTENDEES),
            JSCalendarProperty::UseDefaultAlerts => {
                value.is_same_boolean(self.metadata.use_default_alerts)
            }
            JSCalendarProperty::RecurrenceId => matches!(
                value,
                Value::Element(JSCalendarValue::DateTime(date_time))
                    if self.recurrence_ids.contains(&date_time.timestamp)
            ),
            JSCalendarProperty::RecurrenceIdTimeZone => {
                self.is_base_value(&JSCalendarProperty::TimeZone, value)
            }
            JSCalendarProperty::RecurrenceOverrides | JSCalendarProperty::RecurrenceRule => {
                value.is_null()
            }
            JSCalendarProperty::Pointer(pointer) => match pointer.as_slice() {
                [
                    JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
                    JsonPointerItem::Key(participant_id),
                    JsonPointerItem::Key(Key::Property(JSCalendarProperty::CalendarAddress)),
                ] => self
                    .event
                    .get(&Key::Property(JSCalendarProperty::Participants))
                    .and_then(|participants| participants.as_object_and_get(participant_id))
                    .and_then(|participant| {
                        participant
                            .as_object_and_get(&Key::Property(JSCalendarProperty::CalendarAddress))
                    })
                    .is_some_and(|address| address == value),
                [JsonPointerItem::Key(Key::Property(first)), ..]
                    if first.is_event_metadata() || first.is_series_property() =>
                {
                    false
                }
                _ => return Ok(true),
            },
            JSCalendarProperty::UtcStart | JSCalendarProperty::UtcEnd => false,
            property if property.is_series_property() => self.is_base_value(property, value),
            _ => return Ok(true),
        };

        if is_inherited {
            Ok(false)
        } else {
            Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("This property cannot be modified on a single occurrence."))
        }
    }

    fn is_base_value(&self, property: &JSCalendarProperty<Id>, value: &EventValue<'_>) -> bool {
        match self.event.get(&Key::Property(property.clone())) {
            Some(base) => base == value,
            None => value.is_null(),
        }
    }

    fn is_same_flag(&self, value: &EventValue<'_>, flag: u16) -> bool {
        value.is_same_boolean(self.metadata.flags & flag != 0)
    }

    fn is_same_calendar_ids(&self, value: &EventValue<'_>) -> bool {
        value.as_object().is_some_and(|calendar_ids| {
            calendar_ids.len() == self.metadata.calendar_ids.len()
                && calendar_ids.iter().all(|(key, value)| {
                    matches!(value, Value::Bool(true))
                        && matches!(key, Key::Property(JSCalendarProperty::IdValue(id))
                            if self
                                .metadata
                                .calendar_ids
                                .iter()
                                .any(|name| name.parent_id == id.document_id()))
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::jscalendar::JSCalendar;

    fn patch_keys(json: &str) -> Vec<Result<(), EventError>> {
        let event = JSCalendar::<Id, BlobId>::parse(json).expect("valid JSCalendar");
        event
            .0
            .as_object_and_get(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|overrides| overrides.values())
            .map(OverridePatch::validate_override_patch)
            .collect()
    }

    #[test]
    fn override_patch_rejects_series_and_metadata_keys() {
        for key in [
            "@type",
            "method",
            "organizerCalendarAddress",
            "privacy",
            "prodId",
            "recurrenceId",
            "recurrenceIdTimeZone",
            "sentBy",
            "uid",
            "recurrenceRule",
            "recurrenceOverrides",
            "isDraft",
            "mayInviteSelf",
            "mayInviteOthers",
            "hideAttendees",
            "calendarIds",
            "useDefaultAlerts",
            "utcStart",
            "participants/p1/calendarAddress",
            "recurrenceRule/frequency",
            "calendarIds/abc",
        ] {
            let json = format!(
                r#"{{"@type":"Event","recurrenceOverrides":{{"2030-01-02T09:00:00":{{"{key}":null}}}}}}"#
            );
            assert!(
                patch_keys(&json).iter().all(Result::is_err),
                "{key} was accepted"
            );
        }

        for key in [
            "title",
            "start",
            "relatedTo",
            "excluded",
            "participants/p1/participationStatus",
            "alerts/a1/acknowledged",
            "example.com:foo",
        ] {
            let json = format!(
                r#"{{"@type":"Event","recurrenceOverrides":{{"2030-01-02T09:00:00":{{"{key}":null}}}}}}"#
            );
            assert!(
                patch_keys(&json).iter().all(Result::is_ok),
                "{key} was rejected"
            );
        }
    }

    #[test]
    fn property_names() {
        for name in [
            "example.com:foo",
            "example.com:foo bar",
            "x-1.example:a:b",
            "unknownProp",
        ] {
            assert!(name.is_valid_property_name(), "{name}");
        }
        for name in [
            "",
            ":foo",
            "example.com:",
            "-example.com:foo",
            "example..com:foo",
            "example.com:foo/bar",
            "example.com:foo~bar",
            "example.com:foo\"bar",
            "unknown-prop",
            "unknown prop",
        ] {
            assert!(!name.is_valid_property_name(), "{name}");
        }
    }
}
