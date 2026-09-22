/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::embedded::EmbeddedBlobIds;
use crate::calendar_event::{EventMap, JSCalendarEntries};
use calcard::{
    icalendar::{ICalendar, ICalendarComponent, ICalendarProperty, ICalendarValue},
    jscalendar::{
        JSCalendar, JSCalendarDateTime, JSCalendarProperty, JSCalendarValue, import::ImportOptions,
    },
};
use jmap_tools::{JsonPointerItem, Key, Value};
use types::{
    blob::{BlobClass, BlobId},
    collection::Collection,
    id::Id,
};

type EventValue = Value<'static, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
pub type ServerSetValues = Vec<(JSCalendarProperty<Id>, EventValue)>;

pub const PENDING_DOCUMENT_ID: u32 = u32::MAX;

const TRACKED_PROPERTIES: [JSCalendarProperty<Id>; 9] = [
    JSCalendarProperty::Uid,
    JSCalendarProperty::Type,
    JSCalendarProperty::Created,
    JSCalendarProperty::Updated,
    JSCalendarProperty::Sequence,
    JSCalendarProperty::OrganizerCalendarAddress,
    JSCalendarProperty::TimeZone,
    JSCalendarProperty::Start,
    JSCalendarProperty::Duration,
];

const DATE_PROPERTIES: [JSCalendarProperty<Id>; 3] = [
    JSCalendarProperty::TimeZone,
    JSCalendarProperty::Start,
    JSCalendarProperty::Duration,
];

const COMPONENT_PROPERTIES: [(JSCalendarProperty<Id>, ICalendarProperty); 5] = [
    (JSCalendarProperty::Uid, ICalendarProperty::Uid),
    (JSCalendarProperty::Created, ICalendarProperty::Created),
    (JSCalendarProperty::Updated, ICalendarProperty::Dtstamp),
    (JSCalendarProperty::Sequence, ICalendarProperty::Sequence),
    (
        JSCalendarProperty::OrganizerCalendarAddress,
        ICalendarProperty::Organizer,
    ),
];

#[derive(Debug, Default)]
pub struct TrackedValues {
    values: Vec<(JSCalendarProperty<Id>, Option<EventValue>)>,
    is_origin: Option<bool>,
}

impl TrackedValues {
    pub fn from_patch(
        patch: &Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> Self {
        TrackedValues {
            values: patch
                .as_object()
                .into_iter()
                .flat_map(|object| object.iter())
                .filter_map(|(key, value)| match key {
                    Key::Property(property) if TRACKED_PROPERTIES.contains(property) => {
                        Some((property.clone(), Some(value.clone().into_owned())))
                    }
                    _ => None,
                })
                .collect(),
            is_origin: None,
        }
    }

    pub fn from_event(group: &JSCalendar<'_, Id, BlobId>, is_origin: Option<bool>) -> Self {
        TrackedValues::from_map(group.first_entry(), &TRACKED_PROPERTIES, is_origin)
    }

    pub fn from_dates(group: &JSCalendar<'_, Id, BlobId>) -> Self {
        TrackedValues::from_map(group.first_entry(), &DATE_PROPERTIES, None)
    }

    fn from_map(
        event: Option<&EventMap<'_>>,
        properties: &[JSCalendarProperty<Id>],
        is_origin: Option<bool>,
    ) -> Self {
        TrackedValues {
            values: properties
                .iter()
                .map(|property| {
                    (
                        property.clone(),
                        event
                            .and_then(|event| event.get(&Key::Property(property.clone())))
                            .map(|value| value.clone().into_owned()),
                    )
                })
                .collect(),
            is_origin,
        }
    }

    pub fn with_component(mut self, component: Option<&ICalendarComponent>) -> Self {
        self.values.reserve(COMPONENT_PROPERTIES.len() + 1);
        self.values.push((
            JSCalendarProperty::Type,
            component
                .and_then(|component| component.component_type.to_jscalendar_type())
                .map(|typ| Value::Element(JSCalendarValue::Type(typ))),
        ));
        for (property, ical_property) in COMPONENT_PROPERTIES {
            let value = component
                .and_then(|component| component.property(&ical_property))
                .and_then(|entry| entry.values.first())
                .and_then(|value| match value {
                    ICalendarValue::Text(text) => Some(Value::Str(text.clone().into())),
                    ICalendarValue::Integer(number) => Some(Value::Number((*number).into())),
                    ICalendarValue::PartialDateTime(date_time) if date_time.has_date_and_time() => {
                        date_time.to_timestamp().map(|timestamp| {
                            Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                                timestamp, false,
                            )))
                        })
                    }
                    _ => None,
                });
            self.values.push((property, value));
        }
        self
    }

    pub fn with_origin(mut self, is_origin: bool) -> Self {
        self.is_origin = Some(is_origin);
        self
    }

    pub fn server_set(
        self,
        client: &TrackedValues,
        before: Option<&TrackedValues>,
    ) -> ServerSetValues {
        let mut server_set = Vec::new();
        for (property, after) in self.values {
            let before_value = before.map(|before| before.get(&property));
            if before_value.is_some_and(|before| before == after.as_ref())
                || client.get(&property).is_some_and(|client| match &after {
                    Some(after) => client == after,
                    None => client.is_null(),
                })
            {
                continue;
            }
            match after {
                Some(after) => server_set.push((property, after)),
                None if before_value.flatten().is_some() => {
                    server_set.push((property, Value::Null));
                }
                None => {}
            }
        }
        if let Some(is_origin) = self.is_origin
            && before.is_none_or(|before| before.is_origin != Some(is_origin))
        {
            server_set.push((JSCalendarProperty::IsOrigin, Value::Bool(is_origin)));
        }
        server_set
    }

    fn get(&self, property: &JSCalendarProperty<Id>) -> Option<&EventValue> {
        self.values
            .iter()
            .find(|(tracked, _)| tracked == property)
            .and_then(|(_, value)| value.as_ref())
    }
}

#[derive(Debug, Default)]
pub struct BlobProperties(Vec<JSCalendarProperty<Id>>);

pub struct ImportedValues<'a> {
    pub participants: bool,
    pub blob_properties: &'a BlobProperties,
    pub every_blob_property: bool,
}

impl BlobProperties {
    pub fn from_patch(
        patch: &Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
        is_changed: impl Fn(&BlobId) -> bool,
    ) -> Self {
        let mut properties = Vec::new();
        for (key, value) in patch
            .as_object()
            .into_iter()
            .flat_map(|object| object.iter())
        {
            let property = match key {
                Key::Property(JSCalendarProperty::Pointer(pointer)) => match pointer.first() {
                    Some(JsonPointerItem::Key(Key::Property(property))) => property,
                    _ => continue,
                },
                Key::Property(property) => property,
                _ => continue,
            };
            if !properties.contains(property) && value.any_blob_id(&is_changed) {
                properties.push(property.clone());
            }
        }
        BlobProperties(properties)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ImportedValues<'_> {
    pub fn is_requested(&self) -> bool {
        self.participants || self.every_blob_property || !self.blob_properties.is_empty()
    }

    pub fn values(
        &self,
        ical: &ICalendar,
        account_id: u32,
        document_id: u32,
    ) -> impl Iterator<Item = (JSCalendarProperty<Id>, EventValue)> {
        ical.clone()
            .into_jscalendar_with::<Id, BlobId, _>(
                ImportOptions::new()
                    .include_ical_components(false)
                    .return_first(true)
                    .with_blob_id_generator(EmbeddedBlobIds::new(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                    )),
            )
            .map(JSCalendar::into_inner)
            .into_iter()
            .flat_map(EventValue::into_expanded_object)
            .filter_map(move |(key, value)| match key {
                Key::Property(property)
                    if (self.participants && property == JSCalendarProperty::Participants)
                        || ((self.every_blob_property
                            || self.blob_properties.0.contains(&property))
                            && value.any_blob_id(&|_: &BlobId| true)) =>
                {
                    Some((property, value))
                }
                _ => None,
            })
    }
}

pub trait EmbeddedBlobId {
    fn is_embedded_in(&self, account_id: u32, document_id: u32) -> bool;
}

impl EmbeddedBlobId for BlobId {
    fn is_embedded_in(&self, account_id: u32, document_id: u32) -> bool {
        matches!(
            self.class,
            BlobClass::Embedded {
                account_id: blob_account_id,
                collection,
                document_id: blob_document_id,
            } if blob_account_id == account_id
                && collection == u8::from(Collection::CalendarEvent)
                && blob_document_id == document_id
        )
    }
}

pub trait PendingBlobIds {
    fn resolve_document_id(&mut self, document_id: u32);
}

impl PendingBlobIds for ServerSetValues {
    fn resolve_document_id(&mut self, document_id: u32) {
        for (_, value) in self.iter_mut() {
            value.update_blob_ids(&|blob_id| {
                if let BlobClass::Embedded {
                    document_id: pending @ PENDING_DOCUMENT_ID,
                    ..
                } = &mut blob_id.class
                {
                    *pending = document_id;
                }
            });
        }
    }
}

trait BlobIdValues {
    fn any_blob_id(&self, predicate: &impl Fn(&BlobId) -> bool) -> bool;

    fn update_blob_ids(&mut self, update: &impl Fn(&mut BlobId));
}

impl BlobIdValues for Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>> {
    fn any_blob_id(&self, predicate: &impl Fn(&BlobId) -> bool) -> bool {
        match self {
            Value::Element(JSCalendarValue::BlobId(blob_id)) => predicate(blob_id),
            Value::Array(values) => values.iter().any(|value| value.any_blob_id(predicate)),
            Value::Object(object) => object.values().any(|value| value.any_blob_id(predicate)),
            _ => false,
        }
    }

    fn update_blob_ids(&mut self, update: &impl Fn(&mut BlobId)) {
        match self {
            Value::Element(JSCalendarValue::BlobId(blob_id)) => update(blob_id),
            Value::Array(values) => {
                for value in values {
                    value.update_blob_ids(update);
                }
            }
            Value::Object(object) => {
                for (_, value) in object.as_mut_vec() {
                    value.update_blob_ids(update);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(json: &str) -> JSCalendar<'_, Id, BlobId> {
        JSCalendar::parse(json).expect("valid JSCalendar")
    }

    fn reported(server_set: &ServerSetValues) -> Vec<String> {
        server_set
            .iter()
            .map(|(property, value)| format!("{}={value:?}", property.to_string()))
            .collect()
    }

    #[test]
    fn server_set_values() {
        let before = group(
            r#"{"@type":"Group","entries":[{"@type":"Event","uid":"a","timeZone":"Europe/Madrid","start":"2030-01-01T09:00:00","duration":"PT1H"}]}"#,
        );
        let after = group(
            r#"{"@type":"Group","entries":[{"@type":"Event","uid":"a","start":"2030-01-01T09:00:00","duration":"PT1H"}]}"#,
        );
        let before = TrackedValues::from_event(&before, Some(true));
        let dates = || TrackedValues::from_dates(&after);

        let requested = group(r#"{"timeZone":null}"#);
        let server_set =
            dates().server_set(&TrackedValues::from_patch(&requested.0), Some(&before));
        assert_eq!(reported(&server_set), Vec::<String>::new());

        let server_set = dates().server_set(&TrackedValues::default(), Some(&before));
        assert_eq!(reported(&server_set), ["timeZone=Null"]);

        let server_set = dates()
            .with_origin(true)
            .server_set(&TrackedValues::default(), None);
        assert_eq!(
            server_set
                .iter()
                .map(|(property, _)| property.to_string())
                .collect::<Vec<_>>(),
            ["start", "duration", "isOrigin"]
        );

        let server_set = dates()
            .with_origin(true)
            .server_set(&TrackedValues::default(), Some(&before));
        assert!(
            !reported(&server_set)
                .iter()
                .any(|property| property.starts_with("isOrigin")),
            "{server_set:?}"
        );
    }

    #[test]
    fn pending_document_ids_are_resolved() {
        let blob_id = BlobId::new(
            types::blob_hash::BlobHash::generate(b"data"),
            BlobClass::Embedded {
                account_id: 1,
                collection: Collection::CalendarEvent.into(),
                document_id: PENDING_DOCUMENT_ID,
            },
        );
        let mut server_set: ServerSetValues = vec![(
            JSCalendarProperty::Links,
            Value::Array(vec![Value::Element(JSCalendarValue::BlobId(blob_id))]),
        )];
        server_set.resolve_document_id(7);
        let [(_, Value::Array(values))] = server_set.as_slice() else {
            panic!("unexpected values {server_set:?}");
        };
        assert!(matches!(
            values.as_slice(),
            [Value::Element(JSCalendarValue::BlobId(blob_id))] if blob_id.is_embedded_in(1, 7)
        ));
    }
}
