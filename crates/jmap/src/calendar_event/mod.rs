/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendar, ArchivedICalendarComponent, ICalendar, ICalendarComponent,
        ICalendarProperty,
    },
    jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarType, JSCalendarValue},
};
use common::{DavName, GroupwareResources, Server};
use groupware::calendar::{
    CalendarEventContent,
    expand::{ComponentRecurrenceId, RecurrenceKey},
    index::ICalendarObjectUid,
};
use jmap_proto::error::set::SetError;
use jmap_tools::{Key, Map, Value};
use std::borrow::Cow;
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{blob::BlobId, collection::Collection, field::CalendarEventField, id::Id};

pub(super) type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
pub(super) type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;

pub mod copy;
pub mod get;
pub mod parse;
pub mod privacy;
pub mod query;
pub mod server_set;
pub mod set;
pub mod user;
pub mod validate;

/*

TODO: Not yet implemented:

- CalendarEvent
    - hideAttendees in outbound scheduling messages

*/

pub trait CalendarSyntheticId {
    fn new(key: RecurrenceKey, document_id: u32) -> Self;

    fn is_synthetic(&self) -> bool;

    fn recurrence_key(&self) -> Option<RecurrenceKey>;
}

impl CalendarSyntheticId for Id {
    fn new(key: RecurrenceKey, document_id: u32) -> Id {
        Id::from_parts(key.prefix(), document_id)
    }

    fn recurrence_key(&self) -> Option<RecurrenceKey> {
        RecurrenceKey::from_prefix(self.prefix_id())
    }

    fn is_synthetic(&self) -> bool {
        self.prefix_id() != 0
    }
}

enum UidEntry {
    Stored {
        document_id: u32,
        calendar_ids: Vec<u32>,
    },
    Created {
        calendar_ids: Vec<u32>,
        recurrence_ids: Vec<i64>,
    },
}

#[derive(Default)]
pub struct UidIndex<'x>(AHashMap<Cow<'x, str>, Vec<UidEntry>>);

impl<'x> UidIndex<'x> {
    pub fn new<'y>(
        resources: &'x GroupwareResources,
        uids: impl IntoIterator<Item = &'y str>,
    ) -> Self {
        let uids = uids.into_iter().collect::<AHashSet<_>>();
        let mut index = AHashMap::with_capacity(uids.len());
        if !uids.is_empty() {
            for resource in resources.resources.iter() {
                if let Some(uid) = resource.uid().filter(|uid| uids.contains(uid)) {
                    index
                        .entry(Cow::Borrowed(uid))
                        .or_insert_with(Vec::new)
                        .push(UidEntry::Stored {
                            document_id: resource.document_id(),
                            calendar_ids: resource
                                .child_names()
                                .iter()
                                .map(|name| name.parent_id)
                                .collect(),
                        });
                }
            }
        }
        UidIndex(index)
    }

    fn documents(&self, uid: &str) -> &[UidEntry] {
        self.0.get(uid).map_or(&[], Vec::as_slice)
    }

    pub fn record(&mut self, ical: &ICalendar, calendar_ids: &[u32]) {
        let Some(uid) = ical.object_uid() else {
            return;
        };
        let entry = UidEntry::Created {
            calendar_ids: calendar_ids.to_vec(),
            recurrence_ids: ical.instance_recurrence_ids(),
        };
        match self.0.get_mut(uid) {
            Some(entries) => entries.push(entry),
            None => {
                self.0.insert(Cow::Owned(uid.to_string()), vec![entry]);
            }
        }
    }

    pub async fn assert_is_unique(
        &self,
        server: &Server,
        account_id: u32,
        ical: &ICalendar,
        names: &[DavName],
        document_id: Option<u32>,
        will_destroy: &[Id],
    ) -> trc::Result<Result<(), SetError<JSCalendarProperty<Id>>>> {
        let Some(uid) = ical.object_uid() else {
            return Ok(Ok(()));
        };
        let instances = ical.instance_recurrence_ids();
        let is_distinct_instance = |recurrence_ids: &[i64]| {
            !instances.is_empty()
                && !recurrence_ids.is_empty()
                && !recurrence_ids
                    .iter()
                    .any(|recurrence_id| instances.contains(recurrence_id))
        };

        for entry in self.documents(uid) {
            let (calendar_ids, is_distinct) = match entry {
                UidEntry::Created {
                    calendar_ids,
                    recurrence_ids,
                } => (calendar_ids, is_distinct_instance(recurrence_ids)),
                UidEntry::Stored {
                    document_id: stored_id,
                    calendar_ids,
                } => {
                    if document_id == Some(*stored_id)
                        || will_destroy
                            .iter()
                            .any(|id| !id.is_synthetic() && id.document_id() == *stored_id)
                    {
                        continue;
                    }
                    let recurrence_ids = server
                        .store()
                        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                            account_id,
                            Collection::CalendarEvent,
                            *stored_id,
                            CalendarEventField::Content,
                        ))
                        .await?
                        .map(|content| {
                            content
                                .unarchive::<CalendarEventContent>()
                                .map(|content| content.data.event.instance_recurrence_ids())
                                .caused_by(trc::location!())
                        })
                        .transpose()?
                        .unwrap_or_default();
                    (calendar_ids, is_distinct_instance(&recurrence_ids))
                }
            };

            if !is_distinct {
                return Ok(Err(duplicate_uid(uid)));
            }

            if let Some(calendar_id) = names
                .iter()
                .map(DavName::parent_id)
                .find(|calendar_id| calendar_ids.contains(calendar_id))
            {
                return Ok(Err(shared_uid_calendar(uid, calendar_id)));
            }
        }

        Ok(Ok(()))
    }
}

fn duplicate_uid(uid: &str) -> SetError<JSCalendarProperty<Id>> {
    SetError::invalid_properties()
        .with_property(JSCalendarProperty::Uid)
        .with_description(format!("An event with UID {uid} already exists."))
}

fn shared_uid_calendar(uid: &str, calendar_id: u32) -> SetError<JSCalendarProperty<Id>> {
    SetError::invalid_properties()
        .with_property(JSCalendarProperty::CalendarIds)
        .with_description(format!(
            concat!(
                "Another occurrence of UID {} is already stored in calendar {}. ",
                "Events that share a UID have to be in different calendars."
            ),
            uid,
            Id::from(calendar_id)
        ))
}

pub(super) trait JSCalendarEntries<'x> {
    fn new_event() -> Self;

    fn first_entry(&self) -> Option<&EventMap<'x>>;

    fn first_entry_mut(&mut self) -> Option<&mut EventValue<'x>>;
}

impl<'x> JSCalendarEntries<'x> for JSCalendar<'x, Id, BlobId> {
    fn new_event() -> Self {
        JSCalendar(Value::Object(Map::from(vec![
            (
                Key::Property(JSCalendarProperty::Type),
                Value::Element(JSCalendarValue::Type(JSCalendarType::Group)),
            ),
            (
                Key::Property(JSCalendarProperty::Entries),
                Value::Array(vec![Value::Object(Map::new())]),
            ),
        ])))
    }

    fn first_entry(&self) -> Option<&EventMap<'x>> {
        self.0
            .as_object_and_get(&Key::Property(JSCalendarProperty::Entries))
            .and_then(Value::as_array)
            .and_then(|entries| entries.first())
            .and_then(Value::as_object)
    }

    fn first_entry_mut(&mut self) -> Option<&mut EventValue<'x>> {
        self.0
            .as_object_mut()?
            .get_mut(&Key::Property(JSCalendarProperty::Entries))?
            .as_array_mut()?
            .first_mut()
            .filter(|entry| entry.as_object().is_some())
    }
}

pub(super) fn is_origin(ical: &ICalendar, addresses: &[String]) -> bool {
    ical.main_component()
        .and_then(|component| component.property(&ICalendarProperty::Organizer))
        .and_then(|entry| entry.calendar_address())
        .is_none_or(|organizer| {
            addresses
                .iter()
                .any(|address| address.eq_ignore_ascii_case(organizer))
        })
}

pub(super) trait EventMainComponent {
    type Component: ComponentRecurrenceId;

    fn scheduling_components(&self) -> impl Iterator<Item = &Self::Component>;

    fn is_override(component: &Self::Component) -> bool;

    fn main_component(&self) -> Option<&Self::Component> {
        let mut components = self.scheduling_components();
        let first = components.next()?;
        if Self::is_override(first) {
            Some(
                components
                    .find(|component| !Self::is_override(component))
                    .unwrap_or(first),
            )
        } else {
            Some(first)
        }
    }

    fn instance_recurrence_ids(&self) -> Vec<i64> {
        let mut recurrence_ids = Vec::new();
        for component in self.scheduling_components() {
            if !Self::is_override(component) {
                return Vec::new();
            } else if let Some(recurrence_id) = component.recurrence_id(Tz::Floating) {
                recurrence_ids.push(recurrence_id.utc);
            }
        }
        recurrence_ids
    }

    fn instance_component(&self, recurrence_id: i64) -> Option<&Self::Component> {
        self.scheduling_components()
            .find(|component| {
                Self::is_override(component)
                    && component
                        .recurrence_id(Tz::Floating)
                        .is_some_and(|id| id.utc == recurrence_id)
            })
            .or_else(|| self.main_component())
    }
}

impl EventMainComponent for ICalendar {
    type Component = ICalendarComponent;

    fn scheduling_components(&self) -> impl Iterator<Item = &ICalendarComponent> {
        self.components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
    }

    fn is_override(component: &ICalendarComponent) -> bool {
        component.is_recurrence_override()
    }
}

impl EventMainComponent for ArchivedICalendar {
    type Component = ArchivedICalendarComponent;

    fn scheduling_components(&self) -> impl Iterator<Item = &ArchivedICalendarComponent> {
        self.components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
    }

    fn is_override(component: &ArchivedICalendarComponent) -> bool {
        component.is_recurrence_override()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVERRIDE_FIRST: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "RECURRENCE-ID:20300102T090000Z\r\n",
        "DTSTART:20300102T100000Z\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "ORGANIZER:mailto:zoe@example.com\r\n",
        "DTSTART:20300101T090000Z\r\n",
        "RRULE:FREQ=DAILY;COUNT=3\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    const INSTANCES: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "ORGANIZER:mailto:zoe@example.com\r\n",
        "RECURRENCE-ID;TZID=Europe/Berlin:20300102T100000\r\n",
        "DTSTART:20300102T100000Z\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    const TWO_INSTANCES: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "ORGANIZER:mailto:zoe@example.com\r\n",
        "RECURRENCE-ID;TZID=Europe/Berlin:20300102T100000\r\n",
        "DTSTART:20300102T100000Z\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:series\r\n",
        "ORGANIZER:mailto:zoe@example.com\r\n",
        "RECURRENCE-ID;TZID=Europe/Berlin:20300103T100000\r\n",
        "DTSTART:20300103T100000Z\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    #[test]
    fn main_component_skips_overrides() {
        let ical = ICalendar::parse(OVERRIDE_FIRST).expect("valid iCalendar");
        let addresses = ["john@example.com".to_string()];
        assert!(!is_origin(&ical, &addresses));
        assert!(is_origin(&ical, &["ZOE@example.com".to_string()]));
        assert!(ical.instance_recurrence_ids().is_empty());

        let ical = ICalendar::parse(INSTANCES).expect("valid iCalendar");
        assert!(!is_origin(&ical, &addresses));
        assert_eq!(ical.instance_recurrence_ids(), [1893574800]);
    }

    #[test]
    fn every_instance_is_reported() {
        let ical = ICalendar::parse(TWO_INSTANCES).expect("valid iCalendar");
        assert_eq!(
            ical.instance_recurrence_ids(),
            [1893574800, 1893661200],
            "{ical}"
        );
    }

    #[test]
    fn archived_instance_recurrence_id_matches_native() {
        let ical = ICalendar::parse(TWO_INSTANCES).expect("valid iCalendar");
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ical).expect("serializable");
        let archived =
            rkyv::access::<ArchivedICalendar, rkyv::rancor::Error>(&bytes).expect("valid archive");
        assert_eq!(
            archived.instance_recurrence_ids(),
            ical.instance_recurrence_ids()
        );
    }
}
