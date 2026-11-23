/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod find;
pub mod instance;
pub mod invitation;
pub mod sent;
pub mod view;
pub mod write;

use super::{
    filter::PropValue,
    groupware::{
        GroupwareFields, GroupwareKind,
        items::{GroupwareItems, LoadedItem},
    },
    timezone::time_zone_definition,
};
use crate::{
    folders::{ContainerClass, FolderEntry, FolderNode},
    store::{FolderKind, FolderRef},
};
use bytes::Bytes;
use exchange_proto::{
    common::UtcSeconds,
    convert::{
        ical::{EventOccurrence, EventParts},
        model::{MessageContent, PropBag},
    },
    ews::{
        calendar::{CalendarFieldSet, CalendarProps},
        types::{
            item::{
                CalendarItem, Item, MimeContent,
                calendar::{DeletedOccurrence, OccurrenceInfo},
            },
            shape::ItemShape,
            value::{DateTime, List, XBinary},
        },
    },
};
use find::EventProp;
use std::borrow::Cow;

pub(crate) type Events = GroupwareItems<CalendarFieldSet>;

impl GroupwareFields for CalendarFieldSet {
    const KIND: GroupwareKind = GroupwareKind::Event;
    type Prop = EventProp;

    fn from_shape(shape: &ItemShape<'_>) -> Self {
        CalendarFieldSet::from_shape(shape)
    }

    fn for_list(self) -> Self {
        CalendarFieldSet::for_list(self)
    }

    fn needs_content(self) -> bool {
        CalendarFieldSet::needs_content(self)
    }

    fn needs_owner(self) -> bool {
        self.needs_attendance()
    }

    fn event_parts(self) -> EventParts {
        CalendarFieldSet::event_parts(self)
    }

    fn value<'p>(_: &Events, _: u32, prop: EventProp, props: &'p PropBag) -> Option<PropValue<'p>> {
        prop.value(CalendarProps::of_props(props))
    }

    fn render<'c>(self, events: &Events, loaded: &'c LoadedItem) -> Item<'c> {
        let mut item = loaded
            .content
            .as_ref()
            .map(|content| render_event(content, self, events.owner()))
            .unwrap_or_default();
        item.item.mime_content = loaded.mime.as_ref().map(event_mime);
        if self.has(CalendarFieldSet::ID) {
            item.item.item_id = Some(events.item_id(loaded.item, loaded.change_id));
        }
        if self.has(CalendarFieldSet::PARENT) {
            item.item.parent_folder_id = Some(events.parent_id(loaded));
        }
        if let Some(occurrences) = loaded.occurrences.as_deref() {
            let info = |occurrence: &EventOccurrence| OccurrenceInfo {
                item_id: Some(events.occurrence_id(
                    loaded.item,
                    loaded.change_id,
                    occurrence.instance.0.as_second(),
                )),
                start: Some(utc(occurrence.start.as_second())),
                end: Some(utc(occurrence.end.as_second())),
                original_start: Some(utc(occurrence.instance.0.as_second())),
            };
            let calendar = &mut item.calendar;
            if self.has(CalendarFieldSet::FIRST_OCCURRENCE) {
                calendar.first_occurrence = occurrences.first.as_ref().map(info);
            }
            if self.has(CalendarFieldSet::LAST_OCCURRENCE) {
                calendar.last_occurrence = occurrences.last.as_ref().map(info);
            }
            if self.has(CalendarFieldSet::MODIFIED_OCCURRENCES) && !occurrences.modified.is_empty()
            {
                calendar.modified_occurrences =
                    Some(List(occurrences.modified.iter().map(&info).collect()));
            }
            if self.has(CalendarFieldSet::DELETED_OCCURRENCES) && !occurrences.deleted.is_empty() {
                calendar.deleted_occurrences = Some(List(
                    occurrences
                        .deleted
                        .iter()
                        .map(|instance| DeletedOccurrence {
                            start: Some(utc(instance.0.as_second())),
                        })
                        .collect(),
                ));
            }
        }
        Item::CalendarItem(Box::new(item))
    }
}

pub(super) fn event_mime(mime: &Bytes) -> MimeContent<'static> {
    MimeContent {
        character_set: Some(Cow::Borrowed("UTF-8")),
        content: XBinary::Bytes(mime.clone()),
    }
}

pub(super) fn render_event<'c>(
    content: &'c MessageContent,
    fields: CalendarFieldSet,
    owner: &[String],
) -> CalendarItem<'c> {
    let props = CalendarProps::new(content);
    let mut item = props.render(fields);
    props.render_attendance(&mut item.calendar, fields, owner);
    if fields.has(CalendarFieldSet::START_TIME_ZONE) {
        item.calendar.start_time_zone = props
            .start_time_zone()
            .map(|definition| Box::new(time_zone_definition(&definition)));
    }
    if fields.has(CalendarFieldSet::END_TIME_ZONE) {
        item.calendar.end_time_zone = props
            .end_time_zone()
            .map(|definition| Box::new(time_zone_definition(&definition)));
    }
    item
}

pub(super) const fn utc(seconds: i64) -> DateTime {
    DateTime::utc(UtcSeconds(seconds))
}

pub(crate) fn calendar_of(entry: &FolderEntry) -> Option<u32> {
    match (entry.node, &entry.class) {
        (
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar,
                id,
            }),
            ContainerClass::Appointment,
        ) => Some(id),
        _ => None,
    }
}
