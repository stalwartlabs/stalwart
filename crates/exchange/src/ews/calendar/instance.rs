/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Events, event_mime, render_event};
use crate::ews::{
    groupware::{
        GroupwareKind, change_id_of,
        items::{GroupwareRef, LoadedItem},
        write::Scheduling,
    },
    item::ItemError,
};
use bytes::Bytes;
use calcard::icalendar::ICalendar;
use common::Server;
use exchange_proto::{
    convert::{
        context::NoDirectory,
        ical::{
            IndexedInstance, RecurrenceId, event_instance_at, event_override_ical,
            event_parts_to_message, is_event_override,
        },
    },
    ews::{
        calendar::CalendarFieldSet,
        schema::CalendarItemType,
        types::{
            ids::{BaseItemId, EwsIdStr, ItemId},
            item::Item,
        },
    },
    ids::{
        ews::{EwsChangeKey, EwsObjectId},
        token::ObjectKind,
    },
};
use groupware::calendar::{CalendarEvent, CalendarEventContent};
use jiff::Timestamp;
use store::write::{Archive, ArchiveBytes};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventTarget {
    Master(u32, GroupwareRef),
    Instance(u32, GroupwareRef, i64),
    Indexed(u32, GroupwareRef, usize),
}

impl EventTarget {
    pub fn decode(id: &BaseItemId<'_>) -> Option<Self> {
        let (id, master) = match id {
            BaseItemId::Item(id) => (id.id.as_str(), false),
            BaseItemId::RecurringMaster { occurrence, .. } => (occurrence.as_str(), true),
            BaseItemId::Occurrence { master, index, .. } => {
                let EwsObjectId::Item {
                    account,
                    kind,
                    container,
                    id,
                } = EwsObjectId::decode(master.as_str())?
                else {
                    return None;
                };
                if GroupwareKind::of_object(kind)? != GroupwareKind::Event {
                    return None;
                }
                let event = GroupwareRef {
                    container,
                    document_id: id,
                };
                return Some(EventTarget::Indexed(
                    account,
                    event,
                    usize::try_from(*index).unwrap_or_default(),
                ));
            }
            BaseItemId::MasterRanges(_) => return None,
        };
        let EwsObjectId::Occurrence {
            account,
            container,
            id,
            instance,
        } = EwsObjectId::decode(id)?
        else {
            return None;
        };
        let event = GroupwareRef {
            container,
            document_id: id,
        };
        Some(if master {
            EventTarget::Master(account, event)
        } else {
            EventTarget::Instance(account, event, instance.cast_signed())
        })
    }
}

pub(crate) struct LoadedInstance {
    pub loaded: LoadedItem,
    pub instance: i64,
    pub kind: CalendarItemType,
}

impl Events {
    pub async fn load_instance(
        &self,
        server: &Server,
        item: GroupwareRef,
        instance: i64,
        fields: CalendarFieldSet,
    ) -> trc::Result<Result<LoadedInstance, ItemError>> {
        self.prepare(server, fields).await?;
        Ok(self
            .load_ical(server, item)
            .await?
            .and_then(|(ical, change_id)| {
                self.instance(&ical, item, change_id, instance, fields)
                    .ok_or(ItemError::NotFound)
            }))
    }

    pub async fn load_indexed(
        &self,
        server: &Server,
        item: GroupwareRef,
        index: usize,
        fields: CalendarFieldSet,
    ) -> trc::Result<Result<LoadedInstance, ItemError>> {
        self.prepare(server, fields).await?;
        Ok(self
            .load_ical(server, item)
            .await?
            .and_then(|(ical, change_id)| {
                let instance = indexed_instance(&ical, index)?;
                self.instance(&ical, item, change_id, instance, fields)
                    .ok_or(ItemError::NotFound)
            }))
    }

    pub(crate) async fn load_ical(
        &self,
        server: &Server,
        item: GroupwareRef,
    ) -> trc::Result<Result<(ICalendar, u64), ItemError>> {
        Ok(self.read_event(server, item).await?.map(|(archive, ical)| {
            (
                self.event_view(item.document_id).apply(ical),
                change_id_of(archive.version),
            )
        }))
    }

    pub(crate) async fn load_scheduled(
        &self,
        server: &Server,
        item: GroupwareRef,
    ) -> trc::Result<Result<(ICalendar, Scheduling), ItemError>> {
        match self.read_event(server, item).await? {
            Ok((archive, ical)) => {
                let event = archive
                    .unarchive::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                Ok(Ok((ical, Scheduling::of(event))))
            }
            Err(err) => Ok(Err(err)),
        }
    }

    async fn read_event(
        &self,
        server: &Server,
        item: GroupwareRef,
    ) -> trc::Result<Result<(Archive<ArchiveBytes>, ICalendar), ItemError>> {
        let (archive, content) = server
            .archive_and_field(
                self.account_id,
                Collection::CalendarEvent,
                item.document_id,
                CalendarEventField::Content.into(),
            )
            .await
            .caused_by(trc::location!())?;
        let (Some(archive), Some(content)) = (archive, content) else {
            return Ok(Err(ItemError::NotFound));
        };
        let ical = content
            .deserialize::<CalendarEventContent>()
            .caused_by(trc::location!())?
            .data
            .event;
        Ok(Ok((archive, ical)))
    }

    pub fn instance(
        &self,
        ical: &ICalendar,
        item: GroupwareRef,
        change_id: u64,
        instance: i64,
        fields: CalendarFieldSet,
    ) -> Option<LoadedInstance> {
        let id = RecurrenceId(Timestamp::from_second(instance).ok()?);
        let content = event_parts_to_message(
            ical,
            Some(id),
            fields.event_parts(),
            &NoDirectory,
            &self.options(),
        )
        .ok()?;
        Some(LoadedInstance {
            loaded: LoadedItem {
                item,
                change_id,
                content: Some(content),
                occurrences: None,
                mime: fields
                    .has(CalendarFieldSet::MIME_CONTENT)
                    .then(|| event_override_ical(ical, id))
                    .flatten()
                    .map(|single| Bytes::from(single.to_string())),
            },
            instance,
            kind: if is_event_override(ical, id) {
                CalendarItemType::Exception
            } else {
                CalendarItemType::Occurrence
            },
        })
    }

    pub fn render_instance<'c>(
        &self,
        loaded: &'c LoadedInstance,
        fields: CalendarFieldSet,
    ) -> Item<'c> {
        let mut item = loaded
            .loaded
            .content
            .as_ref()
            .map(|content| render_event(content, fields, self.owner()))
            .unwrap_or_default();
        item.item.mime_content = loaded.loaded.mime.as_ref().map(event_mime);
        if fields.has(CalendarFieldSet::ITEM_TYPE) {
            item.calendar.calendar_item_type = Some(loaded.kind);
        }
        if fields.has(CalendarFieldSet::IS_RECURRING) {
            item.calendar.is_recurring = Some(true);
        }
        if fields.has(CalendarFieldSet::ID) {
            item.item.item_id = Some(self.occurrence_id(
                loaded.loaded.item,
                loaded.loaded.change_id,
                loaded.instance,
            ));
        }
        if fields.has(CalendarFieldSet::PARENT) {
            item.item.parent_folder_id = Some(self.parent_id(&loaded.loaded));
        }
        Item::CalendarItem(Box::new(item))
    }

    pub fn occurrence_id(
        &self,
        item: GroupwareRef,
        change_id: u64,
        instance: i64,
    ) -> ItemId<'static> {
        ItemId {
            id: self.encode_occurrence(item, instance),
            change_key: Some(EwsIdStr::Minted(
                EwsChangeKey {
                    kind: ObjectKind::Occurrence,
                    change_id,
                }
                .encode(),
            )),
        }
    }

    pub fn unversioned_occurrence_id(&self, item: GroupwareRef, instance: i64) -> ItemId<'static> {
        ItemId {
            id: self.encode_occurrence(item, instance),
            change_key: None,
        }
    }

    fn encode_occurrence(&self, item: GroupwareRef, instance: i64) -> EwsIdStr<'static> {
        EwsIdStr::Minted(
            EwsObjectId::Occurrence {
                account: self.account_id,
                container: item.container,
                id: item.document_id,
                instance: instance.cast_unsigned(),
            }
            .encode(),
        )
    }
}

pub(crate) fn indexed_instance(ical: &ICalendar, index: usize) -> Result<i64, ItemError> {
    match event_instance_at(ical, index) {
        IndexedInstance::Instance(id) => Ok(id.0.as_second()),
        IndexedInstance::Deleted => Err(ItemError::OccurrenceDeleted),
        IndexedInstance::OutOfRange => Err(ItemError::OccurrenceOutOfRange),
        IndexedInstance::NotRecurring => Err(ItemError::NotRecurringMaster),
    }
}
