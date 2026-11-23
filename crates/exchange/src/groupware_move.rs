/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    groupware_write::{
        WriteFailure, assert_card_room, assert_event_room, card_failure, card_name, card_size,
        event_failure, event_name, ical_size, new_uid, set_event_uid, store_failure,
    },
};
use calcard::{
    icalendar::{ArchivedICalendar, ArchivedICalendarComponentType, ICalendar},
    vcard::{VCard, VCardEntry, VCardProperty, VCardValue},
};
use common::{
    DavName, GroupwareResources, Server,
    auth::{AccessToken, AccountInfo},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, CalendarEventContent, SupportedComponent,
        alerts::DefaultAlertsResolver,
        privacy::EventViewer,
        schedule::{AlarmTasks, EventAlarmScheduler},
        storage::{DirectChangeNotification, NotificationQuota},
        write::{
            EventCreate, EventWriter, ItipMode, SupportedComponents, assert_privacy_access,
            assert_unique_uid as assert_unique_event_uid,
        },
    },
    contact::{
        ContactCard, ContactCardContent,
        write::{CardCreate, CardWriter, assert_unique_uid as assert_unique_card_uid},
    },
};
use smallvec::smallvec;
use std::sync::Arc;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, serialize::rkyv_deserialize},
};
use tokio::sync::OnceCell;
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection, VanishedCollection},
    field::{CalendarEventField, ContactField},
    type_state::DataType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupwareRoute {
    Cards { from: u32, to: u32 },
    Events { from: u32, to: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transfer {
    Move,
    Copy,
}

#[derive(Debug, Clone, Copy)]
pub enum GroupwareMove {
    Moved { change_id: Option<u64> },
    Refused(WriteFailure),
}

#[derive(Debug, Clone, Copy)]
pub enum GroupwareCopy {
    Copied {
        document_id: u32,
        change_id: Option<u64>,
    },
    Refused(WriteFailure),
}

impl GroupwareRoute {
    pub fn target(self) -> u32 {
        self.containers().1
    }

    pub fn containers(self) -> (u32, u32) {
        match self {
            GroupwareRoute::Cards { from, to } | GroupwareRoute::Events { from, to } => (from, to),
        }
    }

    pub fn sync_collection(self) -> SyncCollection {
        match self {
            GroupwareRoute::Cards { .. } => SyncCollection::AddressBook,
            GroupwareRoute::Events { .. } => SyncCollection::Calendar,
        }
    }

    pub fn data_type(self) -> DataType {
        match self {
            GroupwareRoute::Cards { .. } => DataType::ContactCard,
            GroupwareRoute::Events { .. } => DataType::CalendarEvent,
        }
    }
}

impl Transfer {
    fn source_acl(self) -> Acl {
        match self {
            Transfer::Move => Acl::RemoveItems,
            Transfer::Copy => Acl::ReadItems,
        }
    }
}

pub struct GroupwareMover<'x> {
    server: &'x Server,
    access_token: &'x AccessToken,
    account_id: u32,
    resources: Arc<GroupwareResources>,
    route: GroupwareRoute,
    from: u32,
    to: u32,
    restricted: Option<SupportedComponents>,
    account_info: OnceCell<AccountInfo>,
    created: usize,
}

impl<'x> GroupwareMover<'x> {
    pub async fn open(
        server: &'x Server,
        access_token: &'x AccessToken,
        account_id: u32,
        route: GroupwareRoute,
        transfer: Transfer,
    ) -> trc::Result<Option<Self>> {
        let resources = server
            .fetch_groupware_resources(account_id, account_id, route.sync_collection())
            .await
            .caused_by(trc::location!())?;
        let (from, to) = route.containers();
        if !access_token.is_member(account_id)
            && !(resources.has_access_to_container(access_token, from, transfer.source_acl())
                && resources.has_access_to_container(access_token, to, Acl::AddItems))
        {
            return Ok(None);
        }
        let restricted = match (route, transfer) {
            (GroupwareRoute::Events { .. }, Transfer::Move) => {
                Some(SupportedComponents::fetch(server, account_id, to).await?)
                    .filter(SupportedComponents::is_restricted)
            }
            _ => None,
        };
        Ok(Some(GroupwareMover {
            server,
            access_token,
            account_id,
            resources,
            route,
            from,
            to,
            restricted,
            account_info: OnceCell::new(),
            created: 0,
        }))
    }

    pub async fn move_item(&self, document_id: u32) -> trc::Result<GroupwareMove> {
        let mut outcome = GroupwareMove::Refused(WriteFailure::Conflict);
        for _ in 0..MAX_STATE_ATTEMPTS {
            outcome = match self.route {
                GroupwareRoute::Cards { .. } => self.move_card(document_id).await?,
                GroupwareRoute::Events { .. } => self.move_event(document_id).await?,
            };
            if !matches!(outcome, GroupwareMove::Refused(WriteFailure::Conflict)) {
                break;
            }
        }
        Ok(outcome)
    }

    pub async fn copy_item(&mut self, document_id: u32) -> trc::Result<GroupwareCopy> {
        let copied = match self.route {
            GroupwareRoute::Cards { .. } => self.copy_card(document_id).await?,
            GroupwareRoute::Events { .. } => self.copy_event(document_id).await?,
        };
        if let GroupwareCopy::Copied { .. } = copied {
            self.created += 1;
        }
        Ok(copied)
    }

    fn target_name(&self, name: String, fresh: impl FnOnce() -> String) -> String {
        let taken = self
            .resources
            .container_resource_path_by_id(self.to)
            .is_some_and(|container| {
                self.resources
                    .by_path(&format!("{}/{name}", container.path()))
                    .is_some()
            });
        if taken { fresh() } else { name }
    }

    async fn archive(
        &self,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                self.account_id,
                collection,
                document_id,
            ))
            .await
            .caused_by(trc::location!())
    }

    async fn commit(
        &self,
        batch: BatchBuilder,
        collection: SyncCollection,
    ) -> trc::Result<GroupwareMove> {
        match self.server.commit_batch(batch).await {
            Ok(ids) => Ok(GroupwareMove::Moved {
                change_id: ids.change_id(self.account_id, collection),
            }),
            Err(err) => store_failure(err).map(GroupwareMove::Refused),
        }
    }

    async fn move_card(&self, document_id: u32) -> trc::Result<GroupwareMove> {
        let (Some(archive), Some(path)) = (
            self.archive(Collection::ContactCard, document_id).await?,
            self.resources
                .format_resource_path_by_parent(document_id, self.from),
        ) else {
            return Ok(GroupwareMove::Refused(WriteFailure::NotFound));
        };
        let card = archive
            .to_unarchived::<ContactCard>()
            .caused_by(trc::location!())?;
        let Some(index) = card
            .inner
            .names
            .iter()
            .position(|name| name.parent_id == self.from)
        else {
            return Ok(GroupwareMove::Refused(WriteFailure::NotFound));
        };
        let filed = card
            .inner
            .names
            .iter()
            .any(|name| name.parent_id == self.to);
        if !filed
            && let Err(err) = assert_unique_card_uid(
                &self.resources,
                self.to,
                Some(card.inner.uid.as_str()).filter(|uid| !uid.is_empty()),
            )
        {
            return card_failure(err).map(GroupwareMove::Refused);
        }
        let mut moved = card
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        let source = moved.names.swap_remove(index);
        if !filed {
            moved.names.push(DavName::new(
                self.target_name(source.name, || card_name(&new_uid())),
                self.to,
            ));
        }
        let mut batch = BatchBuilder::new();
        moved
            .update_meta(
                self.access_token.changed_by(),
                card,
                self.account_id,
                document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        batch.log_vanished_item(VanishedCollection::AddressBook, path);
        self.commit(batch, SyncCollection::AddressBook).await
    }

    async fn move_event(&self, document_id: u32) -> trc::Result<GroupwareMove> {
        let (Some(archive), Some(path)) = (
            self.archive(Collection::CalendarEvent, document_id).await?,
            self.resources
                .format_resource_path_by_parent(document_id, self.from),
        ) else {
            return Ok(GroupwareMove::Refused(WriteFailure::NotFound));
        };
        let event = archive
            .to_unarchived::<CalendarEvent>()
            .caused_by(trc::location!())?;
        let flags = event.inner.flags.to_native();
        let is_owner = self.access_token.is_member(self.account_id);
        if let Err(err) = assert_privacy_access(Some(flags), EventViewer::new(is_owner)) {
            return event_failure(err).map(GroupwareMove::Refused);
        }
        let Some(index) = event
            .inner
            .names
            .iter()
            .position(|name| name.parent_id == self.from)
        else {
            return Ok(GroupwareMove::Refused(WriteFailure::NotFound));
        };
        let filed = event
            .inner
            .names
            .iter()
            .any(|name| name.parent_id == self.to);
        if !filed
            && let Err(err) = assert_unique_event_uid(
                &self.resources,
                self.access_token,
                self.account_id,
                self.to,
                Some(event.inner.uid.as_str()).filter(|uid| !uid.is_empty()),
            )
        {
            return event_failure(err).map(GroupwareMove::Refused);
        }
        if !filed
            && let Some(supported) = &self.restricted
            && let Some(refused) = self.unsupported(supported, document_id).await?
        {
            return Ok(refused);
        }

        let mut batch = BatchBuilder::new();
        let mut quota = NotificationQuota::default();
        self.server
            .notify_calendar_removal(
                self.access_token,
                self.account_id,
                document_id,
                self.from,
                flags,
                &mut quota,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        let mut moved = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        let source = moved.names.swap_remove(index);
        if !filed {
            moved.names.push(DavName::new(
                self.target_name(source.name, || event_name(&new_uid())),
                self.to,
            ));
            self.server
                .notify_calendar_addition(
                    self.access_token,
                    self.account_id,
                    PendingId::Assigned(document_id),
                    self.to,
                    flags,
                    (self.account_id, document_id),
                    &mut quota,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }
        let calendars = moved
            .names
            .iter()
            .map(DavName::parent_id)
            .collect::<Vec<_>>();
        self.server
            .reschedule_event_alarms(
                self.account_id,
                document_id,
                event.inner,
                None,
                &calendars,
                &mut AlarmTasks::None,
                &mut DefaultAlertsResolver::default(),
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        moved
            .update_meta(
                self.access_token.changed_by(),
                event,
                self.account_id,
                document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        batch.log_vanished_item(VanishedCollection::Calendar, path);
        self.commit(batch, SyncCollection::Calendar).await
    }

    async fn unsupported(
        &self,
        supported: &SupportedComponents,
        document_id: u32,
    ) -> trc::Result<Option<GroupwareMove>> {
        let Some(content) = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                self.account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Some(GroupwareMove::Refused(WriteFailure::NotFound)));
        };
        let component = object_component(
            &content
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .data
                .event,
        );
        match supported.assert_supports(component) {
            Ok(()) => Ok(None),
            Err(err) => event_failure(err).map(|failure| Some(GroupwareMove::Refused(failure))),
        }
    }

    async fn copy_card(&self, document_id: u32) -> trc::Result<GroupwareCopy> {
        let (Some(archive), Some(content)) = self
            .server
            .archive_and_field(
                self.account_id,
                Collection::ContactCard,
                document_id,
                ContactField::Content.field(),
            )
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(GroupwareCopy::Refused(WriteFailure::NotFound));
        };
        if !archive
            .unarchive::<ContactCard>()
            .caused_by(trc::location!())?
            .names
            .iter()
            .any(|name| name.parent_id == self.from)
        {
            return Ok(GroupwareCopy::Refused(WriteFailure::NotFound));
        }
        let mut vcard = content
            .deserialize::<ContactCardContent>()
            .caused_by(trc::location!())?
            .card;
        let uid = new_uid();
        replace_card_uid(&mut vcard, &uid);
        let Some(size) = card_size(self.server, &vcard) else {
            return Ok(GroupwareCopy::Refused(WriteFailure::Invalid));
        };
        if let Err(err) =
            assert_card_room(self.server, self.account_id, &self.resources, self.created).await
        {
            return store_failure(err).map(GroupwareCopy::Refused);
        }
        let writer = CardWriter {
            server: self.server,
            access_token: self.access_token,
            account_id: self.account_id,
            resources: &self.resources,
        };
        let written = match writer.prepare_create(self.to) {
            Ok(new) => {
                writer
                    .create(
                        new,
                        CardCreate {
                            name: card_name(&uid),
                            vcard,
                            size: Some(size),
                        },
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        match written {
            Ok(written) => Ok(GroupwareCopy::Copied {
                document_id: written.document_id,
                change_id: written.change_id,
            }),
            Err(err) => card_failure(err).map(GroupwareCopy::Refused),
        }
    }

    async fn copy_event(&self, document_id: u32) -> trc::Result<GroupwareCopy> {
        let (Some(archive), Some(content)) = self
            .server
            .archive_and_field(
                self.account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content.into(),
            )
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(GroupwareCopy::Refused(WriteFailure::NotFound));
        };
        let event = archive
            .unarchive::<CalendarEvent>()
            .caused_by(trc::location!())?;
        if !event.names.iter().any(|name| name.parent_id == self.from) {
            return Ok(GroupwareCopy::Refused(WriteFailure::NotFound));
        }
        let is_owner = self.access_token.is_member(self.account_id);
        if let Err(err) =
            assert_privacy_access(Some(event.flags.to_native()), EventViewer::new(is_owner))
        {
            return event_failure(err).map(GroupwareCopy::Refused);
        }
        let mut ical = rkyv_deserialize::<_, ICalendar>(
            &content
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .data
                .event,
        )
        .caused_by(trc::location!())?;
        let uid = new_uid();
        set_event_uid(&mut ical, &uid);
        let Some(size) = ical_size(self.server, &ical) else {
            return Ok(GroupwareCopy::Refused(WriteFailure::Invalid));
        };
        if let Err(err) =
            assert_event_room(self.server, self.account_id, &self.resources, self.created).await
        {
            return store_failure(err).map(GroupwareCopy::Refused);
        }
        let account_info = self
            .account_info
            .get_or_try_init(|| self.server.account_info(self.account_id))
            .await?;
        let writer = EventWriter {
            server: self.server,
            access_token: self.access_token,
            account_id: self.account_id,
            resources: &self.resources,
            account_info,
        };
        let written = match writer.prepare_create(self.to, &ical).await {
            Ok(new) => {
                writer
                    .create(
                        new,
                        EventCreate {
                            name: event_name(&uid),
                            ical,
                            size: Some(size),
                            itip: ItipMode::Suppress,
                        },
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        match written {
            Ok(written) => Ok(GroupwareCopy::Copied {
                document_id: written.document_id,
                change_id: written.change_id,
            }),
            Err(err) => event_failure(err).map(GroupwareCopy::Refused),
        }
    }
}

pub(crate) fn replace_card_uid(vcard: &mut VCard, uid: &str) {
    let value = smallvec![VCardValue::Text(uid.to_string())];
    match vcard
        .entries
        .iter_mut()
        .find(|entry| entry.name == VCardProperty::Uid)
    {
        Some(entry) => entry.values = value,
        None => vcard.entries.push(VCardEntry {
            group: None,
            name: VCardProperty::Uid,
            params: Vec::new(),
            values: value,
        }),
    }
}

fn object_component(ical: &ArchivedICalendar) -> SupportedComponent {
    ical.components
        .iter()
        .find_map(|component| match component.component_type {
            ArchivedICalendarComponentType::VEvent => Some(SupportedComponent::VEvent),
            ArchivedICalendarComponentType::VTodo => Some(SupportedComponent::VTodo),
            ArchivedICalendarComponentType::VJournal => Some(SupportedComponent::VJournal),
            ArchivedICalendarComponentType::VFreebusy => Some(SupportedComponent::VFreebusy),
            ArchivedICalendarComponentType::VAvailability => {
                Some(SupportedComponent::VAvailability)
            }
            _ => None,
        })
        .unwrap_or(SupportedComponent::Other)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/groupware_move/tests.rs"]
mod tests;
