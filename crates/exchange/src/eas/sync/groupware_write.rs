/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    email::ItemReply,
    groupware::{GroupwareKind, GroupwareTarget, OwnBound, shows_event},
    server_id,
    state::ClientView,
};
use crate::{
    eas::{context::EasContext, convert::body::incoming_text, folder_sync::MAX_STATE_ATTEMPTS},
    groupware_write::{
        EventEdit, WriteFailure, assert_card_room, card_failure, card_name, card_size, ical_size,
        new_card, new_uid, store_failure,
    },
    store::eas::EasClientId,
};
use ahash::AHashSet;
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarProperty,
        ICalendarValue,
    },
};
use common::{GroupwareResources, PROD_ID, Server, auth::AccountInfo};
use exchange_proto::{
    convert::{
        ical::{
            MeetingRole,
            eas::{
                EventChange, EventUpdate, TaskUpdate, TaskWrite, event_change_from_eas,
                event_from_eas, occurrence_change_from_eas, occurrence_delete_from_eas,
                todo_from_eas,
            },
            event_meeting_role,
        },
        vcard::eas::{ContactUpdate, contact_from_eas},
    },
    eas::{
        commands::{
            appdata::{ApplicationData, Calendar, RawApplicationData, Task, contact::Contact},
            sync::{ClientCommand, Ghosting},
        },
        status::{ItemOperationsStatus, SyncStatus},
        tokens::ProtocolVersion,
        types::{Class, EasDateTime},
        wbxml::WbxmlLimits,
    },
    ids::eas::EasServerId,
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent,
        write::{
            EventCreate, EventDeletion, EventWrite, EventWriteError, EventWriter, ItipMode,
            assert_unique_uid,
        },
    },
    contact::{
        ContactCardContent,
        write::{CardCreate, CardWriteError, CardWriter},
    },
};
use jiff::Timestamp;
use registry::schema::enums::StorageQuota;
use smallvec::smallvec;
use std::sync::Arc;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, now, serialize::rkyv_deserialize},
    xxhash_rust::xxh3::xxh3_64,
};
use tokio::sync::OnceCell;
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

const ICAL_EXTENSION: &str = ".ics";
const ICAL_VERSION: &str = "2.0";

const MAX_UID_LEN: usize = 300;
const DEVICE_UID_PREFIX: &str = "eas-";

type Outcome<T> = trc::Result<Result<T, SyncStatus>>;

struct Added {
    document_id: u32,
    uid: Option<String>,
}

enum Created {
    New(Added, Option<u64>),
    Existing(Added),
}

#[derive(Clone, Copy)]
enum Edited {
    Unchanged,
    Written(Option<u64>),
}

impl Created {
    fn new(document_id: u32, change_id: Option<u64>) -> Self {
        Created::New(
            Added {
                document_id,
                uid: None,
            },
            change_id,
        )
    }
}

#[derive(Clone, Copy)]
enum ItemEdit<'a, 'b> {
    Item(&'a RawApplicationData<'b>),
    Occurrence(EasDateTime, &'a RawApplicationData<'b>),
    Exclude(EasDateTime),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoveMode {
    Command,
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddUids {
    Random,
    Device,
}

pub(super) struct GroupwareWriter<'x> {
    server: &'x Server,
    ctx: &'x EasContext<'x>,
    target: GroupwareTarget,
    resources: &'x Arc<GroupwareResources>,
    account_info: OnceCell<AccountInfo>,
    ghosting: Ghosting<'x>,
    replayed: &'x [EasClientId],
    uids: AddUids,
    edited: RoaringBitmap,
    occurrences: AHashSet<(u32, EasDateTime)>,
    created: usize,
    conflicts: Option<&'x RoaringBitmap>,
    pub own: RoaringBitmap,
    pub bound: OwnBound,
    pub client_ids: Vec<EasClientId>,
    pub wrote: bool,
}

impl<'x> GroupwareWriter<'x> {
    pub fn new(
        server: &'x Server,
        ctx: &'x EasContext<'x>,
        target: GroupwareTarget,
        resources: &'x Arc<GroupwareResources>,
        ghosting: Ghosting<'x>,
        replayed: &'x [EasClientId],
    ) -> Self {
        GroupwareWriter {
            server,
            ctx,
            target,
            resources,
            account_info: OnceCell::new(),
            ghosting,
            replayed,
            uids: AddUids::Random,
            edited: RoaringBitmap::new(),
            occurrences: AHashSet::new(),
            created: 0,
            conflicts: None,
            own: RoaringBitmap::new(),
            bound: OwnBound::default(),
            client_ids: Vec::new(),
            wrote: false,
        }
    }

    pub fn with_conflicts(mut self, conflicts: Option<&'x RoaringBitmap>) -> Self {
        self.conflicts = conflicts;
        self
    }

    pub fn with_device_uids(mut self) -> Self {
        self.uids = AddUids::Device;
        self
    }

    pub async fn apply(
        &mut self,
        command: &ClientCommand<'_>,
        view: &mut ClientView,
    ) -> trc::Result<Option<ItemReply>> {
        Ok(match command {
            ClientCommand::Add {
                client_id,
                class,
                data,
                ..
            } => {
                let outcome = match class {
                    Some(class) if *class != self.target.kind.class() => {
                        Err(SyncStatus::CONVERSION_ERROR)
                    }
                    _ => self.add(client_id, data, view).await?,
                };
                Some(match outcome {
                    Ok(Added { document_id, uid }) => ItemReply::Add {
                        class: *class,
                        client_id: client_id.to_string(),
                        server_id: Some(server_id(self.target.container_id, document_id)),
                        status: SyncStatus::SUCCESS,
                        uid,
                    },
                    Err(status) => ItemReply::Add {
                        class: *class,
                        client_id: client_id.to_string(),
                        server_id: None,
                        status,
                        uid: None,
                    },
                })
            }
            ClientCommand::Change {
                server_id,
                instance_id,
                data,
                ..
            } => {
                let edit = match instance_id {
                    Some(instance) => ItemEdit::Occurrence(*instance, data),
                    None => ItemEdit::Item(data),
                };
                self.change(server_id, edit, view)
                    .await?
                    .err()
                    .map(|status| ItemReply::Change {
                        server_id: server_id.to_string(),
                        instance_id: *instance_id,
                        status,
                    })
            }
            ClientCommand::Delete {
                server_id,
                instance_id,
            } => match instance_id {
                Some(instance) => {
                    self.change(server_id, ItemEdit::Exclude(*instance), view)
                        .await?
                }
                None => self.delete(server_id, view).await?,
            }
            .err()
            .map(|status| ItemReply::Delete {
                server_id: server_id.to_string(),
                instance_id: *instance_id,
                status,
            }),
            ClientCommand::Fetch { .. } => None,
        })
    }

    async fn add(
        &mut self,
        client_id: &str,
        data: &RawApplicationData<'_>,
        view: &mut ClientView,
    ) -> Outcome<Added> {
        let added = match self
            .replayed
            .iter()
            .find(|known| known.client_id == client_id)
        {
            Some(known) => Added {
                document_id: known.server_id,
                uid: None,
            },
            None => {
                let outcome = match self.target.kind {
                    GroupwareKind::Contacts => self.add_contact(data).await?,
                    GroupwareKind::Tasks => self.add_task(client_id, data, view).await?,
                    GroupwareKind::Calendar => self.add_event(client_id, data, view).await?,
                };
                match outcome {
                    Ok(Created::New(added, change_id)) => {
                        self.created += 1;
                        self.wrote = true;
                        self.bound.record(change_id);
                        added
                    }
                    Ok(Created::Existing(added)) => added,
                    Err(status) => return Ok(Err(status)),
                }
            }
        };
        let document_id = added.document_id;
        view.held.insert(document_id);
        self.own.insert(document_id);
        self.client_ids.push(EasClientId {
            client_id: client_id.to_string(),
            server_id: document_id,
        });
        Ok(Ok(added))
    }

    async fn change(
        &mut self,
        server_id: &str,
        edit: ItemEdit<'_, '_>,
        view: &ClientView,
    ) -> Outcome<()> {
        let Some(document_id) = self
            .item_id(server_id)
            .filter(|document_id| view.shows(*document_id))
        else {
            return Ok(Err(SyncStatus::OBJECT_NOT_FOUND));
        };
        let first = match edit {
            ItemEdit::Item(_) => self.edited.insert(document_id),
            ItemEdit::Occurrence(instance, _) | ItemEdit::Exclude(instance) => {
                self.occurrences.insert((document_id, instance))
            }
        };
        if !first {
            return Ok(Err(SyncStatus::CONFLICT));
        }
        if self
            .resources
            .format_resource_path_by_parent(document_id, self.target.container_id)
            .is_none()
        {
            return Ok(Err(SyncStatus::OBJECT_NOT_FOUND));
        }
        let outcome = match (self.target.kind, edit) {
            (GroupwareKind::Contacts, ItemEdit::Item(data)) => {
                self.change_contact(document_id, data).await?
            }
            (GroupwareKind::Tasks, ItemEdit::Item(data)) => {
                self.change_task(document_id, data).await?
            }
            (GroupwareKind::Calendar, edit) => self.change_event(document_id, edit).await?,
            (GroupwareKind::Contacts | GroupwareKind::Tasks, _) => {
                Err(SyncStatus::CONVERSION_ERROR)
            }
        };
        Ok(outcome.map(|edited| {
            if let Edited::Written(change_id) = edited {
                self.wrote = true;
                self.bound.record(change_id);
            }
            if !self.is_conflict(document_id) {
                self.own.insert(document_id);
            }
        }))
    }

    async fn delete(&mut self, server_id: &str, view: &mut ClientView) -> Outcome<()> {
        let Some(document_id) = self
            .item_id(server_id)
            .filter(|document_id| view.shows(*document_id))
        else {
            return Ok(Err(SyncStatus::OBJECT_NOT_FOUND));
        };
        if !self.edited.insert(document_id) {
            return Ok(Err(SyncStatus::CONFLICT));
        }
        if let Err(status) = self.remove(document_id, RemoveMode::Command).await? {
            return Ok(Err(status));
        }
        if view.held.remove(document_id) {
            view.removed.insert(document_id);
        }
        Ok(Ok(()))
    }

    pub async fn empty(&mut self) -> trc::Result<bool> {
        let resources = self.resources;
        let mut complete = true;
        for document_id in resources
            .children(self.target.container_id)
            .filter(|path| !path.is_container())
            .map(|path| path.document_id())
        {
            let mut removed = false;
            for _ in 0..MAX_STATE_ATTEMPTS {
                match self.remove(document_id, RemoveMode::Empty).await? {
                    Ok(()) => {
                        removed = true;
                        break;
                    }
                    Err(SyncStatus::CONFLICT) => {}
                    Err(_) => break,
                }
            }
            complete &= removed;
        }
        Ok(complete)
    }

    async fn remove(&mut self, document_id: u32, mode: RemoveMode) -> Outcome<()> {
        let path = self
            .resources
            .format_resource_path_by_parent(document_id, self.target.container_id);
        let outcome = match (self.target.kind, path) {
            (GroupwareKind::Contacts, Some(path)) => {
                let writer = self.card_writer();
                match writer
                    .prepare_delete(self.target.container_id, document_id)
                    .await
                {
                    Ok(deletion) => writer.delete(deletion, Some(path)).await,
                    Err(err) => Err(err),
                }
                .map_err(card_status)
            }
            (GroupwareKind::Tasks | GroupwareKind::Calendar, Some(path)) => {
                let writer = self.event_writer().await?;
                match writer
                    .prepare_delete(self.target.container_id, document_id)
                    .await
                {
                    Ok(mut deletion) => match mode {
                        RemoveMode::Command => {
                            let itip = self
                                .delete_itip(&writer, &mut deletion, document_id)
                                .await?;
                            writer.delete(deletion, None, itip, Some(path)).await
                        }
                        RemoveMode::Empty => {
                            let shown = match deletion.previous() {
                                Some(previous) => self.target.kind.shows(previous),
                                None => {
                                    shows_event(
                                        self.server,
                                        self.ctx.account_id,
                                        self.target.kind,
                                        document_id,
                                    )
                                    .await?
                                }
                            };
                            if shown {
                                writer
                                    .delete(deletion, None, ItipMode::Suppress, Some(path))
                                    .await
                            } else {
                                Err(EventWriteError::NotFound)
                            }
                        }
                    },
                    Err(err) => Err(err),
                }
                .map_err(event_status)
            }
            (_, None) => Err(Ok(SyncStatus::OBJECT_NOT_FOUND)),
        };
        match outcome {
            Ok(()) => self.wrote = true,
            Err(Ok(SyncStatus::OBJECT_NOT_FOUND)) => {}
            Err(status) => return status.map(Err),
        }
        Ok(Ok(()))
    }

    async fn add_contact(&self, data: &RawApplicationData<'_>) -> Outcome<Created> {
        let Some(contact) = self.parse_contact(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let uid = new_uid();
        let name = card_name(&uid);
        let mut card = new_card(uid);
        let notes = contact.body.as_ref().and_then(incoming_text);
        let update = ContactUpdate {
            contact: &contact,
            notes: notes.as_deref(),
            ghosting: Ghosting::Off,
        };
        if contact_from_eas(&mut card, &update).is_err() {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        }
        let Some(size) = card_size(self.server, &card) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        if let Err(err) = assert_card_room(
            self.server,
            self.ctx.account_id,
            self.resources,
            self.created,
        )
        .await
        {
            return store_status(err).map(Err);
        }
        let writer = self.card_writer();
        let written = match writer.prepare_create(self.target.container_id) {
            Ok(new) => {
                writer
                    .create(
                        new,
                        CardCreate {
                            name,
                            vcard: card,
                            size: Some(size),
                        },
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        match written {
            Ok(written) => Ok(Ok(Created::new(written.document_id, written.change_id))),
            Err(err) => card_status(err).map(Err),
        }
    }

    async fn change_contact(
        &self,
        document_id: u32,
        data: &RawApplicationData<'_>,
    ) -> Outcome<Edited> {
        let Some(contact) = self.parse_contact(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let writer = self.card_writer();
        let stored = match writer
            .prepare_update(self.target.container_id, document_id)
            .await
        {
            Ok(stored) => stored,
            Err(err) => return card_status(err).map(Err),
        };
        let mut card = stored
            .content()
            .caused_by(trc::location!())?
            .deserialize::<ContactCardContent>()
            .caused_by(trc::location!())?
            .card;
        let notes = contact.body.as_ref().and_then(incoming_text);
        let update = ContactUpdate {
            contact: &contact,
            notes: notes.as_deref(),
            ghosting: self.ghosting,
        };
        match contact_from_eas(&mut card, &update) {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(Ok(Edited::Unchanged)),
            Err(_) => return Ok(Err(SyncStatus::CONVERSION_ERROR)),
        }
        if self.is_conflict(document_id) {
            return Ok(Err(SyncStatus::CONFLICT));
        }
        if card_size(self.server, &card).is_none() {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        }
        match writer.update(stored, card).await {
            Ok(written) => Ok(Ok(Edited::Written(written.change_id))),
            Err(err) => card_status(err).map(Err),
        }
    }

    async fn add_task(
        &self,
        client_id: &str,
        data: &RawApplicationData<'_>,
        view: &ClientView,
    ) -> Outcome<Created> {
        let Some(task) = self.parse_task(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let now = Timestamp::now();
        let (uid, stable) = self.fallback_uid(client_id, data);
        if let Some(document_id) = self.resent(stable, &uid, view) {
            return Ok(Ok(Created::Existing(Added {
                document_id,
                uid: None,
            })));
        }
        let name = if stable {
            format!("{}{ICAL_EXTENSION}", new_uid())
        } else {
            format!("{uid}{ICAL_EXTENSION}")
        };
        let mut ical = skeleton(ICalendarComponentType::VTodo, &uid, now);
        let description = task.body.as_ref().and_then(incoming_text);
        let update = TaskUpdate {
            task: &task,
            description: description.as_deref(),
            write: TaskWrite::Add,
            now,
        };
        if todo_from_eas(&mut ical, &update).is_err() {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        }
        let Some(size) = ical_size(self.server, &ical) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        if let Err(err) = self.assert_room(StorageQuota::MaxCalendarEvents).await {
            return store_status(err).map(Err);
        }
        let writer = self.event_writer().await?;
        let written = match writer.prepare_create(self.target.container_id, &ical).await {
            Ok(new) => {
                writer
                    .create(
                        new,
                        EventCreate {
                            name,
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
            Ok(written) => Ok(Ok(Created::new(written.document_id, written.change_id))),
            Err(EventWriteError::UidConflict { document_id, .. })
                if stable && view.shows(document_id) =>
            {
                Ok(Ok(Created::Existing(Added {
                    document_id,
                    uid: None,
                })))
            }
            Err(err) => event_status(err).map(Err),
        }
    }

    async fn add_event(
        &self,
        client_id: &str,
        data: &RawApplicationData<'_>,
        view: &ClientView,
    ) -> Outcome<Created> {
        let Some(calendar) = self.parse_calendar(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let modern = self.schedules();
        let given = if modern {
            calendar.client_uid.as_deref()
        } else {
            calendar.uid.as_deref()
        };
        let (uid, stable) = match given.filter(|uid| is_valid_uid(uid)) {
            Some(uid) => (uid.to_string(), true),
            None => self.fallback_uid(client_id, data),
        };
        let writer = self.event_writer().await?;
        let description = calendar.body.as_ref().and_then(incoming_text);
        let now = Timestamp::now();
        let mut ical = skeleton(ICalendarComponentType::VEvent, &uid, now);
        let update = EventUpdate {
            calendar: &calendar,
            description: description.as_deref(),
            organizer: writer
                .account_info
                .addresses()
                .first()
                .map_or("", String::as_str),
            version: self.ctx.version,
            now,
        };
        if event_from_eas(&mut ical, &update).is_err() {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        }
        let Some(size) = ical_size(self.server, &ical) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        if let Some(document_id) = self.resent(stable, &uid, view) {
            return Ok(Ok(Created::Existing(Added {
                document_id,
                uid: modern.then_some(uid),
            })));
        }
        if let Err(err) = self.assert_room(StorageQuota::MaxCalendarEvents).await {
            return store_status(err).map(Err);
        }
        let written = match writer.prepare_create(self.target.container_id, &ical).await {
            Ok(new) => {
                writer
                    .create(
                        new,
                        EventCreate {
                            name: format!("{}{ICAL_EXTENSION}", new_uid()),
                            ical,
                            size: Some(size),
                            itip: if modern {
                                ItipMode::Send
                            } else {
                                ItipMode::Suppress
                            },
                        },
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        let reply_uid = modern.then_some(uid);
        match written {
            Ok(written) => Ok(Ok(Created::New(
                Added {
                    document_id: written.document_id,
                    uid: reply_uid,
                },
                written.change_id,
            ))),
            Err(EventWriteError::UidConflict { document_id, .. })
                if stable && view.shows(document_id) =>
            {
                Ok(Ok(Created::Existing(Added {
                    document_id,
                    uid: reply_uid,
                })))
            }
            Err(err) => event_status(err).map(Err),
        }
    }

    async fn change_task(
        &self,
        document_id: u32,
        data: &RawApplicationData<'_>,
    ) -> Outcome<Edited> {
        let Some(task) = self.parse_task(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let writer = self.event_writer().await?;
        let edit = match EventEdit::open(&writer, self.target.container_id, document_id).await {
            Ok(edit) => edit,
            Err(err) => return event_status(err).map(Err),
        };
        let mut ical = edit.to_ical()?;
        let description = task.body.as_ref().and_then(incoming_text);
        let update = TaskUpdate {
            task: &task,
            description: description.as_deref(),
            write: TaskWrite::Change,
            now: Timestamp::now(),
        };
        match todo_from_eas(&mut ical, &update) {
            Ok(true) => {}
            Ok(false) => return Ok(Ok(Edited::Unchanged)),
            Err(_) => return Ok(Err(SyncStatus::CONVERSION_ERROR)),
        }
        if self.is_conflict(document_id) {
            return Ok(Err(SyncStatus::CONFLICT));
        }
        if ical_size(self.server, &ical).is_none() {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        }
        match edit.commit(ical, ItipMode::Suppress).await {
            Ok(EventWrite::Unchanged) => Ok(Ok(Edited::Unchanged)),
            Ok(EventWrite::Written(written)) => Ok(Ok(Edited::Written(written.change_id))),
            Err(err) => event_status(err).map(Err),
        }
    }

    async fn change_event(&self, document_id: u32, item: ItemEdit<'_, '_>) -> Outcome<Edited> {
        let calendar = match item {
            ItemEdit::Item(data) | ItemEdit::Occurrence(_, data) => {
                let Some(calendar) = self.parse_calendar(data) else {
                    return Ok(Err(SyncStatus::CONVERSION_ERROR));
                };
                Some(calendar)
            }
            ItemEdit::Exclude(_) => None,
        };
        let writer = self.event_writer().await?;
        let edit = match EventEdit::open(&writer, self.target.container_id, document_id).await {
            Ok(edit) => edit,
            Err(err) => return event_status(err).map(Err),
        };
        let mut ical = edit.to_ical()?;
        let organized = self.organizes(&writer, &ical);
        let description = calendar
            .as_ref()
            .and_then(|calendar| calendar.body.as_ref())
            .and_then(incoming_text);
        let change = calendar.as_deref().map(|calendar| EventChange {
            calendar,
            description: description.as_deref(),
            owner: writer.account_info.addresses(),
            version: self.ctx.version,
            ghosting: self.ghosting,
            now: Timestamp::now(),
        });
        let converted = match (item, &change) {
            (ItemEdit::Exclude(instance), _) => {
                occurrence_delete_from_eas(&mut ical, instance).map(|()| true)
            }
            (ItemEdit::Occurrence(instance, _), Some(change)) => {
                occurrence_change_from_eas(&mut ical, instance, change)
            }
            (ItemEdit::Item(_), Some(change)) => event_change_from_eas(&mut ical, change),
            (ItemEdit::Item(_) | ItemEdit::Occurrence(..), None) => {
                return Ok(Err(SyncStatus::CONVERSION_ERROR));
            }
        };
        match converted {
            Ok(true) => {}
            Ok(false) => return Ok(Ok(Edited::Unchanged)),
            Err(_) => return Ok(Err(SyncStatus::CONVERSION_ERROR)),
        }
        if !matches!(item, ItemEdit::Exclude(_)) && self.is_conflict(document_id) {
            return Ok(Err(SyncStatus::CONFLICT));
        }
        if ical_size(self.server, &ical).is_none() {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        }
        let itip = if organized || self.organizes(&writer, &ical) {
            ItipMode::Send
        } else {
            ItipMode::Suppress
        };
        match edit.commit(ical, itip).await {
            Ok(EventWrite::Unchanged) => Ok(Ok(Edited::Unchanged)),
            Ok(EventWrite::Written(written)) => Ok(Ok(Edited::Written(written.change_id))),
            Err(err) => event_status(err).map(Err),
        }
    }

    fn is_conflict(&self, document_id: u32) -> bool {
        self.conflicts
            .is_some_and(|conflicts| conflicts.contains(document_id))
    }

    fn schedules(&self) -> bool {
        self.ctx.version >= ProtocolVersion::V160
    }

    fn organizes(&self, writer: &EventWriter<'_>, ical: &ICalendar) -> bool {
        self.schedules()
            && event_meeting_role(ical, writer.account_info.addresses()) == MeetingRole::Organizer
    }

    async fn delete_itip(
        &self,
        writer: &EventWriter<'_>,
        deletion: &mut EventDeletion,
        document_id: u32,
    ) -> trc::Result<ItipMode> {
        if self.target.kind != GroupwareKind::Calendar
            || !self.schedules()
            || !writer.sends_itip(ItipMode::Send)
        {
            return Ok(ItipMode::Suppress);
        }
        let event = deletion.event().caused_by(trc::location!())?;
        if event.inner.schedule_tag.is_none()
            || event.inner.names.len() > 1
            || event.inner.event_range_end() <= now() as i64
        {
            return Ok(ItipMode::Suppress);
        }
        let stored;
        let ical = match deletion.previous() {
            Some(previous) => previous,
            None => {
                let Some(content) = self
                    .server
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        writer.account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(ItipMode::Suppress);
                };
                stored = content
                    .unarchive::<CalendarEventContent>()
                    .and_then(|content| rkyv_deserialize::<_, ICalendar>(&content.data.event))
                    .caused_by(trc::location!())?;
                deletion.set_content(content);
                &stored
            }
        };
        Ok(
            match event_meeting_role(ical, writer.account_info.addresses()) {
                MeetingRole::Organizer => ItipMode::Send,
                MeetingRole::Attendee | MeetingRole::None => ItipMode::Suppress,
            },
        )
    }

    fn parse_calendar<'a>(&self, data: &RawApplicationData<'a>) -> Option<Box<Calendar<'a>>> {
        match data.parse(Class::Calendar, self.ctx.version, &WbxmlLimits::DEFAULT) {
            Ok(ApplicationData::Calendar(calendar)) => Some(calendar),
            _ => None,
        }
    }

    fn parse_task<'a>(&self, data: &RawApplicationData<'a>) -> Option<Box<Task<'a>>> {
        match data.parse(Class::Tasks, self.ctx.version, &WbxmlLimits::DEFAULT) {
            Ok(ApplicationData::Task(task)) => Some(task),
            _ => None,
        }
    }

    fn parse_contact<'a>(&self, data: &RawApplicationData<'a>) -> Option<Box<Contact<'a>>> {
        match data.parse(Class::Contacts, self.ctx.version, &WbxmlLimits::DEFAULT) {
            Ok(ApplicationData::Contact(contact)) => Some(contact),
            _ => None,
        }
    }

    fn item_id(&self, server_id: &str) -> Option<u32> {
        EasServerId::decode(server_id)
            .filter(|id| id.container == self.target.container_id)
            .map(|id| id.id)
    }

    async fn assert_room(&self, quota: StorageQuota) -> trc::Result<()> {
        if self.created == 0 {
            return Ok(());
        }
        let account = self.server.account(self.ctx.account_id).await?;
        self.server
            .assert_object_quota(&account, quota, self.created + 1, || {
                self.resources.resources.count(false)
            })
    }

    async fn event_writer(&self) -> trc::Result<EventWriter<'_>> {
        let account_info = self
            .account_info
            .get_or_try_init(|| self.server.account_info(self.ctx.account_id))
            .await
            .caused_by(trc::location!())?;
        Ok(EventWriter {
            server: self.server,
            access_token: &self.ctx.access_token,
            account_id: self.ctx.account_id,
            resources: self.resources,
            account_info,
        })
    }

    fn card_writer(&self) -> CardWriter<'_> {
        CardWriter {
            server: self.server,
            access_token: &self.ctx.access_token,
            account_id: self.ctx.account_id,
            resources: self.resources,
        }
    }
}

pub async fn empty_container(
    server: &Server,
    ctx: &EasContext<'_>,
    target: GroupwareTarget,
) -> trc::Result<ItemOperationsStatus> {
    let resources = server
        .fetch_groupware_resources(ctx.account_id, ctx.account_id, target.kind.collection())
        .await?;
    if resources
        .container_resource_by_id(target.container_id)
        .is_none()
    {
        return Ok(ItemOperationsStatus::NOT_FOUND);
    }
    let mut writer = GroupwareWriter::new(server, ctx, target, &resources, Ghosting::Off, &[]);
    Ok(if writer.empty().await? {
        ItemOperationsStatus::SUCCESS
    } else if writer.wrote {
        ItemOperationsStatus::PARTIAL_SUCCESS
    } else {
        ItemOperationsStatus::SERVER_ERROR
    })
}

fn card_status(err: CardWriteError) -> trc::Result<SyncStatus> {
    card_failure(err).map(failure_status)
}

fn event_status(err: EventWriteError) -> trc::Result<SyncStatus> {
    match err {
        EventWriteError::NotFound => Ok(SyncStatus::OBJECT_NOT_FOUND),
        EventWriteError::Forbidden
        | EventWriteError::InvalidObject
        | EventWriteError::UidChanged(_)
        | EventWriteError::UidConflict { .. }
        | EventWriteError::UnsupportedComponent
        | EventWriteError::ScheduleTagMismatch
        | EventWriteError::UserData(_)
        | EventWriteError::TooManyRecipients
        | EventWriteError::Scheduling(..) => Ok(SyncStatus::CONVERSION_ERROR),
        EventWriteError::Store(err) => store_status(err),
    }
}

pub(super) fn store_status(err: trc::Error) -> trc::Result<SyncStatus> {
    store_failure(err).map(failure_status)
}

fn failure_status(failure: WriteFailure) -> SyncStatus {
    match failure {
        WriteFailure::NotFound => SyncStatus::OBJECT_NOT_FOUND,
        WriteFailure::Forbidden | WriteFailure::Invalid | WriteFailure::UidConflict => {
            SyncStatus::CONVERSION_ERROR
        }
        WriteFailure::Quota => SyncStatus::CANNOT_COMPLETE,
        WriteFailure::Conflict => SyncStatus::CONFLICT,
    }
}

fn skeleton(kind: ICalendarComponentType, uid: &str, now: Timestamp) -> ICalendar {
    let text = |name, value: &str| ICalendarEntry {
        name,
        params: Vec::new(),
        values: smallvec![ICalendarValue::Text(value.to_string())],
    };
    ICalendar {
        components: vec![
            ICalendarComponent {
                component_type: ICalendarComponentType::VCalendar,
                entries: vec![
                    text(ICalendarProperty::Version, ICAL_VERSION),
                    text(ICalendarProperty::Prodid, PROD_ID),
                ],
                component_ids: vec![1],
            },
            ICalendarComponent {
                component_type: kind,
                entries: vec![
                    text(ICalendarProperty::Uid, uid),
                    ICalendarEntry {
                        name: ICalendarProperty::Dtstamp,
                        params: Vec::new(),
                        values: smallvec![ICalendarValue::PartialDateTime(
                            PartialDateTime::from_utc_timestamp(now.as_second())
                        )],
                    },
                ],
                component_ids: Vec::new(),
            },
        ],
    }
}

impl GroupwareWriter<'_> {
    fn fallback_uid(&self, client_id: &str, data: &RawApplicationData<'_>) -> (String, bool) {
        if self.uids == AddUids::Device {
            let uid = format!(
                "{DEVICE_UID_PREFIX}{:04x}-{:016x}-{client_id}",
                self.ctx.device.slot,
                xxh3_64(data.content())
            );
            if is_valid_uid(&uid) {
                return (uid, true);
            }
        }
        (new_uid(), false)
    }

    fn resent(&self, stable: bool, uid: &str, view: &ClientView) -> Option<u32> {
        if !stable {
            return None;
        }
        match assert_unique_uid(
            self.resources,
            &self.ctx.access_token,
            self.ctx.account_id,
            self.target.container_id,
            Some(uid),
        ) {
            Err(EventWriteError::UidConflict { document_id, .. }) if view.shows(document_id) => {
                Some(document_id)
            }
            _ => None,
        }
    }
}

fn is_valid_uid(uid: &str) -> bool {
    !uid.is_empty() && uid.len() <= MAX_UID_LEN && !uid.chars().any(char::is_control)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/sync/groupware_write/tests.rs"]
mod tests;
