/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    early_reply::NewMeeting,
    load::{MAX_DECODED, convert_error, convert_options},
    meeting_copy::replaced_attendee_item,
    object_row::is_category,
    save::{SaveMode, SaveTarget, Saved},
};
use crate::{
    contact_group::MemberResolver,
    folders::{ContainerClass, FolderNode},
    groupware_write::{
        EventEdit, WriteFailure, card_failure, card_name, card_size, event_failure, event_name,
        ical_size, new_card, new_event, new_todo, new_uid, set_event_uid,
    },
    identity::org_dn,
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError},
            resolve::DirectoryResolver,
            staged::{RowBaseline, StagedMessage, Touched, TouchedFlags},
            state::MessageObject,
            store::class_has_prefix,
        },
        ids::{ChangeSpace, IdSpace, MapiId},
    },
    store::{FolderKind, FolderRef, alias::GroupwareKind},
};
use calcard::icalendar::{ICalendar, ICalendarParticipationStatus};
use exchange_proto::{
    convert::{
        BlobLimits,
        blob::TaskRecur,
        context::ConvertOptions,
        ical::{
            drop_unscheduled_event_draft, has_recorded_reply, has_unmapped_task_recurrence,
            meeting_response_status, meeting_uid, patch_event_from_message,
            patch_task_from_message, recipients_changed, set_attendees_from_recipients,
            set_participation,
        },
        mime::{BodySource, source_text},
        model::{AttachData, MessageContent, PropBag as ContentBag},
        vcard::{
            DISTLIST_CLASS, distlist_name, is_distlist_member_key, is_distlist_name_key,
            patch_contact_from_message, patch_contact_photo, patch_distlist,
        },
    },
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, sets::PSETID_TASK, tags},
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::write::{
        EventCreate, EventWrite, EventWriteError, EventWriter, ItipMode, UidChange,
        assert_unique_uid,
    },
    contact::{
        ContactCardContent,
        write::{CardCreate, CardWriteError, CardWriter},
    },
};
use jiff::Timestamp;
use std::borrow::Cow;
use trc::AddContext;
use types::{collection::SyncCollection, type_state::DataType};

const MAX_SAVE_ATTEMPTS: usize = 5;
const CONTACT_CLASS: &[u8] = b"IPM.Contact";
const TASK_CLASS: &[u8] = b"IPM.Task";
const APPOINTMENT_CLASS: &[u8] = b"IPM.Appointment";
const TASK_RECURRENCE: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PSETID_TASK,
    lid: 0x8116,
};
const TASK_F_RECURRING: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PSETID_TASK,
    lid: 0x8126,
};
const TASK_DEAD_OCCURRENCE: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PSETID_TASK,
    lid: 0x8109,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupwareFolder {
    AddressBook(u32),
    Calendar(u32, CalendarItem),
}

struct Written {
    id: MapiId,
    origin: Option<u64>,
    change: Option<u64>,
}

impl Written {
    fn unchanged(id: MapiId, origin: u64, change: Option<u64>) -> Self {
        Written {
            id,
            origin: Some(origin),
            change,
        }
    }
}

impl GroupwareFolder {
    pub(super) fn kind(self) -> GroupwareKind {
        match self {
            GroupwareFolder::AddressBook(_) => GroupwareKind::Contact,
            GroupwareFolder::Calendar(..) => GroupwareKind::Event,
        }
    }

    pub(super) fn container(self) -> u32 {
        match self {
            GroupwareFolder::AddressBook(id) | GroupwareFolder::Calendar(id, _) => id,
        }
    }

    pub(super) fn change_space(self) -> ChangeSpace {
        match self {
            GroupwareFolder::AddressBook(_) => ChangeSpace::AddressBook,
            GroupwareFolder::Calendar(..) => ChangeSpace::Calendar,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CalendarItem {
    Event,
    Task,
}

impl CalendarItem {
    fn class(self) -> &'static [u8] {
        match self {
            CalendarItem::Event => APPOINTMENT_CLASS,
            CalendarItem::Task => TASK_CLASS,
        }
    }

    fn accepts(self, props: &ContentBag) -> bool {
        has_class(props, self.class())
            && (self == CalendarItem::Event || task_recurrence_supported(props))
    }

    fn uid(self, props: &ContentBag) -> String {
        match self {
            CalendarItem::Event => meeting_uid(props).map_or_else(new_uid, Cow::into_owned),
            CalendarItem::Task => new_uid(),
        }
    }

    fn skeleton(self, uid: &str) -> ICalendar {
        match self {
            CalendarItem::Event => new_event(uid, Timestamp::now()),
            CalendarItem::Task => new_todo(uid, Timestamp::now()),
        }
    }

    fn patch(
        self,
        ical: &mut ICalendar,
        changes: &ContentBag,
        opts: &ConvertOptions<'_>,
    ) -> Result<(), RopError> {
        match self {
            CalendarItem::Event => patch_event_from_message(ical, None, changes, opts),
            CalendarItem::Task => patch_task_from_message(ical, changes, opts),
        }
        .map_err(convert_error)?;
        Ok(())
    }
}

struct GroupEdit<'x> {
    name: Option<&'x str>,
    members: Option<Vec<String>>,
    notes: ContentBag,
}

struct Edited {
    touched: Touched,
    flags: bool,
    categories: bool,
}

impl Edited {
    fn of(staged: &StagedMessage) -> Self {
        Edited {
            touched: staged.touched.clone(),
            flags: !staged.flags_touched.is_empty(),
            categories: staged.categories_touched,
        }
    }

    fn changes(&self, staged: &ContentBag, stored: &ContentBag) -> Result<ContentBag, RopError> {
        let mut changes = ContentBag::new();
        for (key, value) in staged.iter().filter(|(key, _)| self.covers(key.as_ref())) {
            if stored.get_any(key.as_ref()) != Some(value) {
                changes.set(key.clone(), value.clone());
            }
        }
        for (key, value) in stored.iter().filter(|(key, _)| self.covers(key.as_ref())) {
            if staged.get_any(key.as_ref()).is_none() {
                changes.set(key.clone(), cleared(value));
            }
        }
        let subject = PropKey::tag(tags::SUBJECT.id());
        if staged.get_any(subject.as_ref()).is_none()
            && self.covers(PropKeyRef::Tag(tags::NORMALIZED_SUBJECT.id()))
            && let Some(composed) = staged.composed_subject()
        {
            if stored.text(tags::SUBJECT.id()) == Some(composed.as_ref()) {
                changes.remove_any(subject.as_ref());
            } else {
                changes.set(subject, OwnedPropValue::Unicode(composed.into()));
            }
        }
        if let Some(body) = body_change(staged, |key| changes.get_any(key).is_some())? {
            changes.set(PropKey::tag(tags::BODY.id()), body);
        }
        Ok(changes)
    }

    fn covers(&self, key: PropKeyRef<'_>) -> bool {
        match &self.touched {
            Touched::Structure => true,
            Touched::Keys(keys) => {
                keys.iter().any(|touched| touched.as_ref() == key)
                    || (self.flags && TouchedFlags::is_flag_key(key))
                    || (self.categories && is_category(key))
            }
        }
    }
}

impl RopContext<'_, '_> {
    pub(super) async fn groupware_folder(
        &mut self,
        mailbox_id: u32,
        folder: u64,
    ) -> Result<Option<GroupwareFolder>, RopError> {
        Ok(
            match MapiId::from_counter(folder).and_then(MapiId::to_node) {
                Some(FolderNode::Stored(FolderRef {
                    kind: FolderKind::AddressBook,
                    id,
                })) => Some(GroupwareFolder::AddressBook(id)),
                Some(
                    node @ FolderNode::Stored(FolderRef {
                        kind: FolderKind::Calendar,
                        ..
                    }),
                ) => self
                    .folder_tree(mailbox_id)
                    .await?
                    .get(node)
                    .and_then(|entry| match (entry.node, &entry.class) {
                        (FolderNode::Stored(folder), ContainerClass::Appointment) => {
                            Some(GroupwareFolder::Calendar(folder.id, CalendarItem::Event))
                        }
                        (FolderNode::Stored(folder), ContainerClass::Task) => {
                            Some(GroupwareFolder::Calendar(folder.id, CalendarItem::Task))
                        }
                        _ => None,
                    }),
                _ => None,
            },
        )
    }

    pub(super) async fn save_groupware(
        &mut self,
        message: &MessageObject,
        folder: GroupwareFolder,
        target: SaveTarget,
        uid: Option<String>,
    ) -> Result<Saved, RopError> {
        let folder_id = MapiId::from_counter(message.folder).ok_or(ErrorCode::NOT_FOUND)?;
        let base = match target.base {
            Some(client) if client.space == IdSpace::Email => Some(
                self.mailbox(message.mailbox_id)
                    .await?
                    .stored_item(message.folder, client)
                    .ok_or(ErrorCode::OBJECT_DELETED)?,
            ),
            base => base,
        };
        let target = SaveTarget { base, ..target };
        let written = match folder {
            GroupwareFolder::AddressBook(address_book) => {
                self.save_contact(message, address_book, target, uid)
                    .await?
            }
            GroupwareFolder::Calendar(calendar, item) => {
                self.save_calendar_item(message, (calendar, item), target, uid)
                    .await?
            }
        };
        Ok(Saved {
            folder: folder_id,
            id: written.id,
            origin: written.origin,
            row: RowBaseline::Untracked,
            change: written.change,
        })
    }

    async fn save_contact(
        &mut self,
        message: &MessageObject,
        address_book: u32,
        target: SaveTarget,
        uid: Option<String>,
    ) -> Result<Written, RopError> {
        if !self.types.contains(DataType::ContactCard) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let staged = self.staged_message(message)?;
        let content = staged.content.clone();
        let group = is_class(&content.props, DISTLIST_CLASS.as_bytes());
        if !group && !has_class(&content.props, CONTACT_CLASS) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let edited = Edited::of(staged);
        let server = self.request.server;
        let account_id = message.mailbox_id;
        let resources = server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let writer = CardWriter {
            server,
            access_token: self.request.access_token,
            account_id,
            resources: &resources,
        };
        let Some(base) = target.base else {
            let uid = uid.unwrap_or_else(new_uid);
            let name = card_name(&uid);
            let mut card = new_card(uid);
            if group {
                let members = self
                    .group_uris(account_id, &resources, &content.props, None)
                    .await?;
                patch_distlist(
                    &mut card,
                    distlist_name(&content.props),
                    Some(&members),
                    &|_| false,
                );
                let mut notes = group_notes(&content.props);
                if let Some(body) =
                    body_change(&content.props, |key| content.props.get_any(key).is_some())?
                {
                    notes.set(PropKey::tag(tags::BODY.id()), body);
                }
                if !notes.is_empty() {
                    patch_contact_from_message(&mut card, &notes).map_err(convert_error)?;
                }
            } else {
                patch_contact_from_message(&mut card, &content.props).map_err(convert_error)?;
                if let Some(body) =
                    body_change(&content.props, |key| content.props.get_any(key).is_some())?
                {
                    let mut changes = ContentBag::new();
                    changes.set(PropKey::tag(tags::BODY.id()), body);
                    patch_contact_from_message(&mut card, &changes).map_err(convert_error)?;
                }
                if let ContactPhoto::Bytes(photo) = ContactPhoto::of(&content) {
                    patch_contact_photo(&mut card, Some(photo));
                }
            }
            let size = card_size(server, &card).ok_or(ErrorCode::TOO_BIG)?;
            let written = match writer.prepare_create(address_book) {
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
            }
            .map_err(card_error)?;
            return Ok(Written {
                id: MapiId::new(IdSpace::Contact, written.document_id),
                origin: etag_origin(&written.etag),
                change: written.change_id,
            });
        };
        if base.space != IdSpace::Contact {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let current = resources
            .format_resource_path_by_parent(base.id, address_book)
            .and_then(|_| resources.item_by_id(base.id))
            .map(|item| u64::from(item.etag()))
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let checked = target.origin.filter(|_| target.mode == SaveMode::Checked);
        if checked.is_some_and(|origin| origin != current) {
            return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
        }
        let stored = self.stored_content(message).await?;
        let changes = edited.changes(&content.props, &stored.props)?;
        let group_edit = if group {
            let name = changes
                .iter()
                .any(|(key, _)| is_distlist_name_key(key.as_ref()))
                .then(|| distlist_name(&content.props))
                .flatten();
            let members = if changes
                .iter()
                .any(|(key, _)| is_distlist_member_key(key.as_ref()))
            {
                Some(
                    self.group_uris(account_id, &resources, &content.props, Some(&changes))
                        .await?,
                )
            } else {
                None
            };
            Some(GroupEdit {
                name,
                members,
                notes: group_notes(&changes),
            })
        } else {
            None
        };
        let photo = match &edited.touched {
            Touched::Structure if group => None,
            Touched::Structure => match (ContactPhoto::of(&content), ContactPhoto::of(&stored)) {
                (ContactPhoto::Unavailable, _) | (_, ContactPhoto::Unavailable) => None,
                (staged, stored) => (staged != stored).then(|| staged.bytes()),
            },
            Touched::Keys(_) => None,
        };
        drop(stored);
        let unchanged = match &group_edit {
            Some(edit) => edit.name.is_none() && edit.members.is_none() && edit.notes.is_empty(),
            None => changes.is_empty() && photo.is_none(),
        };
        if unchanged {
            let change = self.loaded_for(message).and_then(|loaded| loaded.change);
            return Ok(Written::unchanged(base, current, change));
        }
        let rights = self.view_rights(account_id).await?;
        for _ in 0..MAX_SAVE_ATTEMPTS {
            let stored = writer
                .prepare_update(address_book, base.id)
                .await
                .map_err(card_error)?;
            let etag = u64::from(
                stored
                    .card()
                    .caused_by(trc::location!())?
                    .inner
                    .etag
                    .to_native(),
            );
            if checked.is_some_and(|origin| origin != etag) {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
            let mut card = stored
                .content()
                .and_then(|content| content.deserialize::<ContactCardContent>())
                .caused_by(trc::location!())?
                .card;
            match &group_edit {
                Some(edit) => {
                    let resolver = edit
                        .members
                        .is_some()
                        .then(|| MemberResolver::new(&resources, &rights, &card));
                    patch_distlist(&mut card, edit.name, edit.members.as_deref(), &|uri| {
                        resolver
                            .as_ref()
                            .is_some_and(|resolver| resolver.keeps_on_save(uri))
                    });
                    if !edit.notes.is_empty() {
                        patch_contact_from_message(&mut card, &edit.notes)
                            .map_err(convert_error)?;
                    }
                }
                None => {
                    patch_contact_from_message(&mut card, &changes).map_err(convert_error)?;
                    if let Some(photo) = photo {
                        patch_contact_photo(&mut card, photo);
                    }
                }
            }
            if card_size(server, &card).is_none() {
                return Err(RopError::Code(ErrorCode::TOO_BIG));
            }
            match writer.update(stored, card).await {
                Ok(written) => {
                    return Ok(Written {
                        id: base,
                        origin: etag_origin(&written.etag),
                        change: written.change_id,
                    });
                }
                Err(err) => match card_failure(err)? {
                    WriteFailure::Conflict => continue,
                    failure => return Err(RopError::Code(failure_code(failure))),
                },
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    async fn save_calendar_item(
        &mut self,
        message: &MessageObject,
        (calendar, item): (u32, CalendarItem),
        target: SaveTarget,
        uid: Option<String>,
    ) -> Result<Written, RopError> {
        if !self.types.contains(DataType::CalendarEvent) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let staged = self.staged_message(message)?;
        let content = staged.content.clone();
        if !item.accepts(&content.props) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let edited = Edited::of(staged);
        let account_id = message.mailbox_id;
        let guids = self.store_guids(account_id).await?;
        let org = org_dn().ok_or(ErrorCode::ERROR)?;
        let opts = convert_options(&org, guids);
        let server = self.request.server;
        let resources = server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let account_info = server
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let writer = EventWriter {
            server,
            access_token: self.request.access_token,
            account_id,
            resources: &resources,
            account_info: &account_info,
        };
        let organizer = account_info.addresses().first().map_or("", String::as_str);
        let Some(base) = target.base else {
            let uid = uid.unwrap_or_else(|| item.uid(&content.props));
            let mut ical = item.skeleton(&uid);
            item.patch(&mut ical, &content.props, &opts)?;
            if let Some(body) =
                body_change(&content.props, |key| content.props.get_any(key).is_some())?
            {
                let mut changes = ContentBag::new();
                changes.set(PropKey::tag(tags::BODY.id()), body);
                item.patch(&mut ical, &changes, &opts)?;
            }
            if item == CalendarItem::Event {
                let resolver =
                    DirectoryResolver::for_content(server, self.request.access_token, &content)
                        .await?;
                set_attendees_from_recipients(&mut ical, &content, organizer, &resolver)
                    .map_err(convert_error)?;
                record_response(&mut ical, &content.props, account_info.addresses());
                drop_unscheduled_event_draft(&mut ical);
            }
            let size = ical_size(server, &ical).ok_or(ErrorCode::TOO_BIG)?;
            let new = writer
                .prepare_create(calendar, &ical)
                .await
                .map_err(event_error)?;
            let replaced = match assert_unique_uid(
                &resources,
                self.request.access_token,
                account_id,
                calendar,
                Some(&uid),
            ) {
                Ok(()) => None,
                Err(EventWriteError::UidConflict {
                    document_id,
                    href: Some(path),
                }) if item == CalendarItem::Event => Some((
                    replaced_attendee_item(&writer, calendar, document_id, &ical).await?,
                    path,
                )),
                Err(err) => return Err(event_error(err)),
            };
            let new_meeting = replaced
                .is_none()
                .then(|| NewMeeting::of(&ical, &content.props, account_info.addresses()))
                .flatten();
            let input = EventCreate {
                name: event_name(&uid),
                ical,
                size: Some(size),
                itip: ItipMode::Suppress,
            };
            let written = match replaced {
                None => writer.create(new, input).await,
                Some((deletion, path)) => {
                    writer
                        .create_replacing(new, input, deletion, Some(path))
                        .await
                }
            }
            .map_err(event_error)?;
            if let Some(new_meeting) = new_meeting {
                Box::pin(new_meeting.apply_early_replies(
                    server,
                    self.request.access_token,
                    &account_info,
                    &uid,
                ))
                .await;
            }
            return Ok(Written {
                id: MapiId::new(IdSpace::Event, written.document_id),
                origin: etag_origin(&written.etag),
                change: written.change_id,
            });
        };
        if base.space != IdSpace::Event {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let current = resources
            .format_resource_path_by_parent(base.id, calendar)
            .and_then(|_| resources.item_by_id(base.id))
            .map(|item| u64::from(item.etag()))
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let checked = target.origin.filter(|_| target.mode == SaveMode::Checked);
        if checked.is_some_and(|origin| origin != current) {
            return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
        }
        let stored = self.stored_content(message).await?;
        let changes = edited.changes(&content.props, &stored.props)?;
        let adopted_uid = (item == CalendarItem::Event)
            .then(|| meeting_uid(&changes))
            .flatten()
            .filter(|uid| meeting_uid(&stored.props).as_ref() != Some(uid))
            .map(Cow::into_owned);
        let resolver = match (item, &edited.touched) {
            (CalendarItem::Event, Touched::Structure) => Some(
                DirectoryResolver::for_content(server, self.request.access_token, &content).await?,
            ),
            _ => None,
        };
        let attendees = resolver.as_ref().filter(|resolver| {
            recipients_changed(&content.recipients, &stored.recipients, *resolver)
        });
        drop(stored);
        if changes.is_empty() && attendees.is_none() {
            let change = self.loaded_for(message).and_then(|loaded| loaded.change);
            return Ok(Written::unchanged(base, current, change));
        }
        for _ in 0..MAX_SAVE_ATTEMPTS {
            let edit = EventEdit::open(&writer, calendar, base.id)
                .await
                .map_err(event_error)?;
            let (etag, change) = edit
                .event()
                .map(|event| {
                    (
                        u64::from(event.inner.etag.to_native()),
                        event.version.change_id(),
                    )
                })
                .caused_by(trc::location!())?;
            if checked.is_some_and(|origin| origin != etag) {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
            let mut ical = edit.to_ical()?;
            if item == CalendarItem::Task && has_unmapped_task_recurrence(&ical) {
                return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
            }
            item.patch(&mut ical, &changes, &opts)?;
            if let Some(uid) = &adopted_uid {
                set_event_uid(&mut ical, uid);
            }
            if let Some(resolver) = attendees {
                set_attendees_from_recipients(&mut ical, &content, organizer, resolver)
                    .map_err(convert_error)?;
            }
            if item == CalendarItem::Event {
                record_response(&mut ical, &changes, account_info.addresses());
                drop_unscheduled_event_draft(&mut ical);
            }
            if ical_size(server, &ical).is_none() {
                return Err(RopError::Code(ErrorCode::TOO_BIG));
            }
            match edit
                .commit_with(ical, ItipMode::Suppress, UidChange::AllowUnscheduled)
                .await
            {
                Ok(EventWrite::Written(written)) => {
                    return Ok(Written {
                        id: base,
                        origin: etag_origin(&written.etag),
                        change: written.change_id,
                    });
                }
                Ok(EventWrite::Unchanged) => return Ok(Written::unchanged(base, etag, change)),
                Err(EventWriteError::UidChanged(_)) => {
                    return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
                }
                Err(err) => match event_failure(err)? {
                    WriteFailure::Conflict => continue,
                    failure => return Err(RopError::Code(failure_code(failure))),
                },
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }
}

fn record_response(ical: &mut ICalendar, changes: &ContentBag, addresses: &[String]) {
    if let Some(status) = meeting_response_status(changes)
        && (status != ICalendarParticipationStatus::NeedsAction
            || !has_recorded_reply(ical, addresses))
    {
        let _ = set_participation(ical, addresses, None, status);
    }
}

fn body_change(
    props: &ContentBag,
    changed: impl Fn(PropKeyRef<'_>) -> bool,
) -> Result<Option<OwnedPropValue>, RopError> {
    let source = if changed(PropKeyRef::Tag(tags::BODY.id())) && has_text(props, tags::BODY.id()) {
        return Ok(None);
    } else if changed(PropKeyRef::Tag(tags::HTML.id())) {
        BodySource::Html
    } else if changed(PropKeyRef::Tag(tags::RTF_COMPRESSED.id())) {
        BodySource::Rtf
    } else {
        return Ok(None);
    };
    let text = source_text(props, source, MAX_DECODED).map_err(convert_error)?;
    Ok(Some(OwnedPropValue::Unicode(
        text.unwrap_or_default().into(),
    )))
}

fn group_notes(props: &ContentBag) -> ContentBag {
    let mut notes = ContentBag::new();
    for (key, value) in props.iter().filter(|(key, _)| {
        is_category(key.as_ref()) || key.as_ref() == PropKeyRef::Tag(tags::BODY.id())
    }) {
        notes.set(key.clone(), value.clone());
    }
    notes
}

fn has_text(props: &ContentBag, id: PropId) -> bool {
    match props.get_any(PropKeyRef::Tag(id)) {
        Some(OwnedPropValue::Unicode(text)) => !text.is_empty(),
        Some(OwnedPropValue::String8(text)) => !text.is_empty(),
        _ => false,
    }
}

fn is_class(props: &ContentBag, class: &[u8]) -> bool {
    match props.get_any(PropKeyRef::Tag(tags::MESSAGE_CLASS.id())) {
        Some(OwnedPropValue::Unicode(value)) => class_has_prefix(value.as_bytes(), class),
        Some(OwnedPropValue::String8(value)) => class_has_prefix(value, class),
        _ => false,
    }
}

fn has_class(props: &ContentBag, class: &[u8]) -> bool {
    props
        .get_any(PropKeyRef::Tag(tags::MESSAGE_CLASS.id()))
        .is_none()
        || is_class(props, class)
}

fn task_recurrence_supported(props: &ContentBag) -> bool {
    if matches!(
        props.get_any(TASK_DEAD_OCCURRENCE),
        Some(OwnedPropValue::Bool(true))
    ) {
        return true;
    }
    let blob = match props.get_any(TASK_RECURRENCE) {
        Some(OwnedPropValue::Binary(blob)) if !blob.is_empty() => Some(blob),
        _ => None,
    };
    match (props.get_any(TASK_F_RECURRING), blob) {
        (Some(OwnedPropValue::Bool(false)), _) => true,
        (_, Some(blob)) => TaskRecur::decode(blob, &BlobLimits::DEFAULT).is_ok(),
        (Some(OwnedPropValue::Bool(true)), None) => false,
        _ => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContactPhoto<'x> {
    Absent,
    Bytes(&'x [u8]),
    Unavailable,
}

impl<'x> ContactPhoto<'x> {
    fn of(content: &'x MessageContent) -> Self {
        content
            .attachments
            .iter()
            .find_map(|attachment| {
                let props = &attachment.props;
                if !matches!(
                    props.get_any(PropKeyRef::Tag(tags::ATTACHMENT_CONTACT_PHOTO.id())),
                    Some(OwnedPropValue::Bool(true))
                ) {
                    return None;
                }
                match (
                    &attachment.data,
                    props.get_any(PropKeyRef::Tag(tags::ATTACH_DATA_BINARY.id())),
                ) {
                    (AttachData::Bytes(bytes), _) => Some(ContactPhoto::Bytes(bytes.as_ref())),
                    (AttachData::None, Some(OwnedPropValue::Binary(bytes))) => {
                        Some(ContactPhoto::Bytes(bytes.as_ref()))
                    }
                    (AttachData::None, _) => None,
                    (AttachData::Deferred(_) | AttachData::Embedded(_), _) => {
                        Some(ContactPhoto::Unavailable)
                    }
                }
            })
            .unwrap_or(ContactPhoto::Absent)
    }

    fn bytes(self) -> Option<&'x [u8]> {
        match self {
            ContactPhoto::Bytes(bytes) => Some(bytes),
            ContactPhoto::Absent | ContactPhoto::Unavailable => None,
        }
    }
}

fn cleared(value: &OwnedPropValue) -> OwnedPropValue {
    match value {
        OwnedPropValue::Unicode(_) | OwnedPropValue::String8(_) => {
            OwnedPropValue::Unicode(Box::default())
        }
        OwnedPropValue::MvUnicode(_) | OwnedPropValue::MvString8(_) => {
            OwnedPropValue::MvUnicode(Box::default())
        }
        _ => OwnedPropValue::Null,
    }
}

pub(super) fn card_error(err: CardWriteError) -> RopError {
    match card_failure(err) {
        Ok(failure) => RopError::Code(failure_code(failure)),
        Err(err) => RopError::Internal(err),
    }
}

pub(super) fn event_error(err: EventWriteError) -> RopError {
    match event_failure(err) {
        Ok(failure) => RopError::Code(failure_code(failure)),
        Err(err) => RopError::Internal(err),
    }
}

fn failure_code(failure: WriteFailure) -> ErrorCode {
    match failure {
        WriteFailure::NotFound => ErrorCode::OBJECT_DELETED,
        WriteFailure::Forbidden => ErrorCode::ACCESS_DENIED,
        WriteFailure::Invalid => ErrorCode::INVALID_PARAM,
        WriteFailure::UidConflict => ErrorCode::DUPLICATE_NAME,
        WriteFailure::Quota => ErrorCode::QUOTA_EXCEEDED,
        WriteFailure::Conflict => ErrorCode::OBJECT_MODIFIED,
    }
}

fn etag_origin(etag: &str) -> Option<u64> {
    etag.strip_prefix('"')?.strip_suffix('"')?.parse().ok()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/groupware_save/tests.rs"]
mod tests;
