/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    calendar_of,
    instance::indexed_instance,
    sent::{CopyMaker, MeetingSend, SentCopies},
};
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        folder::{
            FolderSelector, folder_not_found, resolve_folder, saved_folder_status,
            write::{FolderOp, write_status},
        },
        groupware::{
            items::GroupwareRef,
            write::{CalendarWriter, Committed, Scheduling, failure_error},
        },
        item::ItemError,
    },
    folders::{FolderNode, FolderWrites, SpecialFolder},
    groupware_write::{
        MeetingError, MeetingReply, MeetingResponse, UnchangedReply, event_failure, new_event,
        new_uid, respond_to_meeting, store_failure,
    },
};
use calcard::icalendar::ICalendar;
use common::Server;
use exchange_proto::{
    common::UtcSeconds,
    convert::ical::{
        MeetingRole, ParticipationError, RecurrenceId, event_meeting_role, exclude_event_instance,
        force_reply, is_event_excluded, set_participation,
    },
    ews::{
        Status,
        calendar::{CalendarEdit, CalendarEditError, CalendarFieldSet},
        schema::{SendMeetingInvitations, SendMeetingInvitationsOrCancellations},
        types::{
            change::ItemChange,
            ids::{ItemId, TargetFolderId},
            item::{CalendarItem, Item, ItemFields},
        },
    },
};
use groupware::scheduling::itip::itip_assign_organizer;
use jiff::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EventScope {
    Master,
    Instance(i64),
    Indexed(usize),
}

impl CalendarWriter<'_, CalendarFieldSet> {
    pub async fn create(
        &mut self,
        calendar: u32,
        item: &CalendarItem<'_>,
        send: MeetingSend,
    ) -> trc::Result<Result<(ItemId<'static>, SentCopies), ItemError>> {
        let max_attendees = self.server.core.groupware.max_ical_attendees_per_instance;
        let now = Timestamp::now();
        let edit = match CalendarEdit::from_item(item, max_attendees).and_then(|mut edit| {
            edit.default_times(UtcSeconds(now.as_second()))
                .map(|()| edit)
        }) {
            Ok(edit) => edit,
            Err(err) => return Ok(Err(edit_error(err))),
        };
        let name = new_uid();
        let uid = item
            .calendar
            .uid
            .as_deref()
            .filter(|uid| !uid.is_empty())
            .unwrap_or(&name);
        let mut ical = new_event(uid, now);
        if let Err(err) = edit.apply(&mut ical, None, &self.items.options()) {
            return Ok(Err(edit_error(err)));
        }
        if let Some(organizer) = self
            .items
            .account_info(self.server)
            .await?
            .addresses()
            .first()
        {
            itip_assign_organizer(&mut ical, organizer);
        }
        let source = self.copy_maker(send).await?.map(|_| ical.clone());
        let (id, tag) = match self.create_ical(calendar, &name, ical, send.itip()).await? {
            Ok(created) => created,
            Err(err) => return Ok(Err(err)),
        };
        let copies = match (self.copy_maker(send).await?, source) {
            (Some(maker), Some(source)) => maker.created(source, tag),
            _ => SentCopies::default(),
        };
        Ok(Ok((id, copies)))
    }

    pub async fn update(
        &self,
        event: GroupwareRef,
        scope: EventScope,
        expected_change: Option<u64>,
        changes: &[ItemChange<'_>],
        send: MeetingSend,
    ) -> trc::Result<Result<(ItemId<'static>, SentCopies), ItemError>> {
        let mut edit =
            CalendarEdit::new(self.server.core.groupware.max_ical_attendees_per_instance);
        for change in changes {
            if let Err(err) = edit.change(change) {
                return Ok(Err(edit_error(err)));
            }
        }
        let options = self.items.options();
        let organizer = self
            .items
            .account_info(self.server)
            .await?
            .addresses()
            .first();
        let maker = self.copy_maker(send).await?;
        let mut resolved = None;
        let mut edited = None;
        let updated = self
            .update_ical(event, expected_change, send.itip(), |ical| {
                let instance = scope_instance(ical, scope)?;
                resolved = instance.map(|(instance, _)| instance);
                let previous = maker.as_ref().map(|_| ical.clone());
                edit.apply(ical, instance.map(|(_, id)| id), &options)
                    .map_err(edit_error)?;
                if let Some(organizer) = organizer {
                    itip_assign_organizer(ical, organizer);
                }
                edited = previous.map(|previous| (ical.clone(), previous));
                Ok(())
            })
            .await?;
        Ok(updated.map(|(change_id, committed)| {
            let id = match resolved {
                Some(instance) => self.items.occurrence_id(event, change_id, instance),
                None => self.items.item_id(event, change_id),
            };
            (id, written_copies(maker.as_ref(), edited, committed))
        }))
    }

    pub async fn respond(
        &self,
        event: GroupwareRef,
        scope: EventScope,
        reply: MeetingReply,
        send: MeetingSend,
    ) -> trc::Result<Result<SentCopies, ItemError>> {
        let maker = self.copy_maker(send).await?;
        let loaded = if maker.is_some() || matches!(scope, EventScope::Indexed(_)) {
            match self.items.load_scheduled(self.server, event).await? {
                Ok(loaded) => Some(loaded),
                Err(err) => return Ok(Err(err)),
            }
        } else {
            None
        };
        let instance = match (scope, &loaded) {
            (EventScope::Master, _) => None,
            (EventScope::Instance(instance), _) => Some(instance),
            (EventScope::Indexed(index), Some((ical, _))) => match indexed_instance(ical, index) {
                Ok(instance) => Some(instance),
                Err(err) => return Ok(Err(err)),
            },
            (EventScope::Indexed(_), None) => return Ok(Err(ItemError::NotFound)),
        };
        let instance = match instance.map(Timestamp::from_second).transpose() {
            Ok(instance) => instance.map(RecurrenceId),
            Err(_) => return Ok(Err(ItemError::NotFound)),
        };
        let copies = match (maker, loaded) {
            (Some(maker), Some((previous, before))) => {
                let mut ical = previous.clone();
                match set_participation(&mut ical, maker.owner(), instance, reply.status()) {
                    Ok(true) => maker.updated(ical, &previous, before, before.tag),
                    Ok(false) if force_reply(&mut ical, maker.owner(), instance) => {
                        maker.updated(ical, &previous, before, before.tag)
                    }
                    Ok(false) | Err(_) => SentCopies::default(),
                }
            }
            _ => SentCopies::default(),
        };
        let response = MeetingResponse {
            calendar_id: event.container,
            document_id: event.document_id,
            instance,
            reply,
            itip: send.itip(),
            unchanged: UnchangedReply::Apply,
        };
        let writer = self.event_writer().await?;
        Ok(match respond_to_meeting(&writer, response).await {
            Ok(Ok(_)) => Ok(copies),
            Ok(Err(err)) => Err(meeting_error(err, reply)?),
            Err(err) => Err(failure_error(store_failure(err)?)),
        })
    }

    pub async fn cancel(
        &self,
        event: GroupwareRef,
        scope: EventScope,
        send: MeetingSend,
    ) -> trc::Result<Result<SentCopies, ItemError>> {
        match self.meeting(event).await? {
            Ok((_, _, MeetingRole::Attendee)) => Ok(Err(ItemError::NotOrganizer)),
            Ok((ical, before, MeetingRole::Organizer | MeetingRole::None)) => {
                self.remove(event, scope, send, Some((&ical, before))).await
            }
            Err(err) => Ok(Err(err)),
        }
    }

    pub async fn delete_event(
        &self,
        event: GroupwareRef,
        scope: EventScope,
        send: MeetingSend,
    ) -> trc::Result<Result<SentCopies, ItemError>> {
        if send == MeetingSend::Suppress {
            return self.remove(event, scope, send, None).await;
        }
        match self.meeting(event).await? {
            Ok((ical, before, MeetingRole::Organizer)) => {
                self.remove(event, scope, send, Some((&ical, before))).await
            }
            Ok((_, _, MeetingRole::Attendee | MeetingRole::None)) => {
                self.remove(event, scope, MeetingSend::Suppress, None).await
            }
            Err(err) => Ok(Err(err)),
        }
    }

    async fn remove(
        &self,
        event: GroupwareRef,
        scope: EventScope,
        send: MeetingSend,
        current: Option<(&ICalendar, Scheduling)>,
    ) -> trc::Result<Result<SentCopies, ItemError>> {
        let maker = self.copy_maker(send).await?;
        if scope == EventScope::Master {
            let copies = maker
                .as_ref()
                .zip(current)
                .map(|(maker, (ical, before))| maker.deleted(ical, before))
                .unwrap_or_default();
            return Ok(self.delete(event, send.itip()).await?.map(|()| copies));
        }
        let mut edited = None;
        let removed = self
            .commit_ical(event, None, send.itip(), |ical| {
                let (_, id) = scope_instance(ical, scope)?.ok_or(ItemError::NotFound)?;
                let previous = maker.as_ref().map(|_| ical.clone());
                exclude_event_instance(ical, id).map_err(|_| ItemError::NotFound)?;
                edited = previous.map(|previous| (ical.clone(), previous));
                Ok(())
            })
            .await?;
        Ok(removed.map(|committed| written_copies(maker.as_ref(), edited, committed)))
    }

    async fn meeting(
        &self,
        event: GroupwareRef,
    ) -> trc::Result<Result<(ICalendar, Scheduling, MeetingRole), ItemError>> {
        let owner = self.items.account_info(self.server).await?.addresses();
        Ok(self
            .items
            .load_scheduled(self.server, event)
            .await?
            .map(|(ical, before)| {
                let role = event_meeting_role(&ical, owner);
                (ical, before, role)
            }))
    }

    async fn copy_maker(&self, send: MeetingSend) -> trc::Result<Option<CopyMaker<'_>>> {
        if !send.saves_copy() {
            return Ok(None);
        }
        let sends = self.event_writer().await?.sends_itip(send.itip());
        let owner = self.items.account_info(self.server).await?.addresses();
        Ok(sends.then(|| CopyMaker::new(self.server, owner, send.itip())))
    }
}

fn written_copies(
    maker: Option<&CopyMaker<'_>>,
    edited: Option<(ICalendar, ICalendar)>,
    committed: Committed,
) -> SentCopies {
    match (maker, edited) {
        (Some(maker), Some((ical, previous))) => {
            maker.updated(ical, &previous, committed.before, committed.after)
        }
        _ => SentCopies::default(),
    }
}

fn meeting_error(err: MeetingError, reply: MeetingReply) -> trc::Result<ItemError> {
    Ok(match err {
        MeetingError::Participation(ParticipationError::Organizer) => {
            ItemError::OrganizerResponse(reply)
        }
        MeetingError::Participation(ParticipationError::NotAttendee) => ItemError::Unsupported,
        MeetingError::Participation(ParticipationError::NotRecurring) => ItemError::NotFound,
        MeetingError::Participation(ParticipationError::NoInstance) => ItemError::OccurrenceDeleted,
        MeetingError::Participation(ParticipationError::Unsupported) | MeetingError::TooLarge => {
            ItemError::ItemSave
        }
        MeetingError::Write(err) => failure_error(event_failure(err)?),
    })
}

pub(crate) fn scope_instance(
    ical: &ICalendar,
    scope: EventScope,
) -> Result<Option<(i64, RecurrenceId)>, ItemError> {
    let instance = match scope {
        EventScope::Master => return Ok(None),
        EventScope::Instance(instance) => instance,
        EventScope::Indexed(index) => indexed_instance(ical, index)?,
    };
    let id = Timestamp::from_second(instance)
        .map(RecurrenceId)
        .map_err(|_| ItemError::NotFound)?;
    if is_event_excluded(ical, id) {
        return Err(ItemError::OccurrenceDeleted);
    }
    Ok(Some((instance, id)))
}

pub(crate) async fn calendar_destination(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    id: Option<&TargetFolderId<'_>>,
) -> trc::Result<Result<u32, Status<'static>>> {
    let tree = ctx.folder_tree(server).await?;
    let entry = match id {
        Some(id) => match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => return Ok(Err(saved_folder_status(ctx, status))),
        },
        None => match tree.special(SpecialFolder::Calendar) {
            Some(entry) => entry,
            None => return Ok(Err(folder_not_found())),
        },
    };
    if entry.node != FolderNode::Special(SpecialFolder::Calendar) {
        return Ok(calendar_of(entry).ok_or_else(|| ItemError::CalendarFolder.status()));
    }
    Ok(
        match server
            .folder_event_calendar(caller.access_token, ctx.account.account_id)
            .await?
        {
            Ok(folder) => {
                ctx.folders_changed();
                Ok(folder.id)
            }
            Err(err) => Err(write_status(err, FolderOp::Place)),
        },
    )
}

pub(crate) fn create_send(mode: Option<SendMeetingInvitations>) -> Result<MeetingSend, ItemError> {
    invitation_send(mode).ok_or(ItemError::InvitationsRequired)
}

pub(crate) fn update_send(
    mode: Option<SendMeetingInvitationsOrCancellations>,
) -> Result<MeetingSend, ItemError> {
    match mode {
        Some(SendMeetingInvitationsOrCancellations::SendToNone) => Ok(MeetingSend::Suppress),
        Some(SendMeetingInvitationsOrCancellations::SendOnlyToAll) => Ok(MeetingSend::Send),
        Some(SendMeetingInvitationsOrCancellations::SendOnlyToChanged) => {
            Ok(MeetingSend::SendToChanged)
        }
        Some(SendMeetingInvitationsOrCancellations::SendToAllAndSaveCopy) => {
            Ok(MeetingSend::SendAndSave)
        }
        Some(SendMeetingInvitationsOrCancellations::SendToChangedAndSaveCopy) => {
            Ok(MeetingSend::SendToChangedAndSave)
        }
        None => Err(ItemError::InvitationsOrCancellationsRequired),
    }
}

pub(crate) fn delete_send(mode: Option<SendMeetingInvitations>) -> Result<MeetingSend, ItemError> {
    invitation_send(mode).ok_or(ItemError::CancellationsRequired)
}

fn invitation_send(mode: Option<SendMeetingInvitations>) -> Option<MeetingSend> {
    mode.map(|mode| match mode {
        SendMeetingInvitations::SendToNone => MeetingSend::Suppress,
        SendMeetingInvitations::SendOnlyToAll => MeetingSend::Send,
        SendMeetingInvitations::SendToAllAndSaveCopy => MeetingSend::SendAndSave,
    })
}

pub(crate) fn event_id_only(id: ItemId<'static>) -> Item<'static> {
    Item::CalendarItem(Box::new(CalendarItem {
        item: ItemFields {
            item_id: Some(id),
            ..Default::default()
        },
        ..Default::default()
    }))
}

fn edit_error(err: CalendarEditError) -> ItemError {
    match err {
        CalendarEditError::NotACalendarItem | CalendarEditError::InvalidPropertySet => {
            ItemError::InvalidPropertySet
        }
        CalendarEditError::InvalidPropertyAppend => ItemError::InvalidPropertyAppend,
        CalendarEditError::InvalidRecurrence => ItemError::InvalidRecurrence,
        CalendarEditError::UnsupportedRecurrence => ItemError::UnsupportedRecurrence,
        CalendarEditError::NoOccurrence => ItemError::NoOccurrence,
        CalendarEditError::TooManyAttendees => ItemError::TooManyAttendees,
        CalendarEditError::DurationTooLong => ItemError::DurationTooLong,
        CalendarEditError::EndBeforeStart => ItemError::EndBeforeStart,
        CalendarEditError::Conversion => ItemError::ItemSave,
    }
}
