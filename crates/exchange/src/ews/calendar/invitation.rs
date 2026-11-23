/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Events, utc, write::EventScope};
use crate::ews::{
    context::EwsContext,
    groupware::{items::GroupwareRef, write::CalendarWriter},
    item::{
        EmailIds, ItemError, MailItem,
        fields::ItemFieldSet,
        render::{LoadedMail, MailShape},
    },
};
use calcard::icalendar::ICalendar;
use common::{MessageStoreCache, Server};
use compact_str::ToCompactString;
use email::message::metadata::{AddressHeader, ArchivedMessageMetadata, Occurrence, PartView};
use exchange_proto::{
    common::UtcSeconds,
    convert::ical::{
        EventOccurrences, Invitation, MeetingRole, OccurrenceBounds, RecurrenceId,
        event_invitation, event_invitation_span, event_meeting_role, event_occurrences,
        event_response_requested, meeting_progress,
    },
    ews::{
        calendar::{CalendarFieldSet, invitation_recurrence, legacy_free_busy, response_type},
        schema::{LegacyFreeBusy, MeetingRequestType, ResponseType},
        types::{
            ids::{BaseItemId, ItemId},
            item::{
                Item,
                calendar::{DeletedOccurrence, OccurrenceInfo},
            },
            recurrence::Recurrence,
            value::{DateTime, List},
        },
    },
};
use groupware::{
    calendar::itip::{ItipAutoAdd, ItipIngest, ItipIngestError, ItipOrigin},
    scheduling::ItipError,
};
use registry::schema::enums::Permission;
use std::{borrow::Cow, iter};
use trc::AddContext;
use utils::sanitize_email;

pub(crate) async fn mail_invitation<'c>(
    server: &Server,
    ctx: &EwsContext,
    ids: &EmailIds,
    cache: &'c MessageStoreCache,
    reference: &ItemId<'_>,
) -> trc::Result<Result<MailInvitation<'c>, ItemError>> {
    let item = match ids.resolve(ctx, cache, &BaseItemId::Item(reference.clone())) {
        Ok(item) => item,
        Err(err) => return Ok(Err(err)),
    };
    let Some(mail) = LoadedMail::load(
        server,
        ids.account_id(),
        cache,
        item,
        &MailShape::metadata_only(),
    )
    .await?
    else {
        return Ok(Err(ItemError::NotFound));
    };
    let ical = request_ical(server, &mail, &mail.headers()?).await?;
    Ok(ical.map(|ical| MailInvitation { ical, mail }))
}

pub(crate) struct MailInvitation<'c> {
    pub ical: ICalendar,
    mail: LoadedMail<'c>,
}

impl MailInvitation<'_> {
    pub(crate) fn item(&self) -> MailItem {
        self.mail.item
    }

    fn sender(&self) -> trc::Result<Option<String>> {
        Ok(self.mail.meta()?.and_then(|meta| {
            meta.root()
                .envelope()
                .addresses(AddressHeader::From, Occurrence::Last)
                .mailboxes()
                .find_map(|mailbox| mailbox.address.and_then(sanitize_email))
        }))
    }
}

pub(crate) async fn request_ical(
    server: &Server,
    mail: &LoadedMail<'_>,
    headers: &[u8],
) -> trc::Result<Result<ICalendar, ItemError>> {
    let Some(meta) = mail.meta()? else {
        return Ok(Err(ItemError::NotAMessage));
    };
    match invitation_part(meta, server.core.groupware.itip_inbound_max_ical_size) {
        Ok(part) => part_ical(server, mail, headers, meta, part).await,
        Err(err) => Ok(Err(err)),
    }
}

async fn meeting_ical(
    server: &Server,
    mail: &LoadedMail<'_>,
    headers: &[u8],
) -> trc::Result<Result<(MeetingMethod, ICalendar), ItemError>> {
    let Some(meta) = mail.meta()? else {
        return Ok(Err(ItemError::NotAMessage));
    };
    match meeting_part(meta)
        .filter(|(_, part)| within_limit(part, server.core.groupware.itip_inbound_max_ical_size))
    {
        Some((method, part)) => Ok(part_ical(server, mail, headers, meta, part)
            .await?
            .map(|ical| (method, ical))),
        None => Ok(Err(ItemError::NotAMessage)),
    }
}

pub(crate) async fn meeting_location(
    server: &Server,
    mail: &LoadedMail<'_>,
    headers: &[u8],
) -> trc::Result<Option<String>> {
    Ok(meeting_ical(server, mail, headers)
        .await?
        .ok()
        .and_then(|(_, ical)| event_invitation_span(&ical)?.location.map(str::to_owned)))
}

async fn part_ical(
    server: &Server,
    mail: &LoadedMail<'_>,
    headers: &[u8],
    meta: &ArchivedMessageMetadata,
    part: PartView<'_>,
) -> trc::Result<Result<ICalendar, ItemError>> {
    let fetched;
    let blob = match mail.blob() {
        Some(blob) => blob,
        None => {
            let Some(blob) = server
                .fetch_blob(&meta.blob_hash(), 0..usize::MAX, Some(meta.size() as u64))
                .await
                .caused_by(trc::location!())?
            else {
                return Ok(Err(ItemError::NotAMessage));
            };
            fetched = blob;
            &*fetched
        }
    };
    let raw = meta.raw_message(Some(headers), blob);
    let Some(text) = meta
        .source(part.message(), raw)
        .and_then(|source| part.text(&source))
    else {
        return Ok(Err(ItemError::NotAMessage));
    };
    Ok(ICalendar::parse(text.text.as_ref()).map_err(|_| ItemError::NotAMessage))
}

#[derive(Default)]
pub(crate) struct MeetingValues {
    start: Option<DateTime>,
    end: Option<DateTime>,
    all_day: Option<bool>,
    location: Option<Cow<'static, str>>,
    free_busy: Option<LegacyFreeBusy>,
    uid: Option<Cow<'static, str>>,
    recurrence_id: Option<DateTime>,
    original_start: Option<DateTime>,
    associated: Option<ItemId<'static>>,
    response_requested: Option<bool>,
    request_type: Option<MeetingRequestType>,
    processed: Option<bool>,
    response: Option<ResponseType>,
    out_of_date: Option<bool>,
    recurrence: Option<Box<Recurrence>>,
    modified: Option<List<OccurrenceInfo<'static>>>,
    deleted: Option<List<DeletedOccurrence>>,
}

impl MeetingValues {
    pub(crate) async fn load(
        server: &Server,
        events: Option<&Events>,
        mail: &LoadedMail<'_>,
        headers: &[u8],
        fields: ItemFieldSet,
    ) -> trc::Result<Self> {
        let mut values = MeetingValues::default();
        let events = events.filter(|_| fields.has(ItemFieldSet::MEETING_LOOKUP));
        if events.is_none()
            && !fields.has(
                ItemFieldSet::MEETING_SPAN
                    | ItemFieldSet::MEETING_INVITATION
                    | ItemFieldSet::MEETING_SERIES,
            )
        {
            return Ok(values);
        }
        let Ok((method, ical)) = meeting_ical(server, mail, headers).await? else {
            return Ok(values);
        };
        if fields.has(ItemFieldSet::MEETING_SPAN)
            && let Some(span) = event_invitation_span(&ical)
        {
            if fields.has(ItemFieldSet::MEETING_START) {
                values.start = Some(DateTime::utc(UtcSeconds(span.start.as_second())));
            }
            if fields.has(ItemFieldSet::MEETING_END) {
                values.end = Some(DateTime::utc(UtcSeconds(span.end.as_second())));
            }
            if fields.has(ItemFieldSet::MEETING_ALL_DAY) {
                values.all_day = Some(span.all_day);
            }
            if fields.has(ItemFieldSet::MEETING_LOCATION) {
                values.location = span
                    .location
                    .map(|location| Cow::Owned(location.to_owned()));
            }
            if fields.has(ItemFieldSet::MEETING_FREE_BUSY) {
                values.free_busy = Some(legacy_free_busy(Some(span.intended_status)));
            }
        }
        if fields.has(ItemFieldSet::MEETING_RECURRENCE) {
            values.recurrence = invitation_recurrence(&ical).map(Box::new);
        }
        let occurrences = fields
            .has(ItemFieldSet::MEETING_MODIFIED | ItemFieldSet::MEETING_DELETED)
            .then(|| event_occurrences(&ical, OccurrenceBounds::First))
            .flatten();
        if fields.has(ItemFieldSet::MEETING_DELETED)
            && let Some(occurrences) = &occurrences
            && !occurrences.deleted.is_empty()
        {
            values.deleted = Some(List(
                occurrences
                    .deleted
                    .iter()
                    .map(|instance| DeletedOccurrence {
                        start: Some(utc(instance.0.as_second())),
                    })
                    .collect(),
            ));
        }
        if events.is_none() && !fields.has(ItemFieldSet::MEETING_INVITATION) {
            return Ok(values);
        }
        let Some(invitation) = event_invitation(&ical) else {
            return Ok(values);
        };
        if fields.has(ItemFieldSet::MEETING_UID) {
            values.uid = Some(Cow::Owned(invitation.uid.to_owned()));
        }
        if let Some(instance) = invitation.instance {
            let instance = DateTime::utc(UtcSeconds(instance.0.as_second()));
            if fields.has(ItemFieldSet::MEETING_RECURRENCE_ID) {
                values.recurrence_id = Some(instance);
            }
            if fields.has(ItemFieldSet::MEETING_ORIGINAL_START) {
                values.original_start = Some(instance);
            }
        }
        if fields.has(ItemFieldSet::MEETING_RESPONSE_REQUESTED) {
            values.response_requested = Some(event_response_requested(&ical));
        }
        if fields.has(ItemFieldSet::MEETING_REQUEST_TYPE) {
            values.request_type = Some(if invitation.sequence > 0 {
                MeetingRequestType::FullUpdate
            } else {
                MeetingRequestType::NewMeetingRequest
            });
        }
        let role = match method {
            MeetingMethod::Reply => MeetingRole::Organizer,
            MeetingMethod::Request | MeetingMethod::Cancel => MeetingRole::Attendee,
        };
        let Some(events) = events else {
            return Ok(values);
        };
        let Ok((event, scope)) = events.invited_event(server, invitation, role).await? else {
            let answered = matches!(method, MeetingMethod::Request) && mail.is_answered();
            if fields.has(ItemFieldSet::MEETING_PROCESSED) {
                values.processed = Some(answered);
            }
            if answered && fields.has(ItemFieldSet::MEETING_RESPONSE) {
                values.response = Some(ResponseType::Decline);
            }
            return Ok(values);
        };
        if fields.has(ItemFieldSet::MEETING_EVENT) {
            values.associated = Some(match scope {
                EventScope::Instance(instance) => events.unversioned_occurrence_id(event, instance),
                EventScope::Master | EventScope::Indexed(_) => events.unversioned_id(event),
            });
        }
        if fields.has(ItemFieldSet::MEETING_PROCESSED) {
            values.processed = Some(true);
        }
        if fields.has(ItemFieldSet::MEETING_MODIFIED)
            && let Some(EventOccurrences { modified, .. }) = &occurrences
            && !modified.is_empty()
        {
            values.modified = Some(List(
                modified
                    .iter()
                    .map(|occurrence| {
                        let instance = occurrence.instance.0.as_second();
                        OccurrenceInfo {
                            item_id: Some(events.unversioned_occurrence_id(event, instance)),
                            start: Some(utc(occurrence.start.as_second())),
                            end: Some(utc(occurrence.end.as_second())),
                            original_start: Some(utc(instance)),
                        }
                    })
                    .collect(),
            ));
        }
        if fields.has(ItemFieldSet::MEETING_EVENT_STATE)
            && let Ok((event_ical, _)) = events.load_ical(server, event).await?
            && let Some(progress) = meeting_progress(
                &event_ical,
                events.account_info(server).await?.addresses(),
                invitation.instance,
            )
        {
            if fields.has(ItemFieldSet::MEETING_RESPONSE) {
                values.response = Some(response_type(progress.response_status));
            }
            if fields.has(ItemFieldSet::MEETING_OUT_OF_DATE) {
                values.out_of_date = Some(progress.sequence > invitation.sequence);
            }
        }
        Ok(values)
    }

    pub(crate) fn apply(self, item: &mut Item<'_>, delegated: Option<bool>) {
        let meeting = match item {
            Item::MeetingRequest(request) => {
                let times = &mut request.request;
                times.start = self.start;
                times.end = self.end;
                times.is_all_day_event = self.all_day;
                times.location = self.location;
                times.intended_free_busy_status = self.free_busy;
                times.original_start = self.original_start;
                times.meeting_request_type = self.request_type;
                times.recurrence = self.recurrence;
                times.modified_occurrences = self.modified;
                times.deleted_occurrences = self.deleted;
                if request.message.is_response_requested.is_none() {
                    request.message.is_response_requested = self.response_requested;
                }
                &mut request.meeting
            }
            Item::MeetingResponse(response) => {
                let times = &mut response.response;
                times.start = self.start;
                times.end = self.end;
                times.location = self.location;
                &mut response.meeting
            }
            Item::MeetingCancellation(cancellation) => {
                let times = &mut cancellation.cancellation;
                times.start = self.start;
                times.end = self.end;
                times.location = self.location;
                &mut cancellation.meeting
            }
            _ => return,
        };
        meeting.uid = self.uid;
        meeting.recurrence_id = self.recurrence_id;
        meeting.associated_calendar_item_id = self.associated;
        meeting.has_been_processed = self.processed;
        meeting.response_type = self.response;
        meeting.is_out_of_date = self.out_of_date;
        meeting.is_delegated = delegated;
    }
}

pub(crate) fn invitation_part(
    meta: &ArchivedMessageMetadata,
    max_size: usize,
) -> Result<PartView<'_>, ItemError> {
    request_part(meta)
        .filter(|part| within_limit(part, max_size))
        .ok_or(ItemError::NotAMessage)
}

pub(crate) fn within_limit(part: &PartView<'_>, max_size: usize) -> bool {
    usize::try_from(part.decoded_size()).is_ok_and(|size| size < max_size)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeetingMethod {
    Request,
    Reply,
    Cancel,
}

impl MeetingMethod {
    fn parse(method: &str) -> Option<Self> {
        hashify::map_ignore_case!(method.trim().as_bytes(), MeetingMethod,
            "REQUEST" => MeetingMethod::Request,
            "REPLY" => MeetingMethod::Reply,
            "CANCEL" => MeetingMethod::Cancel,
        )
        .copied()
    }
}

pub(crate) fn meeting_part(
    meta: &ArchivedMessageMetadata,
) -> Option<(MeetingMethod, PartView<'_>)> {
    meta.root().parts().find_map(|part| {
        let content = part.content_type()?;
        if !content.ctype().eq_ignore_ascii_case("text")
            || !content
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("calendar"))
        {
            return None;
        }
        MeetingMethod::parse(content.attribute("method")?).map(|method| (method, part))
    })
}

pub(crate) fn request_part(meta: &ArchivedMessageMetadata) -> Option<PartView<'_>> {
    meeting_part(meta)
        .filter(|(method, _)| *method == MeetingMethod::Request)
        .map(|(_, part)| part)
}

impl Events {
    pub(crate) async fn invited_event(
        &self,
        server: &Server,
        invitation: Invitation<'_>,
        role: MeetingRole,
    ) -> trc::Result<Result<(GroupwareRef, EventScope), ItemError>> {
        let mut candidates = self
            .resources
            .uid_matches(invitation.uid)
            .into_iter()
            .filter_map(|document_id| {
                let container = self
                    .resources
                    .item_by_id(document_id)?
                    .child_names()
                    .first()?
                    .parent_id;
                Some(GroupwareRef {
                    container,
                    document_id,
                })
            })
            .filter(|item| self.check(self.account_id, *item).is_ok());
        let Some(first) = candidates.next() else {
            return Ok(Err(ItemError::NotFound));
        };
        let mut event = first;
        let mut rest = candidates.peekable();
        if rest.peek().is_some() {
            let owner = self.account_info(server).await?.addresses();
            for candidate in iter::once(first).chain(rest) {
                if let Ok((ical, _)) = self.load_ical(server, candidate).await?
                    && event_meeting_role(&ical, owner) == role
                {
                    event = candidate;
                    break;
                }
            }
        }
        let scope = match invitation.instance {
            Some(RecurrenceId(at)) => EventScope::Instance(at.as_second()),
            None => EventScope::Master,
        };
        Ok(Ok((event, scope)))
    }
}

pub(crate) struct InvitedEvent {
    pub event: GroupwareRef,
    pub scope: EventScope,
    pub imported: Option<Events>,
}

impl CalendarWriter<'_, CalendarFieldSet> {
    pub(crate) async fn invited(
        &self,
        ctx: &EwsContext,
        mail: &MailInvitation<'_>,
    ) -> trc::Result<Result<InvitedEvent, ItemError>> {
        let ical = &mail.ical;
        let Some(invitation) = event_invitation(ical) else {
            return Ok(Err(ItemError::NotAMessage));
        };
        match self
            .items
            .invited_event(self.server, invitation, MeetingRole::Attendee)
            .await?
        {
            Ok((event, scope)) => {
                return Ok(Ok(InvitedEvent {
                    event,
                    scope,
                    imported: None,
                }));
            }
            Err(ItemError::NotFound) => (),
            Err(err) => return Ok(Err(err)),
        }
        if let Err(err) = self.import_invitation(mail).await? {
            return Ok(Err(err));
        }
        let events = match Events::load(self.server, ctx).await? {
            Ok(events) => events,
            Err(err) => return Ok(Err(err)),
        };
        Ok(events
            .invited_event(self.server, invitation, MeetingRole::Attendee)
            .await?
            .map(|(event, scope)| InvitedEvent {
                event,
                scope,
                imported: Some(events),
            }))
    }

    async fn import_invitation(
        &self,
        mail: &MailInvitation<'_>,
    ) -> trc::Result<Result<(), ItemError>> {
        let access_token = self.caller.access_token;
        if !(self.server.core.groupware.itip_enabled
            && access_token.is_member(self.items.account_id)
            && access_token.has_permission(Permission::CalendarSchedulingReceive))
        {
            return Ok(Err(ItemError::NotFound));
        }
        let Some(sender) = mail.sender()? else {
            return Ok(Err(ItemError::NotFound));
        };
        let ical = &mail.ical;
        let account_info = self.items.account_info(self.server).await?;
        let owner = account_info.addresses();
        if event_meeting_role(ical, owner) != MeetingRole::Attendee {
            return Ok(Err(ItemError::Unsupported));
        }
        let Some(recipient) = owner.first() else {
            return Ok(Err(ItemError::NotFound));
        };
        match self
            .server
            .itip_ingest_with(
                account_info,
                &sender,
                ItipOrigin::Delivery,
                recipient,
                &ical.to_string(),
                ItipAutoAdd::Consented,
            )
            .await
        {
            Ok(_) => Ok(Ok(())),
            Err(ItipIngestError::Message(ItipError::QuotaExceeded)) => Ok(Err(ItemError::Quota)),
            Err(ItipIngestError::Message(err)) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = self.items.account_id,
                    Details = err.to_compact_string(),
                );
                Ok(Err(ItemError::NotFound))
            }
            Err(ItipIngestError::Internal(err)) => Err(err.caused_by(trc::location!())),
        }
    }
}
