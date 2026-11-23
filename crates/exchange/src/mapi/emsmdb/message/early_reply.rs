/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::calendar::invitation::{MeetingMethod, meeting_part, within_limit};
use ::email::{
    cache::MessageCacheFetch,
    mailbox::INBOX_ID,
    message::metadata::{AddressHeader, MetadataRow, Occurrence},
};
use calcard::icalendar::{ICalendar, ICalendarComponentType, ICalendarMethod, ICalendarProperty};
use common::{
    Server,
    auth::{AccessToken, AccountInfo},
};
use compact_str::{CompactString, ToCompactString};
use exchange_proto::{
    convert::model::PropBag as ContentBag,
    mapi::prop::{OwnedPropValue, PropKeyRef, PropType, tags},
};
use groupware::{
    calendar::itip::{ItipAutoAdd, ItipIngest, ItipIngestError, ItipOrigin},
    scheduling::{ItipError, inbound::itip_method},
};
use registry::schema::enums::Permission;
use std::{cmp::Reverse, collections::BinaryHeap};
use store::{ValueKey, write::now};
use trc::AddContext;
use types::{collection::Collection, field::EmailField};
use utils::sanitize_email;

const REPLY_WINDOW_SECS: u64 = 300;
const CLOCK_SKEW_SECS: u64 = 60;
const MAX_REPLY_CANDIDATES: usize = 32;
const MAX_REPLY_MESSAGE_SIZE: u32 = 512 * 1024;

#[derive(Debug)]
pub(super) struct NewMeeting {
    since: u64,
    until: u64,
    organizer: String,
}

struct Scan<'x> {
    server: &'x Server,
    account_info: &'x AccountInfo,
    organizer: &'x str,
    uid: &'x str,
}

impl NewMeeting {
    pub(super) fn of(ical: &ICalendar, props: &ContentBag, owner: &[String]) -> Option<Self> {
        let mut events = ical
            .components
            .iter()
            .filter(|component| component.component_type == ICalendarComponentType::VEvent);
        if !events
            .clone()
            .any(|component| component.has_property(&ICalendarProperty::Attendee))
        {
            return None;
        }
        let organizer = events.find_map(|component| {
            component
                .property(&ICalendarProperty::Organizer)
                .and_then(|entry| entry.calendar_address())
                .filter(|email| owner.iter().any(|known| known.eq_ignore_ascii_case(email)))
        })?;
        let until = now();
        let window = until.saturating_sub(REPLY_WINDOW_SECS);
        let created = match props.get(PropKeyRef::Tag(tags::CREATION_TIME.id()), PropType::Time) {
            Some(OwnedPropValue::Time(time)) => u64::try_from(time.to_utc().0.0)
                .map_or(window, |created| {
                    created.min(until).saturating_sub(CLOCK_SKEW_SECS)
                }),
            _ => window,
        };
        Some(NewMeeting {
            since: created.max(window),
            until,
            organizer: organizer.to_owned(),
        })
    }

    pub(super) async fn apply_early_replies(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_info: &AccountInfo,
        uid: &str,
    ) {
        let account_id = account_info.account_id();
        if !(server.core.groupware.itip_enabled
            && access_token.is_member(account_id)
            && access_token.has_permission(Permission::CalendarSchedulingReceive))
        {
            return;
        }
        let candidates = match self.candidates(server, account_id).await {
            Ok(candidates) => candidates,
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                return;
            }
        };
        let scan = Scan {
            server,
            account_info,
            organizer: &self.organizer,
            uid,
        };
        for Reverse((_, document_id)) in candidates.into_sorted_vec().into_iter().rev() {
            if let Err(err) = scan.apply(document_id).await {
                trc::error!(err.caused_by(trc::location!()));
            }
        }
    }

    async fn candidates(
        &self,
        server: &Server,
        account_id: u32,
    ) -> trc::Result<BinaryHeap<Reverse<(u64, u32)>>> {
        let cache = server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let mut candidates = BinaryHeap::with_capacity(MAX_REPLY_CANDIDATES + 1);
        for message in cache.emails.iter().filter(|message| {
            (self.since..=self.until).contains(&message.received_at())
                && message.size() <= MAX_REPLY_MESSAGE_SIZE
                && message.has_mailbox_id(INBOX_ID)
        }) {
            candidates.push(Reverse(message.sort_rank()));
            if candidates.len() > MAX_REPLY_CANDIDATES {
                candidates.pop();
            }
        }
        Ok(candidates)
    }
}

impl Scan<'_> {
    async fn apply(&self, document_id: u32) -> trc::Result<()> {
        let account_id = self.account_info.account_id();
        let Some(row) = self
            .server
            .store()
            .get_value::<MetadataRow>(ValueKey::immutable(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let meta = row.unarchive().caused_by(trc::location!())?;
        let Some((MeetingMethod::Reply, part)) = meeting_part(meta) else {
            return Ok(());
        };
        let Some(blob_end) =
            within_limit(&part, self.server.core.groupware.itip_inbound_max_ical_size)
                .then(|| meta.blob_range(part.body_range()))
                .flatten()
                .map(|range| range.end)
        else {
            return Ok(());
        };
        let Some(sender) = meta
            .root()
            .envelope()
            .addresses(AddressHeader::From, Occurrence::Last)
            .mailboxes()
            .find_map(|mailbox| mailbox.address.and_then(sanitize_email))
        else {
            return Ok(());
        };
        if self
            .server
            .account_id_from_email(&sender, true)
            .await
            .caused_by(trc::location!())?
            .is_none()
        {
            return Ok(());
        }
        let Some(blob) = self
            .server
            .fetch_blob(&meta.blob_hash(), 0..blob_end, Some(meta.size() as u64))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let headers = row.raw_headers().caused_by(trc::location!())?;
        let Some(text) = meta
            .source(part.message(), meta.raw_message(Some(&headers), &blob))
            .and_then(|source| part.text(&source))
        else {
            return Ok(());
        };
        let text = text.text;
        let Ok(ical) = ICalendar::parse(&text) else {
            return Ok(());
        };
        if !matches!(itip_method(&ical), Ok(ICalendarMethod::Reply))
            || ical
                .components
                .iter()
                .find(|component| component.component_type == ICalendarComponentType::VEvent)
                .and_then(|component| component.uid())
                != Some(self.uid)
        {
            return Ok(());
        }
        match Box::pin(self.server.itip_ingest_with(
            self.account_info,
            &sender,
            ItipOrigin::Delivery,
            self.organizer,
            &text,
            ItipAutoAdd::Consented,
        ))
        .await
        {
            Ok(_) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageReceived),
                    From = CompactString::from(sender),
                    AccountId = account_id,
                );
            }
            Err(ItipIngestError::Message(
                ItipError::NothingToSend | ItipError::OtherSchedulingAgent,
            )) => (),
            Err(ItipIngestError::Message(err)) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    From = CompactString::from(sender),
                    AccountId = account_id,
                    Details = err.to_compact_string(),
                );
            }
            Err(ItipIngestError::Internal(err)) => {
                trc::error!(err.caused_by(trc::location!()));
            }
        }
        Ok(())
    }
}
