/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::groupware_save::event_error;
use crate::mapi::emsmdb::execute::RopError;
use calcard::icalendar::{ICalendar, ICalendarComponentType, ICalendarProperty};
use exchange_proto::mapi::ErrorCode;
use groupware::calendar::{
    CalendarEventContent,
    identity::CalendarAddresses,
    write::{EventDeletion, EventWriter},
};
use std::borrow::Cow;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

struct MeetingShape<'x> {
    organizer: Cow<'x, str>,
    has_master: bool,
    recurring: bool,
}

pub(super) async fn replaced_attendee_item(
    writer: &EventWriter<'_>,
    calendar: u32,
    document_id: u32,
    copy: &ICalendar,
) -> Result<EventDeletion, RopError> {
    let mut deletion = writer
        .prepare_delete(calendar, document_id)
        .await
        .map_err(event_error)?;
    let account =
        CalendarAddresses::from_emails(writer.account_info.addresses().iter().map(String::as_str));
    let replaces = match deletion.previous() {
        Some(stored) => MeetingShape::replaces(stored, copy, &account),
        None => {
            let content = writer
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
                .ok_or(RopError::Code(ErrorCode::DUPLICATE_NAME))?;
            let stored = rkyv_deserialize::<_, ICalendar>(
                &content
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?
                    .data
                    .event,
            )
            .caused_by(trc::location!())?;
            deletion.set_content(content);
            MeetingShape::replaces(&stored, copy, &account)
        }
    };
    if replaces {
        Ok(deletion)
    } else {
        Err(RopError::Code(ErrorCode::DUPLICATE_NAME))
    }
}

impl<'x> MeetingShape<'x> {
    fn replaces(stored: &ICalendar, copy: &ICalendar, account: &CalendarAddresses) -> bool {
        match (
            MeetingShape::of(stored, account),
            MeetingShape::of(copy, account),
        ) {
            (Some(stored), Some(copy)) => {
                stored.organizer == copy.organizer
                    && (copy.has_master || !stored.has_master)
                    && (copy.recurring || !stored.recurring)
            }
            _ => false,
        }
    }

    fn of(ical: &'x ICalendar, account: &CalendarAddresses) -> Option<Self> {
        let mut organizer: Option<Cow<'x, str>> = None;
        let mut invites_account = false;
        let mut has_master = false;
        let mut recurring = false;
        for component in ical
            .components
            .iter()
            .filter(|component| component.component_type == ICalendarComponentType::VEvent)
        {
            let is_override = component.is_recurrence_override();
            has_master |= !is_override;
            recurring |= is_override || component.is_recurrent();
            for entry in &component.entries {
                match entry.name {
                    ICalendarProperty::Organizer => {
                        let address = CalendarAddresses::normalize(entry.calendar_address()?);
                        if organizer.as_ref().is_some_and(|known| *known != address) {
                            return None;
                        }
                        organizer = Some(address);
                    }
                    ICalendarProperty::Attendee => {
                        invites_account |= entry
                            .calendar_address()
                            .is_some_and(|address| account.contains(address));
                    }
                    _ => {}
                }
            }
        }
        organizer
            .filter(|organizer| invites_account && !account.contains(organizer))
            .map(|organizer| MeetingShape {
                organizer,
                has_master,
                recurring,
            })
    }
}
