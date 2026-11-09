/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    ItipError, ItipMessage,
    attendee::attendee_handle_update,
    event_update::itip_update,
    itip::itip_finalize,
    organizer::organizer_request_full,
    recipient::{RecipientPolicy, itip_messages_per_recipient},
    snapshot::itip_snapshot,
};
use calcard::icalendar::ICalendar;

pub fn itip_create(
    ical: &mut ICalendar,
    account_emails: &[String],
    policy: RecipientPolicy,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    let itip = itip_snapshot(ical, account_emails, false)?;
    if !itip.organizer.is_server_scheduling {
        Err(ItipError::OtherSchedulingAgent)
    } else if !itip.organizer.email.is_local {
        Err(ItipError::NotOrganizer)
    } else {
        organizer_request_full(ical, &itip, None, true)
            .and_then(|messages| itip_messages_per_recipient(messages, policy))
            .inspect(|_| {
                itip_finalize(ical, &[]);
            })
    }
}

pub fn itip_attendee_create(
    ical: &mut ICalendar,
    account_emails: &[String],
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    let new_itip = itip_snapshot(ical, account_emails, false)?;
    if !new_itip.organizer.is_server_scheduling {
        Err(ItipError::OtherSchedulingAgent)
    } else if new_itip.organizer.email.is_local {
        Err(ItipError::NothingToSend)
    } else {
        let old_itip = new_itip.unanswered();
        attendee_handle_update(ical, old_itip, new_itip).inspect(|_| {
            itip_finalize(ical, &[]);
        })
    }
}

pub fn itip_unscheduled_update(
    ical: &mut ICalendar,
    old_ical: &ICalendar,
    account_emails: &[String],
    policy: RecipientPolicy,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    match itip_create(ical, account_emails, policy) {
        Err(ItipError::NotOrganizer) => match itip_update(ical, old_ical, account_emails, policy) {
            Err(ItipError::NoSchedulingInfo | ItipError::NotOrganizerNorAttendee) => {
                itip_attendee_create(ical, account_emails)
            }
            result => result,
        },
        result => result,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/groupware/src/scheduling/event_create/tests.rs"]
mod tests;
