/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    ItipError, ItipMessage,
    attendee::attendee_handle_update,
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

#[cfg(test)]
mod tests {
    use super::*;

    const ATTENDEE: &str = "jane@example.com";

    fn event(part_stat: &str) -> ICalendar {
        ICalendar::parse(format!(
            concat!(
                "BEGIN:VCALENDAR\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:attendee-create\r\n",
                "DTSTART:20260601T090000Z\r\n",
                "ORGANIZER:mailto:org@example.net\r\n",
                "ATTENDEE{}:mailto:jane@example.com\r\n",
                "END:VEVENT\r\n",
                "END:VCALENDAR\r\n"
            ),
            part_stat
        ))
        .expect("valid iCalendar")
    }

    #[test]
    fn attendee_creates_without_a_participation_status_send_no_reply() {
        for part_stat in ["", ";PARTSTAT=NEEDS-ACTION"] {
            let mut ical = event(part_stat);
            assert!(
                itip_attendee_create(&mut ical, &[ATTENDEE.to_string()]).is_err(),
                "expected no reply for {part_stat:?}"
            );
        }
    }

    #[test]
    fn attendee_creates_with_a_participation_status_reply() {
        let mut ical = event(";PARTSTAT=ACCEPTED");
        let messages = itip_attendee_create(&mut ical, &[ATTENDEE.to_string()]).expect("reply");
        let [message] = messages.as_slice() else {
            panic!("expected one reply: {messages:#?}");
        };
        let reply = message.message.to_string();
        assert!(reply.contains("METHOD:REPLY\r\n"), "{reply}");
        assert!(reply.contains("PARTSTAT=ACCEPTED"), "{reply}");
    }
}
