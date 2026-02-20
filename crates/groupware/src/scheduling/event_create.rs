/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    ItipError, ItipMessage, itip::itip_finalize, organizer::organizer_request_full,
    snapshot::itip_snapshot,
};
use calcard::icalendar::ICalendar;

pub fn itip_create(
    ical: &mut ICalendar,
    account_emails: &[String],
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    let itip = itip_snapshot(ical, account_emails, false)?;
    if !itip.organizer.is_server_scheduling {
        Err(ItipError::OtherSchedulingAgent)
    } else if !itip.organizer.email.is_local {
        Err(ItipError::NotOrganizer)
    } else {
        let mut sequences = Vec::new();
        organizer_request_full(ical, &itip, Some(&mut sequences), true).inspect(|_| {
            itip_finalize(ical, &sequences);
        })
    }
}
