/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    InstanceId, ItipError, ItipMessage, ItipSnapshots,
    attendee::{OrganizerSequences, attendee_handle_update},
    busy_status::AcceptedInstances,
    event_cancel::itip_cancel,
    itip::itip_finalize,
    organizer::organizer_handle_update,
    recipient::{RecipientPolicy, itip_messages_per_recipient},
    snapshot::itip_snapshot,
};
use ahash::AHashSet;
use calcard::icalendar::ICalendar;

pub fn itip_update(
    ical: &mut ICalendar,
    old_ical: &ICalendar,
    account_emails: &[String],
    policy: RecipientPolicy,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    let old_itip = itip_snapshot(old_ical, account_emails, false)?;
    match itip_snapshot(ical, account_emails, false) {
        Ok(new_itip) => {
            let mut sequences = Vec::new();
            if old_itip.organizer.email != new_itip.organizer.email {
                // RFC 6638 does not support replacing the organizer
                Err(ItipError::OrganizerMismatch)
            } else if old_itip.organizer.email.is_local {
                organizer_handle_update(old_ical, ical, old_itip, new_itip, &mut sequences)
                    .and_then(|messages| itip_messages_per_recipient(messages, policy))
            } else {
                let organizer_sequences = OrganizerSequences::of(&old_itip, &new_itip);
                let accepted = AcceptedInstances::of(&old_itip, &new_itip);
                if organizer_sequences.is_empty() && accepted.is_empty() {
                    attendee_handle_update(ical, old_itip, new_itip)
                } else {
                    drop(new_itip);
                    organizer_sequences.restore(ical);
                    accepted.apply(ical);
                    itip_snapshot(ical, account_emails, false)
                        .and_then(|new_itip| attendee_handle_update(ical, old_itip, new_itip))
                }
            }
            .inspect(|_| {
                itip_finalize(ical, &sequences);
            })
        }
        Err(err) => {
            match &err {
                ItipError::NoSchedulingInfo
                | ItipError::NotOrganizer
                | ItipError::NotOrganizerNorAttendee
                | ItipError::OtherSchedulingAgent => {
                    if old_itip.organizer.email.is_local {
                        // RFC 6638 does not support replacing the organizer, so we cancel the event
                        itip_cancel(old_ical, account_emails, false, policy)
                    } else {
                        Err(ItipError::CannotModifyAddress)
                    }
                }
                _ => Err(err),
            }
        }
    }
}

pub fn itip_retain_changed(
    mut messages: Vec<ItipMessage<ICalendar>>,
    old_ical: &ICalendar,
    ical: &ICalendar,
    account_emails: &[String],
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    if !messages.iter().any(|message| message.from_organizer) {
        return Ok(messages);
    }
    let (Ok(old), Ok(new)) = (
        itip_snapshot(old_ical, account_emails, false),
        itip_snapshot(ical, account_emails, false),
    ) else {
        return Ok(messages);
    };
    let changed = changed_attendees(&old, &new);
    messages.retain_mut(|message| {
        if message.from_organizer {
            message.to.retain(|to| changed.contains(to.as_str()));
        }
        !message.to.is_empty()
    });
    if messages.is_empty() {
        Err(ItipError::NothingToSend)
    } else {
        Ok(messages)
    }
}

fn changed_attendees<'x>(
    old: &'x ItipSnapshots<'_>,
    new: &'x ItipSnapshots<'_>,
) -> AHashSet<&'x str> {
    let mut changed = AHashSet::new();
    let mut before = AHashSet::new();
    let mut after = AHashSet::new();
    let instances = old.components.keys().chain(
        new.components
            .keys()
            .filter(|id| !old.components.contains_key(*id)),
    );
    for id in instances {
        before.clear();
        after.clear();
        before.extend(instance_attendees(old, id));
        after.extend(instance_attendees(new, id));
        changed.extend(before.symmetric_difference(&after).copied());
    }
    changed
}

fn instance_attendees<'x>(
    snapshots: &'x ItipSnapshots<'_>,
    id: &InstanceId,
) -> impl Iterator<Item = &'x str> {
    snapshots
        .components
        .get(id)
        .or_else(|| snapshots.components.get(&InstanceId::Main))
        .into_iter()
        .flat_map(|component| &component.attendees)
        .map(|attendee| attendee.email.email.as_str())
}
