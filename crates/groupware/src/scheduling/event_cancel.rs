/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    InstanceId, ItipError, ItipMessage, ItipSummary,
    attendee::attendee_decline,
    itip::{itip_add_tz, itip_build_envelope},
    snapshot::itip_snapshot,
};
use ahash::AHashSet;
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarMethod,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarStatus, ICalendarValue,
    },
};

pub fn itip_cancel(
    ical: &ICalendar,
    account_emails: &[String],
    is_deletion: bool,
) -> Result<ItipMessage<ICalendar>, ItipError> {
    // Prepare iTIP message
    let itip = itip_snapshot(ical, account_emails, false)?;
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: Vec::with_capacity(2),
    };

    if itip.organizer.email.is_local {
        // Send cancel message
        let mut comp = itip_build_envelope(ICalendarMethod::Cancel);
        comp.component_ids.push(1);
        message.components.push(comp);

        // Fetch guest emails
        let mut recipients = AHashSet::new();
        let mut cancel_guests = AHashSet::new();
        let mut component_type = &ICalendarComponentType::VEvent;
        let mut sequence = 0;
        for (instance_id, comp) in &itip.components {
            component_type = &comp.comp.component_type;
            for attendee in &comp.attendees {
                if attendee.send_update_messages() {
                    recipients.insert(attendee.email.email.clone());
                }
                cancel_guests.insert(&attendee.email);
            }

            // Increment sequence if needed
            if instance_id == &InstanceId::Main {
                sequence = comp.sequence.unwrap_or_default() + 1;
            }
        }

        if !recipients.is_empty() && component_type != &ICalendarComponentType::VFreebusy {
            let instance = itip.main_instance_or_default();
            message.components.push(build_cancel_component(
                instance.comp,
                sequence,
                dt_stamp,
                &[],
            ));

            // Add timezones
            itip_add_tz(&mut message, ical);

            Ok(ItipMessage {
                to: recipients.into_iter().collect(),
                summary: ItipSummary::Cancel(instance.build_summary(None, &[])),
                from: itip.organizer.email.email,
                from_organizer: true,
                message,
            })
        } else {
            Err(ItipError::NothingToSend)
        }
    } else {
        // Send decline message
        message
            .components
            .push(itip_build_envelope(ICalendarMethod::Reply));

        // Decline attendance for all instances that have local attendees
        let mut mail_from = None;
        let mut email_rcpt = AHashSet::new();
        for (instance_id, comp) in &itip.components {
            if let Some((cancel_comp, attendee_email)) = attendee_decline(
                instance_id,
                &itip,
                comp,
                &dt_stamp,
                &mut email_rcpt,
                is_deletion,
            ) {
                // Add cancel component
                let comp_id = message.components.len() as u32;
                message.components[0].component_ids.push(comp_id);
                message.components.push(cancel_comp);
                mail_from = Some(&attendee_email.email);
            }
        }

        if let Some(from) = mail_from {
            // Add timezone information if needed
            itip_add_tz(&mut message, ical);

            email_rcpt.insert(&itip.organizer.email.email);

            Ok(ItipMessage {
                from: from.to_string(),
                from_organizer: false,
                to: email_rcpt.into_iter().map(|e| e.to_string()).collect(),
                summary: ItipSummary::Rsvp {
                    part_stat: ICalendarParticipationStatus::Declined,
                    current: itip.main_instance_or_default().build_summary(None, &[]),
                },
                message,
            })
        } else {
            Err(ItipError::NothingToSend)
        }
    }
}

pub(crate) fn build_cancel_component(
    component: &ICalendarComponent,
    sequence: i64,
    dt_stamp: PartialDateTime,
    attendees: &[&str],
) -> ICalendarComponent {
    let mut cancel_comp = ICalendarComponent {
        component_type: component.component_type.clone(),
        entries: Vec::with_capacity(7),
        component_ids: vec![],
    };
    cancel_comp.add_property(
        ICalendarProperty::Status,
        ICalendarValue::Status(ICalendarStatus::Cancelled),
    );
    cancel_comp.add_dtstamp(dt_stamp);
    cancel_comp.add_sequence(sequence);
    cancel_comp.entries.extend(
        component
            .entries
            .iter()
            .filter(|e| match e.name {
                ICalendarProperty::Organizer
                | ICalendarProperty::Uid
                | ICalendarProperty::Summary
                | ICalendarProperty::Dtstart
                | ICalendarProperty::Dtend
                | ICalendarProperty::Duration
                | ICalendarProperty::Due
                | ICalendarProperty::RecurrenceId
                | ICalendarProperty::Created
                | ICalendarProperty::LastModified
                | ICalendarProperty::Description
                | ICalendarProperty::Location => true,
                ICalendarProperty::Attendee => {
                    attendees.is_empty()
                        || e.values
                            .first()
                            .and_then(|v| v.as_text())
                            .is_some_and(|email| {
                                attendees.iter().any(|attendee| {
                                    email
                                        .strip_suffix(attendee)
                                        .is_some_and(|v| v.ends_with(':') || v.is_empty())
                                })
                            })
                }
                _ => false,
            })
            .cloned(),
    );

    cancel_comp
}
