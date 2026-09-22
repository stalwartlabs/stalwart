/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    Email, InstanceId, ItipError, ItipMessage, ItipSummary,
    attendee::attendee_decline,
    itip::{itip_add_tz, itip_build_envelope},
    recipient::{RecipientPolicy, itip_messages_per_recipient},
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum CancelScope<'x> {
    Event,
    Instance(&'x [&'x str]),
    Attendees(&'x [&'x str]),
}

pub fn itip_cancel(
    ical: &ICalendar,
    account_emails: &[String],
    is_deletion: bool,
    policy: RecipientPolicy,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
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
            message.components.push(CancelScope::Event.build_component(
                instance.comp,
                sequence,
                dt_stamp,
            ));

            // Add timezones
            itip_add_tz(&mut message, ical);

            itip_messages_per_recipient(
                vec![ItipMessage {
                    to: recipients.into_iter().collect(),
                    summary: ItipSummary::Cancel(instance.build_summary(None, &[])),
                    from: itip.organizer.email.email,
                    from_organizer: true,
                    message,
                }],
                policy,
            )
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
        let mut declined_instances = Vec::with_capacity(itip.components.len());
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
                declined_instances.push(instance_id);
            }
        }

        if let Some(from) = mail_from {
            declined_instances.sort_unstable();
            // Add timezone information if needed
            itip_add_tz(&mut message, ical);

            email_rcpt.insert(&itip.organizer.email.email);

            Ok(vec![ItipMessage {
                from: from.to_string(),
                from_organizer: false,
                to: email_rcpt.into_iter().map(|e| e.to_string()).collect(),
                summary: ItipSummary::Rsvp {
                    part_stat: ICalendarParticipationStatus::Declined,
                    current: itip.build_instances_summary(&declined_instances, None, &[]),
                },
                message,
            }])
        } else {
            Err(ItipError::NothingToSend)
        }
    }
}

impl CancelScope<'_> {
    pub(crate) fn build_component(
        self,
        component: &ICalendarComponent,
        sequence: i64,
        dt_stamp: PartialDateTime,
    ) -> ICalendarComponent {
        let mut cancel_comp = ICalendarComponent {
            component_type: component.component_type.clone(),
            entries: Vec::with_capacity(7),
            component_ids: vec![],
        };
        if !matches!(self, CancelScope::Attendees(_)) {
            cancel_comp.add_property(
                ICalendarProperty::Status,
                ICalendarValue::Status(ICalendarStatus::Cancelled),
            );
        }
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
                    ICalendarProperty::Attendee => match self {
                        CancelScope::Event => true,
                        CancelScope::Instance(attendees) | CancelScope::Attendees(attendees) => e
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .and_then(|address| Email::new(address, &[]))
                            .is_some_and(|email| attendees.contains(&email.email.as_str())),
                    },
                    _ => false,
                })
                .cloned(),
        );

        cancel_comp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninvited_attendees_are_matched_after_normalization() {
        let ical = ICalendar::parse(concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:uninvite\r\n",
            "DTSTART:20260601T090000Z\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:John.Doe@Example.COM\r\n",
            "ATTENDEE:mailto:jane@example.com\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        ))
        .expect("valid iCalendar");
        let component = ical
            .components
            .iter()
            .find(|component| component.component_type == ICalendarComponentType::VEvent)
            .expect("event component");
        let removed = ["john.doe@example.com"];
        let has = |component: &ICalendarComponent, name: ICalendarProperty| {
            component.entries.iter().any(|entry| entry.name == name)
        };

        let uninvite =
            CancelScope::Attendees(&removed).build_component(component, 1, PartialDateTime::now());
        let attendees = uninvite
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Attendee)
            .filter_map(|entry| entry.calendar_address())
            .collect::<Vec<_>>();
        assert_eq!(attendees, ["John.Doe@Example.COM"]);
        assert!(!has(&uninvite, ICalendarProperty::Status));

        let cancel =
            CancelScope::Instance(&removed).build_component(component, 1, PartialDateTime::now());
        assert!(has(&cancel, ICalendarProperty::Status));
        assert!(has(&cancel, ICalendarProperty::Attendee));

        let cancel = CancelScope::Event.build_component(component, 1, PartialDateTime::now());
        assert_eq!(
            cancel
                .entries
                .iter()
                .filter(|entry| entry.name == ICalendarProperty::Attendee)
                .count(),
            2
        );
        assert!(has(&cancel, ICalendarProperty::Status));
    }
}
