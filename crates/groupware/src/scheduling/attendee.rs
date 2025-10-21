/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    Email, InstanceId, ItipEntryValue, ItipError, ItipMessage, ItipSnapshot, ItipSnapshots,
    ItipSummary,
    itip::{
        ItipExportAs, can_attendee_modify_property, itip_add_tz, itip_build_envelope,
        itip_export_component,
    },
    organizer::organizer_request_full,
};
use ahash::AHashSet;
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarMethod, ICalendarParameter,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarValue,
    },
};

pub(crate) fn attendee_handle_update(
    new_ical: &ICalendar,
    old_itip: ItipSnapshots<'_>,
    new_itip: ItipSnapshots<'_>,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: Vec::with_capacity(2),
    };
    message
        .components
        .push(itip_build_envelope(ICalendarMethod::Reply));

    let mut mail_from = None;
    let mut email_rcpt = AHashSet::new();
    let mut new_delegates = AHashSet::new();
    let mut part_stat = &ICalendarParticipationStatus::NeedsAction;

    for (instance_id, instance) in &new_itip.components {
        if let Some(old_instance) = old_itip.components.get(instance_id) {
            match (instance.local_attendee(), old_instance.local_attendee()) {
                (Some(local_attendee), Some(old_local_attendee))
                    if local_attendee.email == old_local_attendee.email =>
                {
                    // Check added fields
                    let mut send_update = false;
                    for new_entry in instance.entries.difference(&old_instance.entries) {
                        match (new_entry.name, &new_entry.value) {
                            (ICalendarProperty::Exdate, ItipEntryValue::DateTime(date))
                                if instance_id == &InstanceId::Main =>
                            {
                                if let Some((mut cancel_comp, attendee_email)) = attendee_decline(
                                    instance_id,
                                    &old_itip,
                                    old_instance,
                                    &dt_stamp,
                                    &mut email_rcpt,
                                    false,
                                ) {
                                    // Add EXDATE as RECURRENCE-ID
                                    cancel_comp
                                        .entries
                                        .push(date.to_entry(ICalendarProperty::RecurrenceId));
                                    part_stat = &ICalendarParticipationStatus::Declined;

                                    // Add cancel component
                                    let comp_id = message.components.len() as u32;
                                    message.components[0].component_ids.push(comp_id);
                                    message.components.push(cancel_comp);
                                    mail_from = Some(&attendee_email.email);
                                }
                            }
                            _ => {
                                // Changing these properties is not allowed
                                if !can_attendee_modify_property(
                                    &instance.comp.component_type,
                                    new_entry.name,
                                ) {
                                    return Err(ItipError::CannotModifyProperty(
                                        new_entry.name.clone(),
                                    ));
                                } else {
                                    send_update = send_update
                                        || (instance.comp.component_type
                                            == ICalendarComponentType::VTodo
                                            && matches!(
                                                new_entry.name,
                                                ICalendarProperty::Status
                                                    | ICalendarProperty::PercentComplete
                                                    | ICalendarProperty::Completed
                                            ));
                                }
                            }
                        }
                    }

                    // Send participation status update
                    if local_attendee.is_server_scheduling
                        && ((local_attendee.part_stat != old_local_attendee.part_stat)
                            || local_attendee.force_send.is_some()
                            || send_update)
                    {
                        // Build the attendee list
                        if let Some(new_partstat) = local_attendee.part_stat {
                            part_stat = new_partstat;
                        }
                        let mut attendee_entry_uids = vec![local_attendee.entry_id];
                        let old_delegates = old_instance
                            .external_attendees()
                            .filter(|a| a.is_delegated_from(old_local_attendee))
                            .map(|a| a.email.email.as_str())
                            .collect::<AHashSet<_>>();
                        for external_attendee in instance.external_attendees() {
                            if external_attendee.is_delegated_from(local_attendee) {
                                if external_attendee.send_invite_messages()
                                    && !old_delegates
                                        .contains(&external_attendee.email.email.as_str())
                                {
                                    new_delegates.insert(external_attendee.email.email.as_str());
                                }
                            } else if external_attendee.is_delegated_to(local_attendee) {
                                if external_attendee.send_update_messages() {
                                    email_rcpt.insert(external_attendee.email.email.as_str());
                                }
                            } else {
                                continue;
                            }
                            attendee_entry_uids.push(external_attendee.entry_id);
                        }

                        let comp_id = message.components.len() as u32;
                        message.components[0].component_ids.push(comp_id);
                        message.components.push(itip_export_component(
                            instance.comp,
                            new_itip.uid,
                            &dt_stamp,
                            instance.sequence.unwrap_or_default(),
                            ItipExportAs::Attendee(attendee_entry_uids),
                        ));
                        mail_from = Some(&local_attendee.email.email);
                    }

                    // Check removed fields
                    for removed_entry in old_instance.entries.difference(&instance.entries) {
                        if !can_attendee_modify_property(
                            &instance.comp.component_type,
                            removed_entry.name,
                        ) {
                            // Removing these properties is not allowed
                            return Err(ItipError::CannotModifyProperty(
                                removed_entry.name.clone(),
                            ));
                        }
                    }
                }
                _ => {
                    // Change in local attendee email is not allowed
                    return Err(ItipError::CannotModifyAddress);
                }
            }
        } else if let Some(local_attendee) = instance
            .local_attendee()
            .filter(|_| instance_id != &InstanceId::Main)
        {
            let mut attendee_entry_uids = vec![local_attendee.entry_id];
            for external_attendee in instance.external_attendees() {
                if external_attendee.is_delegated_from(local_attendee) {
                    if external_attendee.send_invite_messages() {
                        new_delegates.insert(external_attendee.email.email.as_str());
                    }
                } else if external_attendee.is_delegated_to(local_attendee) {
                    if external_attendee.send_update_messages() {
                        email_rcpt.insert(external_attendee.email.email.as_str());
                    }
                } else {
                    continue;
                }
                attendee_entry_uids.push(external_attendee.entry_id);
            }

            // A new instance has been added
            let comp_id = message.components.len() as u32;
            message.components[0].component_ids.push(comp_id);
            message.components.push(itip_export_component(
                instance.comp,
                new_itip.uid,
                &dt_stamp,
                instance.sequence.unwrap_or_default(),
                ItipExportAs::Attendee(attendee_entry_uids),
            ));
            mail_from = Some(&local_attendee.email.email);
        } else {
            return Err(ItipError::CannotModifyInstance);
        }
    }

    for (instance_id, old_instance) in &old_itip.components {
        if !new_itip.components.contains_key(instance_id) {
            if instance_id != &InstanceId::Main && old_instance.has_local_attendee() {
                // Send cancel message for removed instances
                if let Some((cancel_comp, attendee_email)) = attendee_decline(
                    instance_id,
                    &old_itip,
                    old_instance,
                    &dt_stamp,
                    &mut email_rcpt,
                    false,
                ) {
                    // Add cancel component
                    let comp_id = message.components.len() as u32;
                    message.components[0].component_ids.push(comp_id);
                    message.components.push(cancel_comp);
                    mail_from = Some(&attendee_email.email);
                }
            } else {
                // Removing instances is not allowed
                return Err(ItipError::CannotModifyInstance);
            }
        }
    }

    if let Some(from) = mail_from {
        email_rcpt.insert(&new_itip.organizer.email.email);

        // Add timezones if needed
        itip_add_tz(&mut message, new_ical);

        let mut responses = vec![ItipMessage {
            from: from.to_string(),
            from_organizer: false,
            to: email_rcpt.into_iter().map(|e| e.to_string()).collect(),
            summary: ItipSummary::Rsvp {
                part_stat: part_stat.clone(),
                current: new_itip
                    .main_instance_or_default()
                    .build_summary(Some(&new_itip.organizer), &[]),
            },
            message,
        }];

        // Invite new delegates
        if !new_delegates.is_empty() {
            let from = from.to_string();
            let new_delegates = new_delegates
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>();
            if let Ok(messages_) = organizer_request_full(new_ical, &new_itip, None, true) {
                for mut message in messages_ {
                    message.from = from.clone();
                    message.to = new_delegates.clone();
                    message.from_organizer = false;
                    responses.push(message);
                }
            }
        }

        Ok(responses)
    } else {
        Err(ItipError::NothingToSend)
    }
}

pub(crate) fn attendee_decline<'x>(
    instance_id: &'x InstanceId,
    itip: &'x ItipSnapshots<'x>,
    comp: &'x ItipSnapshot<'x>,
    dt_stamp: &'x PartialDateTime,
    email_rcpt: &mut AHashSet<&'x str>,
    skip_needs_action: bool,
) -> Option<(ICalendarComponent, &'x Email)> {
    let component = comp.comp;
    let mut cancel_comp = ICalendarComponent {
        component_type: component.component_type.clone(),
        entries: Vec::with_capacity(5),
        component_ids: vec![],
    };

    let mut local_attendee = None;
    let mut delegated_from = None;

    for attendee in &comp.attendees {
        if attendee.email.is_local {
            if attendee.is_server_scheduling
                && attendee.rsvp.is_none_or(|rsvp| rsvp)
                && match attendee.part_stat {
                    Some(
                        ICalendarParticipationStatus::Declined
                        | ICalendarParticipationStatus::Delegated,
                    ) => attendee.force_send.is_some(),
                    Some(ICalendarParticipationStatus::NeedsAction) => !skip_needs_action,
                    _ => true,
                }
            {
                local_attendee = Some(attendee);
            }
        } else if attendee.delegated_to.iter().any(|d| d.is_local) {
            cancel_comp
                .entries
                .push(component.entries[attendee.entry_id as usize].clone());
            delegated_from = Some(&attendee.email.email);
        }
    }

    local_attendee.map(|local_attendee| {
        cancel_comp.add_property(
            ICalendarProperty::Organizer,
            ICalendarValue::Text(itip.organizer.email.to_string()),
        );
        cancel_comp.add_property_with_params(
            ICalendarProperty::Attendee,
            [ICalendarParameter::partstat(
                ICalendarParticipationStatus::Declined,
            )],
            ICalendarValue::Text(local_attendee.email.to_string()),
        );
        cancel_comp.add_uid(itip.uid);
        cancel_comp.add_dtstamp(dt_stamp.clone());
        cancel_comp.add_sequence(comp.sequence.unwrap_or_default());
        cancel_comp.entries.extend(
            component
                .entries
                .iter()
                .filter(|e| {
                    matches!(
                        e.name,
                        ICalendarProperty::Dtstart
                            | ICalendarProperty::Dtend
                            | ICalendarProperty::Duration
                            | ICalendarProperty::Due
                            | ICalendarProperty::Description
                            | ICalendarProperty::Summary
                    )
                })
                .cloned(),
        );

        if let InstanceId::Recurrence(recurrence_id) = instance_id {
            cancel_comp
                .entries
                .push(component.entries[recurrence_id.entry_id as usize].clone());
        }
        if let Some(delegated_from) = delegated_from {
            email_rcpt.insert(delegated_from);
        }

        (cancel_comp, &local_attendee.email)
    })
}
