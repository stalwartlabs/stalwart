/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    InstanceId, ItipError, ItipMessage, ItipSnapshots, ItipSummary,
    event_cancel::build_cancel_component,
    itip::{ItipExportAs, itip_add_tz, itip_build_envelope, itip_export_component},
};
use ahash::{AHashMap, AHashSet};
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarMethod,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarStatus,
    },
};
use std::collections::hash_map::Entry;

pub(crate) fn organizer_handle_update(
    old_ical: &ICalendar,
    new_ical: &ICalendar,
    old_itip: ItipSnapshots<'_>,
    new_itip: ItipSnapshots<'_>,
    increment_sequences: &mut Vec<u16>,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    let mut changed_instances: Vec<(&InstanceId, &str, &ICalendarMethod)> = Vec::new();
    let mut increment_sequence = false;
    let mut changed_properties = AHashSet::new();

    for (instance_id, instance) in &new_itip.components {
        if let Some(old_instance) = old_itip.components.get(instance_id) {
            let changed_entries = instance.entries != old_instance.entries;
            let changed_attendees = instance.attendees != old_instance.attendees;

            if changed_entries || changed_attendees {
                if changed_entries {
                    for entry in instance.entries.symmetric_difference(&old_instance.entries) {
                        increment_sequence = increment_sequence
                            || matches!(
                                entry.name,
                                ICalendarProperty::Dtstart
                                    | ICalendarProperty::Dtend
                                    | ICalendarProperty::Duration
                                    | ICalendarProperty::Due
                                    | ICalendarProperty::Rrule
                                    | ICalendarProperty::Rdate
                                    | ICalendarProperty::Exdate
                                    | ICalendarProperty::Status
                                    | ICalendarProperty::Location
                            );
                        changed_properties.insert(entry.name);
                    }
                }

                if changed_attendees {
                    changed_instances.extend(
                        old_instance
                            .external_attendees()
                            .filter(|attendee| attendee.send_update_messages())
                            .map(|attendee| attendee.email.email.as_str())
                            .collect::<AHashSet<_>>()
                            .difference(
                                &instance
                                    .external_attendees()
                                    .map(|attendee| attendee.email.email.as_str())
                                    .collect::<AHashSet<_>>(),
                            )
                            .map(|attendee| (instance_id, *attendee, &ICalendarMethod::Cancel)),
                    );
                    changed_properties.insert(&ICalendarProperty::Attendee);
                    increment_sequence = true;
                }

                changed_instances.extend(instance.attendees.iter().filter_map(|attendee| {
                    if attendee.send_update_messages() {
                        Some((
                            instance_id,
                            attendee.email.email.as_str(),
                            &ICalendarMethod::Request,
                        ))
                    } else {
                        None
                    }
                }));
            }
        } else if instance_id != &InstanceId::Main {
            changed_properties.insert(&ICalendarProperty::Exdate);
            let method = if matches!(instance.comp.status(), Some(ICalendarStatus::Cancelled)) {
                &ICalendarMethod::Cancel
            } else {
                &ICalendarMethod::Add
            };

            changed_instances.extend(instance.attendees.iter().filter_map(|attendee| {
                if attendee.send_invite_messages() {
                    Some((instance_id, attendee.email.email.as_str(), method))
                } else {
                    None
                }
            }));

            increment_sequence = true;
        } else {
            return Err(ItipError::CannotModifyInstance);
        }
    }

    for (instance_id, old_instance) in &old_itip.components {
        if !new_itip.components.contains_key(instance_id) {
            if instance_id != &InstanceId::Main {
                changed_instances.extend(old_instance.attendees.iter().filter_map(|attendee| {
                    if attendee.send_update_messages() {
                        Some((
                            instance_id,
                            attendee.email.email.as_str(),
                            &ICalendarMethod::Cancel,
                        ))
                    } else {
                        None
                    }
                }));
                changed_properties.insert(&ICalendarProperty::Exdate);
                increment_sequence = true;
            } else {
                return Err(ItipError::CannotModifyInstance);
            }
        }
    }

    if changed_instances.is_empty() {
        return Err(ItipError::NothingToSend);
    }

    // Remove partial notifications for attendees that receive a full update for the main instance
    // or, that will receive both add and remove messages
    let mut send_full_update: AHashSet<&str> = AHashSet::new();
    let mut send_partial_update: AHashMap<&str, AHashMap<&ICalendarMethod, Vec<&InstanceId>>> =
        AHashMap::new();
    for (instance_id, email, method) in &changed_instances {
        if *instance_id == &InstanceId::Main && *method == &ICalendarMethod::Request {
            send_full_update.insert(*email);
            send_partial_update.remove(email);
        } else if !send_full_update.contains(email) {
            match send_partial_update.entry(email) {
                Entry::Occupied(mut entry) => {
                    let entry = entry.get_mut();
                    let is_empty = entry.is_empty();
                    match entry.entry(method) {
                        Entry::Occupied(mut method_entry) => {
                            method_entry.get_mut().push(*instance_id);
                        }
                        Entry::Vacant(method_entry) if is_empty => {
                            method_entry.insert(vec![*instance_id]);
                        }
                        _ => {
                            // Switch to full update for this participant
                            send_full_update.insert(*email);
                            send_partial_update.remove(email);
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(AHashMap::from_iter([(*method, vec![*instance_id])]));
                }
            }
        }
    }

    // Build summary of changed properties
    let new_summary = new_itip
        .main_instance_or_default()
        .build_summary(Some(&new_itip.organizer), &[]);
    let old_summary = old_itip
        .main_instance_or_default()
        .build_summary(Some(&old_itip.organizer), &new_summary);

    // Prepare full updates
    let mut messages = Vec::new();
    if !send_full_update.is_empty() {
        match organizer_request_full(
            new_ical,
            &new_itip,
            increment_sequence.then_some(increment_sequences),
            false,
        ) {
            Ok(messages_) => {
                for mut message in messages_ {
                    message.summary = ItipSummary::Update {
                        method: ICalendarMethod::Request,
                        current: new_summary.clone(),
                        previous: old_summary.clone(),
                    };
                    messages.push(message);
                }
            }
            Err(err) => {
                if send_partial_update.is_empty() {
                    return Err(err);
                }
            }
        }
    }

    // Prepare partial updates
    if !send_partial_update.is_empty() {
        // Group updates by email and method
        let mut updates: AHashMap<(&ICalendarMethod, Vec<&InstanceId>), Vec<&str>> =
            AHashMap::new();
        for (email, partial_updates) in send_partial_update {
            for (method, mut instances) in partial_updates {
                instances.sort_unstable();
                instances.dedup();
                updates.entry((method, instances)).or_default().push(email);
            }
        }

        let dt_stamp = PartialDateTime::now();
        for ((method, instances), emails) in updates {
            let (mut ical, mut itip, is_cancel) = if matches!(method, ICalendarMethod::Cancel) {
                (old_ical, &old_itip, true)
            } else {
                (new_ical, &new_itip, false)
            };

            // Prepare iTIP message
            let mut message = ICalendar {
                components: Vec::with_capacity(instances.len() + 1),
            };
            message.components.push(itip_build_envelope(method.clone()));

            let mut increment_sequences = Vec::new();

            for instance_id in instances {
                let comp = match itip.components.get(instance_id) {
                    Some(comp) => comp,
                    None => {
                        // New component added with CANCELLED status
                        ical = new_ical;
                        itip = &new_itip;
                        itip.components.get(instance_id).unwrap()
                    }
                };
                // Prepare component for iTIP
                let sequence = if increment_sequence {
                    comp.sequence.unwrap_or_default() + 1
                } else {
                    comp.sequence.unwrap_or_default()
                };
                let orig_component = comp.comp;
                let component = if !is_cancel {
                    if increment_sequence {
                        increment_sequences.push(comp.comp_id);
                    }

                    // Export component with updated sequence and participation status
                    itip_export_component(
                        orig_component,
                        itip.uid,
                        &dt_stamp,
                        sequence,
                        ItipExportAs::Organizer(&ICalendarParticipationStatus::NeedsAction),
                    )
                } else {
                    build_cancel_component(orig_component, sequence, dt_stamp.clone(), &emails)
                };

                // Add component to message
                let comp_id = message.components.len() as u32;
                message.components.push(component);
                message.components[0].component_ids.push(comp_id);
            }

            // Add timezones
            itip_add_tz(&mut message, ical);

            messages.push(ItipMessage {
                from: itip.organizer.email.email.clone(),
                from_organizer: true,
                to: emails.into_iter().map(|e| e.to_string()).collect(),
                summary: if method == &ICalendarMethod::Cancel {
                    ItipSummary::Cancel(
                        new_summary
                            .iter()
                            .chain(old_summary.iter())
                            .map(|summary| (&summary.name, summary))
                            .collect::<AHashMap<_, _>>()
                            .into_values()
                            .cloned()
                            .collect(),
                    )
                } else {
                    ItipSummary::Update {
                        method: method.clone(),
                        current: new_summary.clone(),
                        previous: old_summary.clone(),
                    }
                },
                message,
            });
        }
    }

    Ok(messages)
}

pub(crate) fn organizer_request_full(
    ical: &ICalendar,
    itip: &ItipSnapshots<'_>,
    mut increment_sequence: Option<&mut Vec<u16>>,
    is_first_request: bool,
) -> Result<Vec<ItipMessage<ICalendar>>, ItipError> {
    // Prepare iTIP message
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: vec![ICalendarComponent::default(); ical.components.len()],
    };
    message.components[0] = itip_build_envelope(ICalendarMethod::Request);

    let mut recipients = AHashSet::new();
    let mut copy_components = AHashSet::new();

    for comp in itip.components.values() {
        // Skip private components
        if comp.attendees.is_empty() {
            continue;
        }

        // Prepare component for iTIP
        let sequence = if let Some(increment_sequence) = &mut increment_sequence {
            increment_sequence.push(comp.comp_id);
            comp.sequence.unwrap_or_default() + 1
        } else {
            comp.sequence.unwrap_or_default()
        };
        let orig_component = &ical.components[comp.comp_id as usize];
        let mut component = itip_export_component(
            orig_component,
            itip.uid,
            &dt_stamp,
            sequence,
            ItipExportAs::Organizer(&ICalendarParticipationStatus::NeedsAction),
        );

        // Add VALARM sub-components
        if is_first_request {
            for sub_comp_id in &orig_component.component_ids {
                if matches!(
                    ical.components[*sub_comp_id as usize].component_type,
                    ICalendarComponentType::VAlarm
                ) {
                    copy_components.insert(*sub_comp_id);
                    component.component_ids.push(*sub_comp_id);
                }
            }
        }

        // Add component to message
        message.components[comp.comp_id as usize] = component;
        message.components[0]
            .component_ids
            .push(comp.comp_id as u32);

        // Add attendees
        for attendee in &comp.attendees {
            if (is_first_request && attendee.send_invite_messages())
                || (!is_first_request && attendee.send_update_messages())
            {
                recipients.insert(&attendee.email.email);
            }
        }
    }

    // Copy timezones and alarms
    for (comp_id, comp) in ical.components.iter().enumerate() {
        if matches!(comp.component_type, ICalendarComponentType::VTimezone) {
            copy_components.extend(comp.component_ids.iter().copied());
            message.components[0].component_ids.push(comp_id as u32);
        } else if !copy_components.contains(&(comp_id as u32)) {
            continue;
        }
        message.components[comp_id] = comp.clone();
    }
    message.components[0].component_ids.sort_unstable();

    if !recipients.is_empty() {
        Ok(vec![ItipMessage {
            from: itip.organizer.email.email.clone(),
            from_organizer: true,
            to: recipients.into_iter().map(|e| e.to_string()).collect(),
            summary: ItipSummary::Invite(
                itip.main_instance_or_default()
                    .build_summary(Some(&itip.organizer), &[]),
            ),
            message,
        }])
    } else {
        Err(ItipError::NothingToSend)
    }
}
