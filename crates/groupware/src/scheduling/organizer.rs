/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    InstanceId, ItipDateTime, ItipEntryValue, ItipError, ItipMessage, ItipSnapshot, ItipSnapshots,
    ItipSummary, RecurrenceId,
    event_cancel::CancelScope,
    itip::{
        ItipExportAs, itip_add_tz, itip_build_envelope, itip_date_entry, itip_date_params,
        itip_export_component,
    },
};
use ahash::{AHashMap, AHashSet};
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarStatus, ICalendarValue,
    },
};
use std::collections::hash_map::Entry;

pub(crate) struct SequenceIncrement<'x, 'y> {
    previous: &'x ItipSnapshots<'y>,
    component_ids: &'x mut Vec<u16>,
}

impl<'x, 'y> SequenceIncrement<'x, 'y> {
    fn new(previous: &'x ItipSnapshots<'y>, component_ids: &'x mut Vec<u16>) -> Self {
        SequenceIncrement {
            previous,
            component_ids,
        }
    }

    fn sequence(&self, instance_id: &InstanceId, instance: &ItipSnapshot<'_>) -> i64 {
        let sequence = instance.sequence.unwrap_or_default();
        let previous = self
            .previous
            .components
            .get(instance_id)
            .or_else(|| self.previous.main_instance())
            .and_then(|previous| previous.sequence)
            .unwrap_or_default();
        if sequence > previous {
            sequence
        } else {
            sequence + 1
        }
    }

    fn increment(&mut self, instance_id: &InstanceId, instance: &ItipSnapshot<'_>) -> i64 {
        let sequence = self.sequence(instance_id, instance);
        if sequence != instance.sequence.unwrap_or_default() {
            self.component_ids.push(instance.comp_id);
        }
        sequence
    }
}

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
    let mut added_exclusions: Vec<&ItipDateTime<'_>> = Vec::new();
    let mut exclusion_recipients: Vec<&str> = Vec::new();
    let mut cancelled_dates: Vec<i64> = Vec::new();

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

                let mut exclusions = Vec::new();
                let mut is_exclusion_only = instance_id == &InstanceId::Main
                    && changed_entries
                    && !changed_attendees
                    && old_instance
                        .entries
                        .difference(&instance.entries)
                        .next()
                        .is_none();

                if is_exclusion_only {
                    for entry in instance.entries.difference(&old_instance.entries) {
                        match (entry.name, &entry.value) {
                            (ICalendarProperty::Exdate, ItipEntryValue::DateTime(date)) => {
                                exclusions.push(date);
                            }
                            _ => {
                                is_exclusion_only = false;
                                break;
                            }
                        }
                    }
                }

                if is_exclusion_only {
                    added_exclusions = exclusions;
                    exclusion_recipients.extend(
                        instance
                            .attendees
                            .iter()
                            .filter(|attendee| attendee.send_update_messages())
                            .map(|attendee| attendee.email.email.as_str()),
                    );
                    exclusion_recipients.sort_unstable();
                    exclusion_recipients.dedup();
                } else {
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
            }
        } else if instance_id != &InstanceId::Main {
            changed_properties.insert(&ICalendarProperty::Exdate);
            let method = if matches!(instance.comp.status(), Some(ICalendarStatus::Cancelled)) {
                &ICalendarMethod::Cancel
            } else {
                &ICalendarMethod::Request
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

                if let InstanceId::Recurrence(recurrence_id) = instance_id {
                    cancelled_dates.push(recurrence_id.date);
                }
            } else {
                return Err(ItipError::CannotModifyInstance);
            }
        }
    }

    added_exclusions.retain(|date| !cancelled_dates.contains(&date.timestamp));

    if changed_instances.is_empty() && added_exclusions.is_empty() {
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

    // Prepare full updates
    let mut messages = Vec::new();
    if !send_full_update.is_empty() {
        match organizer_request_full(
            new_ical,
            &new_itip,
            increment_sequence
                .then(|| SequenceIncrement::new(&old_itip, &mut *increment_sequences)),
            false,
        ) {
            Ok(messages_) => {
                let new_summary = new_itip
                    .main_instance_or_default()
                    .build_summary(Some(&new_itip.organizer), &[]);
                let old_summary = old_itip
                    .main_instance_or_default()
                    .build_summary(Some(&old_itip.organizer), &new_summary);
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

        let mut increment = increment_sequence
            .then(|| SequenceIncrement::new(&old_itip, &mut *increment_sequences));
        let main_sequence = new_itip
            .main_instance()
            .map(|instance| match &increment {
                Some(increment) => increment.sequence(&InstanceId::Main, instance),
                None => instance.sequence.unwrap_or_default(),
            })
            .unwrap_or_default();
        let dt_stamp = PartialDateTime::now();
        for ((method, instances), emails) in updates {
            let is_cancel = matches!(method, ICalendarMethod::Cancel);
            let mut tz_source = if is_cancel { old_ical } else { new_ical };

            // Prepare iTIP message
            let mut message = ICalendar {
                components: Vec::with_capacity(instances.len() + 1),
            };
            message.components.push(itip_build_envelope(method.clone()));

            for instance_id in &instances {
                let old_instance = old_itip.components.get(*instance_id);
                let new_instance = new_itip.components.get(*instance_id);
                let component = if is_cancel {
                    let Some(instance) = old_instance.or(new_instance) else {
                        continue;
                    };
                    if old_instance.is_none() {
                        tz_source = new_ical;
                    }
                    let sequence = match (new_instance, &mut increment) {
                        (None, _) => (instance.sequence.unwrap_or_default() + 1).max(main_sequence),
                        (Some(new_instance), Some(increment)) => increment
                            .increment(instance_id, new_instance)
                            .max(old_instance.map_or(0, |old_instance| {
                                old_instance.sequence.unwrap_or_default() + 1
                            })),
                        (Some(new_instance), None) => new_instance
                            .sequence
                            .or(instance.sequence)
                            .unwrap_or_default(),
                    };
                    let scope = if old_instance.is_some()
                        && new_instance.is_some_and(|new_instance| {
                            !matches!(new_instance.comp.status(), Some(ICalendarStatus::Cancelled))
                        }) {
                        CancelScope::Attendees(&emails)
                    } else {
                        CancelScope::Instance(&emails)
                    };
                    scope.build_component(instance.comp, sequence, dt_stamp.clone())
                } else {
                    let Some(instance) = new_instance else {
                        continue;
                    };
                    let sequence = match &mut increment {
                        Some(increment) => increment.increment(instance_id, instance),
                        None => instance.sequence.unwrap_or_default(),
                    };

                    // Export component with updated sequence and participation status
                    itip_export_component(
                        instance.comp,
                        new_itip.uid,
                        &dt_stamp,
                        sequence,
                        ItipExportAs::Organizer(&ICalendarParticipationStatus::NeedsAction),
                    )
                };

                // Add component to message
                let comp_id = message.components.len() as u32;
                message.components.push(component);
                if let Some(root) = message.components.first_mut() {
                    root.component_ids.push(comp_id);
                }
            }

            // Add timezones
            itip_add_tz(&mut message, tz_source);

            let current_guests = instances
                .iter()
                .any(|instance_id| new_itip.components.contains_key(*instance_id))
                .then_some(&new_itip.organizer);
            let current = new_itip.build_instances_summary(&instances, current_guests, &[]);
            let previous =
                old_itip.build_instances_summary(&instances, Some(&old_itip.organizer), &current);

            messages.push(ItipMessage {
                from: new_itip.organizer.email.email.clone(),
                from_organizer: true,
                to: emails.into_iter().map(|e| e.to_string()).collect(),
                summary: if is_cancel {
                    let mut fields = current;
                    for field in previous {
                        if !fields.iter().any(|existing| existing.name == field.name) {
                            fields.push(field);
                        }
                    }
                    ItipSummary::Cancel(fields)
                } else {
                    ItipSummary::Update {
                        method: method.clone(),
                        current,
                        previous,
                    }
                },
                message,
            });
        }
    }

    if !added_exclusions.is_empty()
        && !exclusion_recipients.is_empty()
        && send_full_update.is_empty()
        && let Some(main_instance) = new_itip.main_instance()
        && main_instance.entries.iter().any(|entry| {
            matches!(
                entry.name,
                ICalendarProperty::Rrule | ICalendarProperty::Rdate
            )
        })
    {
        let mut increment = increment_sequence
            .then(|| SequenceIncrement::new(&old_itip, &mut *increment_sequences));
        let sequence = match &mut increment {
            Some(increment) => increment.increment(&InstanceId::Main, main_instance),
            None => main_instance.sequence.unwrap_or_default(),
        };
        let dt_stamp = PartialDateTime::now();
        let mut message = ICalendar {
            components: Vec::with_capacity(added_exclusions.len() + 1),
        };
        message
            .components
            .push(itip_build_envelope(ICalendarMethod::Cancel));
        let mut cancelled_instances: Vec<InstanceId> = Vec::with_capacity(added_exclusions.len());
        let mut exdate_sources: AHashMap<(Option<&str>, &PartialDateTime), &ICalendarEntry> =
            AHashMap::with_capacity(added_exclusions.len());
        let mut overrides_by_date = AHashMap::with_capacity(new_itip.components.len());

        for entry in &main_instance.comp.entries {
            if entry.name == ICalendarProperty::Exdate {
                let tz_id = entry.tz_id();
                for value in &entry.values {
                    if let ICalendarValue::PartialDateTime(value) = value {
                        exdate_sources.entry((tz_id, &**value)).or_insert(entry);
                    }
                }
            }
        }
        for (instance_id, instance) in &new_itip.components {
            if let InstanceId::Recurrence(recurrence_id) = instance_id {
                overrides_by_date
                    .entry(recurrence_id.date)
                    .or_insert((instance_id, instance));
            }
        }

        for date in added_exclusions {
            let Some(source) = exdate_sources.get(&(date.tz_id, date.date)).copied() else {
                continue;
            };

            let overridden = overrides_by_date.get(&date.timestamp).copied();
            let instance_id = match overridden {
                Some((instance_id, _)) => instance_id.clone(),
                None => InstanceId::Recurrence(RecurrenceId {
                    entry_id: 0,
                    date: date.timestamp,
                    this_and_future: false,
                }),
            };
            let overridden = overridden.map(|(_, instance)| instance);
            let params = itip_date_params(source);
            let value = ICalendarValue::PartialDateTime(Box::new(date.date.clone()));
            let dt_start = match overridden
                .and_then(|instance| instance.comp.property(&ICalendarProperty::Dtstart))
            {
                Some(entry) => itip_date_entry(ICalendarProperty::Dtstart, entry),
                None => ICalendarEntry {
                    name: ICalendarProperty::Dtstart,
                    params: params.clone(),
                    values: vec![value.clone()],
                },
            };

            let mut component = CancelScope::Instance(&exclusion_recipients).build_component(
                main_instance.comp,
                sequence,
                dt_stamp.clone(),
            );
            component.entries.retain(|entry| {
                !matches!(
                    entry.name,
                    ICalendarProperty::Dtstart
                        | ICalendarProperty::Dtend
                        | ICalendarProperty::Duration
                        | ICalendarProperty::Due
                )
            });
            component.entries.push(ICalendarEntry {
                name: ICalendarProperty::RecurrenceId,
                params,
                values: vec![value],
            });
            component.entries.push(dt_start);

            let comp_id = message.components.len() as u32;
            message.components.push(component);
            if let Some(root) = message.components.first_mut() {
                root.component_ids.push(comp_id);
            }
            cancelled_instances.push(instance_id);
        }

        if !cancelled_instances.is_empty() {
            itip_add_tz(&mut message, new_ical);

            let mut fields = new_itip.build_instances_summary(&cancelled_instances, None, &[]);
            fields.push(main_instance.guest_field(&new_itip.organizer));

            messages.push(ItipMessage {
                from: new_itip.organizer.email.email.clone(),
                from_organizer: true,
                to: exclusion_recipients
                    .into_iter()
                    .map(|email| email.to_string())
                    .collect(),
                summary: ItipSummary::Cancel(fields),
                message,
            });
        }
    }

    if messages.is_empty() {
        return Err(ItipError::NothingToSend);
    }

    increment_sequences.sort_unstable();
    increment_sequences.dedup();

    Ok(messages)
}

pub(crate) fn organizer_request_full(
    ical: &ICalendar,
    itip: &ItipSnapshots<'_>,
    mut increment: Option<SequenceIncrement<'_, '_>>,
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

    for (instance_id, comp) in &itip.components {
        // Skip private components
        if comp.attendees.is_empty() {
            continue;
        }

        // Prepare component for iTIP
        let sequence = match &mut increment {
            Some(increment) => increment.increment(instance_id, comp),
            None => comp.sequence.unwrap_or_default(),
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
    message.add_missing_timezones();

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

#[cfg(test)]
mod tests {
    use crate::scheduling::{
        ItipMessage,
        event_create::itip_create,
        event_update::itip_update,
        recipient::{AttendeeVisibility, RecipientPolicy},
    };
    use calcard::icalendar::ICalendar;

    const ORGANIZER: &str = "org@example.com";

    fn policy() -> RecipientPolicy {
        RecipientPolicy {
            visibility: AttendeeVisibility::All,
            max_recipients: usize::MAX,
            max_instances: 3000,
        }
    }

    fn event(master: &str, overrides: &str) -> ICalendar {
        ICalendar::parse(format!(
            concat!(
                "BEGIN:VCALENDAR\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:sequence\r\n",
                "DTSTART:20260601T090000Z\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "{}",
                "END:VEVENT\r\n",
                "{}",
                "END:VCALENDAR\r\n"
            ),
            master, overrides
        ))
        .expect("valid iCalendar")
    }

    fn create(mut ical: ICalendar) -> ICalendar {
        itip_create(&mut ical, &[ORGANIZER.to_string()], policy()).expect("invitations");
        ical
    }

    fn update(stored: &ICalendar, mut ical: ICalendar) -> (ICalendar, Vec<ItipMessage<ICalendar>>) {
        let messages =
            itip_update(&mut ical, stored, &[ORGANIZER.to_string()], policy()).expect("updates");
        (ical, messages)
    }

    fn only_message(messages: &[ItipMessage<ICalendar>], recipient: &str) -> String {
        let matching = messages
            .iter()
            .filter(|message| message.to.iter().any(|to| to == recipient))
            .collect::<Vec<_>>();
        let [message] = matching.as_slice() else {
            panic!("expected one message to {recipient}: {messages:#?}");
        };
        message.message.to_string()
    }

    #[test]
    fn partial_updates_raise_the_stored_sequence() {
        let instance = |location: &str| {
            format!(
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:sequence\r\n",
                    "RECURRENCE-ID:20260602T090000Z\r\n",
                    "DTSTART:20260602T090000Z\r\n",
                    "SEQUENCE:0\r\n",
                    "LOCATION:{}\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE:mailto:a@example.com\r\n",
                    "END:VEVENT\r\n"
                ),
                location
            )
        };
        let master = "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n";
        let stored = create(event(master, &instance("Room 1")));

        let (stored, messages) = update(&stored, event(master, &instance("Room 2")));
        let message = only_message(&messages, "a@example.com");
        assert!(
            message.contains("RECURRENCE-ID:20260602T090000Z"),
            "{message}"
        );
        assert!(message.contains("SEQUENCE:1\r\n"), "{message}");
        let stored_text = stored.to_string();
        assert!(stored_text.contains("SEQUENCE:1\r\n"), "{stored_text}");

        let next = ICalendar::parse(stored_text.replace("Room 2", "Room 3")).expect("valid");
        let (_, messages) = update(&stored, next);
        let message = only_message(&messages, "a@example.com");
        assert!(message.contains("SEQUENCE:2\r\n"), "{message}");
    }

    #[test]
    fn cancelled_instances_raise_their_sequence() {
        let stored = create(event(
            "SEQUENCE:0\r\nRRULE:FREQ=WEEKLY\r\nATTENDEE:mailto:b@example.com\r\n",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:sequence\r\n",
                "RECURRENCE-ID:20260608T090000Z\r\n",
                "DTSTART:20260608T090000Z\r\n",
                "SEQUENCE:2\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE:mailto:c@example.com\r\n",
                "END:VEVENT\r\n"
            ),
        ));

        let (_, messages) = update(
            &stored,
            event(
                "SEQUENCE:2\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,TU\r\nATTENDEE:mailto:b@example.com\r\n",
                "",
            ),
        );
        let request = only_message(&messages, "b@example.com");
        assert!(request.contains("SEQUENCE:2\r\n"), "{request}");
        let cancel = only_message(&messages, "c@example.com");
        assert!(cancel.contains("METHOD:CANCEL\r\n"), "{cancel}");
        assert!(cancel.contains("STATUS:CANCELLED\r\n"), "{cancel}");
        assert!(cancel.contains("SEQUENCE:3\r\n"), "{cancel}");
    }

    #[test]
    fn added_exclusions_cancel_the_occurrence() {
        let master = "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n";
        let stored = create(event(master, ""));

        let (updated, messages) = update(
            &stored,
            event(&format!("{master}EXDATE:20260602T090000Z\r\n"), ""),
        );
        let message = only_message(&messages, "a@example.com");
        assert!(message.contains("METHOD:CANCEL\r\n"), "{message}");
        assert!(message.contains("STATUS:CANCELLED\r\n"), "{message}");
        assert!(
            message.contains("RECURRENCE-ID:20260602T090000Z\r\n"),
            "{message}"
        );
        assert!(
            message.contains("DTSTART:20260602T090000Z\r\n"),
            "{message}"
        );
        assert!(!message.contains("RRULE"), "{message}");
        assert!(!message.contains("EXDATE"), "{message}");
        assert!(message.contains("SEQUENCE:1\r\n"), "{message}");
        let stored_text = updated.to_string();
        assert!(stored_text.contains("SEQUENCE:1\r\n"), "{stored_text}");
    }

    #[test]
    fn added_exclusions_share_a_single_cancel() {
        let master = "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n";
        let stored = create(event(master, ""));

        let (_, messages) = update(
            &stored,
            event(
                &format!("{master}EXDATE:20260602T090000Z,20260603T090000Z\r\n"),
                "",
            ),
        );
        let message = only_message(&messages, "a@example.com");
        assert_eq!(
            message
                .lines()
                .filter_map(|line| line.strip_prefix("RECURRENCE-ID:"))
                .collect::<Vec<_>>(),
            ["20260602T090000Z", "20260603T090000Z"],
            "{message}"
        );
        assert_eq!(message.matches("STATUS:CANCELLED").count(), 2, "{message}");
    }

    #[test]
    fn grouped_cancels_stay_within_the_recipient_budget() {
        let attendees = (0..6)
            .map(|index| format!("ATTENDEE:mailto:a{index}@example.com\r\n"))
            .collect::<String>();
        let master = format!("RRULE:FREQ=DAILY;COUNT=40\r\n{attendees}");
        let stored = create(event(&master, ""));
        let exdates = (0..20)
            .map(|index| format!("EXDATE:202606{:02}T090000Z\r\n", index + 2))
            .collect::<String>();

        let mut updated = event(&format!("{master}{exdates}"), "");
        let messages = itip_update(
            &mut updated,
            &stored,
            &[ORGANIZER.to_string()],
            RecipientPolicy {
                visibility: AttendeeVisibility::All,
                max_recipients: 100,
                max_instances: 3000,
            },
        )
        .expect("updates");
        assert_eq!(messages.len(), 1, "{messages:#?}");
        assert_eq!(messages[0].to.len(), 6, "{messages:#?}");
        assert_eq!(
            messages[0]
                .message
                .to_string()
                .matches("BEGIN:VEVENT")
                .count(),
            20,
            "{messages:#?}"
        );
    }

    #[test]
    fn exclusions_reuse_the_surviving_override_start() {
        let master = "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n";
        let instance = concat!(
            "BEGIN:VEVENT\r\n",
            "UID:sequence\r\n",
            "RECURRENCE-ID:20260602T090000Z\r\n",
            "DTSTART:20260602T140000Z\r\n",
            "SEQUENCE:0\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:a@example.com\r\n",
            "END:VEVENT\r\n"
        );
        let stored = create(event(master, instance));

        let (_, messages) = update(
            &stored,
            event(&format!("{master}EXDATE:20260602T090000Z\r\n"), instance),
        );
        let message = only_message(&messages, "a@example.com");
        assert!(
            message.contains("RECURRENCE-ID:20260602T090000Z\r\n"),
            "{message}"
        );
        assert!(
            message.contains("DTSTART:20260602T140000Z\r\n"),
            "{message}"
        );
    }

    #[test]
    fn exclusions_match_the_time_zone_of_their_entry() {
        let master = concat!(
            "RRULE:FREQ=DAILY;COUNT=5\r\n",
            "ATTENDEE:mailto:a@example.com\r\n"
        );
        let stored = create(event(master, ""));

        let (_, messages) = update(
            &stored,
            event(
                &format!(
                    "{master}EXDATE;TZID=Europe/Berlin:20260602T090000\r\nEXDATE;TZID=America/New_York:20260602T090000\r\n"
                ),
                "",
            ),
        );
        let message = only_message(&messages, "a@example.com");
        assert_eq!(
            message
                .lines()
                .filter(|line| line.starts_with("RECURRENCE-ID"))
                .collect::<Vec<_>>(),
            [
                "RECURRENCE-ID;TZID=Europe/Berlin:20260602T090000",
                "RECURRENCE-ID;TZID=America/New_York:20260602T090000"
            ],
            "{message}"
        );
    }

    #[test]
    fn todo_exclusions_drop_the_master_due_date() {
        let todo = |exdate: &str| {
            ICalendar::parse(format!(
                concat!(
                    "BEGIN:VCALENDAR\r\n",
                    "BEGIN:VTODO\r\n",
                    "UID:task\r\n",
                    "DTSTART:20260601T090000Z\r\n",
                    "DUE:20260601T100000Z\r\n",
                    "RRULE:FREQ=DAILY;COUNT=5\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE:mailto:a@example.com\r\n",
                    "{}",
                    "END:VTODO\r\n",
                    "END:VCALENDAR\r\n"
                ),
                exdate
            ))
            .expect("valid iCalendar")
        };
        let stored = create(todo(""));

        let (_, messages) = update(&stored, todo("EXDATE:20260602T090000Z\r\n"));
        let message = only_message(&messages, "a@example.com");
        assert!(!message.contains("DUE:"), "{message}");
        assert!(
            message.contains("DTSTART:20260602T090000Z\r\n"),
            "{message}"
        );
    }

    #[test]
    fn exclusions_without_recipients_send_nothing() {
        let master =
            "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE;PARTSTAT=DECLINED:mailto:a@example.com\r\n";
        let stored = event(master, "");

        let mut updated = event(&format!("{master}EXDATE:20260602T090000Z\r\n"), "");
        assert!(
            itip_update(&mut updated, &stored, &[ORGANIZER.to_string()], policy()).is_err(),
            "expected no scheduling messages"
        );
    }

    #[test]
    fn exclusions_without_a_recurrence_send_nothing() {
        let master = "ATTENDEE:mailto:a@example.com\r\n";
        let stored = create(event(master, ""));

        let mut updated = event(&format!("{master}EXDATE:20260602T090000Z\r\n"), "");
        assert!(
            itip_update(&mut updated, &stored, &[ORGANIZER.to_string()], policy(),).is_err(),
            "expected no scheduling messages"
        );
    }

    #[test]
    fn exclusions_combined_with_other_changes_send_a_request() {
        let master = "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n";
        let stored = create(event(master, ""));

        let (_, messages) = update(
            &stored,
            event(
                &format!("{master}LOCATION:Room 1\r\nEXDATE:20260602T090000Z\r\n"),
                "",
            ),
        );
        let message = only_message(&messages, "a@example.com");
        assert!(message.contains("METHOD:REQUEST\r\n"), "{message}");
        assert!(message.contains("EXDATE:20260602T090000Z"), "{message}");
    }

    #[test]
    fn exclusions_of_removed_overrides_are_cancelled_once() {
        let master = "RRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n";
        let stored = create(event(
            master,
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:sequence\r\n",
                "RECURRENCE-ID:20260602T090000Z\r\n",
                "DTSTART:20260602T100000Z\r\n",
                "SEQUENCE:0\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE:mailto:a@example.com\r\n",
                "END:VEVENT\r\n"
            ),
        ));

        let (_, messages) = update(
            &stored,
            event(&format!("{master}EXDATE:20260602T090000Z\r\n"), ""),
        );
        let message = only_message(&messages, "a@example.com");
        assert!(message.contains("METHOD:CANCEL\r\n"), "{message}");
        assert_eq!(message.matches("RECURRENCE-ID").count(), 1, "{message}");
        assert!(message.contains("DTSTART:20260602T100000Z"), "{message}");
    }

    #[test]
    fn all_day_exclusions_keep_the_date_value_type() {
        let all_day = |exdate: &str| {
            ICalendar::parse(format!(
                concat!(
                    "BEGIN:VCALENDAR\r\n",
                    "BEGIN:VEVENT\r\n",
                    "UID:all-day\r\n",
                    "DTSTART;VALUE=DATE:20260601\r\n",
                    "RRULE:FREQ=DAILY;COUNT=5\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE:mailto:a@example.com\r\n",
                    "{}",
                    "END:VEVENT\r\n",
                    "END:VCALENDAR\r\n"
                ),
                exdate
            ))
            .expect("valid iCalendar")
        };
        let stored = create(all_day(""));

        let (_, messages) = update(&stored, all_day("EXDATE;VALUE=DATE:20260602\r\n"));
        let message = only_message(&messages, "a@example.com");
        assert!(
            message.contains("RECURRENCE-ID;VALUE=DATE:20260602\r\n"),
            "{message}"
        );
        assert!(
            message.contains("DTSTART;VALUE=DATE:20260602\r\n"),
            "{message}"
        );
    }

    #[test]
    fn sequences_raised_by_the_client_are_not_incremented_again() {
        let master = |sequence: &str, location: &str| {
            format!(
                "SEQUENCE:{sequence}\r\nLOCATION:{location}\r\nRRULE:FREQ=DAILY;COUNT=5\r\nATTENDEE:mailto:a@example.com\r\n"
            )
        };
        let instance = concat!(
            "BEGIN:VEVENT\r\n",
            "UID:sequence\r\n",
            "RECURRENCE-ID:20260602T090000Z\r\n",
            "DTSTART:20260602T090000Z\r\n",
            "SEQUENCE:0\r\n",
            "LOCATION:Room 9\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:a@example.com\r\n",
            "END:VEVENT\r\n"
        );
        let stored = create(event(&master("0", "Room 1"), instance));
        let sequences = |ical: &str| {
            ical.lines()
                .filter_map(|line| line.strip_prefix("SEQUENCE:"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };

        for (client_sequence, raised_instance) in [("1", false), ("1", true), ("0", false)] {
            let overrides = if raised_instance {
                instance.replace("SEQUENCE:0", "SEQUENCE:1")
            } else {
                instance.to_string()
            };
            let (updated, messages) = update(
                &stored,
                event(&master(client_sequence, "Room 2"), &overrides),
            );
            let request = only_message(&messages, "a@example.com");
            let case =
                format!("client sequence {client_sequence}, raised instance {raised_instance}");
            assert_eq!(sequences(&request), ["1", "1"], "{case}\n{request}");
            let stored_text = updated.to_string();
            assert_eq!(sequences(&stored_text), ["1", "1"], "{case}\n{stored_text}");
        }
    }
}
