/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    Attendee, InstanceId, ItipError, ItipMessage, ItipSnapshot, ItipSnapshots, RecurrenceId,
    organizer::organizer_request_full,
    recipient::{RecipientPolicy, itip_messages_per_recipient, series::Series},
};
use ahash::AHashSet;
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
    ICalendarParameter, ICalendarParameterName, ICalendarProperty, ICalendarStatus, ICalendarValue,
    Uri,
};

#[derive(Debug)]
pub enum MergeAction {
    AddEntries {
        component_id: u16,
        entries: Vec<ICalendarEntry>,
    },
    RemoveEntries {
        component_id: u16,
        entries: AHashSet<ICalendarProperty>,
    },
    AddParameters {
        component_id: u16,
        entry_id: u16,
        parameters: Vec<ICalendarParameter>,
    },
    RemoveParameters {
        component_id: u16,
        entry_id: u16,
        parameters: Vec<ICalendarParameterName>,
    },
    AddComponent {
        components: Vec<ICalendarComponent>,
    },
    RemoveComponent {
        component_id: u16,
    },
}

enum EntryChange {
    Parameters {
        entry_id: u16,
        remove: Vec<ICalendarParameterName>,
        add: Vec<ICalendarParameter>,
    },
    Entries {
        remove: AHashSet<ICalendarProperty>,
        add: Vec<ICalendarEntry>,
    },
}

pub enum MergeResult {
    Actions(Vec<MergeAction>),
    Message(ItipMessage<ICalendar>),
    None,
}

pub fn itip_process_message(
    ical: &ICalendar,
    snapshots: ItipSnapshots<'_>,
    itip: &ICalendar,
    itip_snapshots: ItipSnapshots<'_>,
    sender: String,
    policy: RecipientPolicy,
) -> Result<MergeResult, ItipError> {
    if snapshots.organizer.email != itip_snapshots.organizer.email {
        return Err(ItipError::OrganizerMismatch);
    }

    let method = itip_method(itip)?;
    let mut merge_actions = Vec::new();

    if snapshots.organizer.email.is_local {
        // Handle attendee updates
        if snapshots.organizer.email.email == sender {
            return Err(ItipError::OrganizerIsLocalAddress);
        }
        match method {
            ICalendarMethod::Reply => {
                handle_reply(
                    ical,
                    &snapshots,
                    &itip_snapshots,
                    &sender,
                    policy.max_instances,
                    &mut merge_actions,
                )?;
            }
            ICalendarMethod::Refresh => {
                if !snapshots
                    .components
                    .values()
                    .any(|instance| instance.attendee_by_email(&sender).is_some())
                {
                    return Err(ItipError::SenderIsNotParticipant(sender));
                }
                let message = organizer_request_full(ical, &snapshots, None, false)?
                    .into_iter()
                    .next()
                    .ok_or(ItipError::NothingToSend)?;
                return itip_messages_per_recipient(
                    vec![ItipMessage {
                        to: vec![sender],
                        ..message
                    }],
                    policy,
                )?
                .into_iter()
                .next()
                .map(MergeResult::Message)
                .ok_or(ItipError::NothingToSend);
            }
            _ => return Err(ItipError::UnsupportedMethod(method.clone())),
        }
    } else {
        // Handle organizer and attendees updates
        match method {
            ICalendarMethod::Request => {
                let mut is_full_update = false;
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    is_full_update = is_full_update || instance_id == &InstanceId::Main;
                    let itip_component = &itip.components[itip_snapshot.comp_id as usize];

                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        // Merge instances
                        if itip_snapshot.sequence.unwrap_or_default()
                            >= snapshot.sequence.unwrap_or_default()
                        {
                            let mut changed_entries = itip_snapshot
                                .entries
                                .symmetric_difference(&snapshot.entries)
                                .map(|entry| entry.name.clone())
                                .collect::<AHashSet<_>>();
                            if itip_snapshot.attendees != snapshot.attendees {
                                changed_entries.insert(ICalendarProperty::Attendee);
                            }
                            if itip_snapshot.dtstamp.is_some()
                                && itip_snapshot.dtstamp != snapshot.dtstamp
                            {
                                changed_entries.insert(ICalendarProperty::Dtstamp);
                            }
                            changed_entries.insert(ICalendarProperty::Sequence);

                            if !changed_entries.is_empty() {
                                let entries = itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| changed_entries.contains(&entry.name))
                                    .cloned()
                                    .collect();
                                merge_actions.push(MergeAction::RemoveEntries {
                                    component_id: snapshot.comp_id,
                                    entries: changed_entries,
                                });
                                merge_actions.push(MergeAction::AddEntries {
                                    component_id: snapshot.comp_id,
                                    entries,
                                });
                            }
                        } else {
                            return Err(ItipError::OutOfSequence);
                        }
                    } else {
                        // Add instance
                        merge_actions.push(MergeAction::AddComponent {
                            components: vec![ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(entry.name, ICalendarProperty::Other(_))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            }],
                        });
                    }
                }

                if is_full_update {
                    for (instance_id, snapshot) in &snapshots.components {
                        if !itip_snapshots.components.contains_key(instance_id) {
                            // Remove instance
                            merge_actions.push(MergeAction::RemoveComponent {
                                component_id: snapshot.comp_id,
                            });
                        }
                    }
                }
            }
            ICalendarMethod::Add => {
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if !snapshots.components.contains_key(instance_id) {
                        let itip_component = &itip.components[itip_snapshot.comp_id as usize];
                        merge_actions.push(MergeAction::AddComponent {
                            components: vec![ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(entry.name, ICalendarProperty::Other(_))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            }],
                        });
                    }
                }
            }
            ICalendarMethod::Cancel => {
                let mut cancel_all_instances = false;
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        if itip_snapshot.sequence.unwrap_or_default()
                            >= snapshot.sequence.unwrap_or_default()
                        {
                            // Cancel instance
                            let itip_component = itip_snapshot.comp;
                            merge_actions.push(MergeAction::RemoveEntries {
                                component_id: snapshot.comp_id,
                                entries: [
                                    ICalendarProperty::Organizer,
                                    ICalendarProperty::Attendee,
                                    ICalendarProperty::Status,
                                    ICalendarProperty::Sequence,
                                ]
                                .into_iter()
                                .collect(),
                            });
                            merge_actions.push(MergeAction::AddEntries {
                                component_id: snapshot.comp_id,
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::Organizer
                                                | ICalendarProperty::Attendee
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: [ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )]
                                        .into(),
                                    }])
                                    .collect(),
                            });
                            cancel_all_instances =
                                cancel_all_instances || instance_id == &InstanceId::Main;
                        } else {
                            return Err(ItipError::OutOfSequence);
                        }
                    } else {
                        let itip_component = itip_snapshot.comp;
                        merge_actions.push(MergeAction::AddComponent {
                            components: vec![ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(
                                            entry.name,
                                            ICalendarProperty::Status | ICalendarProperty::Other(_)
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: [ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )]
                                        .into(),
                                    }])
                                    .collect(),
                                component_ids: vec![],
                            }],
                        });
                    }
                }

                if cancel_all_instances {
                    // Remove all instances
                    let itip_main = itip_snapshots.components.get(&InstanceId::Main).unwrap();
                    let itip_component = itip_main.comp;
                    for (instance_id, snapshot) in &snapshots.components {
                        if !itip_snapshots.components.contains_key(instance_id) {
                            merge_actions.push(MergeAction::RemoveEntries {
                                component_id: snapshot.comp_id,
                                entries: [
                                    ICalendarProperty::Organizer,
                                    ICalendarProperty::Attendee,
                                    ICalendarProperty::Status,
                                ]
                                .into_iter()
                                .collect(),
                            });
                            merge_actions.push(MergeAction::AddEntries {
                                component_id: snapshot.comp_id,
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::Organizer
                                                | ICalendarProperty::Attendee
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: [ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )]
                                        .into(),
                                    }])
                                    .collect(),
                            });
                        }
                    }
                }
            }
            ICalendarMethod::Reply
                if itip_snapshots.components.values().any(|snapshot| {
                    snapshot.external_attendees().any(|a| {
                        a.email.email == sender && a.delegated_from.iter().any(|a| a.is_local)
                    })
                }) =>
            {
                handle_reply(
                    ical,
                    &snapshots,
                    &itip_snapshots,
                    &sender,
                    policy.max_instances,
                    &mut merge_actions,
                )?;
            }
            _ => return Err(ItipError::UnsupportedMethod(method.clone())),
        }
    }

    if !merge_actions.is_empty() {
        Ok(MergeResult::Actions(merge_actions))
    } else {
        Ok(MergeResult::None)
    }
}

pub fn itip_import_message(ical: &mut ICalendar) -> Result<(), ItipError> {
    let mut expect_object_type = None;
    for comp in ical.components.iter_mut() {
        if comp.component_type.is_scheduling_object() {
            match expect_object_type {
                Some(expected) if expected != &comp.component_type => {
                    return Err(ItipError::MultipleObjectTypes);
                }
                None => {
                    expect_object_type = Some(&comp.component_type);
                }
                _ => {}
            }
        } else if comp.component_type == ICalendarComponentType::VCalendar {
            comp.entries
                .retain(|entry| !matches!(entry.name, ICalendarProperty::Method));
        }
    }

    Ok(())
}

fn handle_reply(
    ical: &ICalendar,
    snapshots: &ItipSnapshots<'_>,
    itip_snapshots: &ItipSnapshots<'_>,
    sender: &str,
    max_instances: usize,
    merge_actions: &mut Vec<MergeAction>,
) -> Result<(), ItipError> {
    let replied_dates = itip_snapshots
        .components
        .keys()
        .filter_map(|instance_id| match instance_id {
            InstanceId::Recurrence(recurrence_id) => Some(recurrence_id.date),
            InstanceId::Main => None,
        })
        .collect::<AHashSet<_>>();
    let mut series = None;

    for (instance_id, itip_snapshot) in &itip_snapshots.components {
        let Some(updated_attendee) = itip_snapshot.attendee_by_email(sender) else {
            return Err(ItipError::SenderIsNotParticipant(sender.to_string()));
        };

        if let Some((answered_id, snapshot)) = snapshots.matching_instance(instance_id) {
            let attendee = snapshot
                .attendee_by_email(sender)
                .ok_or_else(|| ItipError::SenderIsNotParticipant(sender.to_string()))?;
            let participation =
                EntryChange::participation(snapshot, attendee, itip_snapshot, updated_attendee);
            if !participation.is_empty() {
                for (other_id, other) in &snapshots.components {
                    if let InstanceId::Recurrence(other_recurrence) = other_id
                        && answered_id.covers(other_recurrence)
                        && !replied_dates.contains(&other_recurrence.date)
                        && let Some(other_attendee) = other.attendee_by_email(sender)
                        && other_attendee == attendee
                    {
                        for change in EntryChange::participation(
                            other,
                            other_attendee,
                            itip_snapshot,
                            updated_attendee,
                        ) {
                            change.push_actions(other.comp_id, merge_actions);
                        }
                    }
                }
            }
            for change in participation
                .into_iter()
                .chain(EntryChange::todo_progress(snapshot, itip_snapshot))
            {
                change.push_actions(snapshot.comp_id, merge_actions);
            }
        } else if let InstanceId::Recurrence(recurrence_id) = instance_id
            && let Some(source) = snapshots.occurrence_source(recurrence_id)
        {
            let attendee = source
                .attendee_by_email(sender)
                .ok_or_else(|| ItipError::SenderIsNotParticipant(sender.to_string()))?;
            let progress = EntryChange::todo_progress(source, itip_snapshot);
            let reports_progress = matches!(
                &progress,
                Some(EntryChange::Entries { add, .. })
                    if add.iter().any(|entry| !source.comp.entries.contains(entry))
            );
            if !attendee.answers_differently(updated_attendee) && !reports_progress {
                continue;
            }
            let series = series.get_or_insert_with(|| {
                Series::new(
                    ical,
                    snapshots.main_instance().map(|main| main.comp),
                    max_instances,
                )
            });
            if !series.has_occurrence(recurrence_id.date) {
                continue;
            }

            let mut occurrence = source.comp.clone();
            for change in
                EntryChange::participation(source, attendee, itip_snapshot, updated_attendee)
                    .into_iter()
                    .chain(progress)
            {
                change.apply(&mut occurrence);
            }
            if let Some(components) = itip_snapshot
                .comp
                .entries
                .get(usize::from(recurrence_id.entry_id))
                .and_then(|entry| series.occurrence(occurrence, entry, recurrence_id.date))
            {
                merge_actions.push(MergeAction::AddComponent { components });
            }
        }
    }

    Ok(())
}

impl EntryChange {
    fn participation(
        snapshot: &ItipSnapshot<'_>,
        attendee: &Attendee<'_>,
        itip_snapshot: &ItipSnapshot<'_>,
        updated_attendee: &Attendee<'_>,
    ) -> Vec<EntryChange> {
        let mut changes = Vec::new();
        let itip_component = itip_snapshot.comp;
        let changed_part_stat = attendee.part_stat != updated_attendee.part_stat;
        let changed_rsvp = attendee.rsvp != updated_attendee.rsvp;
        let changed_delegated_to = attendee.delegated_to != updated_attendee.delegated_to;
        let has_request_status = !itip_snapshot.request_status.is_empty();

        if changed_part_stat || changed_rsvp || changed_delegated_to || has_request_status {
            // Update participant status
            let mut add_parameters = Vec::new();
            let mut remove_parameters = Vec::new();
            if changed_part_stat {
                remove_parameters.push(ICalendarParameterName::Partstat);
                if let Some(part_stat) = updated_attendee.part_stat {
                    add_parameters.push(ICalendarParameter::partstat(part_stat.clone()));
                }
            }

            if changed_rsvp {
                remove_parameters.push(ICalendarParameterName::Rsvp);
                if let Some(rsvp) = updated_attendee.rsvp {
                    add_parameters.push(ICalendarParameter::rsvp(rsvp));
                }
            }

            if changed_delegated_to {
                remove_parameters.push(ICalendarParameterName::DelegatedTo);
                if !updated_attendee.delegated_to.is_empty() {
                    add_parameters.extend(updated_attendee.delegated_to.iter().map(|email| {
                        ICalendarParameter::delegated_to(Uri::Location(email.to_string()))
                    }));
                }
            }

            // RFC 6638 4.2: the status defaults to 2.0 when the reply carries none
            remove_parameters.push(ICalendarParameterName::ScheduleStatus);
            add_parameters.push(ICalendarParameter::schedule_status(if has_request_status {
                itip_snapshot.request_status.join(",")
            } else {
                "2.0".to_string()
            }));

            changes.push(EntryChange::Parameters {
                entry_id: attendee.entry_id,
                remove: remove_parameters,
                add: add_parameters,
            });

            // Add unknown delegated attendees
            for delegated_to in &updated_attendee.delegated_to {
                if let Some(itip_delegated) = itip_snapshot.attendee_by_email(&delegated_to.email) {
                    if let Some(delegated) = snapshot.attendee_by_email(&delegated_to.email) {
                        if delegated != itip_delegated {
                            changes.push(EntryChange::Parameters {
                                entry_id: delegated.entry_id,
                                remove: vec![
                                    ICalendarParameterName::DelegatedTo,
                                    ICalendarParameterName::DelegatedFrom,
                                    ICalendarParameterName::Partstat,
                                    ICalendarParameterName::Rsvp,
                                    ICalendarParameterName::ScheduleStatus,
                                    ICalendarParameterName::Role,
                                ],
                                add: itip_component.entries[itip_delegated.entry_id as usize]
                                    .params
                                    .iter()
                                    .filter(|param| {
                                        matches!(
                                            param.name,
                                            ICalendarParameterName::DelegatedTo
                                                | ICalendarParameterName::DelegatedFrom
                                                | ICalendarParameterName::Partstat
                                                | ICalendarParameterName::Rsvp
                                                | ICalendarParameterName::ScheduleStatus
                                                | ICalendarParameterName::Role
                                        )
                                    })
                                    .cloned()
                                    .collect(),
                            });
                        }
                    } else {
                        changes.push(EntryChange::Entries {
                            remove: AHashSet::new(),
                            add: vec![
                                itip_component.entries[itip_delegated.entry_id as usize].clone(),
                            ],
                        });
                    }
                }
            }
        }

        changes
    }

    fn todo_progress(
        snapshot: &ItipSnapshot<'_>,
        itip_snapshot: &ItipSnapshot<'_>,
    ) -> Option<EntryChange> {
        // Add changed properties for VTODO
        if snapshot.comp.component_type != ICalendarComponentType::VTodo {
            return None;
        }

        let mut remove_entries = AHashSet::new();
        let mut add_entries = Vec::new();
        for entry in itip_snapshot.comp.entries.iter() {
            if matches!(
                entry.name,
                ICalendarProperty::PercentComplete
                    | ICalendarProperty::Status
                    | ICalendarProperty::Completed
            ) {
                remove_entries.insert(entry.name.clone());
                add_entries.push(entry.clone());
            }
        }

        (!add_entries.is_empty()).then_some(EntryChange::Entries {
            remove: remove_entries,
            add: add_entries,
        })
    }

    fn push_actions(self, component_id: u16, merge_actions: &mut Vec<MergeAction>) {
        match self {
            EntryChange::Parameters {
                entry_id,
                remove,
                add,
            } => {
                merge_actions.push(MergeAction::RemoveParameters {
                    component_id,
                    entry_id,
                    parameters: remove,
                });
                merge_actions.push(MergeAction::AddParameters {
                    component_id,
                    entry_id,
                    parameters: add,
                });
            }
            EntryChange::Entries { remove, add } => {
                if !remove.is_empty() {
                    merge_actions.push(MergeAction::RemoveEntries {
                        component_id,
                        entries: remove,
                    });
                }
                merge_actions.push(MergeAction::AddEntries {
                    component_id,
                    entries: add,
                });
            }
        }
    }

    fn apply(self, component: &mut ICalendarComponent) {
        match self {
            EntryChange::Parameters {
                entry_id,
                remove,
                add,
            } => {
                if let Some(entry) = component.entries.get_mut(usize::from(entry_id)) {
                    entry.params.retain(|param| !remove.contains(&param.name));
                    entry.params.extend(add);
                }
            }
            EntryChange::Entries { remove, add } => {
                component
                    .entries
                    .retain(|entry| !remove.contains(&entry.name));
                component.entries.extend(add);
            }
        }
    }
}

impl InstanceId {
    fn covers(&self, occurrence: &RecurrenceId) -> bool {
        match self {
            InstanceId::Main => true,
            InstanceId::Recurrence(range) => range.this_and_future && occurrence.date > range.date,
        }
    }
}

impl Attendee<'_> {
    fn answers_differently(&self, reply: &Attendee<'_>) -> bool {
        self.part_stat != reply.part_stat
            || self.rsvp != reply.rsvp
            || self.delegated_to != reply.delegated_to
    }
}

pub fn itip_merge_changes(
    ical: &mut ICalendar,
    changes: Vec<MergeAction>,
) -> Result<(), ItipError> {
    let mut remove_component_ids: Vec<u32> = Vec::new();
    for action in changes {
        match action {
            MergeAction::AddEntries {
                component_id,
                entries,
            } => {
                let component = &mut ical.components[component_id as usize];
                component.entries.extend(entries);
            }
            MergeAction::RemoveEntries {
                component_id,
                entries,
            } => {
                let component = &mut ical.components[component_id as usize];
                component
                    .entries
                    .retain(|entry| !entries.contains(&entry.name));
            }
            MergeAction::AddParameters {
                component_id,
                entry_id,
                parameters,
            } => {
                ical.components[component_id as usize].entries[entry_id as usize]
                    .params
                    .extend(parameters);
            }
            MergeAction::RemoveParameters {
                component_id,
                entry_id,
                parameters,
            } => {
                ical.components[component_id as usize].entries[entry_id as usize]
                    .params
                    .retain(|param| !parameters.contains(&param.name));
            }
            MergeAction::AddComponent { mut components } => {
                let comp_id = ical.components.len() as u32;
                if let Some(root) = ical
                    .components
                    .get_mut(0)
                    .filter(|c| c.component_type == ICalendarComponentType::VCalendar)
                {
                    root.component_ids.push(comp_id);
                    for component_id in components
                        .iter_mut()
                        .flat_map(|component| component.component_ids.iter_mut())
                    {
                        *component_id += comp_id;
                    }
                    ical.components.extend(components);
                }
            }
            MergeAction::RemoveComponent { component_id } => {
                remove_component_ids.push(component_id as u32);
            }
        }
    }

    if remove_component_ids.is_empty() || ical.remove_component_ids(&remove_component_ids) {
        Ok(())
    } else {
        Err(ItipError::CannotModifyInstance)
    }
}

pub fn itip_method(ical: &ICalendar) -> Result<&ICalendarMethod, ItipError> {
    ical.components
        .first()
        .and_then(|comp| {
            comp.entries.iter().find_map(|entry| {
                if entry.name == ICalendarProperty::Method {
                    entry.values.first().and_then(|value| {
                        if let ICalendarValue::Method(method) = value {
                            Some(method)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        })
        .ok_or(ItipError::MissingMethod)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduling::{recipient::AttendeeVisibility, snapshot::itip_snapshot};
    use calcard::common::timezone::Tz;

    const ORGANIZER: &str = "org@example.com";
    const ATTENDEE: &str = "bob@example.com";
    const WEEKLY: &str = "weekly@example.com";
    const RETREAT: &str = "retreat@example.com";

    fn calendar(method: &str, components: &str) -> ICalendar {
        ICalendar::parse(format!(
            "BEGIN:VCALENDAR\r\n{method}VERSION:2.0\r\nPRODID:-//Test//EN\r\n{components}END:VCALENDAR\r\n"
        ))
        .expect("valid iCalendar")
    }

    fn weekly_series(extra: &str, overrides: &str) -> ICalendar {
        calendar(
            "",
            &format!(
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:weekly@example.com\r\n",
                    "SEQUENCE:2\r\n",
                    "DTSTAMP:20250101T000000Z\r\n",
                    "DTSTART;TZID=Europe/Berlin:20250106T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20250106T100000\r\n",
                    "RRULE:FREQ=WEEKLY;COUNT=4\r\n",
                    "{}",
                    "SUMMARY:Weekly sync\r\n",
                    "LOCATION:Room 1\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE;PARTSTAT=ACCEPTED:mailto:org@example.com\r\n",
                    "ATTENDEE;PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:bob@example.com\r\n",
                    "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.com\r\n",
                    "BEGIN:VALARM\r\n",
                    "ACTION:DISPLAY\r\n",
                    "TRIGGER:-PT15M\r\n",
                    "DESCRIPTION:Reminder\r\n",
                    "END:VALARM\r\n",
                    "END:VEVENT\r\n",
                    "{}"
                ),
                extra, overrides
            ),
        )
    }

    fn moved_this_and_future() -> &'static str {
        concat!(
            "BEGIN:VEVENT\r\n",
            "UID:weekly@example.com\r\n",
            "SEQUENCE:3\r\n",
            "DTSTAMP:20250101T000000Z\r\n",
            "RECURRENCE-ID;RANGE=THISANDFUTURE;TZID=Europe/Berlin:20250113T090000\r\n",
            "DTSTART;TZID=Europe/Berlin:20250113T110000\r\n",
            "DTEND;TZID=Europe/Berlin:20250113T120000\r\n",
            "SUMMARY:Moved sync\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE;PARTSTAT=ACCEPTED:mailto:org@example.com\r\n",
            "ATTENDEE;PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:bob@example.com\r\n",
            "END:VEVENT\r\n"
        )
    }

    fn reply(uid: &str, sender: &str, recurrence_id: &str) -> ICalendar {
        answer(uid, sender, "DECLINED", &format!("{recurrence_id}\r\n"))
    }

    fn answer(uid: &str, sender: &str, part_stat: &str, recurrence_id: &str) -> ICalendar {
        calendar(
            "METHOD:REPLY\r\n",
            &format!(
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:{}\r\n",
                    "SEQUENCE:2\r\n",
                    "DTSTAMP:20250102T000000Z\r\n",
                    "{}",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE;PARTSTAT={}:mailto:{}\r\n",
                    "REQUEST-STATUS:2.0;Success\r\n",
                    "END:VEVENT\r\n"
                ),
                uid, recurrence_id, part_stat, sender
            ),
        )
    }

    fn receive(ical: &mut ICalendar, reply: &ICalendar, sender: &str) -> Result<bool, ItipError> {
        receive_within(ical, reply, sender, 3000)
    }

    fn receive_within(
        ical: &mut ICalendar,
        reply: &ICalendar,
        sender: &str,
        max_instances: usize,
    ) -> Result<bool, ItipError> {
        let accounts = [ORGANIZER.to_string()];
        let snapshots = itip_snapshot(ical, &accounts, false)?;
        let itip_snapshots = itip_snapshot(reply, &accounts, false)?;
        match itip_process_message(
            ical,
            snapshots,
            reply,
            itip_snapshots,
            sender.to_string(),
            RecipientPolicy {
                visibility: AttendeeVisibility::All,
                max_recipients: usize::MAX,
                max_instances,
            },
        )? {
            MergeResult::Actions(actions) => itip_merge_changes(ical, actions).map(|()| true),
            MergeResult::Message(_) | MergeResult::None => Ok(false),
        }
    }

    fn occurrence(ical: &ICalendar, recurrence_id: &str) -> String {
        ical.to_string()
            .split("BEGIN:VEVENT\r\n")
            .filter_map(|block| block.split_once("END:VEVENT").map(|(block, _)| block))
            .find(|block| {
                block
                    .lines()
                    .any(|line| line.starts_with("RECURRENCE-ID") && line.ends_with(recurrence_id))
            })
            .unwrap_or_default()
            .to_string()
    }

    fn starts(ical: &ICalendar) -> Vec<String> {
        let mut starts = ical
            .expand_dates(Tz::UTC, 100)
            .events
            .iter()
            .map(|event| event.start.to_string())
            .collect::<Vec<_>>();
        starts.sort();
        starts
    }

    #[test]
    fn a_reply_for_one_occurrence_copies_it_from_the_series() {
        let mut ical = weekly_series("", "");
        assert!(matches!(
            receive(
                &mut ical,
                &reply(WEEKLY, ATTENDEE, "RECURRENCE-ID:20250113T080000Z"),
                ATTENDEE
            ),
            Ok(true)
        ));

        let occurrence = occurrence(&ical, "20250113T090000");
        for line in [
            "RECURRENCE-ID;TZID=Europe/Berlin:20250113T090000",
            "DTSTART;TZID=Europe/Berlin:20250113T090000",
            "DTEND;TZID=Europe/Berlin:20250113T100000",
            "SEQUENCE:2",
            "DTSTAMP:20250101T000000Z",
            "SUMMARY:Weekly sync",
            "LOCATION:Room 1",
            "ATTENDEE;PARTSTAT=ACCEPTED:mailto:org@example.com",
            "ATTENDEE;PARTSTAT=DECLINED;SCHEDULE-STATUS=2.0:mailto:bob@example.com",
            "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.com",
            "BEGIN:VALARM",
            "TRIGGER:-PT15M",
        ] {
            assert!(
                occurrence
                    .lines()
                    .any(|occurrence_line| occurrence_line == line),
                "RFC 6638 Section 4.2: missing {line}\n{ical}"
            );
        }
        assert!(!occurrence.contains("RRULE"), "{ical}");
        assert!(
            ical.to_string().contains(
                "ATTENDEE;PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:bob@example.com\r\n"
            ),
            "the series keeps the attendee's answer\n{ical}"
        );
        assert_eq!(
            starts(&ical),
            [
                "2025-01-06T09:00:00+01:00",
                "2025-01-13T09:00:00+01:00",
                "2025-01-20T09:00:00+01:00",
                "2025-01-27T09:00:00+01:00"
            ],
            "{ical}"
        );
    }

    #[test]
    fn a_reply_for_an_occurrence_the_series_does_not_have_is_ignored() {
        for recurrence_id in [
            "RECURRENCE-ID;TZID=Europe/Berlin:20250127T090000",
            "RECURRENCE-ID;TZID=Europe/Berlin:20250114T090000",
        ] {
            let mut ical = weekly_series("EXDATE;TZID=Europe/Berlin:20250127T090000\r\n", "");
            let original = ical.to_string();
            assert!(
                matches!(
                    receive(&mut ical, &reply(WEEKLY, ATTENDEE, recurrence_id), ATTENDEE),
                    Ok(false)
                ),
                "{recurrence_id}"
            );
            assert_eq!(ical.to_string(), original, "{recurrence_id}");
        }
    }

    #[test]
    fn a_reply_for_one_occurrence_from_an_uninvited_sender_is_rejected() {
        let mut ical = weekly_series("", "");
        assert!(matches!(
            receive(
                &mut ical,
                &reply(
                    WEEKLY,
                    "mallory@example.com",
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250113T090000"
                ),
                "mallory@example.com"
            ),
            Err(ItipError::SenderIsNotParticipant(_))
        ));
    }

    #[test]
    fn an_occurrence_after_a_this_and_future_change_copies_that_change() {
        let mut ical = weekly_series("", moved_this_and_future());
        assert!(matches!(
            receive(
                &mut ical,
                &reply(
                    WEEKLY,
                    ATTENDEE,
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250120T090000"
                ),
                ATTENDEE
            ),
            Ok(true)
        ));

        let occurrence = occurrence(&ical, "20250120T090000");
        for line in [
            "RECURRENCE-ID;TZID=Europe/Berlin:20250120T090000",
            "DTSTART;TZID=Europe/Berlin:20250120T110000",
            "DTEND;TZID=Europe/Berlin:20250120T120000",
            "SEQUENCE:3",
            "SUMMARY:Moved sync",
            "ATTENDEE;PARTSTAT=DECLINED;SCHEDULE-STATUS=2.0:mailto:bob@example.com",
        ] {
            assert!(
                occurrence
                    .lines()
                    .any(|occurrence_line| occurrence_line == line),
                "RFC 5545 Section 3.8.4.4: missing {line}\n{ical}"
            );
        }
        assert_eq!(
            starts(&ical),
            [
                "2025-01-06T09:00:00+01:00",
                "2025-01-13T11:00:00+01:00",
                "2025-01-20T11:00:00+01:00",
                "2025-01-27T11:00:00+01:00"
            ],
            "{ical}"
        );
    }

    #[test]
    fn a_reply_without_range_updates_the_override_with_the_same_recurrence_id() {
        let mut ical = weekly_series("", moved_this_and_future());
        assert!(matches!(
            receive(
                &mut ical,
                &reply(
                    WEEKLY,
                    ATTENDEE,
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250113T090000"
                ),
                ATTENDEE
            ),
            Ok(true)
        ));

        assert_eq!(
            ical.to_string().matches("BEGIN:VEVENT").count(),
            2,
            "{ical}"
        );
        let occurrence = occurrence(&ical, "20250113T090000");
        assert!(occurrence.contains("RANGE=THISANDFUTURE"), "{ical}");
        assert!(
            occurrence.lines().any(|line| {
                line == "ATTENDEE;PARTSTAT=DECLINED;SCHEDULE-STATUS=2.0:mailto:bob@example.com"
            }),
            "RFC 5546 Section 2.1.5: UID and RECURRENCE-ID reference the instance\n{ical}"
        );
    }

    #[test]
    fn an_occurrence_of_an_all_day_series_keeps_its_days() {
        let mut ical = calendar(
            "",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:retreat@example.com\r\n",
                "SEQUENCE:0\r\n",
                "DTSTAMP:20250101T000000Z\r\n",
                "DTSTART;VALUE=DATE:20250106\r\n",
                "DTEND;VALUE=DATE:20250108\r\n",
                "RRULE:FREQ=WEEKLY;COUNT=3\r\n",
                "SUMMARY:Retreat\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                "END:VEVENT\r\n"
            ),
        );
        assert!(matches!(
            receive(
                &mut ical,
                &reply(RETREAT, ATTENDEE, "RECURRENCE-ID;VALUE=DATE:20250113"),
                ATTENDEE
            ),
            Ok(true)
        ));

        let occurrence = occurrence(&ical, "20250113");
        for line in [
            "RECURRENCE-ID;VALUE=DATE:20250113",
            "DTSTART;VALUE=DATE:20250113",
            "DTEND;VALUE=DATE:20250115",
            "SUMMARY:Retreat",
        ] {
            assert!(
                occurrence
                    .lines()
                    .any(|occurrence_line| occurrence_line == line),
                "RFC 5545 Section 3.8.5.3: missing {line}\n{ical}"
            );
        }
    }

    #[test]
    fn an_occurrence_from_a_period_lasts_as_long_as_the_period() {
        let mut ical = calendar(
            "",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:review@example.com\r\n",
                "SEQUENCE:0\r\n",
                "DTSTAMP:20250101T000000Z\r\n",
                "DTSTART:20250106T090000Z\r\n",
                "DURATION:PT1H\r\n",
                "RDATE;VALUE=PERIOD:20250110T140000Z/PT3H\r\n",
                "SUMMARY:Review\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                "END:VEVENT\r\n"
            ),
        );
        assert!(matches!(
            receive(
                &mut ical,
                &reply(
                    "review@example.com",
                    ATTENDEE,
                    "RECURRENCE-ID:20250110T140000Z"
                ),
                ATTENDEE
            ),
            Ok(true)
        ));

        let occurrence = occurrence(&ical, "20250110T140000Z");
        for line in [
            "RECURRENCE-ID:20250110T140000Z",
            "DTSTART:20250110T140000Z",
            "DURATION:PT3H",
            "SUMMARY:Review",
        ] {
            assert!(
                occurrence
                    .lines()
                    .any(|occurrence_line| occurrence_line == line),
                "RFC 5545 Section 3.8.5.2: missing {line}\n{ical}"
            );
        }
        assert!(!occurrence.contains("DURATION:PT1H"), "{ical}");
        assert_eq!(
            starts(&ical),
            ["2025-01-06T09:00:00+00:00", "2025-01-10T14:00:00+00:00"],
            "{ical}"
        );
    }

    #[test]
    fn a_reply_that_changes_nothing_adds_no_occurrence() {
        let mut ical = weekly_series("", "");
        let original = ical.to_string();
        assert!(matches!(
            receive(
                &mut ical,
                &answer(
                    WEEKLY,
                    ATTENDEE,
                    "ACCEPTED",
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250113T090000\r\n"
                ),
                ATTENDEE
            ),
            Ok(false)
        ));
        assert_eq!(ical.to_string(), original);
    }

    #[test]
    fn a_series_reply_reaches_occurrences_not_answered_separately() {
        let mut ical = weekly_series("", "");
        for (sender, part_stat, recurrence_id) in [
            (
                ATTENDEE,
                "DECLINED",
                "RECURRENCE-ID;TZID=Europe/Berlin:20250113T090000\r\n",
            ),
            (
                "carol@example.com",
                "DECLINED",
                "RECURRENCE-ID;TZID=Europe/Berlin:20250120T090000\r\n",
            ),
            ("carol@example.com", "ACCEPTED", ""),
        ] {
            assert!(
                matches!(
                    receive(
                        &mut ical,
                        &answer(WEEKLY, sender, part_stat, recurrence_id),
                        sender
                    ),
                    Ok(true)
                ),
                "{sender} {part_stat} {recurrence_id}"
            );
        }

        let accepted = "ATTENDEE;PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:carol@example.com";
        assert!(
            occurrence(&ical, "20250113T090000")
                .lines()
                .any(|line| line == accepted),
            "RFC 6638 Section 4.2: the series answer applies where carol did not answer\n{ical}"
        );
        assert!(
            occurrence(&ical, "20250120T090000").lines().any(|line| {
                line == "ATTENDEE;PARTSTAT=DECLINED;SCHEDULE-STATUS=2.0:mailto:carol@example.com"
            }),
            "carol's own answer for the occurrence stays\n{ical}"
        );
        assert_eq!(ical.to_string().matches(accepted).count(), 2, "{ical}");
    }

    #[test]
    fn a_recurrence_id_the_series_never_generates_is_ignored() {
        for (series, recurrence_id) in [
            (
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:weekly@example.com\r\n",
                    "DTSTAMP:20250101T000000Z\r\n",
                    "DTSTART:20250106T090000Z\r\n",
                    "DTEND:20250106T100000Z\r\n",
                    "SUMMARY:Single\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                    "END:VEVENT\r\n"
                ),
                "RECURRENCE-ID:20250106T090000Z",
            ),
            (
                concat!(
                    "BEGIN:VEVENT\r\n",
                    "UID:weekly@example.com\r\n",
                    "DTSTAMP:20250101T000000Z\r\n",
                    "DTSTART;TZID=Europe/Berlin:20250105T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20250105T100000\r\n",
                    "RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=3\r\n",
                    "SUMMARY:Mondays\r\n",
                    "ORGANIZER:mailto:org@example.com\r\n",
                    "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                    "END:VEVENT\r\n"
                ),
                "RECURRENCE-ID;TZID=Europe/Berlin:20250105T090000",
            ),
        ] {
            let mut ical = calendar("", series);
            let original = ical.to_string();
            assert!(
                matches!(
                    receive(&mut ical, &reply(WEEKLY, ATTENDEE, recurrence_id), ATTENDEE),
                    Ok(false)
                ),
                "RFC 5546 Section 3.2.3: {recurrence_id}"
            );
            assert_eq!(ical.to_string(), original, "{recurrence_id}");
        }
    }

    #[test]
    fn a_this_and_future_shift_is_measured_in_the_series_time_zone() {
        let mut ical = calendar(
            "",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:weekly@example.com\r\n",
                "SEQUENCE:0\r\n",
                "DTSTAMP:20250101T000000Z\r\n",
                "DTSTART;TZID=Europe/Berlin:20250315T090000\r\n",
                "DTEND;TZID=Europe/Berlin:20250315T100000\r\n",
                "RRULE:FREQ=WEEKLY;COUNT=6\r\n",
                "SUMMARY:Saturday sync\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                "END:VEVENT\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:weekly@example.com\r\n",
                "SEQUENCE:1\r\n",
                "DTSTAMP:20250101T000000Z\r\n",
                "RECURRENCE-ID;RANGE=THISANDFUTURE:20250322T080000Z\r\n",
                "DTSTART;TZID=Europe/Berlin:20250323T090000\r\n",
                "DTEND;TZID=Europe/Berlin:20250323T100000\r\n",
                "SUMMARY:Sunday sync\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                "END:VEVENT\r\n"
            ),
        );
        let before = starts(&ical);
        assert!(matches!(
            receive(
                &mut ical,
                &reply(
                    WEEKLY,
                    ATTENDEE,
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250329T090000"
                ),
                ATTENDEE
            ),
            Ok(true)
        ));

        let occurrence = occurrence(&ical, "20250329T090000");
        for line in [
            "DTSTART;TZID=Europe/Berlin:20250330T090000",
            "DTEND;TZID=Europe/Berlin:20250330T100000",
            "SUMMARY:Sunday sync",
        ] {
            assert!(
                occurrence
                    .lines()
                    .any(|occurrence_line| occurrence_line == line),
                "RFC 5545 Section 3.8.4.4: missing {line}\n{ical}"
            );
        }
        assert_eq!(starts(&ical), before, "the reply moves nothing\n{ical}");
    }

    #[test]
    fn a_period_with_an_end_keeps_its_exact_end() {
        let mut ical = calendar(
            "",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:weekly@example.com\r\n",
                "SEQUENCE:0\r\n",
                "DTSTAMP:20250101T000000Z\r\n",
                "DTSTART;TZID=Europe/Berlin:20250328T120000\r\n",
                "DURATION:PT1H\r\n",
                "RDATE;VALUE=PERIOD;TZID=Europe/Berlin:20250329T120000/20250331T120000\r\n",
                "SUMMARY:Offsite\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com\r\n",
                "END:VEVENT\r\n"
            ),
        );
        assert!(matches!(
            receive(
                &mut ical,
                &reply(
                    WEEKLY,
                    ATTENDEE,
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250329T120000"
                ),
                ATTENDEE
            ),
            Ok(true)
        ));

        let occurrence = occurrence(&ical, "20250329T120000");
        assert!(
            occurrence
                .lines()
                .any(|line| line == "DTEND;TZID=Europe/Berlin:20250331T120000"),
            "RFC 5545 Section 3.8.5.2: the period ends where it says, across the DST change\n{ical}"
        );
        assert!(!occurrence.contains("DURATION"), "{ical}");
    }

    #[test]
    fn a_series_as_long_as_the_expansion_limit_is_complete() {
        let mut ical = weekly_series("", "");
        let original = ical.to_string();
        assert!(matches!(
            receive_within(
                &mut ical,
                &reply(
                    WEEKLY,
                    ATTENDEE,
                    "RECURRENCE-ID;TZID=Europe/Berlin:20250203T090000"
                ),
                ATTENDEE,
                4
            ),
            Ok(false)
        ));
        assert_eq!(ical.to_string(), original);
    }
}
