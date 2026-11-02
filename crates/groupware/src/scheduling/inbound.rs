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
        if matches!(
            method,
            ICalendarMethod::Request | ICalendarMethod::Add | ICalendarMethod::Cancel
        ) && snapshots.organizer.email.email != sender
        {
            return Err(ItipError::SenderIsNotOrganizer);
        }

        // Handle organizer and attendees updates
        match method {
            ICalendarMethod::Request => {
                let full_update_sequence = itip_snapshots
                    .components
                    .get(&InstanceId::Main)
                    .map(|snapshot| snapshot.sequence.unwrap_or_default());
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
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

                if let Some(sequence) = full_update_sequence {
                    for (instance_id, snapshot) in &snapshots.components {
                        if snapshot.sequence.unwrap_or_default() <= sequence
                            && !itip_snapshots.components.contains_key(instance_id)
                        {
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
    itip: &ICalendar,
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

    if !remove_component_ids.is_empty() && !ical.remove_component_ids(&remove_component_ids) {
        return Err(ItipError::CannotModifyInstance);
    }

    merge_timezones(ical, itip);
    Ok(())
}

fn merge_timezones(ical: &mut ICalendar, itip: &ICalendar) {
    let Some(root) = ical
        .components
        .first()
        .filter(|root| root.component_type == ICalendarComponentType::VCalendar)
    else {
        return;
    };
    let mut insert_at = root
        .component_ids
        .iter()
        .position(|component_id| {
            ical.component_by_id(*component_id)
                .is_none_or(|comp| comp.component_type != ICalendarComponentType::VTimezone)
        })
        .unwrap_or(root.component_ids.len());

    for tz in itip.timezones() {
        let Some(tz_id) = timezone_id(tz) else {
            continue;
        };

        let mut is_referenced = false;
        for component in &ical.components {
            if component.component_type == ICalendarComponentType::VTimezone {
                if timezone_id(component) == Some(tz_id) {
                    is_referenced = false;
                    break;
                }
            } else if !is_referenced {
                is_referenced = component
                    .entries
                    .iter()
                    .any(|entry| entry.tz_id() == Some(tz_id));
            }
        }
        if !is_referenced {
            continue;
        }

        let tz_component_id = ical.components.len() as u32;
        ical.components.reserve(tz.component_ids.len() + 1);
        ical.components.push(ICalendarComponent {
            component_type: ICalendarComponentType::VTimezone,
            entries: tz.entries.clone(),
            component_ids: Vec::new(),
        });
        ical.components.extend(
            tz.component_ids
                .iter()
                .filter_map(|component_id| itip.component_by_id(*component_id))
                .map(|item| ICalendarComponent {
                    component_type: item.component_type.clone(),
                    entries: item.entries.clone(),
                    component_ids: Vec::new(),
                }),
        );
        let last_item_id = ical.components.len() as u32;
        if let Some(tz_component) = ical.components.get_mut(tz_component_id as usize) {
            tz_component.component_ids = (tz_component_id + 1..last_item_id).collect();
        }
        if let Some(root) = ical.components.first_mut() {
            root.component_ids.insert(insert_at, tz_component_id);
            insert_at += 1;
        }
    }

    ical.add_missing_timezones();
}

fn timezone_id(component: &ICalendarComponent) -> Option<&str> {
    component
        .property(&ICalendarProperty::Tzid)
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_text())
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/groupware/src/scheduling/inbound/tests.rs"]
mod tests;
