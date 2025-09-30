/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    InstanceId, ItipError, ItipMessage, ItipSnapshots, organizer::organizer_request_full,
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
        component: ICalendarComponent,
    },
    RemoveComponent {
        component_id: u16,
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
                handle_reply(&snapshots, &itip_snapshots, &sender, &mut merge_actions)?;
            }
            ICalendarMethod::Refresh => {
                return organizer_request_full(ical, &snapshots, None, false).and_then(
                    |messages| {
                        messages
                            .into_iter()
                            .next()
                            .map(|mut message| {
                                message.to = vec![sender];
                                MergeResult::Message(message)
                            })
                            .ok_or(ItipError::NothingToSend)
                    },
                );
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
                            component: ICalendarComponent {
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
                            },
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
                            component: ICalendarComponent {
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
                            },
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
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
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
                            component: ICalendarComponent {
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
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
                                    }])
                                    .collect(),
                                component_ids: vec![],
                            },
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
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
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
                handle_reply(&snapshots, &itip_snapshots, &sender, &mut merge_actions)?;
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
    snapshots: &ItipSnapshots<'_>,
    itip_snapshots: &ItipSnapshots<'_>,
    sender: &str,
    merge_actions: &mut Vec<MergeAction>,
) -> Result<(), ItipError> {
    for (instance_id, itip_snapshot) in &itip_snapshots.components {
        if let Some(snapshot) = snapshots.components.get(instance_id) {
            if let (Some(attendee), Some(updated_attendee)) = (
                snapshot.attendee_by_email(sender),
                itip_snapshot.attendee_by_email(sender),
            ) {
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
                            add_parameters.extend(updated_attendee.delegated_to.iter().map(
                                |email| {
                                    ICalendarParameter::delegated_to(Uri::Location(
                                        email.to_string(),
                                    ))
                                },
                            ));
                        }
                    }

                    if has_request_status {
                        remove_parameters.push(ICalendarParameterName::ScheduleStatus);
                        add_parameters.push(ICalendarParameter::schedule_status(
                            itip_snapshot.request_status.join(","),
                        ));
                    }

                    merge_actions.push(MergeAction::RemoveParameters {
                        component_id: snapshot.comp_id,
                        entry_id: attendee.entry_id,
                        parameters: remove_parameters,
                    });
                    merge_actions.push(MergeAction::AddParameters {
                        component_id: snapshot.comp_id,
                        entry_id: attendee.entry_id,
                        parameters: add_parameters,
                    });

                    // Add unknown delegated attendees
                    for delegated_to in &updated_attendee.delegated_to {
                        if let Some(itip_delegated) =
                            itip_snapshot.attendee_by_email(&delegated_to.email)
                        {
                            if let Some(delegated) = snapshot.attendee_by_email(&delegated_to.email)
                            {
                                if delegated != itip_delegated {
                                    merge_actions.push(MergeAction::RemoveParameters {
                                        component_id: snapshot.comp_id,
                                        entry_id: delegated.entry_id,
                                        parameters: vec![
                                            ICalendarParameterName::DelegatedTo,
                                            ICalendarParameterName::DelegatedFrom,
                                            ICalendarParameterName::Partstat,
                                            ICalendarParameterName::Rsvp,
                                            ICalendarParameterName::ScheduleStatus,
                                            ICalendarParameterName::Role,
                                        ],
                                    });
                                    merge_actions.push(MergeAction::AddParameters {
                                        component_id: snapshot.comp_id,
                                        entry_id: delegated.entry_id,
                                        parameters: itip_component.entries
                                            [itip_delegated.entry_id as usize]
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
                                merge_actions.push(MergeAction::AddEntries {
                                    component_id: snapshot.comp_id,
                                    entries: vec![
                                        itip_component.entries[itip_delegated.entry_id as usize]
                                            .clone(),
                                    ],
                                });
                            }
                        }
                    }
                }

                // Add changed properties for VTODO
                if snapshot.comp.component_type == ICalendarComponentType::VTodo {
                    let mut remove_entries = AHashSet::new();
                    let mut add_entries = Vec::new();

                    for entry in itip_component.entries.iter() {
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

                    if !add_entries.is_empty() {
                        merge_actions.push(MergeAction::RemoveEntries {
                            component_id: snapshot.comp_id,
                            entries: remove_entries,
                        });
                        merge_actions.push(MergeAction::AddEntries {
                            component_id: snapshot.comp_id,
                            entries: add_entries,
                        });
                    }
                }
            } else {
                return Err(ItipError::SenderIsNotParticipant(sender.to_string()));
            }
        } else if itip_snapshot.attendee_by_email(sender).is_some() {
            // Add component
            let itip_component = itip_snapshot.comp;
            let is_todo = itip_component.component_type == ICalendarComponentType::VTodo;
            merge_actions.push(MergeAction::AddComponent {
                component: ICalendarComponent {
                    component_type: itip_component.component_type.clone(),
                    entries: itip_component
                        .entries
                        .iter()
                        .filter(|entry| {
                            matches!(
                                entry.name,
                                ICalendarProperty::Organizer
                                    | ICalendarProperty::Attendee
                                    | ICalendarProperty::Uid
                                    | ICalendarProperty::Dtstamp
                                    | ICalendarProperty::Sequence
                                    | ICalendarProperty::RecurrenceId
                            ) || (is_todo
                                && matches!(
                                    entry.name,
                                    ICalendarProperty::PercentComplete
                                        | ICalendarProperty::Status
                                        | ICalendarProperty::Completed
                                ))
                        })
                        .cloned()
                        .collect(),
                    component_ids: vec![],
                },
            });
        } else {
            return Err(ItipError::SenderIsNotParticipant(sender.to_string()));
        }
    }

    Ok(())
}

pub fn itip_merge_changes(ical: &mut ICalendar, changes: Vec<MergeAction>) {
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
            MergeAction::AddComponent { component } => {
                let comp_id = ical.components.len() as u32;
                if let Some(root) = ical
                    .components
                    .get_mut(0)
                    .filter(|c| c.component_type == ICalendarComponentType::VCalendar)
                {
                    root.component_ids.push(comp_id);
                    ical.components.push(component);
                }
            }
            MergeAction::RemoveComponent { component_id } => {
                remove_component_ids.push(component_id as u32);
            }
        }
    }

    if !remove_component_ids.is_empty() {
        ical.remove_component_ids(&remove_component_ids);
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
