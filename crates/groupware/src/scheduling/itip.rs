/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{Email, ItipMessage, ItipMessages, ItipSummary};
use calcard::{
    common::{IanaString, PartialDateTime},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarScheduleAgentValue,
        ICalendarValue,
    },
};
use common::PROD_ID;
use registry::schema::structs::{
    Task, TaskCalendarItipContents, TaskCalendarItipMessage, TaskStatus,
};
use store::write::BatchBuilder;

pub(crate) fn itip_build_envelope(method: ICalendarMethod) -> ICalendarComponent {
    ICalendarComponent {
        component_type: ICalendarComponentType::VCalendar,
        entries: vec![
            ICalendarEntry {
                name: ICalendarProperty::Version,
                params: vec![],
                values: vec![ICalendarValue::Text("2.0".to_string())],
            },
            ICalendarEntry {
                name: ICalendarProperty::Prodid,
                params: vec![],
                values: vec![ICalendarValue::Text(PROD_ID.to_string())],
            },
            ICalendarEntry {
                name: ICalendarProperty::Method,
                params: vec![],
                values: vec![ICalendarValue::Method(method)],
            },
        ],
        component_ids: Default::default(),
    }
}

pub fn itip_assign_organizer(ical: &mut ICalendar, organizer_address: &str) -> bool {
    let mut assigned = false;

    for component in &mut ical.components {
        if !component.component_type.is_scheduling_object() {
            continue;
        }

        let mut has_organizer = false;
        let mut has_attendee = false;

        for entry in &component.entries {
            match entry.name {
                ICalendarProperty::Organizer => has_organizer = true,
                ICalendarProperty::Attendee => has_attendee = true,
                _ => {}
            }
        }

        if has_attendee && !has_organizer {
            component.entries.push(ICalendarEntry {
                name: ICalendarProperty::Organizer,
                params: vec![],
                values: vec![ICalendarValue::Text(format!("mailto:{organizer_address}"))],
            });
            assigned = true;
        }
    }

    assigned
}

pub(crate) const ITIP_STATUS_INVALID_USER: &str = "3.7";

fn itip_is_server_scheduling(entry: &ICalendarEntry) -> bool {
    !entry.params.iter().any(|param| {
        matches!(
            (&param.name, &param.value),
            (
                ICalendarParameterName::ScheduleAgent,
                ICalendarParameterValue::ScheduleAgent(
                    ICalendarScheduleAgentValue::Client | ICalendarScheduleAgentValue::None
                )
            )
        )
    })
}

fn itip_unreachable_entries(
    ical: &ICalendar,
    account_emails: &[String],
) -> Option<Vec<(usize, usize)>> {
    let (comp_id, entry_id, entry) = ical
        .components
        .iter()
        .enumerate()
        .filter(|(_, comp)| comp.component_type.is_scheduling_object())
        .find_map(|(comp_id, comp)| {
            comp.entries
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.name == ICalendarProperty::Organizer)
                .map(|(entry_id, entry)| (comp_id, entry_id, entry))
        })?;

    if !itip_is_server_scheduling(entry) {
        return None;
    }

    match Email::new(entry.values.first()?.as_text()?, account_emails) {
        Some(email) if !email.is_local => return None,
        Some(_) => {}
        None => return Some(vec![(comp_id, entry_id)]),
    }

    let mut unreachable = Vec::new();

    for (comp_id, comp) in ical.components.iter().enumerate() {
        if !comp.component_type.is_scheduling_object() {
            continue;
        }

        for (entry_id, entry) in comp.entries.iter().enumerate() {
            if entry.name != ICalendarProperty::Attendee || !itip_is_server_scheduling(entry) {
                continue;
            }

            let rsvp = !entry.params.iter().any(|param| {
                matches!(
                    (&param.name, &param.value),
                    (
                        ICalendarParameterName::Rsvp,
                        ICalendarParameterValue::Bool(false)
                    )
                )
            });

            if rsvp
                && entry
                    .values
                    .first()
                    .and_then(|value| value.as_text())
                    .is_some_and(|value| Email::new(value, account_emails).is_none())
            {
                unreachable.push((comp_id, entry_id));
            }
        }
    }

    Some(unreachable)
}

pub fn itip_unreachable_recipient<'x>(
    ical: &'x ICalendar,
    account_emails: &[String],
) -> Option<&'x str> {
    itip_unreachable_entries(ical, account_emails)?
        .first()
        .and_then(|(comp_id, entry_id)| {
            ical.components[*comp_id].entries[*entry_id]
                .values
                .first()
                .and_then(|value| value.as_text())
        })
}

pub fn itip_set_unreachable_status(ical: &mut ICalendar, account_emails: &[String]) {
    let Some(unreachable) = itip_unreachable_entries(ical, account_emails) else {
        return;
    };

    for (comp_id, comp) in ical.components.iter_mut().enumerate() {
        if !comp.component_type.is_scheduling_object() {
            continue;
        }

        for (entry_id, entry) in comp.entries.iter_mut().enumerate() {
            if !matches!(
                entry.name,
                ICalendarProperty::Organizer | ICalendarProperty::Attendee
            ) {
                continue;
            }

            entry.params.retain(|param| {
                param.name != ICalendarParameterName::ScheduleStatus
                    || param.value.as_text() != Some(ITIP_STATUS_INVALID_USER)
            });

            if unreachable.contains(&(comp_id, entry_id)) {
                entry.params.push(ICalendarParameter::schedule_status(
                    ITIP_STATUS_INVALID_USER.to_string(),
                ));
            }
        }
    }
}

pub(crate) enum ItipExportAs<'x> {
    Organizer(&'x ICalendarParticipationStatus),
    Attendee(Vec<u16>),
}

pub(crate) fn itip_export_component(
    component: &ICalendarComponent,
    uid: &str,
    dt_stamp: &PartialDateTime,
    sequence: i64,
    export_as: ItipExportAs<'_>,
) -> ICalendarComponent {
    let is_todo = component.component_type == ICalendarComponentType::VTodo;
    let mut comp = ICalendarComponent {
        component_type: component.component_type.clone(),
        entries: Vec::with_capacity(component.entries.len() + 1),
        component_ids: Default::default(),
    };

    comp.add_dtstamp(dt_stamp.clone());
    comp.add_sequence(sequence);
    comp.add_uid(uid);

    for (entry_id, entry) in component.entries.iter().enumerate() {
        match (&entry.name, &export_as) {
            (
                ICalendarProperty::Organizer | ICalendarProperty::Attendee,
                ItipExportAs::Organizer(partstat),
            ) => {
                let mut new_entry = ICalendarEntry {
                    name: entry.name.clone(),
                    params: Vec::with_capacity(entry.params.len()),
                    values: entry.values.clone(),
                };
                let mut has_partstat = false;
                let mut rsvp = true;

                for entry in &entry.params {
                    match &entry.name {
                        ICalendarParameterName::ScheduleStatus
                        | ICalendarParameterName::ScheduleAgent
                        | ICalendarParameterName::ScheduleForceSend => {}
                        _ => {
                            match &entry.name {
                                ICalendarParameterName::Rsvp => {
                                    rsvp = !matches!(
                                        entry.value,
                                        ICalendarParameterValue::Bool(false)
                                    );
                                }
                                ICalendarParameterName::Partstat => {
                                    has_partstat = true;
                                }
                                _ => {}
                            }

                            new_entry.params.push(entry.clone())
                        }
                    }
                }

                if !has_partstat && rsvp && entry.name == ICalendarProperty::Attendee {
                    new_entry
                        .params
                        .push(ICalendarParameter::partstat((*partstat).clone()));
                }

                comp.entries.push(new_entry);
            }
            (
                ICalendarProperty::Organizer | ICalendarProperty::Attendee,
                ItipExportAs::Attendee(attendee_entry_ids),
            ) if attendee_entry_ids.contains(&(entry_id as u16))
                || entry.name == ICalendarProperty::Organizer =>
            {
                comp.entries.push(ICalendarEntry {
                    name: entry.name.clone(),
                    params: entry
                        .params
                        .iter()
                        .filter(|param| {
                            !matches!(
                                &param.name,
                                ICalendarParameterName::ScheduleStatus
                                    | ICalendarParameterName::ScheduleAgent
                                    | ICalendarParameterName::ScheduleForceSend
                            )
                        })
                        .cloned()
                        .collect(),
                    values: entry.values.clone(),
                });
            }
            (
                ICalendarProperty::RequestStatus
                | ICalendarProperty::Dtstamp
                | ICalendarProperty::Sequence
                | ICalendarProperty::Uid,
                _,
            ) => {}
            (_, ItipExportAs::Organizer(_))
            | (
                ICalendarProperty::RecurrenceId
                | ICalendarProperty::Dtstart
                | ICalendarProperty::Dtend
                | ICalendarProperty::Duration
                | ICalendarProperty::Due
                | ICalendarProperty::Description
                | ICalendarProperty::Summary,
                _,
            ) => {
                comp.entries.push(entry.clone());
            }
            (
                ICalendarProperty::Status
                | ICalendarProperty::PercentComplete
                | ICalendarProperty::Completed,
                _,
            ) if is_todo => {
                comp.entries.push(entry.clone());
            }
            _ => {}
        }
    }

    if matches!(export_as, ItipExportAs::Attendee(_)) {
        comp.entries.push(ICalendarEntry {
            name: ICalendarProperty::RequestStatus,
            params: vec![],
            values: vec![
                ICalendarValue::Text("2.0".to_string()),
                ICalendarValue::Text("Success".to_string()),
            ],
        });
    }

    comp
}

pub(crate) fn itip_finalize(ical: &mut ICalendar, scheduling_object_ids: &[u16]) {
    for comp in ical.components.iter_mut() {
        if comp.component_type.is_scheduling_object() {
            // Remove scheduling info from non-updated components
            for entry in comp.entries.iter_mut() {
                if matches!(
                    entry.name,
                    ICalendarProperty::Organizer | ICalendarProperty::Attendee
                ) {
                    entry.params.retain(|param| {
                        !matches!(param.name, ICalendarParameterName::ScheduleForceSend)
                    });
                }
            }
        }
    }

    for comp_id in scheduling_object_ids {
        let comp = &mut ical.components[*comp_id as usize];
        let mut found_sequence = false;
        for entry in &mut comp.entries {
            if entry.name == ICalendarProperty::Sequence {
                if let Some(ICalendarValue::Integer(seq)) = entry.values.first_mut() {
                    *seq += 1;
                } else {
                    entry.values = vec![ICalendarValue::Integer(1)];
                }
                found_sequence = true;
                break;
            }
        }

        if !found_sequence {
            comp.add_sequence(1);
        }
    }
}

pub(crate) fn itip_add_tz(message: &mut ICalendar, ical: &ICalendar) {
    let mut has_timezones = false;

    if message.components.iter().any(|c| {
        has_timezones = has_timezones || c.component_type == ICalendarComponentType::VTimezone;

        !has_timezones
            && c.entries.iter().any(|e| {
                e.params
                    .iter()
                    .any(|p| matches!(p.name, ICalendarParameterName::Tzid))
            })
    }) && !has_timezones
    {
        message.copy_timezones(ical);
    }

    message.add_missing_timezones();
}

#[inline]
pub(crate) fn can_attendee_modify_property(
    component_type: &ICalendarComponentType,
    property: &ICalendarProperty,
) -> bool {
    match component_type {
        ICalendarComponentType::VEvent | ICalendarComponentType::VJournal => {
            matches!(
                property,
                ICalendarProperty::Exdate
                    | ICalendarProperty::Summary
                    | ICalendarProperty::Description
                    | ICalendarProperty::Comment
            )
        }
        ICalendarComponentType::VTodo => matches!(
            property,
            ICalendarProperty::Exdate
                | ICalendarProperty::Summary
                | ICalendarProperty::Description
                | ICalendarProperty::Status
                | ICalendarProperty::PercentComplete
                | ICalendarProperty::Completed
                | ICalendarProperty::Comment
        ),
        _ => false,
    }
}

impl ItipMessages {
    pub fn new(messages: Vec<ItipMessage<ICalendar>>) -> Self {
        ItipMessages {
            messages: messages
                .into_iter()
                .map(|m| TaskCalendarItipContents {
                    from: m.from,
                    i_calendar_data: m.message.to_string(),
                    is_from_organizer: m.from_organizer,
                    summary: serde_json::to_string(&m.summary).unwrap_or_default(),
                    to: m.to.into(),
                })
                .collect(),
        }
    }

    pub fn queue(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        batch.schedule_task(Task::CalendarItipMessage(TaskCalendarItipMessage {
            account_id: batch.last_account_id().unwrap().into(),
            document_id: batch.last_document_id().unwrap().into(),
            messages: self.messages.into(),
            status: TaskStatus::now(),
        }));

        Ok(())
    }
}

impl From<ItipMessage<ICalendar>> for ItipMessage<String> {
    fn from(message: ItipMessage<ICalendar>) -> Self {
        ItipMessage {
            from: message.from,
            from_organizer: message.from_organizer,
            to: message.to,
            summary: message.summary,
            message: message.message.to_string(),
        }
    }
}

impl ItipSummary {
    pub fn method(&self) -> &str {
        match self {
            ItipSummary::Invite(_) => ICalendarMethod::Request.as_str(),
            ItipSummary::Update { method, .. } => method.as_str(),
            ItipSummary::Cancel(_) => ICalendarMethod::Cancel.as_str(),
            ItipSummary::Rsvp { .. } => ICalendarMethod::Reply.as_str(),
        }
    }
}
