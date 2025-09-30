/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{
    Attendee, Email, InstanceId, ItipDateTime, ItipEntry, ItipEntryValue, ItipError, ItipField,
    ItipParticipant, ItipSnapshot, ItipSnapshots, ItipTime, ItipValue, Organizer, RecurrenceId,
};
use ahash::AHashMap;
use calcard::icalendar::{
    ICalendar, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
    ICalendarScheduleAgentValue, ICalendarValue, Uri,
};

pub fn itip_snapshot<'x, 'y>(
    ical: &'x ICalendar,
    account_emails: &'y [String],
    force_add_client_scheduling: bool,
) -> Result<ItipSnapshots<'x>, ItipError> {
    if !ical.components.iter().any(|comp| {
        comp.component_type.is_scheduling_object()
            && comp
                .entries
                .iter()
                .any(|e| matches!(e.name, ICalendarProperty::Organizer))
    }) {
        return Err(ItipError::NoSchedulingInfo);
    }

    let mut organizer: Option<Organizer<'x>> = None;
    let mut uid: Option<&'x str> = None;
    let mut components = AHashMap::new();
    let mut expect_object_type = None;
    let mut has_local_emails = false;
    let mut tz_resolver = None;

    for (comp_id, comp) in ical.components.iter().enumerate() {
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

            let mut sched_comp = ItipSnapshot {
                comp_id: comp_id as u16,
                comp,
                attendees: Default::default(),
                dtstamp: Default::default(),
                entries: Default::default(),
                sequence: Default::default(),
                request_status: Default::default(),
            };
            let mut instance_id = InstanceId::Main;

            for (entry_id, entry) in comp.entries.iter().enumerate() {
                match &entry.name {
                    ICalendarProperty::Organizer => {
                        if let Some(email) = entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .and_then(|v| Email::new(v, account_emails))
                        {
                            let mut part = Organizer {
                                entry_id: entry_id as u16,
                                email,
                                is_server_scheduling: true,
                                name: None,
                                force_send: None,
                            };
                            has_local_emails |= part.email.is_local;

                            for param in &entry.params {
                                match (&param.name, &param.value) {
                                    (
                                        ICalendarParameterName::ScheduleAgent,
                                        ICalendarParameterValue::ScheduleAgent(
                                            ICalendarScheduleAgentValue::Client
                                            | ICalendarScheduleAgentValue::None,
                                        ),
                                    ) => {
                                        part.is_server_scheduling = false;
                                    }
                                    (
                                        ICalendarParameterName::ScheduleForceSend,
                                        ICalendarParameterValue::ScheduleForceSend(force_send),
                                    ) => {
                                        part.force_send = Some(force_send);
                                    }
                                    (
                                        ICalendarParameterName::Cn,
                                        ICalendarParameterValue::Text(name),
                                    ) => {
                                        part.name = Some(name.as_str());
                                    }
                                    _ => {}
                                }
                            }

                            if !part.is_server_scheduling && !force_add_client_scheduling {
                                return Err(ItipError::OtherSchedulingAgent);
                            }

                            match organizer {
                                Some(existing_organizer)
                                    if existing_organizer.email.email != part.email.email =>
                                {
                                    return Err(ItipError::MultipleOrganizer);
                                }
                                None => {
                                    organizer = Some(part);
                                }
                                _ => {}
                            }
                        }
                    }
                    ICalendarProperty::Attendee => {
                        if let Some(email) = entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .and_then(|v| Email::new(v, account_emails))
                        {
                            let mut part = Attendee {
                                entry_id: entry_id as u16,
                                email,
                                name: None,
                                rsvp: None,
                                is_server_scheduling: true,
                                force_send: None,
                                part_stat: None,
                                delegated_from: vec![],
                                delegated_to: vec![],
                                cu_type: None,
                                role: None,
                                sent_by: None,
                            };

                            for param in &entry.params {
                                match (&param.name, &param.value) {
                                    (
                                        ICalendarParameterName::ScheduleAgent,
                                        ICalendarParameterValue::ScheduleAgent(agent),
                                    ) => {
                                        part.is_server_scheduling =
                                            agent == &ICalendarScheduleAgentValue::Server;
                                    }
                                    (
                                        ICalendarParameterName::Rsvp,
                                        ICalendarParameterValue::Bool(rsvp),
                                    ) => {
                                        part.rsvp = Some(*rsvp);
                                    }
                                    (
                                        ICalendarParameterName::ScheduleForceSend,
                                        ICalendarParameterValue::ScheduleForceSend(force_send),
                                    ) => {
                                        part.force_send = Some(force_send);
                                    }
                                    (
                                        ICalendarParameterName::Partstat,
                                        ICalendarParameterValue::Partstat(value),
                                    ) => {
                                        part.part_stat = Some(value);
                                    }
                                    (
                                        ICalendarParameterName::Cutype,
                                        ICalendarParameterValue::Cutype(value),
                                    ) => {
                                        part.cu_type = Some(value);
                                    }
                                    (
                                        ICalendarParameterName::DelegatedFrom,
                                        ICalendarParameterValue::Uri(uri),
                                    ) => {
                                        if let Some(uri) = Email::from_uri(uri, account_emails) {
                                            part.delegated_from.push(uri);
                                        }
                                    }
                                    (
                                        ICalendarParameterName::DelegatedTo,
                                        ICalendarParameterValue::Uri(uri),
                                    ) => {
                                        if let Some(uri) = Email::from_uri(uri, account_emails) {
                                            part.delegated_to.push(uri);
                                        }
                                    }
                                    (
                                        ICalendarParameterName::Role,
                                        ICalendarParameterValue::Role(value),
                                    ) => {
                                        part.role = Some(value);
                                    }
                                    (
                                        ICalendarParameterName::SentBy,
                                        ICalendarParameterValue::Uri(value),
                                    ) => {
                                        part.sent_by = Email::from_uri(value, account_emails);
                                    }
                                    (
                                        ICalendarParameterName::Cn,
                                        ICalendarParameterValue::Text(name),
                                    ) => {
                                        part.name = Some(name.as_str());
                                    }
                                    _ => {}
                                }
                            }

                            has_local_emails |= part.email.is_local
                                && (force_add_client_scheduling || part.is_server_scheduling);

                            sched_comp.attendees.insert(part);
                        }
                    }
                    ICalendarProperty::Uid => {
                        if let Some(uid_) = entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .map(|v| v.trim())
                            .filter(|v| !v.is_empty())
                        {
                            match uid {
                                Some(existing_uid) if existing_uid != uid_ => {
                                    return Err(ItipError::MultipleUid);
                                }
                                None => {
                                    uid = Some(uid_);
                                }
                                _ => {}
                            }
                        }
                    }
                    ICalendarProperty::Sequence => {
                        if let Some(sequence) = entry.values.first().and_then(|v| v.as_integer()) {
                            sched_comp.sequence = Some(sequence);
                        }
                    }
                    ICalendarProperty::RecurrenceId => {
                        if let Some(date) =
                            entry.values.first().and_then(|v| v.as_partial_date_time())
                        {
                            let mut this_and_future = false;
                            let mut tz_id = None;

                            for param in &entry.params {
                                match (&param.name, &param.value) {
                                    (
                                        ICalendarParameterName::Tzid,
                                        ICalendarParameterValue::Text(id),
                                    ) => {
                                        tz_id = Some(id.as_str());
                                    }
                                    (ICalendarParameterName::Range, _) => {
                                        this_and_future = true;
                                    }
                                    _ => (),
                                }
                            }

                            instance_id = InstanceId::Recurrence(RecurrenceId {
                                entry_id: entry_id as u16,
                                date: date
                                    .to_date_time_with_tz(
                                        tz_resolver
                                            .get_or_insert_with(|| ical.build_tz_resolver())
                                            .resolve_or_default(tz_id),
                                    )
                                    .map(|dt| dt.timestamp())
                                    .unwrap_or_else(|| date.to_timestamp().unwrap_or_default()),
                                this_and_future,
                            });
                        }
                    }
                    ICalendarProperty::RequestStatus => {
                        if let Some(value) = entry.values.first().and_then(|v| v.as_text()) {
                            sched_comp.request_status.push(value);
                        }
                    }
                    ICalendarProperty::Dtstamp => {
                        sched_comp.dtstamp =
                            entry.values.first().and_then(|v| v.as_partial_date_time());
                    }
                    ICalendarProperty::Dtstart
                    | ICalendarProperty::Dtend
                    | ICalendarProperty::Duration
                    | ICalendarProperty::Due
                    | ICalendarProperty::Rrule
                    | ICalendarProperty::Rdate
                    | ICalendarProperty::Exdate
                    | ICalendarProperty::Status
                    | ICalendarProperty::Location
                    | ICalendarProperty::Summary
                    | ICalendarProperty::Description
                    | ICalendarProperty::Priority
                    | ICalendarProperty::PercentComplete
                    | ICalendarProperty::Completed => {
                        let tz_id = entry.tz_id();
                        for value in &entry.values {
                            let value = match value {
                                ICalendarValue::Uri(Uri::Location(v)) => {
                                    ItipEntryValue::Text(v.as_str())
                                }
                                ICalendarValue::PartialDateTime(date) => {
                                    let tz = tz_resolver
                                        .get_or_insert_with(|| ical.build_tz_resolver())
                                        .resolve_or_default(tz_id);
                                    ItipEntryValue::DateTime(ItipDateTime {
                                        date: date.as_ref(),
                                        tz_id,
                                        tz_code: tz.as_id(),
                                        timestamp: date
                                            .to_date_time_with_tz(tz)
                                            .map(|dt| dt.timestamp())
                                            .unwrap_or_else(|| {
                                                date.to_timestamp().unwrap_or_default()
                                            }),
                                    })
                                }
                                ICalendarValue::Duration(v) => ItipEntryValue::Duration(v),
                                ICalendarValue::RecurrenceRule(v) => ItipEntryValue::RRule(v),
                                ICalendarValue::Period(v) => ItipEntryValue::Period(v),
                                ICalendarValue::Integer(v) => ItipEntryValue::Integer(*v),
                                ICalendarValue::Text(v) => ItipEntryValue::Text(v.as_str()),
                                ICalendarValue::Status(v) => ItipEntryValue::Status(v),
                                _ => continue,
                            };
                            sched_comp.entries.insert(ItipEntry {
                                name: &entry.name,
                                value,
                            });
                        }
                    }
                    _ => {}
                }
            }

            if components.insert(instance_id, sched_comp).is_some() {
                return Err(ItipError::MultipleObjectInstances);
            }
        }
    }

    if has_local_emails {
        Ok(ItipSnapshots {
            organizer: organizer.ok_or(ItipError::NoSchedulingInfo)?,
            uid: uid.ok_or(ItipError::MissingUid)?,
            components,
        })
    } else {
        Err(ItipError::NotOrganizerNorAttendee)
    }
}

impl ItipSnapshots<'_> {
    pub fn sender_is_organizer_or_attendee(&self, email: &str) -> bool {
        self.organizer.email.email == email
            || self.components.values().any(|snapshot| {
                snapshot
                    .attendees
                    .iter()
                    .any(|attendee| attendee.email.email == email)
            })
    }

    pub fn main_instance(&self) -> Option<&ItipSnapshot<'_>> {
        self.components.get(&InstanceId::Main)
    }

    pub fn main_instance_or_default(&self) -> &ItipSnapshot<'_> {
        self.main_instance()
            .unwrap_or_else(|| self.components.values().next().unwrap())
    }
}

impl ItipSnapshot<'_> {
    pub fn has_local_attendee(&self) -> bool {
        self.attendees
            .iter()
            .any(|attendee| attendee.email.is_local)
    }

    pub fn local_attendee(&self) -> Option<&Attendee<'_>> {
        self.attendees
            .iter()
            .find(|attendee| attendee.email.is_local)
    }

    pub fn external_attendees(&self) -> impl Iterator<Item = &Attendee<'_>> + '_ {
        self.attendees.iter().filter(|item| !item.email.is_local)
    }

    pub fn attendee_by_email(&self, email: &str) -> Option<&Attendee<'_>> {
        self.attendees
            .iter()
            .find(|attendee| attendee.email.email == email)
    }

    pub fn build_summary(
        &self,
        include_guests: Option<&Organizer<'_>>,
        skip_fields: &[ItipField],
    ) -> Vec<ItipField> {
        let mut fields = Vec::with_capacity(5);

        for entry in &self.entries {
            if matches!(
                entry.name,
                ICalendarProperty::Summary
                    | ICalendarProperty::Description
                    | ICalendarProperty::Dtstart
                    | ICalendarProperty::Location
                    | ICalendarProperty::Rrule
            ) {
                let value = match &entry.value {
                    ItipEntryValue::DateTime(dt) => ItipValue::Time(ItipTime {
                        start: dt.timestamp,
                        tz_id: dt.tz_code,
                    }),
                    ItipEntryValue::RRule(rule) => ItipValue::Rrule(Box::new((*rule).clone())),
                    ItipEntryValue::Text(value) => ItipValue::Text(value.to_string()),
                    _ => continue,
                };
                let field = ItipField {
                    name: entry.name.clone(),
                    value,
                };

                if !skip_fields.contains(&field) {
                    fields.push(field);
                }
            }
        }

        if let Some(organizer) = include_guests {
            let mut attendees = Vec::with_capacity(self.attendees.len());
            for attendee in &self.attendees {
                if attendee.email.email != organizer.email.email {
                    attendees.push(ItipParticipant {
                        email: attendee.email.email.to_string(),
                        name: attendee.name.map(|n| n.to_string()),
                        is_organizer: false,
                    });
                }
            }
            attendees.push(ItipParticipant {
                email: organizer.email.email.to_string(),
                name: organizer.name.map(|n| n.to_string()),
                is_organizer: true,
            });
            attendees.sort_by(|a, b| {
                if a.is_organizer && !b.is_organizer {
                    std::cmp::Ordering::Less
                } else if !a.is_organizer && b.is_organizer {
                    std::cmp::Ordering::Greater
                } else if let (Some(a_name), Some(b_name)) = (a.name.as_deref(), b.name.as_deref())
                {
                    match a_name.cmp(b_name) {
                        std::cmp::Ordering::Equal => a.email.cmp(&b.email),
                        ord => ord,
                    }
                } else {
                    a.email.cmp(&b.email)
                }
            });

            let field = ItipField {
                name: ICalendarProperty::Attendee,
                value: ItipValue::Participants(attendees),
            };

            if !skip_fields.contains(&field) {
                fields.push(field);
            }
        }

        fields
    }
}
