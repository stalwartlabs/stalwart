/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::calendar::expand::SECONDS_PER_DAY;
use crate::scheduling::{
    Attendee, Email, InstanceId, ItipDateTime, ItipEntry, ItipEntryValue, ItipError, ItipField,
    ItipParticipant, ItipSnapshot, ItipSnapshots, ItipTime, ItipValue, Organizer, RecurrenceId,
};
use ahash::AHashMap;
use calcard::icalendar::{
    ICalendar, ICalendarDuration, ICalendarParameterName, ICalendarParameterValue,
    ICalendarParticipationStatus, ICalendarProperty, ICalendarScheduleAgentValue, ICalendarValue,
    Uri,
};
use std::borrow::Borrow;

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
                recurrence_time: None,
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

                            let tz = tz_resolver
                                .get_or_insert_with(|| ical.build_tz_resolver())
                                .resolve_or_default(tz_id);
                            let start = date
                                .to_date_time_with_tz(tz)
                                .map(|dt| dt.timestamp())
                                .unwrap_or_else(|| date.to_timestamp().unwrap_or_default());

                            sched_comp.recurrence_time = Some(ItipTime {
                                start,
                                tz_id: tz.as_id(),
                            });
                            instance_id = InstanceId::Recurrence(RecurrenceId {
                                entry_id: entry_id as u16,
                                date: start,
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
                    | ICalendarProperty::Conference
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

impl<'x> ItipSnapshots<'x> {
    pub(crate) fn unanswered(&self) -> ItipSnapshots<'x> {
        ItipSnapshots {
            organizer: self.organizer.clone(),
            uid: self.uid,
            components: self
                .components
                .iter()
                .map(|(instance_id, instance)| (instance_id.clone(), instance.unanswered()))
                .collect(),
        }
    }

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

    pub fn instance_time(&self, instance_id: &InstanceId) -> Option<ItipTime> {
        let instance = self.components.get(instance_id);
        if let Some(time) = instance.and_then(ItipSnapshot::start_time) {
            return Some(time);
        }

        match instance_id {
            InstanceId::Main => None,
            InstanceId::Recurrence(recurrence_id) => instance
                .and_then(|instance| instance.recurrence_time)
                .or_else(|| {
                    self.main_instance()
                        .and_then(ItipSnapshot::start_time)
                        .map(|master_start| ItipTime {
                            start: recurrence_id.date,
                            tz_id: master_start.tz_id,
                        })
                }),
        }
    }

    pub fn build_instance_summary(
        &self,
        instance_id: &InstanceId,
        include_guests: Option<&Organizer<'_>>,
        skip_fields: &[ItipField],
    ) -> Vec<ItipField> {
        let instance = self.components.get(instance_id);
        let Some(master) = self.main_instance() else {
            return instance.map_or_else(Vec::new, |instance| {
                instance.build_summary(include_guests, skip_fields)
            });
        };
        let InstanceId::Recurrence(recurrence_id) = instance_id else {
            return master.build_summary(include_guests, skip_fields);
        };

        let mut fields = Vec::with_capacity(SUMMARY_IDENTITY.len() + 3);
        for name in SUMMARY_IDENTITY {
            let source = instance
                .filter(|instance| instance.entries.iter().any(|entry| entry.name == &name))
                .unwrap_or(master);
            fields.extend(source.summary_fields(&name));
        }
        if let Some(time) = self.instance_time(instance_id) {
            fields.push(ItipField {
                name: ICalendarProperty::Dtstart,
                value: ItipValue::Time(time),
            });
        }
        if recurrence_id.this_and_future {
            fields.extend(master.summary_fields(&ICalendarProperty::Rrule));
        }

        instance
            .unwrap_or(master)
            .finish_summary(fields, include_guests, skip_fields)
    }

    pub fn build_instances_summary(
        &self,
        instance_ids: &[impl Borrow<InstanceId>],
        include_guests: Option<&Organizer<'_>>,
        skip_fields: &[ItipField],
    ) -> Vec<ItipField> {
        let Some((first, rest)) = instance_ids.split_first() else {
            return Vec::new();
        };
        let mut fields = self.build_instance_summary(first.borrow(), include_guests, skip_fields);

        for instance_id in rest {
            let Some(time) = self.instance_time(instance_id.borrow()) else {
                continue;
            };
            let field = ItipField {
                name: ICalendarProperty::Dtstart,
                value: ItipValue::Time(time),
            };
            if !fields.contains(&field) && !skip_fields.contains(&field) {
                fields.push(field);
            }
        }

        fields
    }
}

const SUMMARY_IDENTITY: [ICalendarProperty; 4] = [
    ICalendarProperty::Summary,
    ICalendarProperty::Description,
    ICalendarProperty::Location,
    ICalendarProperty::Conference,
];

impl<'x> ItipSnapshot<'x> {
    pub fn length(&self) -> Option<ICalendarDuration> {
        let mut start = None;
        let mut end = None;
        for entry in &self.entries {
            match (entry.name, &entry.value) {
                (ICalendarProperty::Duration, ItipEntryValue::Duration(duration)) => {
                    return Some((*duration).clone());
                }
                (ICalendarProperty::Dtstart, ItipEntryValue::DateTime(date)) => start = Some(date),
                (ICalendarProperty::Dtend, ItipEntryValue::DateTime(date)) => end = Some(date),
                _ => {}
            }
        }
        let (start, end) = (start?, end?);
        let seconds = end.timestamp - start.timestamp;
        (seconds > 0).then(|| {
            if start.date.has_time() {
                ICalendarDuration::from_seconds(seconds)
            } else {
                ICalendarDuration::from_days((seconds + SECONDS_PER_DAY / 2) / SECONDS_PER_DAY)
            }
        })
    }

    fn unanswered(&self) -> ItipSnapshot<'x> {
        ItipSnapshot {
            comp_id: self.comp_id,
            comp: self.comp,
            attendees: self
                .attendees
                .iter()
                .map(|attendee| {
                    let mut attendee = attendee.clone();
                    if attendee.email.is_local && attendee.part_stat.is_some() {
                        attendee.part_stat = Some(&ICalendarParticipationStatus::NeedsAction);
                    }
                    attendee
                })
                .collect(),
            dtstamp: self.dtstamp,
            entries: self.entries.clone(),
            sequence: self.sequence,
            request_status: self.request_status.clone(),
            recurrence_time: self.recurrence_time,
        }
    }

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
        let mut fields = Vec::with_capacity(6);

        for entry in &self.entries {
            if matches!(
                entry.name,
                ICalendarProperty::Summary
                    | ICalendarProperty::Description
                    | ICalendarProperty::Dtstart
                    | ICalendarProperty::Location
                    | ICalendarProperty::Conference
                    | ICalendarProperty::Rrule
            ) && let Some(value) = entry.value.to_summary_value()
            {
                fields.push(ItipField {
                    name: entry.name.clone(),
                    value,
                });
            }
        }

        self.finish_summary(fields, include_guests, skip_fields)
    }

    pub fn guest_field(&self, organizer: &Organizer<'_>) -> ItipField {
        let mut attendees = Vec::with_capacity(self.attendees.len() + 1);
        for attendee in &self.attendees {
            if attendee.email.email != organizer.email.email {
                attendees.push(ItipParticipant {
                    email: attendee.email.email.clone(),
                    name: attendee.name.map(|name| name.to_string()),
                    is_organizer: false,
                });
            }
        }
        attendees.push(ItipParticipant {
            email: organizer.email.email.clone(),
            name: organizer.name.map(|name| name.to_string()),
            is_organizer: true,
        });
        attendees.sort_unstable();

        ItipField {
            name: ICalendarProperty::Attendee,
            value: ItipValue::Participants(attendees),
        }
    }

    fn start_time(&self) -> Option<ItipTime> {
        self.entries
            .iter()
            .find_map(|entry| match (entry.name, &entry.value) {
                (ICalendarProperty::Dtstart, ItipEntryValue::DateTime(start)) => Some(ItipTime {
                    start: start.timestamp,
                    tz_id: start.tz_code,
                }),
                _ => None,
            })
    }

    fn summary_fields<'y>(
        &'y self,
        name: &'y ICalendarProperty,
    ) -> impl Iterator<Item = ItipField> + 'y {
        self.entries.iter().filter_map(move |entry| {
            if entry.name != name {
                return None;
            }
            entry.value.to_summary_value().map(|value| ItipField {
                name: name.clone(),
                value,
            })
        })
    }

    fn finish_summary(
        &self,
        mut fields: Vec<ItipField>,
        include_guests: Option<&Organizer<'_>>,
        skip_fields: &[ItipField],
    ) -> Vec<ItipField> {
        if !skip_fields.is_empty() {
            fields.retain(|field| !skip_fields.contains(field));
        }

        if let Some(organizer) = include_guests {
            let field = self.guest_field(organizer);
            if !skip_fields.contains(&field) {
                fields.push(field);
            }
        }

        fields
    }
}

impl ItipEntryValue<'_> {
    fn to_summary_value(&self) -> Option<ItipValue> {
        match self {
            ItipEntryValue::DateTime(date) => Some(ItipValue::Time(ItipTime {
                start: date.timestamp,
                tz_id: date.tz_code,
            })),
            ItipEntryValue::RRule(rule) => Some(ItipValue::Rrule(Box::new((*rule).clone()))),
            ItipEntryValue::Text(value) => Some(ItipValue::Text(value.to_string())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduling::RecurrenceId;

    const ORGANIZER: &str = "org@example.com";

    fn calendar(overrides: &str) -> ICalendar {
        ICalendar::parse(format!(
            concat!(
                "BEGIN:VCALENDAR\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:instance-summary\r\n",
                "DTSTART:20260601T090000Z\r\n",
                "RRULE:FREQ=DAILY;COUNT=5\r\n",
                "SUMMARY:Series title\r\n",
                "DESCRIPTION:Series description\r\n",
                "LOCATION:Series room\r\n",
                "ORGANIZER:mailto:org@example.com\r\n",
                "ATTENDEE:mailto:jane@example.com\r\n",
                "END:VEVENT\r\n",
                "{}",
                "END:VCALENDAR\r\n"
            ),
            overrides
        ))
        .expect("valid iCalendar")
    }

    fn recurrence(date: i64, this_and_future: bool) -> InstanceId {
        InstanceId::Recurrence(RecurrenceId {
            entry_id: 0,
            date,
            this_and_future,
        })
    }

    fn field(fields: &[ItipField], name: ICalendarProperty) -> Option<&ItipValue> {
        fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| &field.value)
    }

    fn text(fields: &[ItipField], name: ICalendarProperty) -> Option<&str> {
        match field(fields, name) {
            Some(ItipValue::Text(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    fn start(fields: &[ItipField]) -> Option<i64> {
        match field(fields, ICalendarProperty::Dtstart) {
            Some(ItipValue::Time(time)) => Some(time.start),
            _ => None,
        }
    }

    fn starts(fields: &[ItipField]) -> Vec<i64> {
        fields
            .iter()
            .filter_map(|field| match (&field.name, &field.value) {
                (ICalendarProperty::Dtstart, ItipValue::Time(time)) => Some(time.start),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn sparse_override_inherits_master_identity_and_recurrence_time() {
        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\n",
            "UID:instance-summary\r\n",
            "RECURRENCE-ID:20260602T090000Z\r\n",
            "STATUS:CANCELLED\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:jane@example.com\r\n",
            "END:VEVENT\r\n",
        ));
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let fields = snapshots.build_instance_summary(&recurrence(1780390800, false), None, &[]);

        assert_eq!(
            text(&fields, ICalendarProperty::Summary),
            Some("Series title")
        );
        assert_eq!(
            text(&fields, ICalendarProperty::Description),
            Some("Series description")
        );
        assert_eq!(
            text(&fields, ICalendarProperty::Location),
            Some("Series room")
        );
        assert_eq!(start(&fields), Some(1780390800));
        assert!(field(&fields, ICalendarProperty::Rrule).is_none());
    }

    #[test]
    fn override_fields_replace_the_master_ones() {
        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\n",
            "UID:instance-summary\r\n",
            "RECURRENCE-ID:20260602T090000Z\r\n",
            "DTSTART:20260602T140000Z\r\n",
            "LOCATION:Other room\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:jane@example.com\r\n",
            "END:VEVENT\r\n",
        ));
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let fields = snapshots.build_instance_summary(&recurrence(1780390800, false), None, &[]);

        assert_eq!(
            text(&fields, ICalendarProperty::Summary),
            Some("Series title")
        );
        assert_eq!(
            text(&fields, ICalendarProperty::Location),
            Some("Other room")
        );
        assert_eq!(start(&fields), Some(1780408800));
        assert!(field(&fields, ICalendarProperty::Rrule).is_none());
    }

    #[test]
    fn this_and_future_override_keeps_the_master_rule() {
        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\n",
            "UID:instance-summary\r\n",
            "RECURRENCE-ID;RANGE=THISANDFUTURE:20260602T090000Z\r\n",
            "DTSTART:20260602T140000Z\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:jane@example.com\r\n",
            "END:VEVENT\r\n",
        ));
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let fields = snapshots.build_instance_summary(&recurrence(1780390800, true), None, &[]);

        assert!(field(&fields, ICalendarProperty::Rrule).is_some());
        assert_eq!(start(&fields), Some(1780408800));
    }

    #[test]
    fn absent_instance_uses_the_master_identity_and_the_recurrence_time() {
        let ical = calendar("");
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let fields = snapshots.build_instance_summary(&recurrence(1780390800, false), None, &[]);

        assert_eq!(
            text(&fields, ICalendarProperty::Summary),
            Some("Series title")
        );
        assert_eq!(start(&fields), Some(1780390800));
        assert!(field(&fields, ICalendarProperty::Rrule).is_none());
    }

    #[test]
    fn the_main_instance_is_described_as_before() {
        let ical = calendar("");
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let fields = snapshots.build_instance_summary(&InstanceId::Main, None, &[]);

        assert_eq!(start(&fields), Some(1780304400));
        assert!(field(&fields, ICalendarProperty::Rrule).is_some());
    }

    #[test]
    fn several_instances_carry_one_start_each() {
        let ical = calendar(concat!(
            "BEGIN:VEVENT\r\n",
            "UID:instance-summary\r\n",
            "RECURRENCE-ID:20260602T090000Z\r\n",
            "ORGANIZER:mailto:org@example.com\r\n",
            "ATTENDEE:mailto:jane@example.com\r\n",
            "END:VEVENT\r\n",
        ));
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let second = recurrence(1780390800, false);
        let third = recurrence(1780477200, false);
        let fields = snapshots.build_instances_summary(&[&second, &third], None, &[]);

        assert_eq!(starts(&fields), vec![1780390800, 1780477200]);
        assert_eq!(
            text(&fields, ICalendarProperty::Summary),
            Some("Series title")
        );
    }

    #[test]
    fn skipped_fields_are_dropped_last() {
        let ical = calendar("");
        let snapshots = itip_snapshot(&ical, &[ORGANIZER.to_string()], false).expect("snapshot");
        let instance_id = recurrence(1780390800, false);
        let current = snapshots.build_instance_summary(&instance_id, None, &[]);
        let previous = snapshots.build_instance_summary(&instance_id, None, &current);

        assert!(previous.is_empty(), "{previous:#?}");
    }
}
