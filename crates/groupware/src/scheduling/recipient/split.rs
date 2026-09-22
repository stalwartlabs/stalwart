/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AttendeeVisibility, RecipientPolicy,
    series::{Recurrence, Series, SeriesPlan},
};
use crate::scheduling::{
    Email, ItipField, ItipMessage, ItipParticipant, ItipSummary, ItipTime, ItipValue,
    event_cancel::CancelScope,
    itip::{itip_add_tz, itip_build_envelope},
};
use ahash::{AHashMap, RandomState};
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameterName, ICalendarProperty, ICalendarValue, Uri,
    },
};
use indexmap::IndexMap;
use std::{borrow::Cow, iter};

const PARTICIPANTS_POINTER: &str = "participants";

pub(super) struct RecipientSplit<'x> {
    ical: &'x ICalendar,
    visibility: AttendeeVisibility,
    addresses: AHashMap<String, u32>,
    components: Vec<SchedulingComponent<'x>>,
    series: Series<'x>,
}

struct SchedulingComponent<'x> {
    id: u32,
    recurrence: Option<Recurrence<'x>>,
    attendees: Vec<u32>,
    participant_ids: Vec<(u32, Cow<'x, str>)>,
    owners: Vec<(usize, EntryOwner<'x>)>,
    alarms: Vec<(u32, Option<u32>)>,
}

#[derive(Debug, Clone, Copy)]
enum EntryOwner<'x> {
    Address(u32),
    Participant(&'x str),
    Unknown,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct RecipientView {
    included: Vec<u32>,
    excluded: Vec<u32>,
}

trait AddressReferences {
    fn address_references(&self) -> impl Iterator<Item = &str>;
}

impl<'x> RecipientSplit<'x> {
    pub(super) fn split(
        message: ItipMessage<ICalendar>,
        policy: RecipientPolicy,
        result: &mut Vec<ItipMessage<ICalendar>>,
    ) {
        let ItipMessage {
            from,
            from_organizer,
            mut to,
            summary,
            message: ical,
        } = message;
        to.sort_unstable();

        let split = RecipientSplit::new(&ical, policy);
        let groups = split.groups(to);
        if let [(view, _)] = groups.as_slice()
            && split.visibility == AttendeeVisibility::All
            && view.is_complete(split.components.len())
        {
            result.push(ItipMessage {
                from,
                from_organizer,
                to: groups
                    .into_iter()
                    .next()
                    .map(|(_, recipients)| recipients)
                    .unwrap_or_default(),
                summary,
                message: ical,
            });
        } else {
            result.reserve(groups.len());
            result.extend(groups.into_iter().filter_map(|(view, recipients)| {
                split.message(&view, recipients, &from, &summary)
            }));
        }
    }

    fn new(ical: &'x ICalendar, policy: RecipientPolicy) -> Self {
        let scheduling_components = || {
            ical.components
                .first()
                .into_iter()
                .flat_map(|root| root.component_ids.iter())
                .filter_map(|id| {
                    ical.components
                        .get(*id as usize)
                        .filter(|component| component.component_type.is_scheduling_object())
                        .map(|component| (*id, component))
                })
        };
        let series = Series::new(
            ical,
            scheduling_components()
                .find(|(_, component)| !component.is_recurrence_override())
                .map(|(_, component)| component),
            policy.max_instances,
        );
        let is_hidden = policy.visibility == AttendeeVisibility::RecipientOnly;
        let mut addresses = AHashMap::new();
        let mut references = Vec::new();
        let mut components = Vec::new();

        for (id, component) in scheduling_components() {
            let mut scheduling = SchedulingComponent {
                id,
                recurrence: None,
                attendees: Vec::new(),
                participant_ids: Vec::new(),
                owners: Vec::new(),
                alarms: Vec::new(),
            };
            for (index, entry) in component.entries.iter().enumerate() {
                match &entry.name {
                    ICalendarProperty::Attendee => {
                        let address = entry
                            .values
                            .first()
                            .and_then(|value| value.as_text())
                            .and_then(|value| Email::new(value, &[]))
                            .map(|email| {
                                let next_id = addresses.len() as u32;
                                *addresses.entry(email.email).or_insert(next_id)
                            });
                        if let Some(address) = address {
                            scheduling.attendees.push(address);
                            if is_hidden && let Some(participant_id) = entry.participant_id() {
                                scheduling.participant_ids.push((address, participant_id));
                            }
                        }
                        if is_hidden {
                            scheduling.owners.push((
                                index,
                                address.map_or(EntryOwner::Unknown, EntryOwner::Address),
                            ));
                        }
                    }
                    ICalendarProperty::RecurrenceId if scheduling.recurrence.is_none() => {
                        scheduling.recurrence = Some(series.recurrence(entry));
                    }
                    ICalendarProperty::Jsprop if is_hidden => {
                        if let Some(owner) = EntryOwner::from_jsprop(entry) {
                            scheduling.owners.push((index, owner));
                        }
                    }
                    ICalendarProperty::Other(_)
                        if is_hidden && entry.address_references().next().is_some() =>
                    {
                        references.push((components.len(), index, entry));
                    }
                    _ => {}
                }
            }
            scheduling.attendees.sort_unstable();
            scheduling.attendees.dedup();
            components.push(scheduling);
        }

        if is_hidden {
            for (position, index, entry) in references {
                if let Some(owner) = EntryOwner::from_references(entry, &addresses)
                    && let Some(scheduling) = components.get_mut(position)
                {
                    scheduling.owners.push((index, owner));
                }
            }
            for (scheduling, (_, component)) in components.iter_mut().zip(scheduling_components()) {
                scheduling.owners.sort_by_key(|(index, _)| *index);
                scheduling.alarms = component
                    .component_ids
                    .iter()
                    .filter_map(|id| {
                        let alarm = ical.components.get(*id as usize).filter(|alarm| {
                            alarm.component_type == ICalendarComponentType::VAlarm
                        })?;
                        let mut owners = alarm
                            .entries
                            .iter()
                            .filter(|entry| entry.name == ICalendarProperty::Attendee)
                            .map(|entry| {
                                entry
                                    .values
                                    .first()
                                    .and_then(|value| value.as_text())
                                    .and_then(|value| Email::new(value, &[]))
                                    .and_then(|email| addresses.get(&email.email).copied())
                            });
                        let owner = owners.next()?;
                        Some((
                            *id,
                            owners
                                .all(|other| other == owner)
                                .then_some(owner)
                                .flatten(),
                        ))
                    })
                    .collect();
            }
        }

        RecipientSplit {
            ical,
            visibility: policy.visibility,
            addresses,
            components,
            series,
        }
    }

    fn groups(&self, recipients: Vec<String>) -> Vec<(RecipientView, Vec<String>)> {
        match self.visibility {
            AttendeeVisibility::All => {
                let mut groups =
                    IndexMap::<RecipientView, Vec<String>, RandomState>::with_capacity_and_hasher(
                        recipients.len(),
                        RandomState::new(),
                    );
                for recipient in recipients {
                    groups
                        .entry(self.view(&recipient))
                        .or_default()
                        .push(recipient);
                }
                groups.into_iter().collect()
            }
            AttendeeVisibility::RecipientOnly => recipients
                .into_iter()
                .map(|recipient| (self.view(&recipient), vec![recipient]))
                .collect(),
        }
    }

    fn view(&self, recipient: &str) -> RecipientView {
        let address = self.addresses.get(recipient).copied();
        let mut included = Vec::with_capacity(self.components.len());
        let mut excluded = Vec::new();
        let mut attends_main = false;
        for component in &self.components {
            if address.is_some_and(|address| component.attendees.binary_search(&address).is_ok()) {
                attends_main |= component.recurrence.is_none();
                included.push(component.id);
            } else if component.recurrence.is_some() {
                excluded.push(component.id);
            }
        }
        if included.is_empty() {
            included.extend(self.components.iter().map(|component| component.id));
        }
        if !attends_main {
            excluded.clear();
        }
        RecipientView { included, excluded }
    }

    fn message(
        &self,
        view: &RecipientView,
        recipients: Vec<String>,
        from: &str,
        summary: &ItipSummary,
    ) -> Option<ItipMessage<ICalendar>> {
        let root = self.ical.components.first()?;
        let recipient = recipients
            .first()
            .filter(|_| self.visibility == AttendeeVisibility::RecipientOnly)
            .map(String::as_str);
        let address = recipient.and_then(|recipient| self.addresses.get(recipient).copied());
        let plan = (!view.excluded.is_empty()).then(|| {
            let mut excluded = view.excluded.iter().peekable();
            self.series.plan(
                &self
                    .components
                    .iter()
                    .filter(|component| excluded.next_if(|id| **id == component.id).is_some())
                    .filter_map(|component| component.recurrence.as_ref())
                    .collect::<Vec<_>>(),
            )
        });
        let has_main_instances = plan.as_ref().is_none_or(SeriesPlan::has_instances);

        let mut components = vec![ICalendarComponent::default(); self.ical.components.len()];
        let mut root_ids = Vec::with_capacity(root.component_ids.len());
        let mut children = Vec::new();
        let mut has_scheduling = false;
        let mut has_main = false;
        let mut scheduling = self.components.iter().peekable();
        let mut included = view.included.iter().peekable();

        for id in &root.component_ids {
            let Some(source) = self.ical.components.get(*id as usize) else {
                continue;
            };
            match scheduling.next_if(|component| component.id == *id) {
                Some(component) => {
                    let is_main = component.recurrence.is_none();
                    if included.next_if(|included| **included == *id).is_some()
                        && (!is_main || has_main_instances)
                        && let Some(slot) = components.get_mut(*id as usize)
                    {
                        *slot = component.copy(
                            source,
                            address,
                            plan.as_ref()
                                .filter(|_| is_main)
                                .map(|plan| (plan, &self.series)),
                            &mut children,
                        );
                        root_ids.push(*id);
                        has_scheduling = true;
                        has_main |= is_main;
                    }
                }
                None if !source.component_type.is_scheduling_object() => {
                    root_ids.push(*id);
                    children.push(*id);
                }
                None => {}
            }
        }

        if !has_scheduling {
            return match summary {
                ItipSummary::Update { current, .. } => {
                    self.cancel_message(recipients, from, current)
                }
                _ => None,
            };
        }

        let mut is_copied = vec![false; self.ical.components.len()];
        while let Some(id) = children.pop() {
            if let (Some(source), Some(slot), Some(is_copied)) = (
                self.ical.components.get(id as usize),
                components.get_mut(id as usize),
                is_copied.get_mut(id as usize),
            ) && id != 0
                && !*is_copied
                && !source.component_type.is_scheduling_object()
            {
                *is_copied = true;
                *slot = source.clone();
                children.extend(&source.component_ids);
            }
        }
        if let Some(slot) = components.first_mut() {
            *slot = ICalendarComponent {
                component_type: root.component_type.clone(),
                entries: root.entries.clone(),
                component_ids: root_ids,
            };
        }

        let message = ICalendar { components };
        let summary = if !has_main && !view.is_complete(self.components.len()) {
            summary.for_slice(&self.slice_instances(view), recipient)
        } else {
            summary.visible_to(recipient)
        };

        Some(ItipMessage {
            from: from.to_string(),
            from_organizer: true,
            to: recipients,
            summary,
            message,
        })
    }

    fn slice_instances(&self, view: &RecipientView) -> SliceInstances {
        let mut slice = SliceInstances {
            starts: Vec::with_capacity(view.included.len()),
            earliest: None,
            keeps_rrule: false,
            overrides: Vec::new(),
        };
        let mut participants: Vec<ItipParticipant> = Vec::new();
        let mut included = view.included.iter().peekable();

        for component in &self.components {
            if included.next_if(|id| **id == component.id).is_none() {
                continue;
            }
            let Some(source) = self.ical.components.get(component.id as usize) else {
                continue;
            };
            let recurrence = component.recurrence.as_ref();
            slice.keeps_rrule |= recurrence.is_none_or(Recurrence::is_this_and_future);

            if let Some(start) = source
                .property(&ICalendarProperty::Dtstart)
                .or_else(|| recurrence.map(Recurrence::entry))
                .and_then(|entry| self.series.entry_time(entry))
            {
                if slice
                    .earliest
                    .as_ref()
                    .is_none_or(|earliest| start.start < earliest.start)
                {
                    slice.earliest = Some(start);
                }
                slice.starts.push(start.start);
            }

            for entry in &source.entries {
                match entry.name {
                    ICalendarProperty::Organizer | ICalendarProperty::Attendee => {
                        let is_organizer = entry.name == ICalendarProperty::Organizer;
                        let Some(email) = entry
                            .values
                            .first()
                            .and_then(|value| value.as_text())
                            .and_then(|value| Email::new(value, &[]))
                        else {
                            continue;
                        };
                        match participants
                            .iter_mut()
                            .find(|participant| participant.email == email.email)
                        {
                            Some(participant) => participant.is_organizer |= is_organizer,
                            None => participants.push(ItipParticipant {
                                email: email.email,
                                name: entry
                                    .parameter(&ICalendarParameterName::Cn)
                                    .and_then(|value| value.as_text())
                                    .map(|name| name.to_string()),
                                is_organizer,
                            }),
                        }
                    }
                    ICalendarProperty::Summary
                    | ICalendarProperty::Description
                    | ICalendarProperty::Location
                    | ICalendarProperty::Conference => {
                        if !slice.overrides.iter().any(|field| field.name == entry.name)
                            && let Some(value) = ItipValue::from_entry(entry)
                        {
                            slice.overrides.push(ItipField {
                                name: entry.name.clone(),
                                value,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        if !participants.is_empty() {
            participants.sort_unstable();
            slice.overrides.push(ItipField {
                name: ICalendarProperty::Attendee,
                value: ItipValue::Participants(participants),
            });
        }

        slice
    }

    fn cancel_message(
        &self,
        recipients: Vec<String>,
        from: &str,
        fields: &[ItipField],
    ) -> Option<ItipMessage<ICalendar>> {
        let master = self.series.master_component()?;
        let recipient = recipients
            .first()
            .filter(|_| self.visibility == AttendeeVisibility::RecipientOnly)
            .map(String::as_str);
        let summary = ItipSummary::Cancel(
            fields
                .iter()
                .map(|field| field.visible_to(recipient))
                .collect(),
        );
        let sequence = master
            .property(&ICalendarProperty::Sequence)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_integer())
            .unwrap_or_default();
        let dt_stamp = master
            .property(&ICalendarProperty::Dtstamp)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_partial_date_time())
            .cloned()
            .unwrap_or_else(PartialDateTime::now);
        let attendees = recipients.iter().map(String::as_str).collect::<Vec<_>>();
        let mut envelope = itip_build_envelope(ICalendarMethod::Cancel);
        envelope.component_ids.push(1);
        let mut message = ICalendar {
            components: vec![
                envelope,
                CancelScope::Attendees(&attendees).build_component(master, sequence, dt_stamp),
            ],
        };
        itip_add_tz(&mut message, self.ical);

        Some(ItipMessage {
            from: from.to_string(),
            from_organizer: true,
            summary,
            to: recipients,
            message,
        })
    }
}

impl SchedulingComponent<'_> {
    fn copy(
        &self,
        source: &ICalendarComponent,
        address: Option<u32>,
        plan: Option<(&SeriesPlan<'_>, &Series<'_>)>,
        children: &mut Vec<u32>,
    ) -> ICalendarComponent {
        let participant_id = self
            .participant_ids
            .iter()
            .find(|(owner, _)| Some(*owner) == address)
            .map(|(_, participant_id)| participant_id.as_ref());
        let mut owners = self.owners.iter().peekable();
        let mut entries = Vec::with_capacity(
            source.entries.len() + plan.map_or(0, |(plan, _)| plan.exdate_count()),
        );
        for (index, entry) in source.entries.iter().enumerate() {
            if owners
                .next_if(|(owner_index, _)| *owner_index == index)
                .is_some_and(|(_, owner)| !owner.is_visible_to(address, participant_id))
            {
                continue;
            }
            match plan {
                Some((plan, series)) => {
                    entries.extend(plan.entry(series, entry).map(|entry| entry.into_owned()))
                }
                None => entries.push(entry.clone()),
            }
        }
        if let Some((plan, _)) = plan {
            entries.extend(plan.exdates());
        }

        let mut alarms = self.alarms.iter().peekable();
        let component_ids = source
            .component_ids
            .iter()
            .copied()
            .filter(|id| {
                alarms
                    .next_if(|(alarm_id, _)| alarm_id == id)
                    .is_none_or(|(_, owner)| owner.is_some_and(|owner| Some(owner) == address))
            })
            .collect::<Vec<_>>();
        children.extend(&component_ids);

        ICalendarComponent {
            component_type: source.component_type.clone(),
            entries,
            component_ids,
        }
    }
}

impl<'x> EntryOwner<'x> {
    fn from_jsprop(entry: &'x ICalendarEntry) -> Option<Self> {
        let pointer = entry
            .parameter(&ICalendarParameterName::Jsptr)
            .and_then(|value| value.as_text())
            .unwrap_or_default();
        let participants = pointer
            .strip_prefix(PARTICIPANTS_POINTER)
            .filter(|rest| rest.is_empty() || rest.starts_with('/'));
        match participants
            .and_then(|rest| rest.strip_prefix('/'))
            .map(|rest| rest.split_once('/').map_or(rest, |(id, _)| id))
            .filter(|id| !id.is_empty())
        {
            Some(participant_id) => Some(EntryOwner::Participant(participant_id)),
            None if participants.is_some()
                || entry
                    .values
                    .iter()
                    .filter_map(|value| value.as_text())
                    .any(|value| value.contains(PARTICIPANTS_POINTER)) =>
            {
                Some(EntryOwner::Unknown)
            }
            None => None,
        }
    }

    fn from_references(entry: &ICalendarEntry, addresses: &AHashMap<String, u32>) -> Option<Self> {
        let mut owners = entry
            .address_references()
            .filter_map(|reference| Email::new(reference, &[]))
            .filter_map(|email| addresses.get(&email.email).copied());
        let owner = owners.next()?;
        Some(if owners.all(|other| other == owner) {
            EntryOwner::Address(owner)
        } else {
            EntryOwner::Unknown
        })
    }

    fn is_visible_to(&self, address: Option<u32>, participant_id: Option<&str>) -> bool {
        match self {
            EntryOwner::Address(owner) => address == Some(*owner),
            EntryOwner::Participant(segment) => participant_id.is_some_and(|participant_id| {
                EntryOwner::pointer_segment_eq(segment, participant_id)
            }),
            EntryOwner::Unknown => false,
        }
    }

    fn pointer_segment_eq(segment: &str, value: &str) -> bool {
        let mut bytes = segment.bytes();
        iter::from_fn(|| match bytes.next()? {
            b'~' => match bytes.next() {
                Some(b'0') => Some(b'~'),
                Some(b'1') => Some(b'/'),
                _ => Some(u8::MAX),
            },
            byte => Some(byte),
        })
        .eq(value.bytes())
    }
}

impl RecipientView {
    fn is_complete(&self, components: usize) -> bool {
        self.excluded.is_empty() && self.included.len() == components
    }
}

impl AddressReferences for ICalendarEntry {
    fn address_references(&self) -> impl Iterator<Item = &str> {
        self.params
            .iter()
            .filter_map(|param| param.value.as_text())
            .chain(self.values.iter().filter_map(|value| value.as_text()))
            .filter(|reference| reference.contains('@'))
    }
}

impl ItipField {
    fn visible_to(&self, recipient: Option<&str>) -> Self {
        match (&self.value, recipient) {
            (ItipValue::Participants(participants), Some(recipient)) => ItipField {
                name: self.name.clone(),
                value: ItipValue::Participants(
                    participants
                        .iter()
                        .filter(|participant| {
                            participant.is_organizer || participant.email == recipient
                        })
                        .cloned()
                        .collect(),
                ),
            },
            _ => self.clone(),
        }
    }
}

impl ItipSummary {
    fn visible_to(&self, recipient: Option<&str>) -> Self {
        let visible = |fields: &[ItipField]| -> Vec<ItipField> {
            fields
                .iter()
                .map(|field| field.visible_to(recipient))
                .collect()
        };
        match self {
            ItipSummary::Invite(current) => ItipSummary::Invite(visible(current)),
            ItipSummary::Update {
                method,
                current,
                previous,
            } => {
                let current = visible(current);
                let previous = previous
                    .iter()
                    .map(|field| field.visible_to(recipient))
                    .filter(|field| !current.contains(field))
                    .collect();
                ItipSummary::Update {
                    method: method.clone(),
                    current,
                    previous,
                }
            }
            ItipSummary::Cancel(current) => ItipSummary::Cancel(visible(current)),
            ItipSummary::Rsvp { part_stat, current } => ItipSummary::Rsvp {
                part_stat: part_stat.clone(),
                current: visible(current),
            },
        }
    }

    fn for_slice(&self, slice: &SliceInstances, recipient: Option<&str>) -> Self {
        match self {
            ItipSummary::Invite(current) => ItipSummary::Invite(slice.filter(current, recipient)),
            ItipSummary::Update {
                method, current, ..
            } => ItipSummary::Update {
                method: method.clone(),
                current: slice.filter(current, recipient),
                previous: Vec::new(),
            },
            ItipSummary::Cancel(current) => ItipSummary::Cancel(slice.filter(current, recipient)),
            ItipSummary::Rsvp { part_stat, current } => ItipSummary::Rsvp {
                part_stat: part_stat.clone(),
                current: slice.filter(current, recipient),
            },
        }
    }
}

struct SliceInstances {
    starts: Vec<i64>,
    earliest: Option<ItipTime>,
    keeps_rrule: bool,
    overrides: Vec<ItipField>,
}

impl SliceInstances {
    fn filter(&self, fields: &[ItipField], recipient: Option<&str>) -> Vec<ItipField> {
        let mut filtered = Vec::with_capacity(fields.len() + 1);
        let mut has_start = false;

        for field in fields {
            match (&field.name, &field.value) {
                (ICalendarProperty::Dtstart, ItipValue::Time(start)) => {
                    if !self.starts.contains(&start.start) {
                        continue;
                    }
                    has_start = true;
                }
                (ICalendarProperty::Rrule, _) if !self.keeps_rrule => continue,
                _ => {}
            }

            match self
                .overrides
                .iter()
                .find(|replacement| replacement.name == field.name)
            {
                Some(replacement) => {
                    let replacement = replacement.visible_to(recipient);
                    if !filtered.contains(&replacement) {
                        filtered.push(replacement);
                    }
                }
                None => filtered.push(field.visible_to(recipient)),
            }
        }

        if !has_start && let Some(earliest) = &self.earliest {
            filtered.push(ItipField {
                name: ICalendarProperty::Dtstart,
                value: ItipValue::Time(*earliest),
            });
        }
        for replacement in &self.overrides {
            if !filtered.iter().any(|field| field.name == replacement.name) {
                filtered.push(replacement.visible_to(recipient));
            }
        }

        filtered
    }
}

impl ItipValue {
    fn from_entry(entry: &ICalendarEntry) -> Option<Self> {
        entry
            .values
            .first()
            .and_then(|value| match value {
                ICalendarValue::Text(text) => Some(text.as_str()),
                ICalendarValue::Uri(Uri::Location(uri)) => Some(uri.as_str()),
                _ => None,
            })
            .map(|text| ItipValue::Text(text.to_string()))
    }
}
