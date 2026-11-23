/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ConvertError, RecurrenceId,
    patch::{target, vevents_mut},
    series::{Series, sequence},
    to_message::{address, first_text, intended_status},
};
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
    ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole,
    ICalendarParticipationStatus, ICalendarProperty, ICalendarUserTypes, ICalendarValue,
};
use jiff::Timestamp;
use std::mem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendeeRole {
    Required,
    Optional,
    Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingRole {
    None,
    Organizer,
    Attendee,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitee {
    pub email: Box<str>,
    pub name: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invitation<'x> {
    pub uid: &'x str,
    pub instance: Option<RecurrenceId>,
    pub sequence: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvitationSpan<'x> {
    pub start: Timestamp,
    pub end: Timestamp,
    pub all_day: bool,
    pub location: Option<&'x str>,
    pub intended_status: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AttendeeLists {
    required: Option<Vec<Invitee>>,
    optional: Option<Vec<Invitee>>,
    resource: Option<Vec<Invitee>>,
}

impl AttendeeRole {
    fn of(entry: &ICalendarEntry) -> Self {
        let mut role = AttendeeRole::Required;
        for param in &entry.params {
            match &param.value {
                ICalendarParameterValue::Cutype(
                    ICalendarUserTypes::Resource | ICalendarUserTypes::Room,
                ) => return AttendeeRole::Resource,
                ICalendarParameterValue::Role(ICalendarParticipationRole::OptParticipant) => {
                    role = AttendeeRole::Optional;
                }
                ICalendarParameterValue::Role(ICalendarParticipationRole::NonParticipant) => {
                    role = AttendeeRole::Resource;
                }
                ICalendarParameterValue::Role(_) => role = AttendeeRole::Required,
                _ => {}
            }
        }
        role
    }

    fn param(self) -> ICalendarParameter {
        match self {
            AttendeeRole::Required => {
                ICalendarParameter::role(ICalendarParticipationRole::ReqParticipant)
            }
            AttendeeRole::Optional => {
                ICalendarParameter::role(ICalendarParticipationRole::OptParticipant)
            }
            AttendeeRole::Resource => ICalendarParameter::cutype(ICalendarUserTypes::Resource),
        }
    }
}

impl AttendeeLists {
    pub fn set(&mut self, role: AttendeeRole, invitees: Vec<Invitee>) {
        *self.list_mut(role) = None;
        let mut kept: Vec<Invitee> = Vec::with_capacity(invitees.len());
        for invitee in invitees {
            if self.find(&invitee.email).is_none()
                && !kept
                    .iter()
                    .any(|other| other.email.eq_ignore_ascii_case(&invitee.email))
            {
                kept.push(invitee);
            }
        }
        *self.list_mut(role) = Some(kept);
    }

    pub fn invitee_count(&self) -> usize {
        self.lists()
            .map(|(_, list)| list.map_or(0, <[Invitee]>::len))
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.lists().all(|(_, list)| list.is_none())
    }

    fn list_mut(&mut self, role: AttendeeRole) -> &mut Option<Vec<Invitee>> {
        match role {
            AttendeeRole::Required => &mut self.required,
            AttendeeRole::Optional => &mut self.optional,
            AttendeeRole::Resource => &mut self.resource,
        }
    }

    fn lists(&self) -> impl Iterator<Item = (AttendeeRole, Option<&[Invitee]>)> {
        [
            (AttendeeRole::Required, self.required.as_deref()),
            (AttendeeRole::Optional, self.optional.as_deref()),
            (AttendeeRole::Resource, self.resource.as_deref()),
        ]
        .into_iter()
    }

    fn replaces(&self, role: AttendeeRole) -> bool {
        self.lists()
            .any(|(listed, list)| listed == role && list.is_some())
    }

    fn invitees(&self) -> impl Iterator<Item = (AttendeeRole, &Invitee)> {
        self.lists().flat_map(|(role, list)| {
            list.unwrap_or_default()
                .iter()
                .map(move |invitee| (role, invitee))
        })
    }

    fn find(&self, email: &str) -> Option<(usize, AttendeeRole)> {
        self.invitees()
            .enumerate()
            .find(|(_, (_, invitee))| invitee.email.eq_ignore_ascii_case(email))
            .map(|(index, (role, _))| (index, role))
    }

    fn apply(&self, component: &mut ICalendarComponent, seen: &mut Vec<bool>) {
        seen.clear();
        seen.resize(self.invitees().count(), false);
        component.entries.retain_mut(|entry| {
            if entry.name != ICalendarProperty::Attendee {
                return true;
            }
            let current = AttendeeRole::of(entry);
            match address(entry).and_then(|email| self.find(email)) {
                Some((index, role)) => {
                    let Some(flag) = seen.get_mut(index) else {
                        return false;
                    };
                    if mem::replace(flag, true) {
                        return false;
                    }
                    if role != current {
                        entry.params.retain(|param| {
                            !matches!(
                                param.name,
                                ICalendarParameterName::Role | ICalendarParameterName::Cutype
                            )
                        });
                        entry.params.push(role.param());
                    }
                    true
                }
                None => !self.replaces(current),
            }
        });
        for ((role, invitee), _) in self.invitees().zip(seen.iter()).filter(|(_, seen)| !**seen) {
            let mut params = Vec::with_capacity(4);
            if let Some(name) = invitee.name.as_deref() {
                params.push(ICalendarParameter::cn(name.to_string()));
            }
            params.push(role.param());
            params.push(ICalendarParameter::partstat(
                ICalendarParticipationStatus::NeedsAction,
            ));
            params.push(ICalendarParameter::rsvp(true));
            component.entries.push(ICalendarEntry {
                name: ICalendarProperty::Attendee,
                params,
                values: [ICalendarValue::Text(format!("mailto:{}", invitee.email))].into(),
            });
        }
    }
}

pub fn set_event_attendees(
    ical: &mut ICalendar,
    instance: Option<RecurrenceId>,
    lists: &AttendeeLists,
) -> Result<(), ConvertError> {
    let mut seen = Vec::new();
    match instance {
        Some(_) => {
            let index = target(ical, instance)?;
            let component = ical
                .components
                .get_mut(index)
                .ok_or(ConvertError::Unsupported)?;
            lists.apply(component, &mut seen);
        }
        None => {
            for component in vevents_mut(ical) {
                lists.apply(component, &mut seen);
            }
        }
    }
    Ok(())
}

pub fn event_invitation(ical: &ICalendar) -> Option<Invitation<'_>> {
    let series = Series::new(ical)?;
    let uid = series.uid()?;
    let sequence = series.component(series.main).map_or(0, sequence);
    let instance = match series.master {
        Some(_) => None,
        None => {
            let mut overrides = series.overrides();
            let (_, _, instance) = overrides.next()?;
            if overrides.next().is_some() {
                return None;
            }
            Some(instance)
        }
    };
    Some(Invitation {
        uid,
        instance,
        sequence,
    })
}

pub fn event_response_requested(ical: &ICalendar) -> bool {
    Series::new(ical)
        .and_then(|series| series.component(series.main))
        .is_some_and(requests_response)
}

pub(super) fn requests_response(component: &ICalendarComponent) -> bool {
    component
        .properties(&ICalendarProperty::Attendee)
        .flat_map(|entry| entry.params.iter())
        .any(|param| {
            param.name == ICalendarParameterName::Rsvp
                && matches!(param.value, ICalendarParameterValue::Bool(true))
        })
}

pub fn event_invitation_span(ical: &ICalendar) -> Option<InvitationSpan<'_>> {
    let series = Series::new(ical)?;
    let main = series.component(series.main)?;
    let span = series.span(main)?;
    Some(InvitationSpan {
        start: span.start.to_timestamp(),
        end: span.end.to_timestamp(),
        all_day: span.all_day,
        location: first_text(main, &ICalendarProperty::Location),
        intended_status: intended_status(main),
    })
}

pub fn event_meeting_role(ical: &ICalendar, owner: &[String]) -> MeetingRole {
    let mine = |entry: &ICalendarEntry| address(entry).is_some_and(|email| is_owner(owner, email));
    let Some(organizer) = Series::new(ical)
        .and_then(|series| series.component(series.main))
        .and_then(|main| main.property(&ICalendarProperty::Organizer))
    else {
        return MeetingRole::None;
    };
    if mine(organizer) {
        return MeetingRole::Organizer;
    }
    if ical
        .components
        .iter()
        .filter(|component| component.component_type == ICalendarComponentType::VEvent)
        .flat_map(|component| component.properties(&ICalendarProperty::Attendee))
        .any(mine)
    {
        MeetingRole::Attendee
    } else {
        MeetingRole::None
    }
}

fn is_owner(owner: &[String], email: &str) -> bool {
    owner.iter().any(|known| known.eq_ignore_ascii_case(email))
}
