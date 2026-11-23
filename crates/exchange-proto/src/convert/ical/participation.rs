/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarEntry, ICalendarParameter, ICalendarParameterName,
    ICalendarParameterValue, ICalendarParticipationStatus, ICalendarProperty,
    ICalendarScheduleAgentValue, ICalendarScheduleForceSendValue, ICalendarUserTypes,
};
use smallvec::SmallVec;

use super::{
    RecurrenceId,
    patch::target,
    props::{RESPONSE_STATUS, STATE_FLAGS, state_flags, track_status},
    series::{Series, sequence},
    to_message::address,
};
use crate::{convert::model::PropBag, mapi::prop::OwnedPropValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeetingProgress {
    pub response_status: i32,
    pub sequence: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipationError {
    Unsupported,
    Organizer,
    NotAttendee,
    NotRecurring,
    NoInstance,
}

pub fn set_participation(
    ical: &mut ICalendar,
    own_addresses: &[String],
    instance: Option<RecurrenceId>,
    status: ICalendarParticipationStatus,
) -> Result<bool, ParticipationError> {
    let own_entry = |entry: &ICalendarEntry| is_own(entry, own_addresses);
    let series = Series::new(ical).ok_or(ParticipationError::Unsupported)?;
    let main = series
        .component(series.main)
        .ok_or(ParticipationError::Unsupported)?;
    if main
        .property(&ICalendarProperty::Organizer)
        .is_none_or(own_entry)
    {
        return Err(ParticipationError::Organizer);
    }
    if let Some(id) = instance
        && series.find_override(id).is_none()
        && !series
            .master
            .and_then(|master| series.component(master))
            .is_some_and(|master| master.is_recurrent())
    {
        return Err(ParticipationError::NotRecurring);
    }
    let mut overrides: SmallVec<[usize; 4]> = match instance {
        Some(_) => SmallVec::new(),
        None => series.overrides().map(|(index, _, _)| index).collect(),
    };
    let index = target(ical, instance).map_err(|_| match instance {
        Some(_) => ParticipationError::NoInstance,
        None => ParticipationError::Unsupported,
    })?;
    overrides.retain(|other| *other != index);
    let component = ical
        .components
        .get_mut(index)
        .ok_or(ParticipationError::Unsupported)?;
    let mut changed = match set_own_status(component, &own_entry, &status) {
        Some(changed) => changed,
        None => return Err(ParticipationError::NotAttendee),
    };
    for index in overrides {
        if let Some(component) = ical.components.get_mut(index) {
            changed |= set_own_status(component, &own_entry, &status).unwrap_or_default();
        }
    }
    Ok(changed)
}

pub fn force_reply(
    ical: &mut ICalendar,
    own_addresses: &[String],
    instance: Option<RecurrenceId>,
) -> bool {
    let Some(component) = target(ical, instance)
        .ok()
        .and_then(|index| ical.components.get_mut(index))
    else {
        return false;
    };
    let mut forced = false;
    for entry in own_attendees(component, &|entry| is_own(entry, own_addresses)) {
        let client_scheduled = entry.params.iter().any(|param| {
            matches!(
                &param.value,
                ICalendarParameterValue::ScheduleAgent(agent)
                    if agent != &ICalendarScheduleAgentValue::Server
            )
        });
        if client_scheduled {
            continue;
        }
        entry
            .params
            .retain(|param| param.name != ICalendarParameterName::ScheduleForceSend);
        entry.params.push(ICalendarParameter::schedule_force_send(
            ICalendarScheduleForceSendValue::Reply,
        ));
        forced = true;
    }
    forced
}

pub fn invited_address<'a>(ical: &ICalendar, own_addresses: &'a [String]) -> Option<&'a str> {
    ical.components
        .iter()
        .flat_map(|component| component.properties(&ICalendarProperty::Attendee))
        .filter_map(address)
        .find_map(|smtp| {
            own_addresses
                .iter()
                .find(|own| own.eq_ignore_ascii_case(smtp))
        })
        .map(String::as_str)
}

pub fn set_meeting_state(props: &mut PropBag, ical: &ICalendar, own_addresses: &[String]) {
    let Some(series) = Series::new(ical) else {
        return;
    };
    let Some(main) = series.component(series.main) else {
        return;
    };
    let status = match main.property(&ICalendarProperty::Organizer) {
        Some(organizer) if is_own(organizer, own_addresses) => Some(track_status::ORGANIZED),
        organizer => {
            if organizer.is_some() {
                let flags = match props.get_any(STATE_FLAGS.prop()) {
                    Some(OwnedPropValue::I32(flags)) => *flags,
                    _ => 0,
                };
                props.set(
                    STATE_FLAGS.key(),
                    OwnedPropValue::I32(flags | state_flags::RECEIVED),
                );
            }
            attendee_status(main, own_addresses)
        }
    };
    if let Some(status) = status {
        props.set(RESPONSE_STATUS.key(), OwnedPropValue::I32(status));
    }
}

pub fn meeting_progress(
    ical: &ICalendar,
    own_addresses: &[String],
    instance: Option<RecurrenceId>,
) -> Option<MeetingProgress> {
    let series = Series::new(ical)?;
    let main = series.component(series.main)?;
    let component = instance
        .and_then(|id| series.find_override(id))
        .and_then(|index| series.component(index))
        .unwrap_or(main);
    let response_status = match main.property(&ICalendarProperty::Organizer) {
        Some(organizer) if is_own(organizer, own_addresses) => track_status::ORGANIZED,
        _ => attendee_status(component, own_addresses).unwrap_or(track_status::NONE),
    };
    Some(MeetingProgress {
        response_status,
        sequence: sequence(component),
    })
}

pub fn has_recorded_reply(ical: &ICalendar, own_addresses: &[String]) -> bool {
    let Some(main) = Series::new(ical).and_then(|series| series.component(series.main)) else {
        return false;
    };
    main.property(&ICalendarProperty::Organizer)
        .is_none_or(|organizer| !is_own(organizer, own_addresses))
        && matches!(
            attendee_status(main, own_addresses),
            Some(track_status::ACCEPTED | track_status::TENTATIVE | track_status::DECLINED)
        )
}

fn is_own(entry: &ICalendarEntry, own_addresses: &[String]) -> bool {
    address(entry).is_some_and(|smtp| {
        own_addresses
            .iter()
            .any(|own| own.eq_ignore_ascii_case(smtp))
    })
}

fn attendee_status(main: &ICalendarComponent, own_addresses: &[String]) -> Option<i32> {
    let attendee = main
        .properties(&ICalendarProperty::Attendee)
        .find(|entry| is_own(entry, own_addresses))?;
    Some(
        match attendee.params.iter().find_map(|param| match &param.value {
            ICalendarParameterValue::Partstat(status) => Some(status),
            _ => None,
        }) {
            Some(ICalendarParticipationStatus::Accepted) => track_status::ACCEPTED,
            Some(ICalendarParticipationStatus::Tentative) => track_status::TENTATIVE,
            Some(ICalendarParticipationStatus::Declined) => track_status::DECLINED,
            _ => track_status::NOT_RESPONDED,
        },
    )
}

fn set_own_status(
    component: &mut ICalendarComponent,
    is_own: &impl Fn(&ICalendarEntry) -> bool,
    status: &ICalendarParticipationStatus,
) -> Option<bool> {
    let mut found = false;
    let mut changed = false;
    for entry in own_attendees(component, is_own) {
        found = true;
        let value = ICalendarParameterValue::Partstat(status.clone());
        match entry
            .params
            .iter_mut()
            .find(|param| param.name == ICalendarParameterName::Partstat)
        {
            Some(param) if param.value == value => {}
            Some(param) => {
                param.value = value;
                changed = true;
            }
            None => {
                entry.params.push(ICalendarParameter::partstat(value));
                changed = true;
            }
        }
    }
    found.then_some(changed)
}

fn own_attendees<'c>(
    component: &'c mut ICalendarComponent,
    is_own: &'c impl Fn(&ICalendarEntry) -> bool,
) -> impl Iterator<Item = &'c mut ICalendarEntry> {
    let individual = component
        .properties(&ICalendarProperty::Attendee)
        .any(|entry| is_own(entry) && !is_group(entry));
    component
        .properties_mut(&ICalendarProperty::Attendee)
        .filter(move |entry| is_own(entry) && !(individual && is_group(entry)))
}

fn is_group(entry: &ICalendarEntry) -> bool {
    entry
        .params
        .iter()
        .any(|param| param.value == ICalendarParameterValue::Cutype(ICalendarUserTypes::Group))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/participation/tests.rs"]
mod tests;
