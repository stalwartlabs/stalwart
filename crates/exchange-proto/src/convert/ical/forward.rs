/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
    ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
    ICalendarValue,
};
use smallvec::smallvec;
use std::borrow::Cow;

use super::{RecurrenceId, override_ical, series::Series};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardError {
    NoEvent,
    NoInstance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Organizer<'c> {
    pub address: &'c str,
    pub name: Option<&'c str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventText<'c> {
    pub summary: Option<&'c str>,
    pub description: Option<&'c str>,
    pub organizer: Option<Organizer<'c>>,
}

impl Organizer<'_> {
    fn entry(self) -> ICalendarEntry {
        ICalendarEntry {
            name: ICalendarProperty::Organizer,
            params: self
                .name
                .map(|name| vec![ICalendarParameter::cn(name.to_string())])
                .unwrap_or_default(),
            values: smallvec![ICalendarValue::Text(format!("mailto:{}", self.address))],
        }
    }
}

pub fn forwarded_event(
    ical: &ICalendar,
    instance: Option<RecurrenceId>,
) -> Result<Cow<'_, ICalendar>, ForwardError> {
    let series = Series::new(ical).ok_or(ForwardError::NoEvent)?;
    let Some(instance) = instance else {
        return Ok(Cow::Borrowed(ical));
    };
    if let Some(keep) = series.find_override(instance) {
        return override_ical(ical, keep)
            .map(Cow::Owned)
            .ok_or(ForwardError::NoEvent);
    }
    if series
        .master
        .and_then(|master| series.component(master))
        .is_some_and(ICalendarComponent::is_recurrent)
        && series.is_instance(instance)
    {
        Ok(Cow::Borrowed(ical))
    } else {
        Err(ForwardError::NoInstance)
    }
}

pub fn event_text(ical: &ICalendar) -> Option<EventText<'_>> {
    let series = Series::new(ical)?;
    let event = series.component(series.main)?;
    let text = |property: ICalendarProperty| {
        event
            .property(&property)
            .and_then(|entry| entry.values.first())
            .and_then(ICalendarValue::as_text)
    };
    Some(EventText {
        summary: text(ICalendarProperty::Summary),
        description: text(ICalendarProperty::Description),
        organizer: event
            .property(&ICalendarProperty::Organizer)
            .and_then(|entry| {
                Some(Organizer {
                    address: entry.calendar_address()?,
                    name: entry
                        .parameter(&ICalendarParameterName::Cn)
                        .and_then(ICalendarParameterValue::as_text),
                })
            }),
    })
}

pub fn publish(ical: &mut ICalendar, fallback: Option<Organizer<'_>>) {
    for component in &mut ical.components {
        component.entries.retain(|entry| {
            !matches!(
                entry.name,
                ICalendarProperty::Attendee
                    | ICalendarProperty::Method
                    | ICalendarProperty::RequestStatus
            )
        });
        for entry in &mut component.entries {
            if entry.name == ICalendarProperty::Organizer {
                entry.params.retain(|param| {
                    !matches!(
                        param.name,
                        ICalendarParameterName::ScheduleAgent
                            | ICalendarParameterName::ScheduleForceSend
                            | ICalendarParameterName::ScheduleStatus
                    )
                });
            }
        }
        if component.component_type == ICalendarComponentType::VCalendar {
            component.entries.push(ICalendarEntry {
                name: ICalendarProperty::Method,
                params: Vec::new(),
                values: smallvec![ICalendarValue::Method(ICalendarMethod::Publish)],
            });
        }
    }
    let lacks_organizer = |component: &ICalendarComponent| {
        component.component_type == ICalendarComponentType::VEvent
            && !component.has_property(&ICalendarProperty::Organizer)
    };
    if !ical.components.iter().any(lacks_organizer) {
        return;
    }
    let Some(organizer) = fallback.map(Organizer::entry).or_else(|| {
        ical.components
            .iter()
            .find_map(|component| component.property(&ICalendarProperty::Organizer))
            .cloned()
    }) else {
        return;
    };
    for component in ical
        .components
        .iter_mut()
        .filter(|component| lacks_organizer(component))
    {
        component.entries.push(organizer.clone());
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/forward/tests.rs"]
mod tests;
