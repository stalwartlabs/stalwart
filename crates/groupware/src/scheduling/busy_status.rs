/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::{InstanceId, ItipSnapshot, ItipSnapshots};
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarEntry, ICalendarParticipationStatus, ICalendarProperty,
    ICalendarValue,
};

const BUSY_STATUS: &str = "X-MICROSOFT-CDO-BUSYSTATUS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdoStatus {
    Busy,
    Intended,
}

impl CdoStatus {
    pub fn of(name: &ICalendarProperty) -> Option<Self> {
        match name {
            ICalendarProperty::Other(name) => hashify::map_ignore_case!(name.as_bytes(), CdoStatus,
                b"X-MICROSOFT-CDO-BUSYSTATUS" => CdoStatus::Busy,
                b"X-MICROSOFT-CDO-INTENDEDSTATUS" => CdoStatus::Intended,
            )
            .copied(),
            _ => None,
        }
    }

    pub fn values(self, entries: &[ICalendarEntry]) -> Option<&[ICalendarValue]> {
        entries
            .iter()
            .find(|entry| CdoStatus::of(&entry.name) == Some(self))
            .map(|entry| entry.values.as_slice())
    }
}

fn is_kept_on_new_instance(name: &ICalendarProperty) -> bool {
    !matches!(name, ICalendarProperty::Other(_)) || CdoStatus::of(name).is_some()
}

pub(crate) fn new_instance_entries(instance: &ItipSnapshot<'_>) -> Vec<ICalendarEntry> {
    let mut entries = instance
        .comp
        .entries
        .iter()
        .filter(|entry| is_kept_on_new_instance(&entry.name))
        .cloned()
        .collect();
    adopt_if_accepted(instance, &mut entries);
    entries
}

pub fn cdo_status_names<'x>(
    itip: &'x ICalendarComponent,
    stored: &'x ICalendarComponent,
) -> impl Iterator<Item = &'x ICalendarProperty> {
    itip.entries
        .iter()
        .chain(&stored.entries)
        .map(|entry| &entry.name)
        .filter(|name| CdoStatus::of(name).is_some())
}

pub fn adopt_intended_status(entries: &mut Vec<ICalendarEntry>) {
    let Some(intended) = CdoStatus::Intended
        .values(entries)
        .map(<[ICalendarValue]>::to_vec)
    else {
        return;
    };
    match entries
        .iter_mut()
        .find(|entry| CdoStatus::of(&entry.name) == Some(CdoStatus::Busy))
    {
        Some(entry) => entry.values = intended.into(),
        None => entries.push(ICalendarEntry {
            name: ICalendarProperty::Other(BUSY_STATUS.to_string()),
            params: vec![],
            values: intended.into(),
        }),
    }
}

pub(crate) fn adopt_if_accepted(instance: &ItipSnapshot<'_>, entries: &mut Vec<ICalendarEntry>) {
    if instance
        .local_attendee()
        .is_some_and(|attendee| attendee.part_stat == Some(&ICalendarParticipationStatus::Accepted))
    {
        adopt_intended_status(entries);
    }
}

pub(crate) struct AcceptedInstances(Vec<u16>);

impl AcceptedInstances {
    pub(crate) fn of(old_itip: &ItipSnapshots<'_>, new_itip: &ItipSnapshots<'_>) -> Self {
        AcceptedInstances(
            new_itip
                .components
                .iter()
                .filter_map(|(instance_id, instance)| {
                    let attendee = instance.local_attendee()?;
                    let old_instance = match (old_itip.components.get(instance_id), instance_id) {
                        (Some(old_instance), _) => old_instance,
                        (None, InstanceId::Recurrence(recurrence_id)) => {
                            old_itip.occurrence_source(recurrence_id)?
                        }
                        (None, InstanceId::Main) => return None,
                    };
                    let old_attendee = old_instance.attendee_by_email(&attendee.email.email)?;
                    let intended = CdoStatus::Intended.values(&instance.comp.entries)?;
                    let busy = CdoStatus::Busy.values(&instance.comp.entries);
                    (attendee.part_stat == Some(&ICalendarParticipationStatus::Accepted)
                        && old_attendee.part_stat != Some(&ICalendarParticipationStatus::Accepted)
                        && busy == CdoStatus::Busy.values(&old_instance.comp.entries)
                        && busy != Some(intended))
                    .then_some(instance.comp_id)
                })
                .collect(),
        )
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn apply(self, ical: &mut ICalendar) {
        for comp_id in self.0 {
            if let Some(component) = ical.components.get_mut(usize::from(comp_id)) {
                adopt_intended_status(&mut component.entries);
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/groupware/src/scheduling/busy_status/tests.rs"]
mod tests;
