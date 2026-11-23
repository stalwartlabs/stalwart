/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::icalendar::{
    ICalendar, ICalendarAction, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
    ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
    ICalendarRelationshipType, ICalendarValue, ICalendarValueType,
};
use jiff::Timestamp;
use smallvec::{SmallVec, smallvec};

use super::{
    RecurrenceId,
    patch::{TimeTarget, push_alarm, remove_components},
    props::REMINDER_DESCRIPTION,
    series::{Series, Span},
    to_message::{alarm_fire, instance_span},
};
use crate::{common::time::FileTime, convert::ConvertError};

pub(super) const SIGNAL_NEVER: FileTime = FileTime(0x0CB3_4557_A3DD_4000);
const REMINDER_UID_SUFFIX: &str = "-reminder";
const SNOOZE_UID_SUFFIX: &str = "-snooze";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlarmState {
    Pending,
    Dismissed,
    Snoozed(Timestamp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OccurrenceReminder {
    Dismiss,
    Snooze(Timestamp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlarmOwner {
    Component,
    Series,
}

impl AlarmOwner {
    fn of(series: &Series<'_>, index: usize) -> Self {
        if series.master == Some(index) && series.is_recurring() {
            AlarmOwner::Series
        } else {
            AlarmOwner::Component
        }
    }
}

fn is_display(alarm: &ICalendarComponent) -> bool {
    alarm
        .property(&ICalendarProperty::Action)
        .and_then(|entry| entry.values.first())
        .is_none_or(|value| matches!(value, ICalendarValue::Action(ICalendarAction::Display)))
}

fn is_snooze(alarm: &ICalendarComponent) -> bool {
    snoozes(alarm, None)
}

pub(super) fn is_reminder(alarm: &ICalendarComponent) -> bool {
    is_display(alarm) && !is_snooze(alarm)
}

fn snoozes(alarm: &ICalendarComponent, reminder: Option<&str>) -> bool {
    alarm
        .properties(&ICalendarProperty::RelatedTo)
        .any(|entry| {
            matches!(
                entry.parameter(&ICalendarParameterName::Reltype),
                Some(ICalendarParameterValue::Reltype(
                    ICalendarRelationshipType::Snooze
                ))
            ) && reminder.is_none_or(|uid| {
                entry
                    .values
                    .first()
                    .and_then(ICalendarValue::as_text)
                    .is_some_and(|related| related == uid)
            })
        })
}

fn instant(
    series: &Series<'_>,
    alarm: &ICalendarComponent,
    property: &ICalendarProperty,
) -> Option<Timestamp> {
    series
        .resolve_first(alarm.property(property)?)
        .map(|at| at.to_timestamp())
}

pub(super) fn acknowledged(series: &Series<'_>, index: usize) -> Option<Timestamp> {
    let reminder = series
        .ical
        .alarms_for_id(u32::try_from(index).ok()?)
        .find(|alarm| is_reminder(alarm))?;
    instant(series, reminder, &ICalendarProperty::Acknowledged)
}

pub(super) fn current_state(series: &Series<'_>, index: usize, span: &Span) -> Option<AlarmState> {
    if series.is_recurring() {
        return None;
    }
    alarm_fire(series, index, span)
        .map(|fire| alarm_state(series, index, fire, AlarmOwner::Component))
}

pub(super) fn occurrence_state(
    series: &Series<'_>,
    index: usize,
    span: &Span,
) -> Option<AlarmState> {
    let owner = AlarmOwner::of(series, index);
    alarm_fire(series, index, span).map(|fire| alarm_state(series, index, fire, owner))
}

pub fn set_occurrence_reminder(
    ical: &mut ICalendar,
    instance: RecurrenceId,
    action: OccurrenceReminder,
    now: Timestamp,
) -> Result<(), ConvertError> {
    let (index, fire, acknowledged, owner, alarms) = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let (index, span) = instance_span(&series, instance).ok_or(ConvertError::Unsupported)?;
        let Some(fire) = alarm_fire(&series, index, &span) else {
            return Ok(());
        };
        let alarms = TargetAlarms::of(ical, index);
        let acknowledged = alarms
            .reminder
            .and_then(|id| ical.components.get(id))
            .and_then(|reminder| instant(&series, reminder, &ICalendarProperty::Acknowledged));
        (
            index,
            fire,
            acknowledged,
            AlarmOwner::of(&series, index),
            alarms,
        )
    };
    let Some(reminder) = alarms.reminder else {
        return Ok(());
    };
    if owner == AlarmOwner::Series && acknowledged.is_some_and(|acknowledged| acknowledged > fire) {
        return Ok(());
    }
    let latest = acknowledged.map_or(fire, |acknowledged| acknowledged.max(fire));
    let signal = match action {
        OccurrenceReminder::Dismiss => {
            if let Some(alarm) = ical.components.get_mut(reminder) {
                set_acknowledged(alarm, latest);
            }
            remove_components(ical, &alarms.snoozes);
            return Ok(());
        }
        OccurrenceReminder::Snooze(signal) => signal,
    };
    if fire > now || signal <= fire {
        return Ok(());
    }
    let Some(event_uid) = ical
        .components
        .get(index)
        .and_then(ICalendarComponent::uid)
        .map(str::to_string)
    else {
        return Ok(());
    };
    let Some(alarm) = ical.components.get_mut(reminder) else {
        return Ok(());
    };
    let reminder_uid = ensure_uid(alarm, &event_uid);
    set_acknowledged(alarm, latest);
    let (first, rest) = match alarms.snoozes.split_first() {
        Some((first, rest)) => (Some(*first), rest),
        None => (None, &[][..]),
    };
    match first.and_then(|id| ical.components.get_mut(id)) {
        Some(existing) if triggers_at(existing, signal) => {}
        Some(existing) => *existing = snooze_alarm(reminder_uid, signal),
        None => push_alarm(ical, index, snooze_alarm(reminder_uid, signal)),
    }
    remove_components(ical, rest);
    Ok(())
}

pub(super) enum SeriesSnoozes {
    Other(SmallVec<[usize; 2]>),
    Owned(SmallVec<[usize; 2]>),
}

impl SeriesSnoozes {
    pub fn of(ical: &ICalendar, master: usize, instance: RecurrenceId) -> Self {
        let alarms = TargetAlarms::of(ical, master);
        if alarms.snoozes.is_empty() {
            return SeriesSnoozes::Other(alarms.snoozes);
        }
        let Some(series) = Series::new(ical) else {
            return SeriesSnoozes::Other(alarms.snoozes);
        };
        let fire = instance_span(&series, instance)
            .filter(|(index, _)| *index == master)
            .and_then(|(index, span)| alarm_fire(&series, index, &span));
        let acknowledged = alarms
            .reminder
            .and_then(|id| ical.components.get(id))
            .and_then(|reminder| instant(&series, reminder, &ICalendarProperty::Acknowledged));
        if fire.is_some() && fire == acknowledged {
            SeriesSnoozes::Owned(alarms.snoozes)
        } else {
            SeriesSnoozes::Other(alarms.snoozes)
        }
    }

    pub fn ids(&self) -> &[usize] {
        match self {
            SeriesSnoozes::Other(ids) | SeriesSnoozes::Owned(ids) => ids,
        }
    }
}

pub(super) fn triggers_at(alarm: &ICalendarComponent, at: Timestamp) -> bool {
    alarm
        .property(&ICalendarProperty::Trigger)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::PartialDateTime(value) => value.to_timestamp(),
            _ => None,
        })
        .is_some_and(|seconds| seconds == at.as_second())
}

pub(super) fn alarm_state(
    series: &Series<'_>,
    index: usize,
    fire: Timestamp,
    owner: AlarmOwner,
) -> AlarmState {
    let Ok(id) = u32::try_from(index) else {
        return AlarmState::Pending;
    };
    let Some(reminder) = series
        .ical
        .alarms_for_id(id)
        .find(|alarm| is_reminder(alarm))
    else {
        return AlarmState::Pending;
    };
    let uid = reminder.uid();
    let acknowledged = instant(series, reminder, &ICalendarProperty::Acknowledged);
    let snoozed = (owner == AlarmOwner::Component || acknowledged == Some(fire))
        .then(|| {
            series
                .ical
                .alarms_for_id(id)
                .filter(|alarm| is_display(alarm) && snoozes(alarm, uid))
                .filter_map(|alarm| {
                    let at = instant(series, alarm, &ICalendarProperty::Trigger)?;
                    instant(series, alarm, &ICalendarProperty::Acknowledged)
                        .is_none_or(|acknowledged| acknowledged < at)
                        .then_some(at)
                })
                .max()
        })
        .flatten();
    match snoozed {
        Some(at) => AlarmState::Snoozed(at),
        None if acknowledged.is_some_and(|acknowledged| acknowledged >= fire) => {
            AlarmState::Dismissed
        }
        None => AlarmState::Pending,
    }
}

pub(super) struct TargetAlarms {
    pub reminder: Option<usize>,
    pub snoozes: SmallVec<[usize; 2]>,
    pub others: usize,
}

impl TargetAlarms {
    pub fn of(ical: &ICalendar, target: usize) -> Self {
        let mut alarms = TargetAlarms {
            reminder: None,
            snoozes: SmallVec::new(),
            others: 0,
        };
        let Some(component) = ical.components.get(target) else {
            return alarms;
        };
        for (id, alarm) in component.component_ids.iter().filter_map(|id| {
            let id = usize::try_from(*id).ok()?;
            ical.components
                .get(id)
                .filter(|alarm| alarm.component_type == ICalendarComponentType::VAlarm)
                .map(|alarm| (id, alarm))
        }) {
            if is_snooze(alarm) {
                alarms.snoozes.push(id);
            } else if alarms.reminder.is_none() && is_display(alarm) {
                alarms.reminder = Some(id);
            } else {
                alarms.others += 1;
            }
        }
        let uid = alarms
            .reminder
            .and_then(|id| ical.components.get(id))
            .and_then(ICalendarComponent::uid);
        alarms.snoozes.retain(|id| {
            uid.is_some_and(|uid| {
                ical.components
                    .get(*id)
                    .is_some_and(|alarm| snoozes(alarm, Some(uid)))
            })
        });
        alarms
    }
}

pub(super) fn set_acknowledged(alarm: &mut ICalendarComponent, at: Timestamp) {
    clear_acknowledged(alarm);
    alarm
        .entries
        .push(utc_entry(ICalendarProperty::Acknowledged, at, Vec::new()));
}

pub(super) fn clear_acknowledged(alarm: &mut ICalendarComponent) {
    alarm
        .entries
        .retain(|entry| entry.name != ICalendarProperty::Acknowledged);
}

pub(super) fn ensure_uid(alarm: &mut ICalendarComponent, event_uid: &str) -> String {
    if let Some(uid) = alarm.uid() {
        return uid.to_string();
    }
    let uid = format!("{event_uid}{REMINDER_UID_SUFFIX}");
    alarm
        .entries
        .push(text_entry(ICalendarProperty::Uid, uid.clone(), Vec::new()));
    uid
}

pub(super) fn snooze_alarm(reminder_uid: String, at: Timestamp) -> ICalendarComponent {
    ICalendarComponent {
        component_type: ICalendarComponentType::VAlarm,
        entries: vec![
            text_entry(
                ICalendarProperty::Uid,
                format!("{reminder_uid}{SNOOZE_UID_SUFFIX}-{}", at.as_second()),
                Vec::new(),
            ),
            utc_entry(
                ICalendarProperty::Trigger,
                at,
                vec![ICalendarParameter {
                    name: ICalendarParameterName::Value,
                    value: ICalendarParameterValue::Value(ICalendarValueType::DateTime),
                }],
            ),
            text_entry(
                ICalendarProperty::RelatedTo,
                reminder_uid,
                vec![ICalendarParameter {
                    name: ICalendarParameterName::Reltype,
                    value: ICalendarParameterValue::Reltype(ICalendarRelationshipType::Snooze),
                }],
            ),
            ICalendarEntry {
                name: ICalendarProperty::Action,
                params: Vec::new(),
                values: smallvec![ICalendarValue::Action(ICalendarAction::Display)],
            },
            text_entry(
                ICalendarProperty::Description,
                REMINDER_DESCRIPTION.to_string(),
                Vec::new(),
            ),
        ],
        component_ids: Vec::new(),
    }
}

fn utc_entry(
    name: ICalendarProperty,
    at: Timestamp,
    params: Vec<ICalendarParameter>,
) -> ICalendarEntry {
    let mut entry = TimeTarget::utc().entry(name, at, false);
    entry.params.extend(params);
    entry
}

fn text_entry(
    name: ICalendarProperty,
    value: String,
    params: Vec<ICalendarParameter>,
) -> ICalendarEntry {
    ICalendarEntry {
        name,
        params,
        values: smallvec![ICalendarValue::Text(value)],
    }
}
