/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use bytes::Bytes;

use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarAction, ICalendarClassification, ICalendarComponent,
        ICalendarComponentType, ICalendarDuration, ICalendarEntry, ICalendarFrequency,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarRecurrenceRule, ICalendarRelated, ICalendarTransparency, ICalendarValue,
        ICalendarValueType,
    },
};
use jiff::{
    SignedDuration, Timestamp,
    civil::{Date, DateTime, Time},
};
use smallvec::smallvec;

use super::{
    RecurrenceId, RecurrenceSet,
    alarm::{
        AlarmState, SIGNAL_NEVER, SeriesSnoozes, TargetAlarms, clear_acknowledged, current_state,
        ensure_uid, set_acknowledged, snooze_alarm, triggers_at,
    },
    props::*,
    series::{Series, TimeForm, recurrence_rules, time_form},
    signal::SignalEdit,
    to_message::{alarm_fire, other_text, tz_definition},
};
use crate::{
    common::time::FileTime,
    convert::{
        BlobLimits, ConvertError,
        blob::{
            AppointmentRecur, ExceptionInfo, PatternType, RecurAnchor, RecurrencePattern,
            RuleCount, TzDefinition, local_from_minutes, local_minutes, with_seconds_of,
        },
        model::{LossKind, PatchReport, PropBag},
        tags::{self, KEYWORDS_NAME},
    },
    mapi::prop::{OwnedPropValue, PropKeyRef, sets::PS_PUBLIC_STRINGS},
};

const DEFAULT_REMINDER_MINUTES: u32 = 15;
const REMINDER_CLIENT_DEFAULT: i32 = 0x5AE9_80E1;
const SECONDS_PER_MINUTE: i64 = 60;
const MINUTES_PER_DAY: u32 = 1440;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Subject,
    Body,
    Location,
    Sensitivity,
    Importance,
    Keywords,
    BusyStatus,
    ConferencingType,
    Sequence,
    LastSequence,
    SequenceTime,
    Invited,
    StartWhole,
    EndWhole,
    SubType,
    ReminderSet,
    ReminderDelta,
    ReminderSignal,
    Recur,
    TzStart,
    TzRecur,
    Derived,
}

const LID_FIELDS: [(Lid, Field); 27] = [
    (LOCATION, Field::Location),
    (BUSY_STATUS, Field::BusyStatus),
    (CONFERENCING_TYPE, Field::ConferencingType),
    (SEQUENCE, Field::Sequence),
    (LAST_SEQUENCE, Field::LastSequence),
    (SEQUENCE_TIME, Field::SequenceTime),
    (F_INVITED, Field::Invited),
    (START_WHOLE, Field::StartWhole),
    (END_WHOLE, Field::EndWhole),
    (SUB_TYPE, Field::SubType),
    (REMINDER_SET, Field::ReminderSet),
    (REMINDER_DELTA, Field::ReminderDelta),
    (REMINDER_SIGNAL_TIME, Field::ReminderSignal),
    (RECUR, Field::Recur),
    (TZDEF_START, Field::TzStart),
    (TZDEF_RECUR, Field::TzRecur),
    (COMMON_START, Field::Derived),
    (COMMON_END, Field::Derived),
    (DURATION, Field::Derived),
    (CLIP_START, Field::Derived),
    (CLIP_END, Field::Derived),
    (RECURRING, Field::Derived),
    (IS_RECURRING, Field::Derived),
    (RECURRENCE_TYPE, Field::Derived),
    (TZ_DESCRIPTION, Field::Derived),
    (GLOBAL_OBJECT_ID, Field::Derived),
    (CLEAN_GLOBAL_OBJECT_ID, Field::Derived),
];
const DERIVED_LIDS: [Lid; 4] = [REMINDER_TIME, IS_EXCEPTION, EXCEPTION_REPLACE, WHERE];

fn field(key: PropKeyRef<'_>) -> Option<Field> {
    match key {
        PropKeyRef::Tag(id) => Some(match id {
            tags::SUBJECT => Field::Subject,
            tags::BODY => Field::Body,
            tags::SENSITIVITY => Field::Sensitivity,
            tags::IMPORTANCE => Field::Importance,
            tags::START_DATE | tags::END_DATE | tags::SUBJECT_PREFIX | tags::NORMALIZED_SUBJECT => {
                Field::Derived
            }
            _ => return None,
        }),
        PropKeyRef::Lid { set, lid } => LID_FIELDS
            .iter()
            .find(|(known, _)| known.set == set && known.lid == lid)
            .map(|(_, field)| *field)
            .or_else(|| {
                DERIVED_LIDS
                    .iter()
                    .any(|known| known.set == set && known.lid == lid)
                    .then_some(Field::Derived)
            }),
        PropKeyRef::Name { set, name } => {
            (set == PS_PUBLIC_STRINGS && name == KEYWORDS_NAME).then_some(Field::Keywords)
        }
    }
}

#[derive(Clone)]
pub(super) struct TimeTarget {
    pub tz: Tz,
    pub tzid: Option<String>,
}

#[derive(Clone, Copy)]
pub(super) enum ReminderMode {
    Tracked(Timestamp),
    Untracked,
}

impl ReminderMode {
    fn acknowledge_at(self, fire: Option<Timestamp>) -> Option<Timestamp> {
        match self {
            ReminderMode::Tracked(now) => fire.filter(|fire| *fire <= now).map(|_| now),
            ReminderMode::Untracked => None,
        }
    }

    fn now(self) -> Option<Timestamp> {
        match self {
            ReminderMode::Tracked(now) => Some(now),
            ReminderMode::Untracked => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rearm {
    ClearsAcknowledged,
    KeepsAcknowledged,
}

#[derive(Default)]
struct Pending<'b> {
    start: Option<Timestamp>,
    end: Option<Timestamp>,
    all_day: Option<bool>,
    reminder_set: Option<bool>,
    reminder_delta: Option<u32>,
    reminder_signal: Option<FileTime>,
    recur: Option<&'b [u8]>,
    tz_start: Option<&'b [u8]>,
    tz_recur: Option<&'b [u8]>,
}

pub(super) fn event(
    ical: &mut ICalendar,
    instance: Option<RecurrenceId>,
    changes: &PropBag,
    mode: ReminderMode,
) -> Result<PatchReport, ConvertError> {
    let target = target(ical, instance)?;
    let dismissed = matches!(mode, ReminderMode::Tracked(_))
        && target_state(ical, target) == Some(AlarmState::Dismissed);
    let mut report = PatchReport::default();
    let mut pending = Pending::default();
    let (is_master, is_main) = Series::new(ical).map_or((false, false), |series| {
        (series.master == Some(target), series.main == target)
    });
    for (key, value) in changes.iter() {
        let Some(field) = field(key.as_ref()) else {
            report.unmapped.set(key.clone(), value.clone());
            continue;
        };
        let field = match field {
            Field::Invited
            | Field::LastSequence
            | Field::SequenceTime
            | Field::ConferencingType
                if !is_main =>
            {
                Field::Derived
            }
            field => field,
        };
        if !apply(ical, target, field, value, &mut pending, &mut report) {
            report.unmapped.set(key.clone(), value.clone());
        }
    }
    if changes.text(tags::SUBJECT).is_none()
        && let Some(subject) = changes.composed_subject()
        && let Some(component) = ical.components.get_mut(target)
    {
        set_text(component, ICalendarProperty::Summary, &subject);
    }
    let mut replaced = None;
    if let Some(blob) = pending.recur {
        if is_master {
            replaced = rezone(ical, target, &mut pending, &mut report);
            if let Some((start, end)) = recurrence(
                ical,
                target,
                blob,
                &pending,
                PatternMatch::Rule,
                Exceptions::FromBlob,
                &mut report,
            )? {
                pending.start = Some(start);
                pending.end = Some(end);
            }
        } else {
            report.unmapped.set(
                RECUR.key(),
                OwnedPropValue::Binary(Bytes::copy_from_slice(blob)),
            );
        }
    }
    times(ical, target, &mut pending, replaced, &mut report);
    reminder(ical, target, &pending, mode, &mut report);
    if dismissed
        && pending.reminder_set.is_none()
        && target_state(ical, target) == Some(AlarmState::Pending)
    {
        let alarms = TargetAlarms::of(ical, target);
        remove_reminder(ical, alarms);
    }
    Ok(report)
}

pub(super) fn target(
    ical: &mut ICalendar,
    instance: Option<RecurrenceId>,
) -> Result<usize, ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let Some(id) = instance else {
        return Ok(series.main);
    };
    if let Some(index) = series.find_override(id) {
        return if series.excluded(id) {
            Err(ConvertError::Unsupported)
        } else {
            Ok(index)
        };
    }
    if !series.is_instance(id) {
        return Err(ConvertError::Unsupported);
    }
    let master = series.master.ok_or(ConvertError::Unsupported)?;
    let span = series
        .component(master)
        .and_then(|component| series.span(component))
        .ok_or(ConvertError::Unsupported)?;
    let form = series
        .component(master)
        .and_then(|component| component.property(&ICalendarProperty::Dtstart))
        .map(|entry| TimeTarget::of_start(&series, entry))
        .ok_or(ConvertError::Unsupported)?;
    let has_end = series
        .component(master)
        .is_some_and(|component| component.has_property(&ICalendarProperty::Dtend));
    let duration = span.duration();
    Ok(create_override(
        ical,
        master,
        id.0,
        &form,
        span.all_day,
        has_end.then_some(duration),
    ))
}

pub(super) fn create_override(
    ical: &mut ICalendar,
    master: usize,
    start: Timestamp,
    form: &TimeTarget,
    all_day: bool,
    duration: Option<SignedDuration>,
) -> usize {
    let Some(source) = ical.components.get(master) else {
        return master;
    };
    let mut component = ICalendarComponent {
        component_type: ICalendarComponentType::VEvent,
        entries: source
            .entries
            .iter()
            .filter(|entry| {
                !matches!(
                    entry.name,
                    ICalendarProperty::Rrule
                        | ICalendarProperty::Rdate
                        | ICalendarProperty::Exdate
                        | ICalendarProperty::Exrule
                        | ICalendarProperty::Dtstart
                        | ICalendarProperty::Dtend
                        | ICalendarProperty::RecurrenceId
                )
            })
            .cloned()
            .collect(),
        component_ids: Vec::new(),
    };
    let snoozes = SeriesSnoozes::of(ical, master, RecurrenceId(start));
    let alarms: Vec<ICalendarComponent> = source
        .component_ids
        .iter()
        .filter_map(|id| usize::try_from(*id).ok())
        .filter(|id| !snoozes.ids().contains(id))
        .filter_map(|id| ical.components.get(id))
        .cloned()
        .collect();
    component
        .entries
        .push(form.entry(ICalendarProperty::RecurrenceId, start, all_day));
    component
        .entries
        .push(form.entry(ICalendarProperty::Dtstart, start, all_day));
    if let Some(end) = duration.and_then(|duration| start.checked_add(duration).ok()) {
        component
            .entries
            .push(form.entry(ICalendarProperty::Dtend, end, all_day));
    }
    for alarm in alarms {
        if let Ok(id) = u32::try_from(ical.components.len()) {
            ical.components.push(alarm);
            component.component_ids.push(id);
        }
    }
    if let SeriesSnoozes::Owned(ids) = &snoozes
        && let Some(source) = ical.components.get_mut(master)
    {
        source
            .component_ids
            .retain(|id| usize::try_from(*id).is_ok_and(|id| !ids.contains(&id)));
        component
            .component_ids
            .extend(ids.iter().filter_map(|id| u32::try_from(*id).ok()));
    }
    let index = ical.components.len();
    ical.components.push(component);
    if let (Some(root), Ok(id)) = (ical.components.first_mut(), u32::try_from(index))
        && root.component_type == ICalendarComponentType::VCalendar
    {
        root.component_ids.push(id);
    }
    index
}

fn apply<'b>(
    ical: &mut ICalendar,
    target: usize,
    field: Field,
    value: &'b OwnedPropValue,
    pending: &mut Pending<'b>,
    report: &mut PatchReport,
) -> bool {
    let Some(component) = ical.components.get_mut(target) else {
        return false;
    };
    match (field, value) {
        (Field::Derived, _) => {}
        (Field::Subject, OwnedPropValue::Unicode(text)) => {
            set_text(component, ICalendarProperty::Summary, text)
        }
        (Field::Body, OwnedPropValue::Unicode(text)) => {
            set_text(component, ICalendarProperty::Description, text)
        }
        (Field::Location, OwnedPropValue::Unicode(text)) => {
            set_text(component, ICalendarProperty::Location, text)
        }
        (Field::Sensitivity, OwnedPropValue::I32(level)) => {
            let value = match *level {
                sensitivity::PERSONAL => ICalendarValue::Text(PERSONAL_CLASS.into()),
                sensitivity::PRIVATE => {
                    ICalendarValue::Classification(ICalendarClassification::Private)
                }
                sensitivity::CONFIDENTIAL => {
                    ICalendarValue::Classification(ICalendarClassification::Confidential)
                }
                _ => ICalendarValue::Classification(ICalendarClassification::Public),
            };
            set_value(component, ICalendarProperty::Class, value);
        }
        (Field::Importance, OwnedPropValue::I32(level)) => {
            let priority = match *level {
                importance::HIGH => 1,
                importance::LOW => 9,
                _ => 5,
            };
            set_value(
                component,
                ICalendarProperty::Priority,
                ICalendarValue::Integer(priority),
            );
            remove_other(component, CDO_IMPORTANCE_NAME);
        }
        (Field::Keywords, OwnedPropValue::MvUnicode(keywords)) => {
            component
                .entries
                .retain(|entry| entry.name != ICalendarProperty::Categories);
            if !keywords.is_empty() {
                component.entries.push(ICalendarEntry {
                    name: ICalendarProperty::Categories,
                    params: Vec::new(),
                    values: keywords
                        .iter()
                        .map(|keyword| ICalendarValue::Text(keyword.to_string()))
                        .collect(),
                });
            }
        }
        (Field::BusyStatus, OwnedPropValue::I32(status)) => {
            if set_busy_status(component, *status) {
                report.lossy.insert(LossKind::BusyStatus);
            }
        }
        (Field::Sequence, OwnedPropValue::I32(sequence)) => {
            set_value(
                component,
                ICalendarProperty::Sequence,
                ICalendarValue::Integer(i64::from(*sequence)),
            );
            remove_other(component, CDO_SEQUENCE_NAME);
        }
        (Field::LastSequence, OwnedPropValue::I32(sequence)) => set_value(
            component,
            ICalendarProperty::Other(LAST_SEQUENCE_NAME.into()),
            ICalendarValue::Text(sequence.to_string()),
        ),
        (Field::SequenceTime, OwnedPropValue::Time(time)) => set_value(
            component,
            ICalendarProperty::Other(SEQUENCE_TIME_NAME.into()),
            ICalendarValue::Text(timestamp(*time).strftime(SEQUENCE_TIME_FORMAT).to_string()),
        ),
        (Field::LastSequence, OwnedPropValue::Null) => remove_other(component, LAST_SEQUENCE_NAME),
        (Field::ConferencingType, OwnedPropValue::I32(kind)) => set_value(
            component,
            ICalendarProperty::Other(CONFERENCING_TYPE_NAME.into()),
            ICalendarValue::Text(kind.to_string()),
        ),
        (Field::ConferencingType, OwnedPropValue::Null) => {
            remove_other(component, CONFERENCING_TYPE_NAME)
        }
        (Field::SequenceTime, OwnedPropValue::Null) => remove_other(component, SEQUENCE_TIME_NAME),
        (Field::Invited, OwnedPropValue::Bool(true)) => remove_other(component, DRAFT_NAME),
        (Field::Invited, OwnedPropValue::Bool(false)) => set_value(
            component,
            ICalendarProperty::Other(DRAFT_NAME.into()),
            ICalendarValue::Text(DRAFT_TRUE.into()),
        ),
        (Field::StartWhole, OwnedPropValue::Time(time)) => pending.start = Some(timestamp(*time)),
        (Field::EndWhole, OwnedPropValue::Time(time)) => pending.end = Some(timestamp(*time)),
        (Field::SubType, OwnedPropValue::Bool(all_day)) => pending.all_day = Some(*all_day),
        (Field::ReminderSet, OwnedPropValue::Bool(set)) => pending.reminder_set = Some(*set),
        (Field::ReminderDelta, OwnedPropValue::I32(delta)) => {
            pending.reminder_delta = Some(if *delta == REMINDER_CLIENT_DEFAULT {
                DEFAULT_REMINDER_MINUTES
            } else {
                u32::try_from(*delta).unwrap_or_default()
            })
        }
        (Field::ReminderSignal, OwnedPropValue::Time(time)) => {
            pending.reminder_signal = Some(*time)
        }
        (Field::Recur, OwnedPropValue::Binary(blob)) => pending.recur = Some(blob),
        (Field::TzStart, OwnedPropValue::Binary(blob)) => pending.tz_start = Some(blob),
        (Field::TzRecur, OwnedPropValue::Binary(blob)) => pending.tz_recur = Some(blob),
        _ => return false,
    }
    true
}

fn pending_zone(
    pending: &mut Pending<'_>,
    year: i16,
    report: &mut PatchReport,
) -> Option<TimeTarget> {
    let (start, recur) = (pending.tz_start.take(), pending.tz_recur.take());
    start
        .map(|blob| (TZDEF_START, blob))
        .or(recur.map(|blob| (TZDEF_RECUR, blob)))
        .map(|(lid, blob)| zone_change(lid, blob, year, report))
}

fn rezone(
    ical: &mut ICalendar,
    target: usize,
    pending: &mut Pending<'_>,
    report: &mut PatchReport,
) -> Option<Tz> {
    if pending.tz_start.is_none() && pending.tz_recur.is_none() {
        return None;
    }
    let (start, end, year, old_tz) = Series::new(ical).and_then(|series| {
        let component = series.component(target)?;
        let span = series.span(component)?;
        (!span.all_day).then(|| {
            (
                span.start.to_timestamp(),
                span.end.to_timestamp(),
                span.start.naive_local().year(),
                component
                    .property(&ICalendarProperty::Dtstart)
                    .map_or(series.tz, |entry| series.entry_zone(entry)),
            )
        })
    })?;
    let form = pending_zone(pending, year, report)?;
    let component = ical.components.get_mut(target)?;
    set_times(component, &form, start, end, false);
    Some(old_tz)
}

fn times(
    ical: &mut ICalendar,
    target: usize,
    pending: &mut Pending<'_>,
    replaced: Option<Tz>,
    report: &mut PatchReport,
) {
    let Some(series) = Series::new(ical) else {
        return;
    };
    let Some(component) = series.component(target) else {
        return;
    };
    let current = series.span(component);
    let current_target = component
        .property(&ICalendarProperty::Dtstart)
        .map(|entry| TimeTarget::of_start(&series, entry))
        .unwrap_or(TimeTarget {
            tz: series.tz,
            tzid: None,
        });
    let recurring_master = series.master == Some(target) && component.is_recurrent();
    let year = current.map_or(1970, |span| span.start.naive_local().year());
    let new_target = pending_zone(pending, year, report);
    let old_tz = replaced.unwrap_or(current_target.tz);
    drop(series);
    if pending.start.is_none()
        && pending.end.is_none()
        && pending.all_day.is_none()
        && new_target.is_none()
        && old_tz == current_target.tz
    {
        return;
    }
    let Some(current) = current else {
        return;
    };
    let form = new_target.unwrap_or(current_target);
    let all_day = pending.all_day.unwrap_or(current.all_day);
    let start = pending.start.unwrap_or(current.start.to_timestamp());
    let end = pending.end.unwrap_or(current.end.to_timestamp());
    let retimed = recurring_master
        && !all_day
        && !current.all_day
        && (form.tz != old_tz || start != current.start.to_timestamp());
    let kept = if retimed { start_exception(ical) } else { None };
    if let Some(component) = ical.components.get_mut(target) {
        set_times(component, &form, start, end, all_day);
    }
    if retimed {
        drop_stale_exceptions(ical, target, &form, kept);
    }
}

fn drop_stale_exceptions(
    ical: &mut ICalendar,
    target: usize,
    form: &TimeTarget,
    kept: Option<StartException>,
) {
    let Some(series) = Series::new(ical).filter(|series| !series.rules_capped()) else {
        return;
    };
    let kept = kept.zip(off_pattern_start(&series));
    let exdates: Vec<Timestamp> = series.exdates().map(|zoned| zoned.to_timestamp()).collect();
    let overrides: Vec<(usize, RecurrenceId)> = series
        .overrides()
        .map(|(index, _, id)| (index, id))
        .collect();
    drop(series);
    if exdates.is_empty() && overrides.is_empty() {
        return;
    }
    let Some(component) = ical.components.get_mut(target) else {
        return;
    };
    let entries: Vec<ICalendarEntry> = component
        .entries
        .extract_if(.., |entry| entry.name == ICalendarProperty::Exdate)
        .collect();
    let mut instances: Vec<RecurrenceId> = exdates
        .iter()
        .copied()
        .map(RecurrenceId)
        .chain(overrides.iter().map(|(_, id)| *id))
        .collect();
    match Series::new(ical) {
        Some(series) => series.retain_instances(&mut instances),
        None => instances.clear(),
    }
    let valid = |id: RecurrenceId| instances.binary_search(&id).is_ok();
    let excluded_start = kept
        .filter(|(exception, _)| exception.excluded)
        .map(|(_, start)| start)
        .filter(|start| !valid(RecurrenceId(*start)));
    let Some(component) = ical.components.get_mut(target) else {
        return;
    };
    if excluded_start.is_none() && exdates.iter().all(|instant| valid(RecurrenceId(*instant))) {
        component.entries.extend(entries);
    } else {
        component.entries.extend(
            exdates
                .iter()
                .copied()
                .filter(|instant| valid(RecurrenceId(*instant)))
                .chain(excluded_start)
                .map(|instant| form.entry(ICalendarProperty::Exdate, instant, false)),
        );
    }
    let stale: Vec<usize> = overrides
        .iter()
        .filter(|(_, id)| {
            !valid(*id)
                && kept.is_none_or(|(exception, _)| exception.excluded || *id != exception.start)
        })
        .map(|(index, _)| *index)
        .collect();
    remove_components(ical, &stale);
    if let Some((exception, start)) = kept
        && !exception.excluded
    {
        retime_override(ical, exception.start, start);
    }
}

fn set_times(
    component: &mut ICalendarComponent,
    form: &TimeTarget,
    start: Timestamp,
    end: Timestamp,
    all_day: bool,
) {
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Dtstart | ICalendarProperty::Dtend | ICalendarProperty::Duration
        )
    });
    if all_day {
        let (first, last) = form.day_span(start, end);
        component
            .entries
            .push(date_entry(ICalendarProperty::Dtstart, first));
        component
            .entries
            .push(date_entry(ICalendarProperty::Dtend, last));
    } else {
        component
            .entries
            .push(form.entry(ICalendarProperty::Dtstart, start, false));
        component
            .entries
            .push(form.entry(ICalendarProperty::Dtend, end.max(start), false));
    }
}

fn zone_change(lid: Lid, blob: &[u8], year: i16, report: &mut PatchReport) -> TimeTarget {
    let definition = TzDefinition::decode(blob, &BlobLimits::DEFAULT).ok();
    let resolved = definition
        .as_ref()
        .and_then(|definition| Tz::from_str(&definition.key_name).ok());
    let exact = match (&definition, resolved) {
        (Some(definition), Some(tz)) => {
            let expected = tz_definition(tz, year..=year);
            definition
                .effective()
                .zip(expected.effective())
                .is_some_and(|(given, expected)| given.same_zone(expected))
        }
        _ => false,
    };
    if !exact {
        report.lossy.insert(LossKind::TimeZone);
        report.unmapped.set(
            lid.key(),
            OwnedPropValue::Binary(Bytes::copy_from_slice(blob)),
        );
    }
    let tz = resolved.unwrap_or(Tz::UTC);
    TimeTarget {
        tz,
        tzid: tz.name().map(|name| name.into_owned()),
    }
}

fn reminder(
    ical: &mut ICalendar,
    target: usize,
    pending: &Pending<'_>,
    mode: ReminderMode,
    report: &mut PatchReport,
) {
    if pending.reminder_set.is_none()
        && pending.reminder_delta.is_none()
        && pending.reminder_signal.is_none()
    {
        return;
    }
    let alarms = TargetAlarms::of(ical, target);
    let display = alarms.reminder;
    if pending.reminder_set.is_some() || pending.reminder_delta.is_some() {
        let shaped = display
            .and_then(|id| ical.components.get(id))
            .and_then(|alarm| alarm.property(&ICalendarProperty::Trigger))
            .is_none_or(|trigger| {
                !matches!(
                    trigger.parameter(&ICalendarParameterName::Related),
                    Some(ICalendarParameterValue::Related(ICalendarRelated::End))
                ) && matches!(trigger.values.first(), Some(ICalendarValue::Duration(duration)) if duration.as_seconds() <= 0)
            });
        if alarms.others > 0 || !shaped {
            report.lossy.insert(LossKind::Reminder);
        }
    }
    if pending.reminder_set == Some(false) {
        match display.zip(mode.acknowledge_at(due(ical, target))) {
            Some((id, now)) => {
                if let Some(alarm) = ical.components.get_mut(id) {
                    set_acknowledged(alarm, now);
                }
                remove_components(ical, &alarms.snoozes);
            }
            None => remove_reminder(ical, alarms),
        }
        return;
    }
    let series_edit = pending
        .reminder_signal
        .zip(mode.now())
        .and_then(|(signal, now)| SignalEdit::of(ical, target, signal, now));
    if pending.reminder_set.is_some() || pending.reminder_delta.is_some() {
        let rearm = if series_edit.is_some()
            || (pending.reminder_delta.is_none() && is_series_override(ical, target))
        {
            Rearm::KeepsAcknowledged
        } else {
            Rearm::ClearsAcknowledged
        };
        set_trigger(ical, target, display, pending, rearm);
    }
    if let Some(edit) = series_edit {
        edit.apply(ical);
        return;
    }
    if let Some(signal) = pending
        .reminder_signal
        .filter(|signal| *signal != SIGNAL_NEVER)
    {
        snooze(ical, target, timestamp(signal), mode);
    }
}

fn is_series_override(ical: &ICalendar, target: usize) -> bool {
    Series::new(ical).is_some_and(|series| {
        series.is_recurring() && series.master.is_some_and(|master| master != target)
    })
}

fn remove_reminder(ical: &mut ICalendar, alarms: TargetAlarms) {
    let mut removed = alarms.snoozes;
    removed.extend(alarms.reminder);
    remove_components(ical, &removed);
}

fn target_state(ical: &ICalendar, target: usize) -> Option<AlarmState> {
    let series = Series::new(ical)?;
    let span = series.span(series.component(target)?)?;
    current_state(&series, target, &span)
}

fn set_trigger(
    ical: &mut ICalendar,
    target: usize,
    display: Option<usize>,
    pending: &Pending<'_>,
    rearm: Rearm,
) {
    let delta = pending.reminder_delta.unwrap_or(DEFAULT_REMINDER_MINUTES);
    let trigger = ICalendarEntry {
        name: ICalendarProperty::Trigger,
        params: Vec::new(),
        values: smallvec![ICalendarValue::Duration(ICalendarDuration::from_seconds(
            -i64::from(delta).saturating_mul(SECONDS_PER_MINUTE)
        ))],
    };
    match display.and_then(|id| ical.components.get_mut(id)) {
        Some(alarm) => {
            if pending.reminder_delta.is_some() {
                alarm
                    .entries
                    .retain(|entry| entry.name != ICalendarProperty::Trigger);
                alarm.entries.push(trigger);
            }
            if pending.reminder_set == Some(true) && rearm == Rearm::ClearsAcknowledged {
                clear_acknowledged(alarm);
            }
        }
        None => {
            let alarm = ICalendarComponent {
                component_type: ICalendarComponentType::VAlarm,
                entries: vec![
                    ICalendarEntry {
                        name: ICalendarProperty::Action,
                        params: Vec::new(),
                        values: smallvec![ICalendarValue::Action(ICalendarAction::Display)],
                    },
                    ICalendarEntry {
                        name: ICalendarProperty::Description,
                        params: Vec::new(),
                        values: smallvec![ICalendarValue::Text(REMINDER_DESCRIPTION.into())],
                    },
                    trigger,
                ],
                component_ids: Vec::new(),
            };
            push_alarm(ical, target, alarm);
        }
    }
}

pub(super) fn push_alarm(ical: &mut ICalendar, target: usize, alarm: ICalendarComponent) {
    let Ok(id) = u32::try_from(ical.components.len()) else {
        return;
    };
    ical.components.push(alarm);
    if let Some(component) = ical.components.get_mut(target) {
        component.component_ids.push(id);
    }
}

fn due(ical: &ICalendar, target: usize) -> Option<Timestamp> {
    let series = Series::new(ical).filter(|series| !series.is_recurring())?;
    let span = series.span(series.component(target)?)?;
    alarm_fire(&series, target, &span)
}

fn snooze(ical: &mut ICalendar, target: usize, signal: Timestamp, mode: ReminderMode) {
    let Some(fire) = due(ical, target) else {
        return;
    };
    let alarms = TargetAlarms::of(ical, target);
    let Some(reminder) = alarms.reminder else {
        return;
    };
    let (first, rest) = match alarms.snoozes.split_first() {
        Some((first, rest)) => (Some(*first), rest),
        None => (None, &[][..]),
    };
    if signal <= fire {
        remove_components(ical, &alarms.snoozes);
        return;
    }
    let Some(now) = mode.acknowledge_at(Some(fire)) else {
        return;
    };
    let Some(event_uid) = ical
        .components
        .get(target)
        .and_then(ICalendarComponent::uid)
        .map(str::to_string)
    else {
        return;
    };
    let Some(alarm) = ical.components.get_mut(reminder) else {
        return;
    };
    let reminder_uid = ensure_uid(alarm, &event_uid);
    set_acknowledged(alarm, now);
    match first.and_then(|id| ical.components.get_mut(id)) {
        Some(existing) if triggers_at(existing, signal) => {}
        Some(existing) => *existing = snooze_alarm(reminder_uid, signal),
        None => push_alarm(ical, target, snooze_alarm(reminder_uid, signal)),
    }
    remove_components(ical, rest);
}

#[derive(Clone, Copy)]
enum PatternMatch {
    Rule,
    RuleAndWeekStart,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Exceptions {
    FromBlob,
    Kept,
}

fn recurrence(
    ical: &mut ICalendar,
    target: usize,
    blob: &[u8],
    pending: &Pending<'_>,
    matching: PatternMatch,
    exceptions: Exceptions,
    report: &mut PatchReport,
) -> Result<Option<(Timestamp, Timestamp)>, ConvertError> {
    let keep_blob = |report: &mut PatchReport, kind: LossKind| {
        report.lossy.insert(kind);
        report.unmapped.set(
            RECUR.key(),
            OwnedPropValue::Binary(Bytes::copy_from_slice(blob)),
        );
    };
    let Ok(recur) = AppointmentRecur::decode(blob, &BlobLimits::DEFAULT) else {
        keep_blob(report, LossKind::Recurrence);
        return Ok(None);
    };
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let component = series.component(target).ok_or(ConvertError::Unsupported)?;
    let span = series.span(component).ok_or(ConvertError::Unsupported)?;
    let form = component
        .property(&ICalendarProperty::Dtstart)
        .map(|entry| TimeTarget {
            tz: series.tz,
            tzid: (time_form(entry) == Some(TimeForm::Zoned))
                .then(|| entry.tz_id().map(str::to_string))
                .flatten(),
        })
        .ok_or(ConvertError::Unsupported)?;
    let anchor = recur_anchor(&series, component).ok_or(ConvertError::Unsupported)?;
    let (current_start, current_end) = (span.start.to_timestamp(), span.end.to_timestamp());
    let (start, end) = (
        pending.start.unwrap_or(current_start),
        pending.end.unwrap_or(current_end),
    );
    let series_start = series.local(start);
    let written = RecurAnchor {
        start: series_start,
        ..anchor
    };
    let stored = component
        .property(&ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => Some(rule),
            _ => None,
        });
    let same_at = |anchor: RecurAnchor| {
        stored
            .and_then(|rule| AppointmentRecur::from_rrule(rule, anchor).ok())
            .is_some_and(|current| same_pattern(&current, &recur, matching))
    };
    let unchanged = same_at(written);
    let rebuild = !unchanged || (start != current_start && !same_at(anchor));
    let rule = if unchanged {
        None
    } else {
        let rule_tz = if span.all_day {
            Tz::Floating
        } else {
            series.tz
        };
        match recur.to_rrule(rule_tz) {
            Ok(mut rule) => {
                if let Some(until) = &mut rule.until {
                    if span.all_day {
                        *until = PartialDateTime {
                            year: until.year,
                            month: until.month,
                            day: until.day,
                            ..PartialDateTime::default()
                        };
                    } else if let Ok(second) = u8::try_from(series_start.second()) {
                        until.second = Some(second);
                    }
                }
                Some(rule)
            }
            Err(_) => {
                keep_blob(report, LossKind::Recurrence);
                return Ok(None);
            }
        }
    };
    let moved = rule
        .as_ref()
        .map(|rule| {
            AppointmentRecur::from_client_rrule(rule, written)
                .map_or(recur.pattern.start_date, |mapped| mapped.pattern.start_date)
        })
        .and_then(local_from_minutes)
        .map(|first| first.date())
        .filter(|first| *first > written.start.date())
        .and_then(|first| {
            series
                .tz
                .from_local(first.to_datetime(written.start.time()))
        })
        .map(|first| {
            let first = first.to_timestamp();
            first
                .checked_add(end.duration_since(start))
                .map(|end| (first, end))
        })
        .transpose()
        .map_err(|_| ConvertError::Unsupported)?;
    if recur.exceptions.iter().any(|exception| {
        exception.appointment_color.is_some()
            || exception.attachment.is_some()
            || exception.change_highlight.is_some_and(|value| value != 0)
    }) {
        keep_blob(report, LossKind::ExceptionDetail);
    }
    let start_offset = recur.start_time_offset;
    let instance = |minutes: u32| {
        local_from_minutes(minutes)
            .map(|local| with_seconds_of(local, series_start))
            .and_then(|local| series.tz.from_local(local))
            .map(|zoned| zoned.to_timestamp())
    };
    let mut modified_days: Vec<u32> = recur
        .exceptions
        .iter()
        .map(|exception| exception.original_start / MINUTES_PER_DAY)
        .collect();
    modified_days.sort_unstable();
    let mut exdates: Vec<Timestamp> = recur
        .pattern
        .deleted_instances
        .iter()
        .filter(|date| {
            modified_days
                .binary_search(&(**date / MINUTES_PER_DAY))
                .is_err()
        })
        .filter_map(|date| instance(date.checked_add(start_offset)?))
        .collect();
    let before_first = |instant: Timestamp| {
        local_minutes(series.local(instant))
            .is_some_and(|minutes| minutes < recur.pattern.start_date)
    };
    let retime = exceptions == Exceptions::FromBlob
        && !rebuild
        && start != current_start
        && before_first(current_start)
        && before_first(start);
    match exceptions {
        Exceptions::Kept => exdates.extend(series.exdates().map(|zoned| zoned.to_timestamp())),
        Exceptions::FromBlob if !rebuild => exdates.extend(
            series
                .exdates()
                .map(|zoned| zoned.to_timestamp())
                .filter(|instant| before_first(*instant))
                .map(|instant| {
                    if retime && instant == current_start {
                        start
                    } else {
                        instant
                    }
                }),
        ),
        Exceptions::FromBlob => {}
    }
    exdates.sort_unstable();
    exdates.dedup();
    let mut originals: Vec<Timestamp> = if rebuild {
        recur
            .exceptions
            .iter()
            .filter_map(|exception| instance(exception.original_start))
            .collect()
    } else {
        Vec::new()
    };
    originals.sort_unstable();
    drop(series);
    let Some(component) = ical.components.get_mut(target) else {
        return Err(ConvertError::Unsupported);
    };
    let (start, end) = moved.unwrap_or((start, end));
    if (start, end) != (current_start, current_end) {
        set_times(component, &form, start, end, span.all_day);
    }
    if let Some(rule) = rule {
        component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::Rrule);
        component.entries.push(ICalendarEntry {
            name: ICalendarProperty::Rrule,
            params: Vec::new(),
            values: smallvec![ICalendarValue::RecurrenceRule(Box::new(rule))],
        });
    }
    component
        .entries
        .retain(|entry| entry.name != ICalendarProperty::Exdate);
    let mut instances = Vec::new();
    if exceptions == Exceptions::Kept {
        if let Some(series) = Series::new(ical) {
            instances.extend(exdates.iter().copied().map(RecurrenceId));
            instances.extend(series.overrides().map(|(_, _, id)| id));
            if series.rules_capped() {
                instances.sort_unstable();
            } else {
                series.retain_instances(&mut instances);
            }
        }
        exdates.retain(|instant| instances.binary_search(&RecurrenceId(*instant)).is_ok());
    }
    let Some(component) = ical.components.get_mut(target) else {
        return Err(ConvertError::Unsupported);
    };
    component.entries.extend(
        exdates
            .iter()
            .map(|instant| form.entry(ICalendarProperty::Exdate, *instant, span.all_day)),
    );
    if retime {
        retime_override(ical, RecurrenceId(current_start), start);
    }
    let Some(series) = Series::new(ical) else {
        return Ok(moved);
    };
    let removed: Vec<usize> = series
        .overrides()
        .filter(|(_, _, id)| {
            exdates.binary_search(&id.0).is_ok()
                || match exceptions {
                    Exceptions::FromBlob => rebuild && originals.binary_search(&id.0).is_err(),
                    Exceptions::Kept => instances.binary_search(id).is_err(),
                }
        })
        .map(|(index, _, _)| index)
        .collect();
    drop(series);
    remove_components(ical, &removed);
    for exception in &recur.exceptions {
        exception_override(ical, exception, &form, span.all_day, series_start);
    }
    Ok(moved)
}

fn exception_override(
    ical: &mut ICalendar,
    exception: &ExceptionInfo,
    form: &TimeTarget,
    all_day: bool,
    series_start: DateTime,
) {
    let instant = |local: DateTime| form.tz.from_local(local).map(|zoned| zoned.to_timestamp());
    let (Some(original), Some(start_local), Some(end_local)) = (
        local_from_minutes(exception.original_start)
            .map(|local| with_seconds_of(local, series_start))
            .and_then(instant),
        local_from_minutes(exception.start),
        local_from_minutes(exception.end),
    ) else {
        return;
    };
    let Ok(index) = target(ical, Some(RecurrenceId(original))) else {
        return;
    };
    let stored = Series::new(ical).and_then(|series| {
        let span = series.span(series.component(index)?)?;
        let (start, end) = (span.start.to_timestamp(), span.end.to_timestamp());
        Some((
            (local_minutes(series.local(start)), start),
            (local_minutes(series.local(end)), end),
        ))
    });
    let keep =
        |minutes: u32, local: DateTime, stored: Option<(Option<u32>, Timestamp)>| match stored {
            Some((Some(stored_minutes), stored)) if stored_minutes == minutes => Some(stored),
            _ => instant(local),
        };
    let (Some(start), Some(end)) = (
        keep(exception.start, start_local, stored.map(|(start, _)| start)),
        keep(exception.end, end_local, stored.map(|(_, end)| end)),
    ) else {
        return;
    };
    let Some(component) = ical.components.get_mut(index) else {
        return;
    };
    let all_day = exception.sub_type.map_or(all_day, |sub_type| sub_type != 0);
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Dtstart | ICalendarProperty::Dtend | ICalendarProperty::Duration
        )
    });
    component
        .entries
        .push(form.entry(ICalendarProperty::Dtstart, start, all_day));
    component
        .entries
        .push(form.entry(ICalendarProperty::Dtend, end.max(start), all_day));
    if let Some(subject) = &exception.subject {
        set_text(component, ICalendarProperty::Summary, subject);
    }
    if let Some(location) = &exception.location {
        set_text(component, ICalendarProperty::Location, location);
    }
    if let Some(status) = exception
        .busy_status
        .and_then(|status| i32::try_from(status).ok())
    {
        set_busy_status(component, status);
    }
}

pub(super) fn set_recurrence(
    ical: &mut ICalendar,
    rule: &ICalendarRecurrenceRule,
    first: Date,
    previous: Option<Timestamp>,
) -> Result<RecurrenceSet, ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let component = series
        .master
        .and_then(|master| series.component(master))
        .ok_or(ConvertError::Unsupported)?;
    let mut anchor = recur_anchor(&series, component).ok_or(ConvertError::Unsupported)?;
    let given = AppointmentRecur::from_client_rrule(rule, anchor).ok();
    let stored = component
        .property(&ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => Some(rule),
            _ => None,
        });
    let same_at = |anchor: RecurAnchor, given: &AppointmentRecur| {
        stored
            .and_then(|rule| AppointmentRecur::from_rrule(rule, anchor).ok())
            .is_some_and(|current| same_pattern(&current, given, PatternMatch::RuleAndWeekStart))
    };
    let pattern_date = |recur: &AppointmentRecur| {
        local_from_minutes(recur.pattern.start_date).map(|start| start.date())
    };
    if given.as_ref().is_some_and(|given| {
        same_at(anchor, given) && pattern_date(given).is_none_or(|date| first <= date)
    }) {
        return Ok(RecurrenceSet::Applied);
    }
    let mut moved = None;
    let recur = match given {
        Some(recur) if pattern_date(&recur) == Some(first) => recur,
        given if first <= anchor.start.date() => {
            return Ok(if given.is_some() {
                RecurrenceSet::StartMismatch
            } else {
                RecurrenceSet::Unmappable
            });
        }
        _ => {
            let time = anchor.start.time();
            let Some(start) = rule_month_start(rule, first)
                .and_then(|date| {
                    AppointmentRecur::from_client_rrule(
                        rule,
                        RecurAnchor {
                            start: date.to_datetime(time),
                            ..anchor
                        },
                    )
                    .ok()
                })
                .and_then(|realigned| pattern_date(&realigned))
                .map(|date| date.to_datetime(time))
            else {
                return Ok(RecurrenceSet::Unmappable);
            };
            anchor.start = start;
            let Ok(realigned) = AppointmentRecur::from_client_rrule(rule, anchor) else {
                return Ok(RecurrenceSet::Unmappable);
            };
            let entry = component
                .property(&ICalendarProperty::Dtstart)
                .ok_or(ConvertError::Unsupported)?;
            let form = TimeTarget::of_start(&series, entry);
            let all_day = time_form(entry) == Some(TimeForm::Date);
            let duration = series
                .span(component)
                .ok_or(ConvertError::Unsupported)?
                .duration();
            let Some((start, end)) = form.tz.from_local(start).and_then(|zoned| {
                let start = zoned.to_timestamp();
                Some((start, start.checked_add(duration).ok()?))
            }) else {
                return Ok(RecurrenceSet::Unmappable);
            };
            moved = Some((form, start, end, all_day));
            realigned
        }
    };
    let echoed = previous
        .map(|previous| RecurAnchor {
            start: series.local(previous),
            ..anchor
        })
        .filter(|before| before.start != anchor.start)
        .is_some_and(|before| {
            AppointmentRecur::from_client_rrule(rule, before)
                .is_ok_and(|given| same_at(before, &given))
        });
    let overrides: Vec<usize> = if echoed {
        Vec::new()
    } else {
        series.overrides().map(|(index, _, _)| index).collect()
    };
    drop(series);
    let exceptions = if echoed {
        Exceptions::Kept
    } else {
        remove_components(ical, &overrides);
        for component in vevents_mut(ical) {
            component.entries.retain(|entry| {
                !matches!(
                    entry.name,
                    ICalendarProperty::Rdate | ICalendarProperty::Exdate
                )
            });
        }
        Exceptions::FromBlob
    };
    let master = Series::new(ical)
        .and_then(|series| series.master)
        .ok_or(ConvertError::Unsupported)?;
    if let Some((form, start, end, all_day)) = moved
        && let Some(component) = ical.components.get_mut(master)
    {
        set_times(component, &form, start, end, all_day);
    }
    let mut blob = Vec::new();
    recur.encode(&mut blob);
    let mut report = PatchReport::default();
    recurrence(
        ical,
        master,
        &blob,
        &Pending::default(),
        PatternMatch::RuleAndWeekStart,
        exceptions,
        &mut report,
    )?;
    Ok(if report.lossy.is_empty() && report.unmapped.is_empty() {
        RecurrenceSet::Applied
    } else {
        RecurrenceSet::Unmappable
    })
}

pub(super) fn exclude_instance(ical: &mut ICalendar, id: RecurrenceId) -> Result<(), ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let master = series.master.ok_or(ConvertError::Unsupported)?;
    let component = series
        .component(master)
        .filter(|component| component.is_recurrent())
        .ok_or(ConvertError::Unsupported)?;
    if series.excluded(id) {
        return Ok(());
    }
    let overridden = series.find_override(id);
    if overridden.is_none() && !series.is_instance(id) {
        return Err(ConvertError::Unsupported);
    }
    let start = component
        .property(&ICalendarProperty::Dtstart)
        .ok_or(ConvertError::Unsupported)?;
    let all_day = time_form(start) == Some(TimeForm::Date);
    let form = TimeTarget::of_start(&series, start);
    drop(series);
    ical.components
        .get_mut(master)
        .ok_or(ConvertError::Unsupported)?
        .entries
        .push(form.entry(ICalendarProperty::Exdate, id.0, all_day));
    if let Some(index) = overridden {
        remove_components(ical, &[index]);
    }
    Ok(())
}

pub(super) fn clear_recurrence(ical: &mut ICalendar) -> Result<(), ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    if series.master.is_none() {
        return Ok(());
    }
    let overrides: Vec<usize> = series.overrides().map(|(index, _, _)| index).collect();
    drop(series);
    remove_components(ical, &overrides);
    for component in vevents_mut(ical) {
        component.entries.retain(|entry| {
            !matches!(
                entry.name,
                ICalendarProperty::Rrule | ICalendarProperty::Rdate | ICalendarProperty::Exdate
            )
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct StartException {
    start: RecurrenceId,
    excluded: bool,
}

pub(super) fn start_exception(ical: &ICalendar) -> Option<StartException> {
    let series = Series::new(ical)?;
    let start = RecurrenceId(off_pattern_start(&series)?);
    let excluded = series.excluded(start);
    (excluded || series.find_override(start).is_some())
        .then_some(StartException { start, excluded })
}

pub(super) fn clear_exceptions(
    ical: &mut ICalendar,
    kept: Option<StartException>,
) -> Result<(), ConvertError> {
    let (overrides, kept) = match Series::new(ical) {
        Some(series) => {
            let kept = kept.zip(off_pattern_start(&series));
            let overrides: Vec<usize> = series
                .overrides()
                .filter(|(_, _, id)| {
                    kept.is_none_or(|(kept, _)| kept.excluded || *id != kept.start)
                })
                .map(|(index, _, _)| index)
                .collect();
            (overrides, kept)
        }
        None => (Vec::new(), None),
    };
    remove_components(ical, &overrides);
    for component in vevents_mut(ical) {
        component.entries.retain(|entry| {
            !matches!(
                entry.name,
                ICalendarProperty::Rdate | ICalendarProperty::Exdate
            )
        });
    }
    match kept {
        Some((kept, start)) if kept.excluded => exclude_instance(ical, RecurrenceId(start)),
        Some((kept, start)) => {
            retime_override(ical, kept.start, start);
            Ok(())
        }
        None => Ok(()),
    }
}

fn off_pattern_start(series: &Series<'_>) -> Option<Timestamp> {
    let master = series.component(series.master?)?;
    let mut rules = recurrence_rules(master);
    let (Some(rule), None) = (rules.next(), rules.next()) else {
        return None;
    };
    let start = series.span(master)?.start;
    let local = start.naive_local();
    let pattern = RecurrencePattern::from_rrule(rule, local, series.tz, RuleCount::Dtstart).ok()?;
    local_minutes(local)
        .is_some_and(|minutes| minutes < pattern.start_date)
        .then(|| start.to_timestamp())
}

fn retime_override(ical: &mut ICalendar, from: RecurrenceId, to: Timestamp) {
    let Some((index, entry)) = Series::new(ical).and_then(|series| {
        let index = series.find_override(from)?;
        let start = series
            .component(series.master?)?
            .property(&ICalendarProperty::Dtstart)?;
        let entry = TimeTarget::of_start(&series, start).entry(
            ICalendarProperty::RecurrenceId,
            to,
            time_form(start) == Some(TimeForm::Date),
        );
        Some((index, entry))
    }) else {
        return;
    };
    if let Some(component) = ical.components.get_mut(index) {
        component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::RecurrenceId);
        component.entries.push(entry);
    }
}

pub(super) fn same_rule(
    series: &Series<'_>,
    master: &ICalendarComponent,
    rule: &ICalendarRecurrenceRule,
    start: &ICalendarEntry,
) -> bool {
    let mut current = recurrence_rules(master);
    let (Some(current), None) = (current.next(), current.next()) else {
        return false;
    };
    let mapped = recur_anchor(series, master).and_then(|anchor| {
        let anchor = RecurAnchor {
            start: series.resolve_first(start)?.naive_local(),
            ..anchor
        };
        Some((
            AppointmentRecur::from_rrule(current, anchor).ok()?,
            AppointmentRecur::from_client_rrule(rule, anchor).ok()?,
        ))
    });
    match mapped {
        Some((current, given)) => same_pattern(&current, &given, PatternMatch::RuleAndWeekStart),
        None => current == rule,
    }
}

pub(super) fn vevents_mut(ical: &mut ICalendar) -> impl Iterator<Item = &mut ICalendarComponent> {
    ical.components
        .iter_mut()
        .filter(|component| component.component_type == ICalendarComponentType::VEvent)
}

fn rule_month_start(rule: &ICalendarRecurrenceRule, from: Date) -> Option<Date> {
    let [month] = rule.bymonth.as_slice() else {
        return Some(from);
    };
    let month = i8::try_from(month.month()).ok()?;
    if rule.freq != ICalendarFrequency::Yearly || month == from.month() {
        return Some(from);
    }
    let year = if month < from.month() {
        from.year().checked_add(1)?
    } else {
        from.year()
    };
    Date::new(year, month, 1).ok()
}

fn recur_anchor(series: &Series<'_>, component: &ICalendarComponent) -> Option<RecurAnchor> {
    let span = series.span(component)?;
    Some(RecurAnchor {
        start: span.start.naive_local(),
        duration_minutes: u32::try_from(span.duration().as_secs() / SECONDS_PER_MINUTE)
            .unwrap_or(u32::MAX),
        tz: series.tz,
    })
}

fn same_pattern(
    current: &AppointmentRecur,
    given: &AppointmentRecur,
    matching: PatternMatch,
) -> bool {
    let (a, b) = (&current.pattern, &given.pattern);
    a.frequency == b.frequency
        && a.pattern == b.pattern
        && a.period == b.period
        && a.end == b.end
        && a.occurrence_count == b.occurrence_count
        && a.start_date == b.start_date
        && a.end_date == b.end_date
        && match matching {
            PatternMatch::Rule => true,
            PatternMatch::RuleAndWeekStart => {
                a.first_dow == b.first_dow
                    || !matches!(a.pattern, PatternType::Week { .. })
                    || a.period <= 1
            }
        }
}

pub(super) fn remove_components(ical: &mut ICalendar, indexes: &[usize]) {
    if indexes.is_empty() {
        return;
    }
    let len = ical.components.len();
    let mut removed = vec![false; len];
    for index in indexes {
        if let Some(slot) = removed.get_mut(*index) {
            *slot = true;
        }
        if let Some(component) = ical.components.get(*index) {
            for child in &component.component_ids {
                if let Some(slot) = usize::try_from(*child)
                    .ok()
                    .and_then(|child| removed.get_mut(child))
                {
                    *slot = true;
                }
            }
        }
    }
    let mut remap: Vec<Option<u32>> = Vec::with_capacity(len);
    let mut next = 0u32;
    for gone in &removed {
        if *gone {
            remap.push(None);
        } else {
            remap.push(Some(next));
            next = next.saturating_add(1);
        }
    }
    let mut keep = removed.iter();
    ical.components
        .retain(|_| keep.next().is_some_and(|gone| !*gone));
    for component in &mut ical.components {
        component.component_ids = component
            .component_ids
            .iter()
            .filter_map(|id| {
                usize::try_from(*id)
                    .ok()
                    .and_then(|id| remap.get(id).copied().flatten())
            })
            .collect();
    }
}

impl TimeTarget {
    pub(super) fn utc() -> Self {
        TimeTarget {
            tz: Tz::UTC,
            tzid: None,
        }
    }

    pub(super) fn of_start(series: &Series<'_>, entry: &ICalendarEntry) -> Self {
        TimeTarget {
            tz: series.entry_zone(entry),
            tzid: (time_form(entry) == Some(TimeForm::Zoned))
                .then(|| entry.tz_id().map(str::to_string))
                .flatten(),
        }
    }

    pub(super) fn date(&self, instant: Timestamp) -> PartialDateTime {
        date_time(
            self.tz.from_timestamp(instant).naive_local(),
            DateForm::Date,
        )
    }

    pub(super) fn day_span(&self, start: Timestamp, end: Timestamp) -> (Date, Date) {
        let first = self.tz.from_timestamp(start).naive_local().date();
        let end = self.tz.from_timestamp(end).naive_local();
        let last = if end.time() == Time::midnight() {
            end.date()
        } else {
            end.date().tomorrow().unwrap_or(end.date())
        };
        (first, last.max(first.tomorrow().unwrap_or(first)))
    }

    pub(super) fn entry(
        &self,
        name: ICalendarProperty,
        instant: Timestamp,
        all_day: bool,
    ) -> ICalendarEntry {
        if all_day {
            return date_entry(name, self.tz.from_timestamp(instant).naive_local().date());
        }
        let mut params = Vec::new();
        let local = self.tz.from_timestamp(instant).naive_local();
        let value = match (&self.tzid, self.tz) {
            (Some(tzid), Tz::Iana(_)) if !self.tz.is_utc() => {
                params.push(ICalendarParameter {
                    name: ICalendarParameterName::Tzid,
                    value: ICalendarParameterValue::Text(tzid.clone()),
                });
                date_time(local, DateForm::Local)
            }
            (_, Tz::Floating) => date_time(local, DateForm::Local),
            _ => date_time(Tz::UTC.from_timestamp(instant).naive_local(), DateForm::Utc),
        };
        ICalendarEntry {
            name,
            params,
            values: smallvec![ICalendarValue::PartialDateTime(value)],
        }
    }
}

fn date_entry(name: ICalendarProperty, date: Date) -> ICalendarEntry {
    ICalendarEntry {
        name,
        params: vec![ICalendarParameter {
            name: ICalendarParameterName::Value,
            value: ICalendarParameterValue::Value(ICalendarValueType::Date),
        }],
        values: smallvec![ICalendarValue::PartialDateTime(date_time(
            date.into(),
            DateForm::Date
        ))],
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DateForm {
    Date,
    Local,
    Utc,
}

fn date_time(local: DateTime, form: DateForm) -> PartialDateTime {
    let timed = form != DateForm::Date;
    let utc = (form == DateForm::Utc).then_some(0);
    PartialDateTime {
        year: u16::try_from(local.year()).ok(),
        month: u8::try_from(local.month()).ok(),
        day: u8::try_from(local.day()).ok(),
        hour: timed.then(|| u8::try_from(local.hour()).ok()).flatten(),
        minute: timed.then(|| u8::try_from(local.minute()).ok()).flatten(),
        second: timed.then(|| u8::try_from(local.second()).ok()).flatten(),
        tz_hour: utc,
        tz_minute: utc,
        tz_minus: false,
    }
}

pub(super) fn timestamp(time: FileTime) -> Timestamp {
    let (seconds, nanos) = time.to_utc();
    Timestamp::new(seconds.0, i32::try_from(nanos).unwrap_or_default()).unwrap_or_default()
}

pub(super) fn set_busy_status(component: &mut ICalendarComponent, status: i32) -> bool {
    let (transparency, lossy) = match status {
        busy::FREE => (ICalendarTransparency::Transparent, false),
        busy::WORKING_ELSEWHERE => (ICalendarTransparency::Transparent, true),
        busy::TENTATIVE | busy::OOF | busy::NO_DATA => (ICalendarTransparency::Opaque, true),
        _ => (ICalendarTransparency::Opaque, false),
    };
    set_value(
        component,
        ICalendarProperty::Transp,
        ICalendarValue::Transparency(transparency),
    );
    set_status_name(component, BUSY_STATUS_NAME, status);
    lossy
}

pub(super) fn set_status_name(component: &mut ICalendarComponent, name: &str, status: i32) {
    let value = match status {
        busy::FREE => "FREE",
        busy::TENTATIVE => "TENTATIVE",
        busy::OOF => "OOF",
        busy::WORKING_ELSEWHERE => "WORKINGELSEWHERE",
        busy::NO_DATA => "NODATA",
        _ => "BUSY",
    };
    set_value(
        component,
        ICalendarProperty::Other(name.into()),
        ICalendarValue::Text(value.into()),
    );
}

pub(super) fn set_disallow_counter(component: &mut ICalendarComponent, disallow: bool) {
    if disallow {
        set_value(
            component,
            ICalendarProperty::Other(DISALLOW_COUNTER_NAME.into()),
            ICalendarValue::Text(DISALLOW_COUNTER_TRUE.into()),
        );
    } else {
        remove_other(component, DISALLOW_COUNTER_NAME);
    }
}

pub(super) fn set_text(component: &mut ICalendarComponent, name: ICalendarProperty, text: &str) {
    if text.is_empty() {
        component.entries.retain(|entry| entry.name != name);
    } else {
        set_value(component, name, ICalendarValue::Text(text.into()));
    }
}

pub(super) fn set_value(
    component: &mut ICalendarComponent,
    name: ICalendarProperty,
    value: ICalendarValue,
) {
    match component.property_mut(&name) {
        Some(entry) => entry.values = smallvec![value],
        None => component.entries.push(ICalendarEntry {
            name,
            params: Vec::new(),
            values: smallvec![value],
        }),
    }
}

pub(super) fn clear_draft(ical: &mut ICalendar) {
    for component in vevents_mut(ical) {
        remove_other(component, DRAFT_NAME);
    }
}

pub(super) fn drop_unscheduled_draft(ical: &mut ICalendar) {
    for component in vevents_mut(ical) {
        if !component.has_property(&ICalendarProperty::Attendee) {
            remove_other(component, DRAFT_NAME);
        }
    }
}

pub(super) fn remove_other(component: &mut ICalendarComponent, name: &str) {
    if other_text(component, name).is_some() {
        component.entries.retain(
            |entry| !matches!(&entry.name, ICalendarProperty::Other(other) if other.eq_ignore_ascii_case(name)),
        );
    }
}
