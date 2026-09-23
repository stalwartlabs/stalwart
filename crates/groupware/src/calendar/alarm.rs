/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ALARM_EMAIL, Alarm, AlarmDelta, AlarmOffset, ArchivedAlarmDelta, ArchivedAlarmOffset,
    ArchivedCalendarEventContent, ArchivedCalendarEventData, ArchivedEventPreferences,
    ArchivedEventUserData, CalendarEventData, DefaultAlert, EventPreferences, PREF_HAS_ALERTS,
    alerts::{DefaultAlerts, SnoozeAlarm},
    expand::{
        ComponentRecurrenceId, NaiveTimestamp, RangeFlags, RecurrenceKey, RecurrenceShift,
        SECONDS_PER_DAY, resolve_local,
    },
    user::BASE_INSTANCE,
};
use calcard::{
    common::timezone::{NominalDuration, Tz, ZonedDateTime},
    icalendar::{
        ArchivedICalendar, ArchivedICalendarComponent, ArchivedICalendarEntry, ICalendar,
        ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry,
        ICalendarParameterName, ICalendarParameterValue, ICalendarProperty, ICalendarRelated,
        ICalendarValue,
    },
};
use std::str::FromStr;
use store::write::{TaskId, bitpack::BitpackIterator};
use utils::codec::leb128::Leb128Reader;

const TZ_BOUND: i64 = 24 * 60 * 60;
const ALARM_KIND_SHIFT: u32 = 16;
const ALARM_INDEX_MASK: u64 = u16::MAX as u64;
const ALARM_KIND_STORED: u64 = 0;
const ALARM_KIND_PERSONAL: u64 = 1;
const ALARM_KIND_DEFAULT: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlarmId {
    Stored(u16),
    Personal(u16),
    Default(u16),
}

impl AlarmId {
    pub fn to_task_id(self) -> u64 {
        let (kind, index) = match self {
            AlarmId::Stored(index) => (ALARM_KIND_STORED, index),
            AlarmId::Personal(index) => (ALARM_KIND_PERSONAL, index),
            AlarmId::Default(index) => (ALARM_KIND_DEFAULT, index),
        };
        (kind << ALARM_KIND_SHIFT) | index as u64
    }

    pub fn from_task_id(task_id: u64) -> Option<Self> {
        let index = (task_id & ALARM_INDEX_MASK) as u16;
        match task_id >> ALARM_KIND_SHIFT {
            ALARM_KIND_STORED => Some(AlarmId::Stored(index)),
            ALARM_KIND_PERSONAL => Some(AlarmId::Personal(index)),
            ALARM_KIND_DEFAULT => Some(AlarmId::Default(index)),
            _ => None,
        }
    }

    pub fn index(self) -> u16 {
        match self {
            AlarmId::Stored(index) | AlarmId::Personal(index) | AlarmId::Default(index) => index,
        }
    }

    pub fn is_default(self) -> bool {
        matches!(self, AlarmId::Default(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlarmTarget {
    Owner,
    Sharee(u32),
}

impl AlarmTarget {
    pub fn for_account(owner_id: u32, target_id: u32) -> Self {
        if target_id == owner_id {
            AlarmTarget::Owner
        } else {
            AlarmTarget::Sharee(target_id)
        }
    }

    pub fn sharee_id(self) -> Option<u32> {
        match self {
            AlarmTarget::Owner => None,
            AlarmTarget::Sharee(account_id) => Some(account_id),
        }
    }

    pub fn account_id(self, owner_id: u32) -> u32 {
        self.sharee_id().unwrap_or(owner_id)
    }

    pub fn task_id(self) -> TaskId {
        match self {
            AlarmTarget::Owner => TaskId::Document,
            AlarmTarget::Sharee(account_id) => TaskId::DocumentTarget(account_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CalendarAlarm {
    pub alarm_id: AlarmId,
    pub event_id: u16,
    pub alarm_time: i64,
    pub typ: CalendarAlarmType,
    pub target: AlarmTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CalendarAlarmType {
    Email {
        event_start: i64,
        event_start_tz: u16,
        event_end: i64,
        event_end_tz: u16,
        recurrence_id: Option<i64>,
    },
    Display {
        recurrence_id: Option<i64>,
    },
}

impl CalendarAlarm {
    pub fn with_target(mut self, target: AlarmTarget) -> Self {
        self.target = target;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersonalAlarm {
    id: u16,
    delta: AlarmDelta,
    is_email_alert: bool,
    snoozed_alarms: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PersonalAlarms {
    base: Vec<PersonalAlarm>,
    instances: Vec<(u32, Vec<PersonalAlarm>)>,
}

impl PersonalAlarm {
    fn new(alert: &ICalendarComponent, siblings: &[ICalendarComponent], id: u16) -> Option<Self> {
        alert.expand_alarm(id, 0).map(|alarm| PersonalAlarm {
            id,
            is_email_alert: alarm.is_email(),
            delta: alarm.delta,
            snoozed_alarms: alert
                .snoozed_alarms()
                .flat_map(|parent| {
                    std::iter::once(parent).chain(
                        siblings
                            .iter()
                            .filter(move |sibling| {
                                sibling.component_type == ICalendarComponentType::VAlarm
                                    && sibling.uid() == Some(parent)
                            })
                            .filter_map(ICalendarComponent::jsid),
                    )
                })
                .map(str::to_string)
                .collect(),
        })
    }

    fn is_kept_with(&self, defaults: &DefaultAlerts) -> bool {
        self.snoozed_alarms
            .iter()
            .any(|id| defaults.contains_id(id))
    }
}

impl PersonalAlarms {
    pub fn new(preferences: &EventPreferences) -> Self {
        let mut alarms = PersonalAlarms::default();
        for instance in preferences
            .instances
            .iter()
            .filter(|instance| instance.flags & PREF_HAS_ALERTS != 0)
        {
            let expanded = instance
                .alerts
                .iter()
                .zip(0u16..)
                .filter_map(|(alert, id)| PersonalAlarm::new(alert, &instance.alerts, id))
                .collect::<Vec<_>>();
            if instance.recurrence_key == BASE_INSTANCE {
                alarms.base = expanded;
            } else {
                alarms.instances.push((instance.recurrence_key, expanded));
            }
        }
        alarms
    }

    pub fn is_empty(&self) -> bool {
        self.base.is_empty() && self.instances.iter().all(|(_, alarms)| alarms.is_empty())
    }

    fn scoped(&self) -> impl Iterator<Item = (&PersonalAlarm, AlarmScope)> {
        self.base
            .iter()
            .map(|alarm| (alarm, AlarmScope::Base))
            .chain(self.instances.iter().flat_map(|(key, alarms)| {
                alarms
                    .iter()
                    .map(move |alarm| (alarm, AlarmScope::Instance(*key)))
            }))
    }

    fn has_instance(&self, recurrence_key: u32) -> bool {
        self.instances.iter().any(|(key, _)| *key == recurrence_key)
    }
}

impl ArchivedEventPreferences {
    pub fn alerts_instance(&self, recurrence_key: Option<u32>) -> Option<&ArchivedEventUserData> {
        recurrence_key
            .and_then(|key| self.instance_with_alerts(key))
            .or_else(|| self.instance_with_alerts(BASE_INSTANCE))
    }

    pub fn personal_alert(
        &self,
        recurrence_key: Option<u32>,
        index: u16,
    ) -> Option<&ArchivedICalendarComponent> {
        self.alerts_instance(recurrence_key)
            .and_then(|instance| instance.alerts.get(index as usize))
    }

    fn instance_with_alerts(&self, recurrence_key: u32) -> Option<&ArchivedEventUserData> {
        self.instances
            .binary_search_by_key(&recurrence_key, |instance| {
                instance.recurrence_key.to_native()
            })
            .ok()
            .and_then(|idx| self.instances.get(idx))
            .filter(|instance| instance.flags.to_native() & PREF_HAS_ALERTS != 0)
    }
}

#[derive(Clone, Copy)]
pub enum TriggeredAlarm<'x> {
    Component(&'x ArchivedICalendarComponent),
    Default {
        alert: &'x DefaultAlert,
        acknowledged: Option<&'x ArchivedICalendarComponent>,
    },
}

impl<'x> TriggeredAlarm<'x> {
    pub fn component(&self) -> Option<&'x ArchivedICalendarComponent> {
        match self {
            TriggeredAlarm::Component(component) => Some(component),
            TriggeredAlarm::Default { .. } => None,
        }
    }

    pub fn alert_id(&self) -> Option<&'x str> {
        match self {
            TriggeredAlarm::Component(component) => component.alarm_jsid(),
            TriggeredAlarm::Default { alert, .. } => Some(alert.id.as_str()),
        }
    }

    pub fn acknowledged(&self) -> Option<i64> {
        match self {
            TriggeredAlarm::Component(component)
            | TriggeredAlarm::Default {
                acknowledged: Some(component),
                ..
            } => component.acknowledged(),
            TriggeredAlarm::Default {
                acknowledged: None, ..
            } => None,
        }
    }
}

pub trait ArchivedAlarmComponent {
    fn alarm_jsid(&self) -> Option<&str>;

    fn acknowledged(&self) -> Option<i64>;
}

impl ArchivedAlarmComponent for ArchivedICalendarComponent {
    fn alarm_jsid(&self) -> Option<&str> {
        self.property(&ICalendarProperty::Jsid)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_text())
    }

    fn acknowledged(&self) -> Option<i64> {
        self.property(&ICalendarProperty::Acknowledged)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date_time| date_time.to_date_time_with_tz(Tz::UTC))
            .map(|date_time| date_time.timestamp())
    }
}

impl ArchivedCalendarEventContent {
    pub fn triggered_alarm<'x>(
        &'x self,
        target: AlarmTarget,
        alarm_id: AlarmId,
        comp_id: u16,
        recurrence_key: Option<u32>,
        defaults: &'x DefaultAlerts,
    ) -> Option<TriggeredAlarm<'x>> {
        let components = &self.data.event.components;
        let preferences = target
            .sharee_id()
            .and_then(|account_id| self.preferences(account_id));
        match alarm_id {
            AlarmId::Default(index) => {
                let alert = defaults.get(index)?;
                let is_acknowledged_copy = |alarm: &&ArchivedICalendarComponent| {
                    alarm.alarm_jsid() == Some(alert.id.as_str())
                };
                let acknowledged = if target.sharee_id().is_some() {
                    preferences
                        .and_then(|preferences| preferences.alerts_instance(recurrence_key))
                        .and_then(|instance| instance.alerts.iter().find(is_acknowledged_copy))
                } else {
                    components
                        .get(comp_id as usize)
                        .into_iter()
                        .flat_map(|component| component.component_ids.iter())
                        .filter_map(|id| components.get(id.to_native() as usize))
                        .find(is_acknowledged_copy)
                };
                Some(TriggeredAlarm::Default {
                    alert,
                    acknowledged,
                })
            }
            AlarmId::Personal(index) => preferences?
                .personal_alert(recurrence_key, index)
                .map(TriggeredAlarm::Component),
            AlarmId::Stored(index) => components
                .get(index as usize)
                .filter(|component| component.component_type == ICalendarComponentType::VAlarm)
                .map(TriggeredAlarm::Component),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AlarmRecurrence {
    is_recurrent: bool,
    shift: Option<RecurrenceShift>,
    tz: Tz,
    flags: RangeFlags,
    recurrence_tz: Tz,
}

impl AlarmRecurrence {
    pub fn recurrence_id(&self, start_date_naive: i64) -> Option<i64> {
        match (self.is_recurrent, &self.shift) {
            (false, _) => None,
            (true, Some(shift)) => shift
                .recurrence_id(self.tz, self.flags, start_date_naive, self.recurrence_tz)
                .map(|recurrence_id| recurrence_id.naive),
            (true, None) => Some(start_date_naive),
        }
    }

    pub fn recurrence_key(&self, start_date_naive: i64) -> Option<u32> {
        self.recurrence_id(start_date_naive)
            .and_then(RecurrenceKey::from_recurrence_id)
            .map(RecurrenceKey::prefix)
    }

    pub fn is_recurrent(&self) -> bool {
        self.is_recurrent
    }

    fn of<C: CalendarComponentView + ComponentRecurrenceId>(
        component: Option<&C>,
        own_tz: Tz,
        tz: Tz,
        flags: RangeFlags,
    ) -> Self {
        component.map_or_else(AlarmRecurrence::default, |component| AlarmRecurrence {
            is_recurrent: component.is_recurrent_or_override(),
            shift: component
                .timestamp(&ICalendarProperty::Dtstart)
                .zip(component.recurrence_id(own_tz))
                .zip(component.recurrence_tz(own_tz))
                .and_then(|((start, recurrence_id), recurrence_tz)| {
                    RecurrenceShift::new(own_tz, start, recurrence_id, recurrence_tz)
                }),
            tz,
            flags,
            recurrence_tz: component.recurrence_tz(tz).unwrap_or(tz),
        })
    }
}

pub trait CalendarEntryView {
    fn as_boolean(&self) -> Option<bool>;

    fn is_date_only(&self) -> bool;

    fn timestamp(&self) -> Option<i64>;
}

pub trait CalendarComponentView {
    type Entry: CalendarEntryView;

    fn entry(&self, property: &ICalendarProperty) -> Option<&Self::Entry>;

    fn is_event_or_todo(&self) -> bool;

    fn is_recurrence_override(&self) -> bool;

    fn is_recurrent_or_override(&self) -> bool;

    fn timestamp(&self, property: &ICalendarProperty) -> Option<i64> {
        self.entry(property).and_then(CalendarEntryView::timestamp)
    }

    fn is_shown_without_time(&self) -> bool {
        self.entry(&ICalendarProperty::ShowWithoutTime)
            .and_then(CalendarEntryView::as_boolean)
            .unwrap_or(false)
            || self
                .entry(&ICalendarProperty::Dtstart)
                .is_some_and(CalendarEntryView::is_date_only)
    }
}

pub trait CalendarView {
    type Component: CalendarComponentView;

    fn components(&self) -> impl Iterator<Item = &Self::Component>;

    fn main_component(&self) -> Option<&Self::Component> {
        self.components()
            .find(|component| component.is_event_or_todo() && !component.is_recurrence_override())
    }
}

macro_rules! calendar_view {
    ($calendar:ty, $component:ty, $entry:ty) => {
        impl CalendarEntryView for $entry {
            fn as_boolean(&self) -> Option<bool> {
                self.values.first().and_then(|value| value.as_boolean())
            }

            fn is_date_only(&self) -> bool {
                self.values
                    .first()
                    .and_then(|value| value.as_partial_date_time())
                    .is_some_and(|date_time| !date_time.has_time())
            }

            fn timestamp(&self) -> Option<i64> {
                self.values
                    .first()?
                    .as_partial_date_time()?
                    .to_date_time()
                    .map(|date_time| date_time.date_time.naive_timestamp())
            }
        }

        impl CalendarComponentView for $component {
            type Entry = $entry;

            fn entry(&self, property: &ICalendarProperty) -> Option<&Self::Entry> {
                self.property(property)
            }

            fn is_event_or_todo(&self) -> bool {
                self.component_type.is_event_or_todo()
            }

            fn is_recurrence_override(&self) -> bool {
                <$component>::is_recurrence_override(self)
            }

            fn is_recurrent_or_override(&self) -> bool {
                <$component>::is_recurrent_or_override(self)
            }
        }

        impl CalendarView for $calendar {
            type Component = $component;

            fn components(&self) -> impl Iterator<Item = &Self::Component> {
                self.components.iter()
            }
        }
    };
}

calendar_view!(ICalendar, ICalendarComponent, ICalendarEntry);
calendar_view!(
    ArchivedICalendar,
    ArchivedICalendarComponent,
    ArchivedICalendarEntry
);

#[derive(Debug, Clone, Copy)]
pub enum AlarmSource<'x> {
    Stored(&'x DefaultAlerts),
    Personal(&'x PersonalAlarms, &'x DefaultAlerts),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlarmScope {
    All,
    Base,
    Instance(u32),
}

impl AlarmScope {
    fn is_occurrence(self) -> bool {
        matches!(self, AlarmScope::Instance(_))
    }

    fn is_behind(self, recurrence_key: Option<u32>) -> bool {
        matches!(
            (self, recurrence_key),
            (AlarmScope::Instance(key), Some(current)) if current > key
        )
    }
}

impl AlarmSource<'_> {
    fn may_have_alarms(&self, has_stored_alarms: bool) -> bool {
        match self {
            AlarmSource::Stored(defaults) => has_stored_alarms || defaults.has_alerts(),
            AlarmSource::Personal(alarms, defaults) if defaults.is_enabled() => {
                defaults.has_alerts()
                    || alarms
                        .scoped()
                        .any(|(alarm, _)| alarm.is_kept_with(defaults))
            }
            AlarmSource::Personal(alarms, _) => !alarms.is_empty(),
        }
    }

    fn has_floating_triggers<D: EventAlarmData + ?Sized>(&self, data: &D) -> bool {
        match self {
            AlarmSource::Stored(_) => data.has_floating_stored_alarms(),
            AlarmSource::Personal(alarms, _) => alarms
                .scoped()
                .any(|(alarm, _)| matches!(alarm.delta, AlarmDelta::FixedFloating(_))),
        }
    }

    fn uses_stored_alarms(&self) -> bool {
        matches!(self, AlarmSource::Stored(_))
    }

    fn shared_candidates(&self, candidates: &mut Vec<AlarmCandidate>) {
        let (defaults, personal) = match self {
            AlarmSource::Stored(defaults) => (*defaults, None),
            AlarmSource::Personal(alarms, defaults) => (*defaults, Some(*alarms)),
        };
        candidates.extend(defaults.indexed_alerts().map(|(index, alert)| {
            AlarmCandidate::new(
                AlarmId::Default(index),
                AlarmScope::All,
                alert.delta(),
                alert.is_email(),
            )
        }));
        if let Some(alarms) = personal {
            let keep_snoozes_only = defaults.is_enabled();
            candidates.extend(
                alarms
                    .scoped()
                    .filter(|(alarm, _)| !keep_snoozes_only || alarm.is_kept_with(defaults))
                    .map(|(alarm, scope)| {
                        AlarmCandidate::new(
                            AlarmId::Personal(alarm.id),
                            scope,
                            alarm.delta.clone(),
                            alarm.is_email_alert,
                        )
                    }),
            );
        }
    }

    fn applies(&self, scope: AlarmScope, recurrence_key: Option<u32>) -> bool {
        match (scope, self) {
            (AlarmScope::All, _) => true,
            (AlarmScope::Instance(key), _) => recurrence_key == Some(key),
            (AlarmScope::Base, AlarmSource::Personal(alarms, _)) => {
                recurrence_key.is_none_or(|key| !alarms.has_instance(key))
            }
            (AlarmScope::Base, AlarmSource::Stored(_)) => true,
        }
    }
}

pub struct AlarmRange<'x> {
    pub comp_id: u16,
    pub start_tz: u16,
    pub end_tz: u16,
    pub duration: i64,
    pub flags: RangeFlags,
    pub instances: &'x [u8],
}

#[derive(Debug, Clone)]
struct AlarmCandidate {
    id: AlarmId,
    scope: AlarmScope,
    delta: AlarmDelta,
    is_email_alert: bool,
    naive_bias: Option<i64>,
    fixed_time: i64,
    is_pending: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct PendingAlarms {
    any: bool,
    any_unbounded: bool,
    min_bias: Option<i64>,
}

impl AlarmCandidate {
    fn new(id: AlarmId, scope: AlarmScope, delta: AlarmDelta, is_email_alert: bool) -> Self {
        AlarmCandidate {
            id,
            scope,
            delta,
            is_email_alert,
            naive_bias: None,
            fixed_time: 0,
            is_pending: false,
        }
    }

    fn from_stored(alarm: Alarm) -> Self {
        let is_email_alert = alarm.is_email();
        AlarmCandidate::new(
            AlarmId::Stored(alarm.id),
            AlarmScope::All,
            alarm.delta,
            is_email_alert,
        )
    }

    fn prepare(
        &mut self,
        duration: i64,
        default_tz: Tz,
        start_time: i64,
        best_so_far: Option<i64>,
    ) {
        match &self.delta {
            AlarmDelta::Start(offset) => {
                self.naive_bias = Some(offset.naive_seconds());
                self.is_pending = true;
            }
            AlarmDelta::End(offset) => {
                self.naive_bias = Some(offset.naive_seconds() + duration);
                self.is_pending = true;
            }
            AlarmDelta::FixedUtc(_) | AlarmDelta::FixedFloating(_) => {
                self.naive_bias = None;
                match self.delta.fixed_timestamp(default_tz).filter(|alarm_time| {
                    *alarm_time > start_time && best_so_far.is_none_or(|best| *alarm_time < best)
                }) {
                    Some(alarm_time) => {
                        self.fixed_time = alarm_time;
                        self.is_pending = true;
                    }
                    None => self.is_pending = false,
                }
            }
        }
    }

    fn alarm_time(
        &self,
        start: &ZonedDateTime,
        end: &ZonedDateTime,
        default_tz: Tz,
    ) -> Option<i64> {
        if self.naive_bias.is_some() {
            self.delta.to_timestamp(start, end, default_tz)
        } else {
            Some(self.fixed_time)
        }
    }
}

impl PendingAlarms {
    fn of(candidates: &[AlarmCandidate]) -> Self {
        let mut pending = PendingAlarms::default();
        for candidate in candidates.iter().filter(|candidate| candidate.is_pending) {
            pending.any = true;
            match candidate.naive_bias {
                Some(bias) => {
                    pending.min_bias =
                        Some(pending.min_bias.map_or(bias, |min_bias| min_bias.min(bias)));
                }
                None => pending.any_unbounded = true,
            }
        }
        pending
    }

    fn is_past(&self, start_date_naive: i64, best_so_far: Option<i64>) -> bool {
        if self.any_unbounded {
            return false;
        }
        match (self.min_bias, best_so_far) {
            (Some(min_bias), Some(best)) => {
                start_date_naive
                    .saturating_add(min_bias)
                    .saturating_sub(TZ_BOUND)
                    >= best
            }
            _ => false,
        }
    }
}

pub trait EventAlarmData {
    fn alarm_base_offset(&self) -> i64;

    fn alarm_ranges(&self) -> impl Iterator<Item = AlarmRange<'_>>;

    fn stored_alarms(&self, comp_id: u16) -> impl Iterator<Item = Alarm>;

    fn has_stored_alarms(&self) -> bool;

    fn has_floating_stored_alarms(&self) -> bool;

    fn component_recurrence(
        &self,
        comp_id: u16,
        component_tz: Tz,
        flags: RangeFlags,
    ) -> AlarmRecurrence;

    fn needs_default_tz(&self, source: &AlarmSource<'_>) -> bool {
        let floating = Tz::Floating.as_id();
        source.may_have_alarms(self.has_stored_alarms())
            && (self
                .alarm_ranges()
                .any(|range| range.start_tz == floating || range.end_tz == floating)
                || source.has_floating_triggers(self))
    }

    fn next_alarm_from(
        &self,
        start_time: i64,
        default_tz: Tz,
        source: &AlarmSource<'_>,
    ) -> Option<CalendarAlarm> {
        if !source.may_have_alarms(self.has_stored_alarms()) {
            return None;
        }

        let base_offset = self.alarm_base_offset();
        let mut next_alarm: Option<CalendarAlarm> = None;
        let mut shared = Vec::new();
        source.shared_candidates(&mut shared);
        let uses_stored_alarms = source.uses_stored_alarms();
        if shared.is_empty() && !uses_stored_alarms {
            return None;
        }
        let mut candidates: Vec<AlarmCandidate> = Vec::with_capacity(shared.len());

        for range in self.alarm_ranges() {
            let comp_id = range.comp_id;
            candidates.clear();
            if uses_stored_alarms {
                candidates.extend(self.stored_alarms(comp_id).map(AlarmCandidate::from_stored));
            }
            candidates.extend_from_slice(&shared);
            if candidates.is_empty() {
                continue;
            }

            let instances = range.instances;
            let Some((offset_or_count, bytes_read)) = instances.read_leb128::<u32>() else {
                continue;
            };
            let duration = range.duration;
            let flags = range.flags;
            let (Some(mut start_tz), Some(mut end_tz)) =
                (Tz::from_id(range.start_tz), Tz::from_id(range.end_tz))
            else {
                continue;
            };
            let component_tz = start_tz;
            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            let best_so_far = next_alarm.as_ref().map(|next| next.alarm_time);
            for candidate in &mut candidates {
                candidate.prepare(duration, default_tz, start_time, best_so_far);
            }
            let recurrence = self.component_recurrence(comp_id, component_tz, flags);
            if !recurrence.is_recurrent() {
                for candidate in &mut candidates {
                    candidate.is_pending &= !candidate.scope.is_occurrence();
                }
            }
            if !PendingAlarms::of(&candidates).any {
                continue;
            }

            let is_packed = instances.len() > bytes_read;
            let packed = is_packed.then(|| {
                BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count)
            });
            let single = (!is_packed).then_some(offset_or_count);

            for start_date_naive in packed
                .into_iter()
                .flatten()
                .chain(single)
                .map(|offset| offset as i64 + base_offset)
            {
                let best_so_far = next_alarm.as_ref().map(|next| next.alarm_time);
                let pending = PendingAlarms::of(&candidates);
                if !pending.any || pending.is_past(start_date_naive, best_so_far) {
                    break;
                }

                let end_date_naive = start_date_naive + duration;
                let mut instance_key = None;
                let mut resolved = None;

                for candidate in &mut candidates {
                    if !candidate.is_pending {
                        continue;
                    }
                    if candidate.scope != AlarmScope::All {
                        let recurrence_key = *instance_key
                            .get_or_insert_with(|| recurrence.recurrence_key(start_date_naive));
                        if !source.applies(candidate.scope, recurrence_key) {
                            if candidate.scope.is_behind(recurrence_key) {
                                candidate.is_pending = false;
                            }
                            continue;
                        }
                    }
                    if let Some(naive_bias) = candidate.naive_bias {
                        let naive_alarm = start_date_naive.saturating_add(naive_bias);
                        if naive_alarm.saturating_add(TZ_BOUND) <= start_time {
                            continue;
                        }
                        if best_so_far
                            .is_some_and(|best| naive_alarm.saturating_sub(TZ_BOUND) >= best)
                        {
                            candidate.is_pending = false;
                            continue;
                        }
                    }

                    let (start, end) = match resolved {
                        Some(resolved) => resolved,
                        None => {
                            let (Some(start), Some(end)) = (
                                flags.resolve_start(start_tz, start_date_naive),
                                flags.resolve_end(end_tz, end_date_naive),
                            ) else {
                                break;
                            };
                            *resolved.insert((start, end))
                        }
                    };

                    if let Some(alarm_time) = candidate.alarm_time(&start, &end, default_tz)
                        && alarm_time > start_time
                    {
                        if next_alarm
                            .as_ref()
                            .is_none_or(|next| alarm_time < next.alarm_time)
                        {
                            next_alarm = Some(CalendarAlarm {
                                alarm_id: candidate.id,
                                event_id: comp_id,
                                alarm_time,
                                typ: if candidate.is_email_alert {
                                    CalendarAlarmType::Email {
                                        event_start: start.timestamp(),
                                        event_start_tz: start_tz.as_id(),
                                        event_end: end.timestamp(),
                                        event_end_tz: end_tz.as_id(),
                                        recurrence_id: recurrence.recurrence_id(start_date_naive),
                                    }
                                } else {
                                    CalendarAlarmType::Display {
                                        recurrence_id: recurrence.recurrence_id(start_date_naive),
                                    }
                                },
                                target: AlarmTarget::Owner,
                            });
                        }
                        candidate.is_pending = false;
                    }
                }
            }
        }

        next_alarm
    }
}

impl EventAlarmData for ArchivedCalendarEventData {
    fn alarm_base_offset(&self) -> i64 {
        self.base_offset.to_native()
    }

    fn alarm_ranges(&self) -> impl Iterator<Item = AlarmRange<'_>> {
        self.time_ranges.iter().map(|range| AlarmRange {
            comp_id: range.id.to_native(),
            start_tz: range.start_tz.to_native(),
            end_tz: range.end_tz.to_native(),
            duration: range.duration.to_native() as i64,
            flags: RangeFlags::from_bits(range.flags),
            instances: range.instances.as_ref(),
        })
    }

    fn stored_alarms(&self, comp_id: u16) -> impl Iterator<Item = Alarm> {
        self.alarms
            .iter()
            .filter(move |alarm| alarm.parent_id == comp_id)
            .map(|alarm| Alarm {
                id: alarm.id.to_native(),
                parent_id: alarm.parent_id.to_native(),
                delta: AlarmDelta::from(&alarm.delta),
                flags: alarm.flags.to_native(),
            })
    }

    fn has_stored_alarms(&self) -> bool {
        !self.alarms.is_empty()
    }

    fn has_floating_stored_alarms(&self) -> bool {
        self.alarms
            .iter()
            .any(|alarm| matches!(alarm.delta, ArchivedAlarmDelta::FixedFloating(_)))
    }

    fn component_recurrence(
        &self,
        comp_id: u16,
        component_tz: Tz,
        flags: RangeFlags,
    ) -> AlarmRecurrence {
        AlarmRecurrence::of(
            self.event.components.get(comp_id as usize),
            self.component_tz(u32::from(comp_id))
                .unwrap_or(component_tz),
            component_tz,
            flags,
        )
    }
}

impl EventAlarmData for CalendarEventData {
    fn alarm_base_offset(&self) -> i64 {
        self.base_offset
    }

    fn alarm_ranges(&self) -> impl Iterator<Item = AlarmRange<'_>> {
        self.time_ranges.iter().map(|range| AlarmRange {
            comp_id: range.id,
            start_tz: range.start_tz,
            end_tz: range.end_tz,
            duration: range.duration as i64,
            flags: RangeFlags::from_bits(range.flags),
            instances: range.instances.as_ref(),
        })
    }

    fn stored_alarms(&self, comp_id: u16) -> impl Iterator<Item = Alarm> {
        self.alarms
            .iter()
            .filter(move |alarm| alarm.parent_id == comp_id)
            .cloned()
    }

    fn has_stored_alarms(&self) -> bool {
        !self.alarms.is_empty()
    }

    fn has_floating_stored_alarms(&self) -> bool {
        self.alarms
            .iter()
            .any(|alarm| matches!(alarm.delta, AlarmDelta::FixedFloating(_)))
    }

    fn component_recurrence(
        &self,
        comp_id: u16,
        component_tz: Tz,
        flags: RangeFlags,
    ) -> AlarmRecurrence {
        AlarmRecurrence::of(
            self.event.components.get(comp_id as usize),
            self.component_tz(u32::from(comp_id))
                .unwrap_or(component_tz),
            component_tz,
            flags,
        )
    }
}

pub trait ExpandAlarm {
    fn expand_alarm(&self, id: u16, parent_id: u16) -> Option<Alarm>;
}

impl ExpandAlarm for ICalendarComponent {
    fn expand_alarm(&self, id: u16, parent_id: u16) -> Option<Alarm> {
        let mut trigger = None;
        let mut flags = 0;

        for entry in self.entries.iter() {
            match &entry.name {
                ICalendarProperty::Trigger => {
                    let mut tz = None;
                    let mut trigger_start = true;

                    for param in entry.params.iter() {
                        match (&param.name, &param.value) {
                            (
                                ICalendarParameterName::Related,
                                ICalendarParameterValue::Related(related),
                            ) => {
                                trigger_start = matches!(related, ICalendarRelated::Start);
                            }
                            (
                                ICalendarParameterName::Tzid,
                                ICalendarParameterValue::Text(tz_id),
                            ) => {
                                tz = Tz::from_str(tz_id).ok();
                            }
                            _ => {}
                        }
                    }

                    trigger = match entry.values.first()? {
                        ICalendarValue::PartialDateTime(dt) => {
                            let tz = tz.unwrap_or(Tz::Floating);

                            dt.to_date_time_with_tz(tz).map(|dt| {
                                let timestamp = dt.timestamp();
                                if !dt.timezone().is_floating() {
                                    AlarmDelta::FixedUtc(timestamp)
                                } else {
                                    AlarmDelta::FixedFloating(timestamp)
                                }
                            })
                        }
                        ICalendarValue::Duration(duration) => {
                            if trigger_start {
                                Some(AlarmDelta::Start(duration.into()))
                            } else {
                                Some(AlarmDelta::End(duration.into()))
                            }
                        }
                        _ => None,
                    };
                }
                ICalendarProperty::Action => {
                    if entry
                        .values
                        .first()
                        .and_then(|v| v.as_text())
                        .is_some_and(|v| v.eq_ignore_ascii_case("email"))
                    {
                        flags |= ALARM_EMAIL;
                    }
                }
                ICalendarProperty::Summary | ICalendarProperty::Description
                    if !entry.is_derived()
                        && entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .is_some_and(|v| v.contains("@email")) =>
                {
                    flags |= ALARM_EMAIL;
                }
                _ => {}
            }
        }

        trigger.map(|delta| Alarm {
            id,
            parent_id,
            delta,
            flags,
        })
    }
}

impl AlarmDelta {
    pub fn to_timestamp(
        &self,
        start: &ZonedDateTime,
        end: &ZonedDateTime,
        default_tz: Tz,
    ) -> Option<i64> {
        match self {
            AlarmDelta::Start(offset) => offset.apply(start),
            AlarmDelta::End(offset) => offset.apply(end),
            AlarmDelta::FixedUtc(_) | AlarmDelta::FixedFloating(_) => {
                self.fixed_timestamp(default_tz)
            }
        }
    }

    fn fixed_timestamp(&self, default_tz: Tz) -> Option<i64> {
        match self {
            AlarmDelta::FixedUtc(timestamp) => Some(*timestamp),
            AlarmDelta::FixedFloating(timestamp) => resolve_local(default_tz, *timestamp),
            AlarmDelta::Start(_) | AlarmDelta::End(_) => None,
        }
    }
}

impl From<&ArchivedAlarmDelta> for AlarmDelta {
    fn from(delta: &ArchivedAlarmDelta) -> Self {
        match delta {
            ArchivedAlarmDelta::Start(offset) => AlarmDelta::Start(offset.into()),
            ArchivedAlarmDelta::End(offset) => AlarmDelta::End(offset.into()),
            ArchivedAlarmDelta::FixedUtc(timestamp) => AlarmDelta::FixedUtc(timestamp.to_native()),
            ArchivedAlarmDelta::FixedFloating(timestamp) => {
                AlarmDelta::FixedFloating(timestamp.to_native())
            }
        }
    }
}

impl AlarmOffset {
    pub fn naive_seconds(&self) -> i64 {
        i64::from(self.days) * SECONDS_PER_DAY + i64::from(self.seconds)
    }

    pub fn apply(&self, from: &ZonedDateTime) -> Option<i64> {
        from.checked_add_nominal(NominalDuration::new(self.days, 0))
            .map(|at| at.timestamp() + i64::from(self.seconds))
    }
}

impl From<&ICalendarDuration> for AlarmOffset {
    fn from(duration: &ICalendarDuration) -> Self {
        let days = i32::try_from(u64::from(duration.weeks) * 7 + u64::from(duration.days))
            .unwrap_or(i32::MAX);
        let seconds = i32::try_from(
            u64::from(duration.hours) * 3600
                + u64::from(duration.minutes) * 60
                + u64::from(duration.seconds),
        )
        .unwrap_or(i32::MAX);
        if duration.neg {
            AlarmOffset {
                days: -days,
                seconds: -seconds,
            }
        } else {
            AlarmOffset { days, seconds }
        }
    }
}

impl From<&ArchivedAlarmOffset> for AlarmOffset {
    fn from(offset: &ArchivedAlarmOffset) -> Self {
        AlarmOffset {
            days: offset.days.to_native(),
            seconds: offset.seconds.to_native(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::{
        ALERT_WITH_TIME, CALENDAR_SUBSCRIBED, Calendar, CalendarPreferences, EventUserData,
        alerts::CalendarSettings,
    };
    use calcard::icalendar::{ICalendar, ICalendarDuration};
    use jiff::civil::DateTime;

    fn naive(day: i8, hour: i8, minute: i8) -> i64 {
        DateTime::new(2030, 1, day, hour, minute, 0, 0)
            .expect("valid date")
            .naive_timestamp()
    }

    fn event_data(ical: &str) -> CalendarEventData {
        CalendarEventData::new(
            ICalendar::parse(ical).expect("valid iCalendar"),
            Tz::Floating,
            100,
        )
    }

    fn valarms(alarms: &str) -> Vec<ICalendarComponent> {
        let ical = ICalendar::parse(format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:alarms\r\nDTSTART:20300101T100000Z\r\n{alarms}END:VEVENT\r\nEND:VCALENDAR\r\n"
        ))
        .expect("valid iCalendar");
        ical.components
            .into_iter()
            .filter(|component| component.component_type == ICalendarComponentType::VAlarm)
            .collect()
    }

    fn preferences(instances: Vec<(u32, Vec<ICalendarComponent>)>) -> EventPreferences {
        EventPreferences {
            account_id: 2,
            updated: 0,
            instances: instances
                .into_iter()
                .map(|(recurrence_key, alerts)| EventUserData {
                    recurrence_key,
                    flags: PREF_HAS_ALERTS,
                    alerts,
                    ..Default::default()
                })
                .collect(),
        }
    }

    fn recurrence_key(naive: i64) -> u32 {
        RecurrenceKey::from_recurrence_id(naive)
            .map(RecurrenceKey::prefix)
            .expect("representable recurrence id")
    }

    fn defaults(ids: &[&str]) -> DefaultAlerts {
        let calendar = Calendar {
            preferences: vec![CalendarPreferences {
                account_id: 2,
                flags: CALENDAR_SUBSCRIBED,
                default_alerts: ids
                    .iter()
                    .map(|id| DefaultAlert {
                        id: id.to_string(),
                        offset: ICalendarDuration::from_seconds(-900),
                        flags: ALERT_WITH_TIME,
                    })
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        DefaultAlerts::merge(
            std::iter::once(&CalendarSettings::from(&calendar)),
            2,
            None,
            true,
        )
    }

    const COUNT_TWO_WITH_OVERRIDE: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:single-left\r\n",
        "DTSTART:20300101T100000Z\r\n",
        "DURATION:PT1H\r\n",
        "RRULE:FREQ=DAILY;COUNT=2\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:single-left\r\n",
        "RECURRENCE-ID:20300102T100000Z\r\n",
        "DTSTART:20300102T120000Z\r\n",
        "DURATION:PT2H\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT15M\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    #[test]
    fn alarm_ids_round_trip_through_task_ids() {
        let ids = [
            AlarmId::Stored(0),
            AlarmId::Stored(7),
            AlarmId::Stored(u16::MAX),
            AlarmId::Personal(0),
            AlarmId::Personal(7),
            AlarmId::Personal(u16::MAX),
            AlarmId::Default(0),
            AlarmId::Default(7),
            AlarmId::Default(u16::MAX),
        ];
        let task_ids = ids.map(AlarmId::to_task_id);
        for (id, task_id) in ids.iter().zip(task_ids) {
            assert_eq!(AlarmId::from_task_id(task_id), Some(*id));
            assert_eq!(id.index(), (task_id & ALARM_INDEX_MASK) as u16);
            assert_eq!(id.is_default(), matches!(id, AlarmId::Default(_)));
        }
        assert_eq!(
            task_ids
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            ids.len()
        );
        assert!(AlarmId::from_task_id(3 << ALARM_KIND_SHIFT).is_none());
    }

    #[test]
    fn offset_alarms_are_evaluated_in_one_instance_pass() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:offsets\r\n",
            "DTSTART:20300101T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "RRULE:FREQ=DAILY;COUNT=5\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER:-PT15M\r\n",
            "END:VALARM\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER;RELATED=END:PT30M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let disabled = DefaultAlerts::disabled();
        let source = AlarmSource::Stored(&disabled);

        let start = data
            .next_alarm_from(naive(2, 0, 0), Tz::Floating, &source)
            .expect("start alarm");
        assert_eq!(start.alarm_time, naive(2, 9, 45));

        let end = data
            .next_alarm_from(naive(2, 10, 0), Tz::Floating, &source)
            .expect("end alarm");
        assert_eq!(end.alarm_time, naive(2, 11, 30));
        assert_ne!(start.alarm_id, end.alarm_id);
        assert!(matches!(start.alarm_id, AlarmId::Stored(_)));
        assert!(matches!(end.alarm_id, AlarmId::Stored(_)));
        assert_eq!(start.event_id, end.event_id);

        assert_eq!(
            data.next_alarm_from(naive(5, 11, 30), Tz::Floating, &source)
                .map(|alarm| alarm.alarm_time),
            None
        );
    }

    #[test]
    fn occurrence_alerts_without_a_matching_instance_do_not_fire() {
        let daily = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:stale-occurrence\r\n",
            "DTSTART:20300101T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "RRULE:FREQ=DAILY;COUNT=5\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let single = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:stale-occurrence\r\n",
            "DTSTART:20300101T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let alerts = valarms("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n");
        let missing = PersonalAlarms::new(&preferences(vec![(
            recurrence_key(naive(3, 5, 0)),
            alerts.clone(),
        )]));
        let disabled = DefaultAlerts::disabled();

        for data in [&daily, &single] {
            assert!(
                data.next_alarm_from(
                    naive(1, 0, 0),
                    Tz::Floating,
                    &AlarmSource::Personal(&missing, &disabled),
                )
                .is_none()
            );
        }

        let with_base = PersonalAlarms::new(&preferences(vec![
            (BASE_INSTANCE, alerts.clone()),
            (recurrence_key(naive(3, 5, 0)), alerts),
        ]));
        let alarm = daily
            .next_alarm_from(
                naive(1, 0, 0),
                Tz::Floating,
                &AlarmSource::Personal(&with_base, &disabled),
            )
            .expect("base alert still fires");
        assert_eq!(alarm.alarm_time, naive(1, 9, 50));
        assert_eq!(alarm.alarm_id, AlarmId::Personal(0));
    }

    #[test]
    fn default_and_stored_alarms_compete_in_one_pass() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:mixed\r\n",
            "DTSTART:20300101T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "RRULE:FREQ=DAILY;COUNT=3\r\n",
            "BEGIN:VALARM\r\n",
            "JSID:snooze\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER;VALUE=DATE-TIME:20300102T093000Z\r\n",
            "RELATED-TO;RELTYPE=SNOOZE:d\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let defaults = defaults(&["d"]);
        let source = AlarmSource::Stored(&defaults);

        let snooze = data
            .next_alarm_from(naive(2, 0, 0), Tz::Floating, &source)
            .expect("snooze fires first");
        assert_eq!(snooze.alarm_time, naive(2, 9, 30));
        assert!(matches!(snooze.alarm_id, AlarmId::Stored(_)));

        let default = data
            .next_alarm_from(naive(2, 9, 30), Tz::Floating, &source)
            .expect("default alert");
        assert_eq!(default.alarm_time, naive(2, 9, 45));
        assert_eq!(default.alarm_id, AlarmId::Default(0));
    }

    #[test]
    fn derived_alarm_texts_do_not_mark_email_alarms() {
        let alarms = valarms(concat!(
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\n",
            "DESCRIPTION;DERIVED=TRUE:Sync @email\r\nEND:VALARM\r\n",
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\n",
            "DESCRIPTION:Sync @email\r\nEND:VALARM\r\n",
        ));
        assert_eq!(
            alarms
                .iter()
                .filter_map(|alarm| alarm.expand_alarm(1, 0))
                .map(|alarm| alarm.is_email())
                .collect::<Vec<_>>(),
            [false, true]
        );
    }

    #[test]
    fn personal_occurrence_alarms_follow_recurrence() {
        let data = event_data(COUNT_TWO_WITH_OVERRIDE);
        assert!(
            data.time_ranges.iter().all(|range| {
                range
                    .instances
                    .read_leb128::<u32>()
                    .is_some_and(|(_, bytes_read)| range.instances.len() == bytes_read)
            }),
            "{:?}",
            data.time_ranges
        );

        let alarms = PersonalAlarms::new(&preferences(vec![
            (
                BASE_INSTANCE,
                valarms("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n"),
            ),
            (recurrence_key(naive(1, 10, 0)), vec![]),
        ]));
        let disabled = DefaultAlerts::disabled();
        let alarm = data
            .next_alarm_from(
                naive(1, 0, 0),
                Tz::Floating,
                &AlarmSource::Personal(&alarms, &disabled),
            )
            .expect("alarm for the second occurrence");
        assert_eq!(alarm.alarm_time, naive(2, 11, 50));
        assert_eq!(alarm.alarm_id, AlarmId::Personal(0));
        assert_eq!(
            alarm.typ,
            CalendarAlarmType::Display {
                recurrence_id: Some(naive(2, 10, 0))
            }
        );
    }

    const ZONED_OVERRIDE: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:zoned-override\r\n",
        "DTSTART;TZID=America/New_York:20300101T100000\r\n",
        "DURATION:PT1H\r\n",
        "RRULE:FREQ=DAILY;COUNT=3\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:zoned-override\r\n",
        "RECURRENCE-ID:20300102T150000Z\r\n",
        "DTSTART;TZID=America/New_York:20300102T120000\r\n",
        "DURATION:PT1H\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    #[test]
    fn utc_recurrence_id_matches_personal_occurrence_keys() {
        let data = event_data(ZONED_OVERRIDE);
        let alarms = PersonalAlarms::new(&preferences(vec![
            (
                BASE_INSTANCE,
                valarms("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n"),
            ),
            (
                recurrence_key(naive(2, 10, 0)),
                valarms("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT30M\r\nEND:VALARM\r\n"),
            ),
        ]));
        let disabled = DefaultAlerts::disabled();
        let alarm = data
            .next_alarm_from(
                naive(1, 20, 0),
                Tz::Floating,
                &AlarmSource::Personal(&alarms, &disabled),
            )
            .expect("alarm of the overridden occurrence");

        assert_eq!(alarm.alarm_time, naive(2, 16, 30));
        assert_eq!(
            alarm.typ,
            CalendarAlarmType::Display {
                recurrence_id: Some(naive(2, 10, 0))
            }
        );

        let recurrence = data.component_recurrence(
            alarm.event_id,
            Tz::from_str("America/New_York").expect("time zone"),
            RangeFlags::default(),
        );
        assert_eq!(
            recurrence.recurrence_key(naive(2, 12, 0)),
            Some(recurrence_key(naive(2, 10, 0)))
        );
    }

    #[test]
    fn moved_occurrence_reports_recurrence_id() {
        let data = event_data(COUNT_TWO_WITH_OVERRIDE);
        let alarm = data
            .next_alarm_from(
                naive(1, 12, 0),
                Tz::Floating,
                &AlarmSource::Stored(&DefaultAlerts::disabled()),
            )
            .expect("alarm of the moved occurrence");
        assert_eq!(alarm.alarm_time, naive(2, 11, 45));
        assert_eq!(
            alarm.typ,
            CalendarAlarmType::Display {
                recurrence_id: Some(naive(2, 10, 0))
            }
        );

        let recurrence = data.component_recurrence(alarm.event_id, Tz::UTC, RangeFlags::default());
        assert_eq!(
            recurrence.recurrence_key(naive(2, 12, 0)),
            Some(recurrence_key(naive(2, 10, 0)))
        );
        assert_eq!(
            recurrence.recurrence_id(naive(3, 12, 0)),
            Some(naive(3, 10, 0))
        );
    }

    #[test]
    fn sharee_snoozes_of_default_alerts_fire() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:snoozed\r\n",
            "DTSTART:20300101T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let defaults = defaults(&["d"]);

        for alerts in [
            concat!(
                "BEGIN:VALARM\r\nJSID:d\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\n",
                "ACKNOWLEDGED:20300101T094600Z\r\nEND:VALARM\r\n",
                "BEGIN:VALARM\r\nJSID:s\r\nACTION:DISPLAY\r\n",
                "TRIGGER;VALUE=DATE-TIME:20300101T095500Z\r\n",
                "RELATED-TO;RELTYPE=SNOOZE:d\r\nEND:VALARM\r\n"
            ),
            concat!(
                "BEGIN:VALARM\r\nUID:original\r\nJSID:d\r\nACTION:DISPLAY\r\n",
                "TRIGGER:-PT15M\r\nACKNOWLEDGED:20300101T094600Z\r\nEND:VALARM\r\n",
                "BEGIN:VALARM\r\nUID:snooze\r\nACTION:DISPLAY\r\n",
                "TRIGGER;VALUE=DATE-TIME:20300101T095500Z\r\n",
                "RELATED-TO;RELTYPE=SNOOZE:original\r\nEND:VALARM\r\n"
            ),
        ] {
            let alarms = PersonalAlarms::new(&preferences(vec![(BASE_INSTANCE, valarms(alerts))]));
            let alarm = data
                .next_alarm_from(
                    naive(1, 9, 50),
                    Tz::Floating,
                    &AlarmSource::Personal(&alarms, &defaults),
                )
                .expect("snooze alarm");
            assert_eq!(alarm.alarm_time, naive(1, 9, 55), "{alerts}");
            assert_eq!(alarm.alarm_id, AlarmId::Personal(1), "{alerts}");

            assert!(
                data.next_alarm_from(
                    naive(1, 9, 50),
                    Tz::Floating,
                    &AlarmSource::Personal(&alarms, &self::defaults(&["other"])),
                )
                .is_none(),
                "{alerts}"
            );
        }
    }

    #[test]
    fn absolute_triggers_in_the_past_are_skipped() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:absolute\r\n",
            "DTSTART:20300101T100000Z\r\n",
            "DURATION:PT1H\r\n",
            "RRULE:FREQ=DAILY;COUNT=50\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER;VALUE=DATE-TIME:20300101T080000Z\r\n",
            "END:VALARM\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER;VALUE=DATE-TIME:20300105T080000Z\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let disabled = DefaultAlerts::disabled();
        let alarm = data
            .next_alarm_from(
                naive(3, 0, 0),
                Tz::Floating,
                &AlarmSource::Stored(&disabled),
            )
            .expect("future absolute trigger");
        assert_eq!(alarm.alarm_time, naive(5, 8, 0));
        assert!(
            data.next_alarm_from(
                naive(6, 0, 0),
                Tz::Floating,
                &AlarmSource::Stored(&disabled)
            )
            .is_none()
        );
    }

    #[test]
    fn floating_alarms_resolve_in_default_time_zone() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:all-day\r\n",
            "DTSTART;VALUE=DATE:20300111\r\n",
            "DURATION:P1D\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER:-PT12H\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let disabled = DefaultAlerts::disabled();
        let source = AlarmSource::Stored(&disabled);
        assert!(data.needs_default_tz(&source));
        let los_angeles = Tz::from_str("America/Los_Angeles").expect("known time zone");
        let alarm = data
            .next_alarm_from(naive(1, 0, 0), los_angeles, &source)
            .expect("all-day alarm");
        assert_eq!(alarm.alarm_time, naive(10, 20, 0));
        let alarm = data
            .next_alarm_from(naive(1, 0, 0), Tz::Floating, &source)
            .expect("all-day alarm");
        assert_eq!(alarm.alarm_time, naive(10, 12, 0));
    }

    #[test]
    fn triggered_personal_alert_is_found_by_recurrence() {
        let preferences = preferences(vec![
            (
                BASE_INSTANCE,
                valarms(
                    "BEGIN:VALARM\r\nJSID:base\r\nACTION:EMAIL\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n",
                ),
            ),
            (
                recurrence_key(naive(2, 10, 0)),
                valarms(concat!(
                    "BEGIN:VALARM\r\nJSID:occurrence\r\nACTION:EMAIL\r\nTRIGGER:-PT5M\r\n",
                    "ACKNOWLEDGED:20300102T095600Z\r\nEND:VALARM\r\n"
                )),
            ),
        ]);
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&preferences).expect("serializable");
        let archived = rkyv::access::<ArchivedEventPreferences, rkyv::rancor::Error>(&bytes)
            .expect("valid archive");
        let alert_id = |key: Option<u32>| {
            archived
                .personal_alert(key, 0)
                .and_then(|alert| alert.alarm_jsid())
        };
        assert_eq!(alert_id(None), Some("base"));
        assert_eq!(
            alert_id(Some(recurrence_key(naive(1, 10, 0)))),
            Some("base")
        );
        assert_eq!(
            alert_id(Some(recurrence_key(naive(2, 10, 0)))),
            Some("occurrence")
        );
        assert_eq!(
            archived
                .personal_alert(Some(recurrence_key(naive(2, 10, 0))), 0)
                .and_then(|alert| alert.acknowledged()),
            Some(naive(2, 9, 56))
        );
        assert!(archived.personal_alert(None, 1).is_none());
        assert!(archived.personal_alert(None, u16::MAX).is_none());
    }

    const SPRING_FORWARD_ALARMS: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:spring-forward\r\n",
        "DTSTART;TZID=America/New_York:20260308T090000\r\n",
        "DTEND;TZID=America/New_York:20260308T100000\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-P1D\r\n",
        "END:VALARM\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT24H\r\n",
        "END:VALARM\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER;RELATED=END:-P1DT30M\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn utc_2026(month: i8, day: i8, hour: i8, minute: i8) -> i64 {
        DateTime::new(2026, month, day, hour, minute, 0, 0)
            .expect("valid date")
            .naive_timestamp()
    }

    #[test]
    fn day_offsets_are_nominal_and_time_offsets_exact_across_daylight_saving() {
        let data = event_data(SPRING_FORWARD_ALARMS);
        let disabled = DefaultAlerts::disabled();
        let source = AlarmSource::Stored(&disabled);
        let mut start_time = utc_2026(3, 6, 0, 0);
        let mut alarm_times = Vec::new();
        while let Some(alarm) = data.next_alarm_from(start_time, Tz::UTC, &source) {
            alarm_times.push(alarm.alarm_time);
            start_time = alarm.alarm_time;
        }
        assert_eq!(
            alarm_times,
            [
                utc_2026(3, 7, 13, 0),
                utc_2026(3, 7, 14, 0),
                utc_2026(3, 7, 14, 30),
            ]
        );
    }

    #[test]
    fn expansion_alarm_times_match_the_scheduler() {
        let data = event_data(SPRING_FORWARD_ALARMS);
        let expansion = data.expand_base(Tz::UTC).expect("base expansion");
        assert_eq!(
            data.alarms
                .iter()
                .map(|alarm| expansion.alarm_time(&alarm.delta, Tz::UTC))
                .collect::<Vec<_>>(),
            [
                Some(utc_2026(3, 7, 14, 0)),
                Some(utc_2026(3, 7, 13, 0)),
                Some(utc_2026(3, 7, 14, 30)),
            ]
        );
    }

    #[test]
    fn end_alarms_follow_an_end_in_the_second_pass_of_a_repeated_hour() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:repeated-hour\r\n",
            "DTSTART;TZID=America/New_York:20261101T013000\r\n",
            "DURATION:PT1H\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER;RELATED=END:-PT10M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let disabled = DefaultAlerts::disabled();
        let source = AlarmSource::Stored(&disabled);
        let alarm = data
            .next_alarm_from(utc_2026(11, 1, 0, 0), Tz::UTC, &source)
            .expect("end alarm");
        assert_eq!(alarm.alarm_time, utc_2026(11, 1, 6, 20));

        let expansion = data.expand_base(Tz::UTC).expect("base expansion");
        assert_eq!(
            expansion.alarm_time(&data.alarms[0].delta, Tz::UTC),
            Some(utc_2026(11, 1, 6, 20))
        );
    }

    fn display_alarms(data: &CalendarEventData, mut start_time: i64) -> Vec<(i64, Option<i64>)> {
        let disabled = DefaultAlerts::disabled();
        let source = AlarmSource::Stored(&disabled);
        let mut alarms = Vec::new();
        while let Some(alarm) = data.next_alarm_from(start_time, Tz::UTC, &source) {
            start_time = alarm.alarm_time;
            let CalendarAlarmType::Display { recurrence_id } = alarm.typ else {
                panic!("display alarm expected, got {alarm:?}");
            };
            alarms.push((alarm.alarm_time, recurrence_id));
        }
        alarms
    }

    #[test]
    fn alarms_of_moved_occurrences_keep_the_recurrence_id_of_the_series() {
        let other_zone = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:other-zone\r\n",
            "DTSTART;TZID=America/New_York:20261029T013000\r\n",
            "DURATION:PT30M\r\n",
            "RRULE:FREQ=DAILY;COUNT=5\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:other-zone\r\n",
            "RECURRENCE-ID;TZID=America/New_York;RANGE=THISANDFUTURE:20261030T013000\r\n",
            "DTSTART;TZID=Europe/London:20261030T063000\r\n",
            "DURATION:PT30M\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER:-PT15M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        assert_eq!(
            display_alarms(&other_zone, utc_2026(10, 29, 0, 0)),
            [
                (utc_2026(10, 30, 6, 15), Some(utc_2026(10, 30, 1, 30))),
                (utc_2026(10, 31, 6, 15), Some(utc_2026(10, 31, 1, 30))),
                (utc_2026(11, 1, 6, 15), Some(utc_2026(11, 1, 1, 30))),
                (utc_2026(11, 2, 7, 15), Some(utc_2026(11, 2, 1, 30))),
            ]
        );

        let same_zone = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:same-zone\r\n",
            "DTSTART;TZID=America/New_York:20260306T230000\r\n",
            "DURATION:PT30M\r\n",
            "RRULE:FREQ=DAILY;COUNT=5\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:same-zone\r\n",
            "RECURRENCE-ID;TZID=America/New_York;RANGE=THISANDFUTURE:20260307T230000\r\n",
            "DTSTART;TZID=America/New_York:20260308T030000\r\n",
            "DURATION:PT30M\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "TRIGGER:-PT15M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        assert_eq!(
            display_alarms(&same_zone, utc_2026(3, 6, 0, 0)),
            [
                (utc_2026(3, 8, 6, 45), Some(utc_2026(3, 7, 23, 0))),
                (utc_2026(3, 9, 6, 45), Some(utc_2026(3, 8, 23, 0))),
                (utc_2026(3, 10, 6, 45), Some(utc_2026(3, 9, 23, 0))),
                (utc_2026(3, 11, 6, 45), Some(utc_2026(3, 10, 23, 0))),
            ]
        );
    }

    #[test]
    fn email_alarms_carry_instants_and_the_recurrence_id() {
        let data = event_data(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:email\r\n",
            "DTSTART;TZID=Europe/Berlin:20300110T090000\r\n",
            "DURATION:PT1H\r\n",
            "RRULE:FREQ=DAILY;COUNT=2\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:EMAIL\r\n",
            "TRIGGER:-PT15M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let disabled = DefaultAlerts::disabled();
        let source = AlarmSource::Stored(&disabled);
        let berlin = Tz::from_str("Europe/Berlin")
            .expect("known time zone")
            .as_id();
        let alarm = data
            .next_alarm_from(naive(10, 9, 0), Tz::UTC, &source)
            .expect("email alarm");
        assert_eq!(alarm.alarm_time, naive(11, 7, 45));
        assert_eq!(
            alarm.typ,
            CalendarAlarmType::Email {
                event_start: naive(11, 8, 0),
                event_start_tz: berlin,
                event_end: naive(11, 9, 0),
                event_end_tz: berlin,
                recurrence_id: Some(naive(11, 9, 0)),
            }
        );
    }

    #[test]
    fn trigger_durations_split_into_nominal_days_and_exact_seconds() {
        for (trigger, expected) in [
            ("-P1D", (-1, 0)),
            ("-P2W", (-14, 0)),
            ("-PT24H", (0, -86_400)),
            ("-P1DT30M", (-1, -1_800)),
            ("PT15M", (0, 900)),
        ] {
            let alarm = valarms(&format!(
                "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:{trigger}\r\nEND:VALARM\r\n"
            ))
            .first()
            .and_then(|alarm| alarm.expand_alarm(0, 0))
            .expect("relative alarm");
            assert_eq!(
                alarm.delta,
                AlarmDelta::Start(AlarmOffset {
                    days: expected.0,
                    seconds: expected.1,
                }),
                "{trigger}"
            );
        }
    }

    #[test]
    fn trigger_durations_beyond_the_stored_range_saturate() {
        let huge = ICalendarDuration {
            neg: true,
            weeks: u32::MAX,
            days: u32::MAX,
            hours: u32::MAX,
            minutes: u32::MAX,
            seconds: u32::MAX,
        };
        assert_eq!(
            AlarmOffset::from(&huge),
            AlarmOffset {
                days: -i32::MAX,
                seconds: -i32::MAX,
            }
        );
        assert_eq!(
            AlarmOffset::from(&ICalendarDuration { neg: false, ..huge }),
            AlarmOffset {
                days: i32::MAX,
                seconds: i32::MAX,
            }
        );
    }
}
