/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::freebusy::freebusy_in_range;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendar, ArchivedICalendarComponent, ArchivedICalendarComponentType,
        ArchivedICalendarEntry, ArchivedICalendarParameter, ArchivedICalendarParameterName,
        ArchivedICalendarParameterValue, ArchivedICalendarProperty, ArchivedICalendarValue,
        ArchivedICalendarValueType, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarValue, ICalendarValueType,
    },
};
use groupware::calendar::{
    Alarm, AlarmDelta, ArchivedAlarm, ArchivedCalendarEventContent, CalendarEventContent,
    expand::CalendarEventExpansion,
};
use rkyv::primitive::ArchivedU32;
use std::borrow::Cow;
use store::write::serialize::rkyv_deserialize;
use types::TimeRange;

const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) trait CalendarView {
    type Component: ComponentView;
    type Alarm: AlarmView;

    fn components(&self) -> &[Self::Component];
    fn alarms(&self) -> &[Self::Alarm];
}

pub(crate) trait ComponentView {
    type Type: PartialEq<ICalendarComponentType>;
    type Entry: EntryView;
    type ChildId: ChildIdView;

    fn component_type(&self) -> &Self::Type;
    fn type_name(&self) -> &str;
    fn has_time_ranges(&self) -> bool;
    fn is_recurrent(&self) -> bool;
    fn is_recurrence_override(&self) -> bool;
    fn entries(&self) -> &[Self::Entry];
    fn child_ids(&self) -> &[Self::ChildId];

    fn is_type(&self, component_type: ICalendarComponentType) -> bool {
        self.component_type() == &component_type
    }

    fn effective_end(&self, property: &ICalendarProperty, default_tz: Tz) -> Option<i64> {
        let applies = match property {
            ICalendarProperty::Dtend => self.is_type(ICalendarComponentType::VEvent),
            ICalendarProperty::Due => self.is_type(ICalendarComponentType::VTodo),
            _ => false,
        };
        if !applies {
            return None;
        }
        let mut start = None;
        let mut duration = None;
        for entry in self.entries() {
            if entry.is_named(&ICalendarProperty::Dtstart) {
                start = entry.date_time_timestamp(default_tz);
            } else if entry.is_named(&ICalendarProperty::Duration) {
                duration = entry.duration_seconds();
            }
        }
        start?.checked_add(duration?)
    }

    fn alarm_repetition(&self) -> AlarmRepetition {
        let mut count = None;
        let mut interval = None;
        for entry in self.entries() {
            if entry.is_named(&ICalendarProperty::Repeat) {
                count = entry.integer_value();
            } else if entry.is_named(&ICalendarProperty::Duration) {
                interval = entry.duration_seconds();
            }
        }
        AlarmRepetition::new(count, interval)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AlarmRepetition {
    count: u64,
    interval: u64,
}

pub(crate) trait EntryView {
    type Name: PartialEq<ICalendarProperty>;
    type Param: ParameterView;

    fn name(&self) -> &Self::Name;
    fn params(&self) -> &[Self::Param];
    fn text_values(&self) -> impl Iterator<Item = Cow<'_, str>>;
    fn date_time_timestamp(&self, default_tz: Tz) -> Option<i64>;
    fn integer_value(&self) -> Option<i64>;
    fn duration_seconds(&self) -> Option<i64>;
    fn freebusy_in_range(&self, range: &TimeRange, default_tz: Tz) -> Option<ICalendarEntry>;
    fn write_value(&self, out: &mut String, with_value: bool);

    fn is_named(&self, property: &ICalendarProperty) -> bool {
        self.name() == property
    }
}

pub(crate) trait ParameterView {
    type Name: PartialEq<ICalendarParameterName>;

    fn name(&self) -> &Self::Name;
    fn text(&self) -> Option<Cow<'_, str>>;

    fn is_named(&self, name: &ICalendarParameterName) -> bool {
        self.name() == name
    }
}

pub(crate) trait AlarmView {
    fn id(&self) -> u32;
    fn parent_id(&self) -> u32;
    fn delta(&self) -> AlarmDelta;
    fn timestamp(&self, expansion: &CalendarEventExpansion, default_tz: Tz) -> Option<i64>;

    fn trigger_offset(&self) -> Option<i64> {
        match self.delta() {
            AlarmDelta::Start(offset) | AlarmDelta::End(offset) => Some(
                i64::from(offset.days.unsigned_abs()) * SECONDS_PER_DAY
                    + i64::from(offset.seconds.unsigned_abs()),
            ),
            AlarmDelta::FixedUtc(_) | AlarmDelta::FixedFloating(_) => None,
        }
    }
}

pub(crate) trait ChildIdView: Sized + From<u32> {
    fn child_id(&self) -> u32;
}

impl ChildIdView for u32 {
    fn child_id(&self) -> u32 {
        *self
    }
}

impl ChildIdView for ArchivedU32 {
    fn child_id(&self) -> u32 {
        self.to_native()
    }
}

impl CalendarView for CalendarEventContent {
    type Component = ICalendarComponent;
    type Alarm = Alarm;

    fn components(&self) -> &[Self::Component] {
        &self.data.event.components
    }

    fn alarms(&self) -> &[Self::Alarm] {
        &self.data.alarms
    }
}

impl CalendarView for ArchivedCalendarEventContent {
    type Component = ArchivedICalendarComponent;
    type Alarm = ArchivedAlarm;

    fn components(&self) -> &[Self::Component] {
        &self.data.event.components
    }

    fn alarms(&self) -> &[Self::Alarm] {
        &self.data.alarms
    }
}

impl CalendarView for ArchivedICalendar {
    type Component = ArchivedICalendarComponent;
    type Alarm = ArchivedAlarm;

    fn components(&self) -> &[Self::Component] {
        &self.components
    }

    fn alarms(&self) -> &[Self::Alarm] {
        &[]
    }
}

impl ComponentView for ICalendarComponent {
    type Type = ICalendarComponentType;
    type Entry = ICalendarEntry;
    type ChildId = u32;

    fn component_type(&self) -> &Self::Type {
        &self.component_type
    }

    fn type_name(&self) -> &str {
        self.component_type.as_str()
    }

    fn has_time_ranges(&self) -> bool {
        self.component_type.has_time_ranges()
    }

    fn is_recurrent(&self) -> bool {
        ICalendarComponent::is_recurrent(self)
    }

    fn is_recurrence_override(&self) -> bool {
        ICalendarComponent::is_recurrence_override(self)
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.entries
    }

    fn child_ids(&self) -> &[Self::ChildId] {
        &self.component_ids
    }
}

impl ComponentView for ArchivedICalendarComponent {
    type Type = ArchivedICalendarComponentType;
    type Entry = ArchivedICalendarEntry;
    type ChildId = ArchivedU32;

    fn component_type(&self) -> &Self::Type {
        &self.component_type
    }

    fn type_name(&self) -> &str {
        self.component_type.as_str()
    }

    fn has_time_ranges(&self) -> bool {
        self.component_type.has_time_ranges()
    }

    fn is_recurrent(&self) -> bool {
        ArchivedICalendarComponent::is_recurrent(self)
    }

    fn is_recurrence_override(&self) -> bool {
        ArchivedICalendarComponent::is_recurrence_override(self)
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.entries
    }

    fn child_ids(&self) -> &[Self::ChildId] {
        &self.component_ids
    }
}

impl EntryView for ICalendarEntry {
    type Name = ICalendarProperty;
    type Param = ICalendarParameter;

    fn name(&self) -> &Self::Name {
        &self.name
    }

    fn params(&self) -> &[Self::Param] {
        &self.params
    }

    fn text_values(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.values.iter().filter_map(ValueText::value_text)
    }

    fn date_time_timestamp(&self, default_tz: Tz) -> Option<i64> {
        self.values
            .first()
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date| date.to_date_time())
            .and_then(|date| date.to_date_time_with_tz(entry_tz(self.tz_id(), default_tz)))
            .map(|date| date.timestamp())
    }

    fn integer_value(&self) -> Option<i64> {
        self.values.first().and_then(ICalendarValue::as_integer)
    }

    fn duration_seconds(&self) -> Option<i64> {
        match self.values.first() {
            Some(ICalendarValue::Duration(duration)) => Some(duration.as_seconds()),
            _ => None,
        }
    }

    fn freebusy_in_range(&self, range: &TimeRange, default_tz: Tz) -> Option<ICalendarEntry> {
        let tz = entry_tz(self.tz_id(), default_tz);
        let values = self
            .values
            .iter()
            .filter(|value| {
                matches!(value, ICalendarValue::Period(period)
                if period.time_range(tz).is_some_and(|(start, end)| {
                    range.overlaps(start.timestamp(), end.timestamp())
                }))
            })
            .cloned()
            .collect::<Vec<_>>();

        (!values.is_empty()).then(|| ICalendarEntry {
            name: ICalendarProperty::Freebusy,
            params: self.params.clone(),
            values: values.into(),
        })
    }

    fn write_value(&self, out: &mut String, with_value: bool) {
        let _ = self.write_with_value(out, with_value);
    }
}

impl EntryView for ArchivedICalendarEntry {
    type Name = ArchivedICalendarProperty;
    type Param = ArchivedICalendarParameter;

    fn name(&self) -> &Self::Name {
        &self.name
    }

    fn params(&self) -> &[Self::Param] {
        &self.params
    }

    fn text_values(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.values.iter().filter_map(ValueText::value_text)
    }

    fn date_time_timestamp(&self, default_tz: Tz) -> Option<i64> {
        self.values
            .first()
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date| date.to_date_time())
            .and_then(|date| date.to_date_time_with_tz(entry_tz(self.tz_id(), default_tz)))
            .map(|date| date.timestamp())
    }

    fn integer_value(&self) -> Option<i64> {
        self.values
            .first()
            .and_then(ArchivedICalendarValue::as_integer)
    }

    fn duration_seconds(&self) -> Option<i64> {
        match self.values.first() {
            Some(ArchivedICalendarValue::Duration(duration)) => Some(duration.as_seconds()),
            _ => None,
        }
    }

    fn freebusy_in_range(&self, range: &TimeRange, default_tz: Tz) -> Option<ICalendarEntry> {
        let mut values = freebusy_in_range(self, range, default_tz).peekable();
        values.peek().is_some().then(|| ICalendarEntry {
            name: ICalendarProperty::Freebusy,
            params: rkyv_deserialize(&self.params).ok().unwrap_or_default(),
            values: values.collect(),
        })
    }

    fn write_value(&self, out: &mut String, with_value: bool) {
        let _ = self.write_to(out, with_value);
    }
}

impl ParameterView for ICalendarParameter {
    type Name = ICalendarParameterName;

    fn name(&self) -> &Self::Name {
        &self.name
    }

    fn text(&self) -> Option<Cow<'_, str>> {
        match &self.value {
            ICalendarParameterValue::Integer(value) => Some(Cow::Owned(value.to_string())),
            ICalendarParameterValue::Duration(value) => Some(Cow::Owned(value.to_string())),
            value => value.as_text().map(Cow::Borrowed),
        }
    }
}

impl ParameterView for ArchivedICalendarParameter {
    type Name = ArchivedICalendarParameterName;

    fn name(&self) -> &Self::Name {
        &self.name
    }

    fn text(&self) -> Option<Cow<'_, str>> {
        match &self.value {
            ArchivedICalendarParameterValue::Integer(value) => {
                Some(Cow::Owned(value.to_native().to_string()))
            }
            ArchivedICalendarParameterValue::Duration(value) => Some(Cow::Owned(value.to_string())),
            value => value.as_text().map(Cow::Borrowed),
        }
    }
}

trait ValueText {
    fn value_text(&self) -> Option<Cow<'_, str>>;
}

impl ValueText for ICalendarValue {
    fn value_text(&self) -> Option<Cow<'_, str>> {
        match self {
            ICalendarValue::Integer(value) => Some(Cow::Owned(value.to_string())),
            ICalendarValue::Float(value) => Some(Cow::Owned(value.to_string())),
            ICalendarValue::Boolean(value) => {
                Some(Cow::Borrowed(if *value { "TRUE" } else { "FALSE" }))
            }
            ICalendarValue::Duration(value) => Some(Cow::Owned(value.to_string())),
            ICalendarValue::RecurrenceRule(value) => Some(Cow::Owned(value.to_string())),
            ICalendarValue::Period(value) => Some(Cow::Owned(value.to_string())),
            ICalendarValue::PartialDateTime(value) => {
                let value_type = match (value.has_date(), value.has_time()) {
                    (true, true) => ICalendarValueType::DateTime,
                    (true, false) => ICalendarValueType::Date,
                    (false, true) => ICalendarValueType::Time,
                    (false, false) => ICalendarValueType::UtcOffset,
                };
                let mut text = String::with_capacity(20);
                value
                    .format_as_ical(&mut text, &value_type)
                    .ok()
                    .map(|_| Cow::Owned(text))
            }
            value => value.as_text().map(Cow::Borrowed),
        }
    }
}

impl ValueText for ArchivedICalendarValue {
    fn value_text(&self) -> Option<Cow<'_, str>> {
        match self {
            ArchivedICalendarValue::Integer(value) => {
                Some(Cow::Owned(value.to_native().to_string()))
            }
            ArchivedICalendarValue::Float(value) => Some(Cow::Owned(value.to_native().to_string())),
            ArchivedICalendarValue::Boolean(value) => {
                Some(Cow::Borrowed(if *value { "TRUE" } else { "FALSE" }))
            }
            ArchivedICalendarValue::Duration(value) => Some(Cow::Owned(value.to_string())),
            ArchivedICalendarValue::RecurrenceRule(value) => {
                Some(Cow::Owned(value.as_ref().to_string()))
            }
            ArchivedICalendarValue::Period(value) => Some(Cow::Owned(value.to_string())),
            ArchivedICalendarValue::PartialDateTime(value) => {
                let value_type = match (value.has_date(), value.has_time()) {
                    (true, true) => ArchivedICalendarValueType::DateTime,
                    (true, false) => ArchivedICalendarValueType::Date,
                    (false, true) => ArchivedICalendarValueType::Time,
                    (false, false) => ArchivedICalendarValueType::UtcOffset,
                };
                let mut text = String::with_capacity(20);
                value
                    .format_as_ical(&mut text, &value_type)
                    .ok()
                    .map(|_| Cow::Owned(text))
            }
            value => value.as_text().map(Cow::Borrowed),
        }
    }
}

impl AlarmRepetition {
    fn new(count: Option<i64>, interval: Option<i64>) -> Self {
        match (
            count.and_then(|count| u64::try_from(count).ok()),
            interval.and_then(|interval| u64::try_from(interval).ok()),
        ) {
            (Some(count), Some(interval)) if count > 0 && interval > 0 => {
                AlarmRepetition { count, interval }
            }
            _ => AlarmRepetition::default(),
        }
    }

    pub fn span(&self) -> i64 {
        i64::try_from(self.count.saturating_mul(self.interval)).unwrap_or(i64::MAX)
    }

    pub fn triggers_in(&self, first: i64, range: &TimeRange) -> bool {
        if first >= range.start {
            first < range.end
        } else if self.count == 0 {
            false
        } else {
            let steps = range.start.abs_diff(first).div_ceil(self.interval);
            steps <= self.count
                && i128::from(first) + i128::from(steps) * i128::from(self.interval)
                    < i128::from(range.end)
        }
    }
}

impl AlarmView for Alarm {
    fn id(&self) -> u32 {
        u32::from(self.id)
    }

    fn parent_id(&self) -> u32 {
        u32::from(self.parent_id)
    }

    fn delta(&self) -> AlarmDelta {
        self.delta.clone()
    }

    fn timestamp(&self, expansion: &CalendarEventExpansion, default_tz: Tz) -> Option<i64> {
        expansion.alarm_time(&self.delta, default_tz)
    }
}

impl AlarmView for ArchivedAlarm {
    fn id(&self) -> u32 {
        u32::from(self.id.to_native())
    }

    fn parent_id(&self) -> u32 {
        u32::from(self.parent_id.to_native())
    }

    fn delta(&self) -> AlarmDelta {
        AlarmDelta::from(&self.delta)
    }

    fn timestamp(&self, expansion: &CalendarEventExpansion, default_tz: Tz) -> Option<i64> {
        expansion.alarm_time(&AlarmDelta::from(&self.delta), default_tz)
    }
}

fn entry_tz(tz_id: Option<&str>, default_tz: Tz) -> Tz {
    tz_id
        .and_then(|tz_id| tz_id.parse().ok())
        .unwrap_or(default_tz)
}
