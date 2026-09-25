/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::freebusy::freebusy_in_range;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendarComponent, ArchivedICalendarComponentType, ArchivedICalendarEntry,
        ArchivedICalendarParameter, ArchivedICalendarParameterName, ArchivedICalendarProperty,
        ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
        ICalendarParameterName, ICalendarProperty, ICalendarValue,
    },
};
use groupware::calendar::{
    Alarm, AlarmDelta, ArchivedAlarm, ArchivedCalendarEventContent, CalendarEventContent,
    expand::CalendarEventExpansion,
};
use rkyv::primitive::ArchivedU32;
use store::write::serialize::rkyv_deserialize;
use types::TimeRange;

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
}

pub(crate) trait EntryView {
    type Name: PartialEq<ICalendarProperty>;
    type Param: ParameterView;

    fn name(&self) -> &Self::Name;
    fn params(&self) -> &[Self::Param];
    fn text_values(&self) -> impl Iterator<Item = &str>;
    fn date_time_timestamp(&self, default_tz: Tz) -> Option<i64>;
    fn freebusy_in_range(&self, range: &TimeRange, default_tz: Tz) -> Option<ICalendarEntry>;
    fn write_value(&self, out: &mut String, with_value: bool);

    fn is_named(&self, property: &ICalendarProperty) -> bool {
        self.name() == property
    }

    fn parameter(&self, name: &ICalendarParameterName) -> Option<&Self::Param> {
        self.params().iter().find(|param| param.is_named(name))
    }
}

pub(crate) trait ParameterView {
    type Name: PartialEq<ICalendarParameterName>;

    fn name(&self) -> &Self::Name;
    fn text(&self) -> Option<&str>;

    fn is_named(&self, name: &ICalendarParameterName) -> bool {
        self.name() == name
    }
}

pub(crate) trait AlarmView {
    fn parent_id(&self) -> u32;
    fn timestamp(&self, expansion: &CalendarEventExpansion, default_tz: Tz) -> Option<i64>;
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

    fn text_values(&self) -> impl Iterator<Item = &str> {
        self.values.iter().filter_map(|value| value.as_text())
    }

    fn date_time_timestamp(&self, default_tz: Tz) -> Option<i64> {
        self.values
            .first()
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date| date.to_date_time())
            .and_then(|date| date.to_date_time_with_tz(entry_tz(self.tz_id(), default_tz)))
            .map(|date| date.timestamp())
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

    fn text_values(&self) -> impl Iterator<Item = &str> {
        self.values.iter().filter_map(|value| value.as_text())
    }

    fn date_time_timestamp(&self, default_tz: Tz) -> Option<i64> {
        self.values
            .first()
            .and_then(|value| value.as_partial_date_time())
            .and_then(|date| date.to_date_time())
            .and_then(|date| date.to_date_time_with_tz(entry_tz(self.tz_id(), default_tz)))
            .map(|date| date.timestamp())
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

    fn text(&self) -> Option<&str> {
        self.value.as_text()
    }
}

impl ParameterView for ArchivedICalendarParameter {
    type Name = ArchivedICalendarParameterName;

    fn name(&self) -> &Self::Name {
        &self.name
    }

    fn text(&self) -> Option<&str> {
        self.value.as_text()
    }
}

impl AlarmView for Alarm {
    fn parent_id(&self) -> u32 {
        self.parent_id as u32
    }

    fn timestamp(&self, expansion: &CalendarEventExpansion, default_tz: Tz) -> Option<i64> {
        expansion.alarm_time(&self.delta, default_tz)
    }
}

impl AlarmView for ArchivedAlarm {
    fn parent_id(&self) -> u32 {
        self.parent_id.to_native() as u32
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
