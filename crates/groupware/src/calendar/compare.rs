/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{expand::NaiveTimestamp, user::UserDataEntry};
use ahash::AHashMap;
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
        ICalendarParameterName, ICalendarParameterValue, ICalendarProperty, ICalendarValue,
        ICalendarValueType, Uri,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonScope {
    SharedData,
    SchedulingData,
}

impl ComparisonScope {
    pub fn component_eq(self, a: &ICalendar, a_id: u32, b: &ICalendar, b_id: u32) -> bool {
        let (Some(a_component), Some(b_component)) =
            (a.component_by_id(a_id), b.component_by_id(b_id))
        else {
            return false;
        };
        a_component.component_type == b_component.component_type
            && self
                .entries(a_component)
                .same_entries(&self.entries(b_component))
            && self.children_eq(a, a_component, b, b_component)
    }

    fn children_eq(
        self,
        a: &ICalendar,
        a_component: &ICalendarComponent,
        b: &ICalendar,
        b_component: &ICalendarComponent,
    ) -> bool {
        let (a_children, b_children) =
            (self.children(a, a_component), self.children(b, b_component));
        if a_children.len() != b_children.len() {
            return false;
        }
        let mut candidates: AHashMap<ChildKey<'_>, Vec<u32>> =
            AHashMap::with_capacity(b_children.len());
        for b_child in b_children {
            let Some(key) = b.child_key(b_child) else {
                return false;
            };
            candidates.entry(key).or_default().push(b_child);
        }

        a_children.into_iter().all(|a_child| {
            let Some(candidates) = a
                .child_key(a_child)
                .and_then(|key| candidates.get_mut(&key))
            else {
                return false;
            };
            match candidates
                .iter()
                .position(|b_child| self.component_eq(a, a_child, b, *b_child))
            {
                Some(index) => {
                    candidates.swap_remove(index);
                    true
                }
                None => false,
            }
        })
    }

    fn entries(self, component: &ICalendarComponent) -> Vec<&ICalendarEntry> {
        let mut entries = component
            .entries
            .iter()
            .filter(|entry| match self {
                ComparisonScope::SharedData => !entry.name.is_volatile(),
                ComparisonScope::SchedulingData => {
                    !entry.name.is_volatile()
                        && !entry.is_user_data()
                        && entry.name != ICalendarProperty::Sequence
                }
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn children(self, ical: &ICalendar, component: &ICalendarComponent) -> Vec<u32> {
        component
            .component_ids
            .iter()
            .copied()
            .filter(|id| {
                self == ComparisonScope::SharedData
                    || ical
                        .component_by_id(*id)
                        .is_some_and(|c| c.component_type != ICalendarComponentType::VAlarm)
            })
            .collect()
    }
}

type ChildKey<'x> = (&'x ICalendarComponentType, Option<i64>);

trait ChildComponentKey {
    fn child_key(&self, comp_id: u32) -> Option<ChildKey<'_>>;
}

impl ChildComponentKey for ICalendar {
    fn child_key(&self, comp_id: u32) -> Option<ChildKey<'_>> {
        let component = self.component_by_id(comp_id)?;
        Some((
            &component.component_type,
            component
                .property(&ICalendarProperty::RecurrenceId)
                .and_then(|entry| entry.values.first())
                .and_then(ICalendarValue::as_partial_date_time)
                .and_then(PartialDateTime::naive_timestamp),
        ))
    }
}

pub trait RecurrenceComponents {
    fn base_component_id(&self) -> Option<u32>;
}

impl RecurrenceComponents for ICalendar {
    fn base_component_id(&self) -> Option<u32> {
        self.components
            .iter()
            .position(|component| {
                component.component_type.is_event_or_todo() && !component.is_recurrence_override()
            })
            .map(|id| id as u32)
    }
}

pub struct RedundantOverrides<'x> {
    ical: &'x ICalendar,
    base: &'x ICalendarComponent,
    base_start: &'x ICalendarEntry,
    base_entries: Vec<&'x ICalendarEntry>,
}

impl<'x> RedundantOverrides<'x> {
    pub fn new(ical: &'x ICalendar) -> Option<Self> {
        let base = ical.component_by_id(ical.base_component_id()?)?;
        Some(RedundantOverrides {
            ical,
            base,
            base_start: base.property(&ICalendarProperty::Dtstart)?,
            base_entries: base.occurrence_entries(),
        })
    }

    pub fn is_redundant(&self, override_id: u32) -> bool {
        let Some(component) = self.ical.component_by_id(override_id) else {
            return false;
        };
        let (Some(recurrence_id), Some(start)) = (
            component.property(&ICalendarProperty::RecurrenceId),
            component.property(&ICalendarProperty::Dtstart),
        ) else {
            return false;
        };
        let Some(shift) = self.base_start.shift_to(start) else {
            return false;
        };

        start.values == recurrence_id.values
            && start.tz_id() == recurrence_id.tz_id()
            && [ICalendarProperty::Dtend, ICalendarProperty::Due]
                .iter()
                .all(
                    |name| match (self.base.property(name), component.property(name)) {
                        (Some(base_entry), Some(entry)) => {
                            base_entry.shift_to(entry) == Some(shift)
                        }
                        (None, None) => true,
                        _ => false,
                    },
                )
            && component
                .occurrence_entries()
                .same_entries(&self.base_entries)
            && ComparisonScope::SharedData.children_eq(self.ical, component, self.ical, self.base)
    }
}

pub trait EntryEquivalence {
    fn is_equivalent(&self, other: &Self) -> bool;

    fn shift_to(&self, other: &Self) -> Option<i64>;
}

impl EntryEquivalence for ICalendarEntry {
    fn is_equivalent(&self, other: &Self) -> bool {
        self.name == other.name
            && self.values.len() == other.values.len()
            && self.values.iter().zip(&other.values).all(|(value, other)| {
                value == other
                    || (self.name.is_calendar_address()
                        && value
                            .as_address()
                            .is_some_and(|address| other.as_address() == Some(address)))
            })
            && self.has_equivalent_params(other)
    }

    fn shift_to(&self, other: &Self) -> Option<i64> {
        let ([ICalendarValue::PartialDateTime(from)], [ICalendarValue::PartialDateTime(to)]) =
            (self.values.as_slice(), other.values.as_slice())
        else {
            return None;
        };
        (from.has_same_shape(to) && self.has_equivalent_params(other))
            .then(|| to.naive_timestamp()?.checked_sub(from.naive_timestamp()?))
            .flatten()
    }
}

pub trait NaiveDateTime {
    fn naive_timestamp(&self) -> Option<i64>;

    fn has_same_shape(&self, other: &Self) -> bool;

    fn shifted(&self, shift: i64) -> Option<PartialDateTime>;
}

impl NaiveDateTime for PartialDateTime {
    fn naive_timestamp(&self) -> Option<i64> {
        self.to_date_time()
            .map(|date_time| date_time.date_time.naive_timestamp())
    }

    fn has_same_shape(&self, other: &Self) -> bool {
        self.has_date() == other.has_date()
            && self.has_time() == other.has_time()
            && self.tz_hour == other.tz_hour
            && self.tz_minute == other.tz_minute
            && self.tz_minus == other.tz_minus
    }

    fn shifted(&self, shift: i64) -> Option<PartialDateTime> {
        let timestamp = self.naive_timestamp()?.checked_add(shift)?;
        let shifted = if self.has_time() {
            PartialDateTime::from_naive_timestamp(timestamp)
        } else {
            PartialDateTime::from_date_timestamp(timestamp)
        };
        Some(PartialDateTime {
            second: shifted.second.filter(|_| self.second.is_some()),
            tz_hour: self.tz_hour,
            tz_minute: self.tz_minute,
            tz_minus: self.tz_minus,
            ..shifted
        })
    }
}

pub trait EntryList {
    fn same_entries(&self, other: &Self) -> bool;
}

impl EntryList for [&ICalendarEntry] {
    fn same_entries(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut matched = vec![false; other.len()];
        self.iter().all(|entry| {
            let start = other.partition_point(|candidate| candidate.name < entry.name);
            other
                .get(start..)
                .unwrap_or_default()
                .iter()
                .zip(matched.get_mut(start..).unwrap_or_default())
                .take_while(|(candidate, _)| candidate.name == entry.name)
                .find(|(candidate, is_matched)| !**is_matched && entry.is_equivalent(candidate))
                .map(|(_, is_matched)| *is_matched = true)
                .is_some()
        })
    }
}

trait OccurrenceEntries {
    fn occurrence_entries(&self) -> Vec<&ICalendarEntry>;
}

impl OccurrenceEntries for ICalendarComponent {
    fn occurrence_entries(&self) -> Vec<&ICalendarEntry> {
        let mut entries = self
            .entries
            .iter()
            .filter(|entry| {
                !entry.name.is_volatile()
                    && !matches!(
                        entry.name,
                        ICalendarProperty::RecurrenceId
                            | ICalendarProperty::Rrule
                            | ICalendarProperty::Rdate
                            | ICalendarProperty::Exrule
                            | ICalendarProperty::Exdate
                            | ICalendarProperty::Dtstart
                            | ICalendarProperty::Dtend
                            | ICalendarProperty::Due
                    )
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

trait EntryParameters {
    fn significant_params(&self) -> impl Iterator<Item = &ICalendarParameter> + Clone;

    fn has_equivalent_params(&self, other: &Self) -> bool;
}

impl EntryParameters for ICalendarEntry {
    fn significant_params(&self) -> impl Iterator<Item = &ICalendarParameter> + Clone {
        self.params.iter().filter(|param| match &param.value {
            ICalendarParameterValue::Value(value_type)
                if param.name == ICalendarParameterName::Value =>
            {
                self.values.is_empty()
                    || !self.values.iter().all(|value| value.is_of_type(value_type))
            }
            _ => true,
        })
    }

    fn has_equivalent_params(&self, other: &Self) -> bool {
        let (params, other_params) = (self.significant_params(), other.significant_params());
        params.clone().count() == other_params.clone().count()
            && params.clone().all(|param| {
                params.clone().filter(|item| *item == param).count()
                    == other_params.clone().filter(|item| *item == param).count()
            })
    }
}

trait ValueClass {
    fn is_of_type(&self, value_type: &ICalendarValueType) -> bool;

    fn as_address(&self) -> Option<&str>;
}

impl ValueClass for ICalendarValue {
    fn is_of_type(&self, value_type: &ICalendarValueType) -> bool {
        match (value_type, self) {
            (ICalendarValueType::Binary, ICalendarValue::Binary(_))
            | (ICalendarValueType::Boolean, ICalendarValue::Boolean(_))
            | (ICalendarValueType::CalAddress, ICalendarValue::Uri(_) | ICalendarValue::Text(_))
            | (ICalendarValueType::Duration, ICalendarValue::Duration(_))
            | (ICalendarValueType::Float, ICalendarValue::Float(_))
            | (ICalendarValueType::Integer, ICalendarValue::Integer(_))
            | (ICalendarValueType::Period, ICalendarValue::Period(_))
            | (ICalendarValueType::Recur, ICalendarValue::RecurrenceRule(_))
            | (ICalendarValueType::Text, ICalendarValue::Text(_))
            | (ICalendarValueType::Uri, ICalendarValue::Uri(_)) => true,
            (ICalendarValueType::Date, ICalendarValue::PartialDateTime(value)) => {
                value.has_date() && !value.has_time()
            }
            (ICalendarValueType::DateTime, ICalendarValue::PartialDateTime(value)) => {
                value.has_date() && value.has_time()
            }
            (ICalendarValueType::Time, ICalendarValue::PartialDateTime(value)) => {
                !value.has_date() && value.has_time()
            }
            _ => false,
        }
    }

    fn as_address(&self) -> Option<&str> {
        match self {
            ICalendarValue::Uri(Uri::Location(address)) | ICalendarValue::Text(address) => {
                Some(address)
            }
            _ => None,
        }
    }
}

pub trait PropertyClass {
    fn is_volatile(&self) -> bool;

    fn is_calendar_address(&self) -> bool;
}

impl PropertyClass for ICalendarProperty {
    fn is_volatile(&self) -> bool {
        matches!(
            self,
            ICalendarProperty::Dtstamp | ICalendarProperty::LastModified
        )
    }

    fn is_calendar_address(&self) -> bool {
        matches!(
            self,
            ICalendarProperty::Organizer
                | ICalendarProperty::Attendee
                | ICalendarProperty::CalendarAddress
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(entries: &str) -> ICalendar {
        ICalendar::parse(format!(
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\n",
                "UID:abc\r\nDTSTAMP:20240101T000000Z\r\n{}END:VEVENT\r\nEND:VCALENDAR\r\n"
            ),
            entries
        ))
        .expect("valid iCalendar")
    }

    fn is_same(a: &str, b: &str) -> bool {
        ComparisonScope::SharedData.component_eq(&event(a), 0, &event(b), 0)
    }

    #[test]
    fn formatting_differences_are_ignored() {
        for (a, b) in [
            (
                "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:b@example.org\r\n",
                "ATTENDEE;RSVP=TRUE;ROLE=REQ-PARTICIPANT;CUTYPE=INDIVIDUAL:mailto:b@example.org\r\n",
            ),
            (
                "DTSTART;VALUE=DATE-TIME;TZID=Europe/Berlin:20240506T090000\r\n",
                "DTSTART;TZID=Europe/Berlin:20240506T090000\r\n",
            ),
            (
                "URL;VALUE=URI:https://example.com/meet\r\n",
                "URL:https://example.com/meet\r\n",
            ),
            (
                "X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=Main;X-TITLE=Room:geo:52.5,13.4\r\n",
                "X-APPLE-STRUCTURED-LOCATION;X-TITLE=Room;X-ADDRESS=Main;VALUE=URI:geo:52.5,13.4\r\n",
            ),
            (
                "SUMMARY:A\r\nDTSTAMP:20250101T000000Z\r\nLAST-MODIFIED:20250101T000000Z\r\n",
                "SUMMARY:A\r\n",
            ),
        ] {
            assert!(is_same(a, b), "{a} != {b}");
            assert!(is_same(b, a), "{b} != {a}");
        }
    }

    #[test]
    fn calendar_address_value_types_are_equivalent() {
        let a = event("ORGANIZER;CN=Alice:mailto:a@example.org\r\n");
        let mut b = a.clone();
        for entry in b
            .components
            .iter_mut()
            .flat_map(|component| component.entries.iter_mut())
            .filter(|entry| entry.name == ICalendarProperty::Organizer)
        {
            entry.values = [ICalendarValue::Text("mailto:a@example.org".to_string())].into();
        }
        assert!(ComparisonScope::SharedData.component_eq(&a, 0, &b, 0));
    }

    #[test]
    fn real_changes_are_detected() {
        for (a, b) in [
            (
                "ATTENDEE;PARTSTAT=ACCEPTED:mailto:b@example.org\r\n",
                "ATTENDEE;PARTSTAT=DECLINED:mailto:b@example.org\r\n",
            ),
            (
                "ATTENDEE;ROLE=CHAIR:mailto:b@example.org\r\n",
                "ATTENDEE;ROLE=CHAIR;ROLE=CHAIR:mailto:b@example.org\r\n",
            ),
            (
                "DTSTART;VALUE=DATE:20240506\r\n",
                "DTSTART;TZID=Europe/Berlin:20240506T000000\r\n",
            ),
            (
                "X-FOO;VALUE=URI:https://example.com\r\n",
                "X-FOO:https://example.com\r\n",
            ),
            ("SUMMARY:A\r\nSUMMARY:A\r\n", "SUMMARY:A\r\n"),
            ("LOCATION:Room 1\r\n", ""),
        ] {
            assert!(!is_same(a, b), "{a} == {b}");
            assert!(!is_same(b, a), "{b} == {a}");
        }
    }

    #[test]
    fn redundant_overrides_require_equal_entries() {
        let override_of = |entries: &str| {
            ICalendar::parse(format!(
                concat!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\n",
                    "UID:abc\r\nDTSTART;TZID=Europe/Berlin:20240506T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20240506T093000\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\n",
                    "SUMMARY:Sync\r\nLOCATION:Room 1\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:abc\r\n",
                    "RECURRENCE-ID;TZID=Europe/Berlin:20240513T090000\r\n{}",
                    "END:VEVENT\r\nEND:VCALENDAR\r\n"
                ),
                entries
            ))
            .expect("valid iCalendar")
        };
        for (entries, is_redundant) in [
            (
                concat!(
                    "DTSTART;TZID=Europe/Berlin:20240513T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20240513T093000\r\n",
                    "LOCATION:Room 1\r\nSUMMARY:Sync\r\n",
                ),
                true,
            ),
            (
                concat!(
                    "DTSTART;TZID=Europe/Berlin:20240513T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20240513T093000\r\nSUMMARY:Sync\r\n",
                ),
                false,
            ),
            (
                concat!(
                    "DTSTART;TZID=Europe/Berlin:20240513T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20240513T100000\r\n",
                    "LOCATION:Room 1\r\nSUMMARY:Sync\r\n",
                ),
                false,
            ),
            (
                concat!(
                    "DTSTART;TZID=Europe/Berlin:20240513T100000\r\n",
                    "DTEND;TZID=Europe/Berlin:20240513T103000\r\n",
                    "LOCATION:Room 1\r\nSUMMARY:Sync\r\n",
                ),
                false,
            ),
            (
                concat!(
                    "DTSTART;TZID=Europe/Berlin:20240513T090000\r\n",
                    "DTEND;TZID=Europe/Berlin:20240513T093000\r\n",
                    "LOCATION:Room 1\r\nSUMMARY:Sync\r\nDESCRIPTION:Extra\r\n",
                ),
                false,
            ),
        ] {
            let ical = override_of(entries);
            assert_eq!(
                RedundantOverrides::new(&ical).unwrap().is_redundant(2),
                is_redundant,
                "{entries}"
            );
        }
    }

    fn series(overrides: &[(&str, &str)], alarms: usize) -> ICalendar {
        let mut text = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n");
        text.push_str(concat!(
            "BEGIN:VEVENT\r\nUID:abc\r\nDTSTAMP:20240101T000000Z\r\n",
            "DTSTART:20300601T090000Z\r\nDURATION:PT1H\r\nRRULE:FREQ=DAILY;COUNT=30\r\n",
            "SUMMARY:Series\r\n"
        ));
        for index in 0..alarms {
            text.push_str(&format!(
                concat!(
                    "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT{}M\r\n",
                    "DESCRIPTION:Alarm {}\r\nEND:VALARM\r\n"
                ),
                (index + 1) * 5,
                index
            ));
        }
        text.push_str("END:VEVENT\r\n");
        for (recurrence_id, summary) in overrides {
            text.push_str(&format!(
                concat!(
                    "BEGIN:VEVENT\r\nUID:abc\r\nDTSTAMP:20240101T000000Z\r\n",
                    "RECURRENCE-ID:{}\r\nDTSTART:{}\r\nDURATION:PT1H\r\nSUMMARY:{}\r\n",
                    "END:VEVENT\r\n"
                ),
                recurrence_id, recurrence_id, summary
            ));
        }
        text.push_str("END:VCALENDAR\r\n");
        ICalendar::parse(text).expect("valid iCalendar")
    }

    #[test]
    fn reordered_children_are_matched_by_recurrence_id() {
        let overrides = [
            ("20300602T090000Z", "Second"),
            ("20300603T090000Z", "Third"),
            ("20300604T090000Z", "Fourth"),
        ];
        let mut reversed = overrides;
        reversed.reverse();

        let (a, b) = (series(&overrides, 2), series(&reversed, 2));
        assert!(
            ComparisonScope::SharedData.component_eq(&a, 0, &b, 0),
            "{b}"
        );
        assert!(
            ComparisonScope::SharedData.component_eq(&b, 0, &a, 0),
            "{a}"
        );

        let changed = series(
            &[
                ("20300604T090000Z", "Fourth"),
                ("20300603T090000Z", "Changed"),
                ("20300602T090000Z", "Second"),
            ],
            2,
        );
        assert!(!ComparisonScope::SharedData.component_eq(&a, 0, &changed, 0));

        let moved = series(
            &[
                ("20300604T090000Z", "Fourth"),
                ("20300605T090000Z", "Third"),
                ("20300602T090000Z", "Second"),
            ],
            2,
        );
        assert!(!ComparisonScope::SharedData.component_eq(&a, 0, &moved, 0));
        assert!(!ComparisonScope::SharedData.component_eq(&a, 0, &series(&overrides, 1), 0));
    }
}
