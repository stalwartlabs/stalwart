/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedCalendarEventData, CalendarEventData};
use calcard::icalendar::{
    ArchivedICalendarEntry, ArchivedICalendarProperty, ArchivedICalendarValue, ICalendar,
    ICalendarEntry, ICalendarProperty, ICalendarValue,
};
use types::OverlapCondition;

pub trait ICalendarOverlap {
    fn overlap_condition(&self, comp_id: u32) -> OverlapCondition;
}

#[derive(Debug, Default, Clone, Copy)]
struct TodoDates {
    start: bool,
    recurrence_id: bool,
    end: bool,
    duration: bool,
    due: bool,
    completed: bool,
    created: bool,
}

trait TodoDateEntry {
    fn add_to(&self, dates: &mut TodoDates);
}

impl ICalendarOverlap for ICalendar {
    fn overlap_condition(&self, comp_id: u32) -> OverlapCondition {
        let Some(component) = self
            .component_by_id(comp_id)
            .filter(|component| component.component_type.is_todo())
        else {
            return OverlapCondition::Event;
        };
        let dates = TodoDates::of(&component.entries);
        dates
            .inherits_length()
            .then(|| {
                let uid = component.uid();
                self.components.iter().find(|series| {
                    series.component_type == component.component_type
                        && series.uid() == uid
                        && !series.is_recurrence_override()
                        && series.entries.iter().any(|entry| {
                            matches!(
                                entry.name,
                                ICalendarProperty::Rrule
                                    | ICalendarProperty::Rdate
                                    | ICalendarProperty::Exdate
                            )
                        })
                })
            })
            .flatten()
            .and_then(|series| TodoDates::of(&series.entries).condition())
            .or_else(|| dates.condition())
            .unwrap_or_default()
    }
}

impl CalendarEventData {
    pub fn has_unbounded_todo(&self) -> bool {
        self.event.components.iter().any(|component| {
            component.component_type.is_todo() && TodoDates::of(&component.entries).is_unbounded()
        })
    }

    pub fn undated_todos(&self) -> impl Iterator<Item = u32> + '_ {
        self.event
            .components
            .iter()
            .zip(0u32..)
            .filter(|(component, _)| {
                component.component_type.is_todo()
                    && TodoDates::of(&component.entries).condition().is_none()
            })
            .map(|(_, comp_id)| comp_id)
    }
}

impl ArchivedCalendarEventData {
    pub fn undated_todos(&self) -> impl Iterator<Item = u32> + '_ {
        self.event
            .components
            .iter()
            .zip(0u32..)
            .filter(|(component, _)| {
                component.component_type.is_todo()
                    && TodoDates::of(component.entries.iter())
                        .condition()
                        .is_none()
            })
            .map(|(_, comp_id)| comp_id)
    }
}

impl TodoDates {
    fn of<'x, E: TodoDateEntry + 'x>(entries: impl IntoIterator<Item = &'x E>) -> Self {
        let mut dates = TodoDates::default();
        for entry in entries {
            entry.add_to(&mut dates);
        }
        dates
    }

    fn is_unbounded(self) -> bool {
        matches!(self.condition(), None | Some(OverlapCondition::TodoCreated))
    }

    fn inherits_length(self) -> bool {
        self.recurrence_id && !(self.start || self.end || self.duration || self.due)
    }

    fn condition(self) -> Option<OverlapCondition> {
        match (
            self.start || self.recurrence_id,
            self.duration,
            self.due,
            self.completed,
            self.created,
        ) {
            (true, true, _, _, _) => Some(OverlapCondition::TodoStartDuration),
            (true, false, true, _, _) => Some(OverlapCondition::TodoStartDue),
            (true, false, false, _, _) => Some(OverlapCondition::TodoStart),
            (false, _, true, _, _) => Some(OverlapCondition::TodoDue),
            (false, _, false, true, true) => Some(OverlapCondition::TodoCreatedCompleted),
            (false, _, false, true, false) => Some(OverlapCondition::TodoCompleted),
            (false, _, false, false, true) => Some(OverlapCondition::TodoCreated),
            (false, _, false, false, false) => None,
        }
    }
}

impl TodoDateEntry for ICalendarEntry {
    fn add_to(&self, dates: &mut TodoDates) {
        let is_date_time = || {
            matches!(
                self.values.first(),
                Some(ICalendarValue::PartialDateTime(value)) if value.to_date_time().is_some()
            )
        };
        match self.name {
            ICalendarProperty::Dtstart => dates.start |= is_date_time(),
            ICalendarProperty::RecurrenceId => dates.recurrence_id |= is_date_time(),
            ICalendarProperty::Dtend => dates.end |= is_date_time(),
            ICalendarProperty::Due => dates.due |= is_date_time(),
            ICalendarProperty::Completed => dates.completed |= is_date_time(),
            ICalendarProperty::Created => dates.created |= is_date_time(),
            ICalendarProperty::Duration => {
                dates.duration |= matches!(self.values.first(), Some(ICalendarValue::Duration(_)));
            }
            _ => {}
        }
    }
}

impl TodoDateEntry for ArchivedICalendarEntry {
    fn add_to(&self, dates: &mut TodoDates) {
        let is_date_time = || {
            matches!(
                self.values.first(),
                Some(ArchivedICalendarValue::PartialDateTime(value)) if value.to_date_time().is_some()
            )
        };
        match self.name {
            ArchivedICalendarProperty::Dtstart => dates.start |= is_date_time(),
            ArchivedICalendarProperty::RecurrenceId => dates.recurrence_id |= is_date_time(),
            ArchivedICalendarProperty::Dtend => dates.end |= is_date_time(),
            ArchivedICalendarProperty::Due => dates.due |= is_date_time(),
            ArchivedICalendarProperty::Completed => dates.completed |= is_date_time(),
            ArchivedICalendarProperty::Created => dates.created |= is_date_time(),
            ArchivedICalendarProperty::Duration => {
                dates.duration |= matches!(
                    self.values.first(),
                    Some(ArchivedICalendarValue::Duration(_))
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::{
        ArchivedCalendarEventData, CalendarEventData,
        expand::{NaiveTimestamp, RangeFlags},
    };
    use calcard::common::timezone::Tz;
    use jiff::civil::DateTime;
    use types::{OverlapRule, TimeRange};

    fn event_data(components: &str) -> CalendarEventData {
        CalendarEventData::new(
            ICalendar::parse(format!("BEGIN:VCALENDAR\r\n{components}END:VCALENDAR\r\n"))
                .expect("valid iCalendar"),
            Tz::UTC,
            100,
        )
    }

    fn todo(properties: &str) -> String {
        format!("BEGIN:VTODO\r\nUID:todo\r\n{properties}END:VTODO\r\n")
    }

    fn conditions(data: &CalendarEventData, comp_id: u16) -> Vec<OverlapCondition> {
        data.time_ranges
            .iter()
            .filter(|range| range.id == comp_id)
            .map(|range| RangeFlags::from_bits(range.flags).condition())
            .collect()
    }

    fn undated_todos(data: &CalendarEventData) -> Vec<u32> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(data).expect("archive");
        rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&bytes)
            .expect("access")
            .undated_todos()
            .collect()
    }

    #[test]
    fn rfc4791_9_9_each_todo_state_selects_its_condition() {
        for (properties, expected) in [
            (
                "DTSTART:20250106T090000Z\r\nDURATION:PT1H\r\n",
                Some(OverlapCondition::TodoStartDuration),
            ),
            (
                "DTSTART:20250106T090000Z\r\nDURATION:PT0S\r\n",
                Some(OverlapCondition::TodoStartDuration),
            ),
            (
                "DTSTART:20250106T090000Z\r\nDUE:20250106T170000Z\r\n",
                Some(OverlapCondition::TodoStartDue),
            ),
            (
                "DTSTART:20250106T090000Z\r\n",
                Some(OverlapCondition::TodoStart),
            ),
            (
                "DTSTART;VALUE=DATE:20250106\r\n",
                Some(OverlapCondition::TodoStart),
            ),
            (
                "DTSTART:20250106T090000Z\r\nCOMPLETED:20250107T090000Z\r\nCREATED:20250101T090000Z\r\n",
                Some(OverlapCondition::TodoStart),
            ),
            ("DUE:20250106T170000Z\r\n", Some(OverlapCondition::TodoDue)),
            (
                "DUE:20250106T170000Z\r\nCOMPLETED:20250107T090000Z\r\nCREATED:20250101T090000Z\r\n",
                Some(OverlapCondition::TodoDue),
            ),
            (
                "COMPLETED:20250107T090000Z\r\nCREATED:20250101T090000Z\r\n",
                Some(OverlapCondition::TodoCreatedCompleted),
            ),
            (
                "COMPLETED:20250107T090000Z\r\n",
                Some(OverlapCondition::TodoCompleted),
            ),
            (
                "CREATED:20250101T090000Z\r\n",
                Some(OverlapCondition::TodoCreated),
            ),
            ("SUMMARY:Someday\r\n", None),
            ("DURATION:PT1H\r\nSUMMARY:Someday\r\n", None),
        ] {
            let data = event_data(&todo(properties));
            assert_eq!(
                conditions(&data, 1),
                expected.into_iter().collect::<Vec<_>>(),
                "RFC 4791 Section 9.9: the condition depends on the presence of DTSTART, DURATION, DUE, COMPLETED and CREATED\n{properties}"
            );
            assert_eq!(
                undated_todos(&data),
                if expected.is_none() { &[1][..] } else { &[] },
                "RFC 4791 Section 9.9: a VTODO without any of them always overlaps\n{properties}"
            );
        }

        let data = event_data(
            "BEGIN:VEVENT\r\nUID:event\r\nDTSTART:20250106T090000Z\r\nDURATION:PT1H\r\nEND:VEVENT\r\n",
        );
        assert_eq!(conditions(&data, 1), [OverlapCondition::Event]);
        assert!(undated_todos(&data).is_empty());
    }

    #[test]
    fn rfc4791_9_9_overrides_are_classified_by_their_effective_properties() {
        let series = todo(
            "DTSTART:20250106T090000Z\r\nDUE:20250106T170000Z\r\nRRULE:FREQ=DAILY;COUNT=5\r\n",
        );
        for (occurrence, expected) in [
            (
                "RECURRENCE-ID:20250107T090000Z\r\nSUMMARY:Renamed\r\n",
                OverlapCondition::TodoStartDue,
            ),
            (
                "RECURRENCE-ID:20250107T090000Z\r\nDTSTART:20250107T100000Z\r\n",
                OverlapCondition::TodoStart,
            ),
            (
                "RECURRENCE-ID:20250107T090000Z\r\nDUE:20250107T180000Z\r\n",
                OverlapCondition::TodoStartDue,
            ),
            (
                "RECURRENCE-ID:20250107T090000Z\r\nDURATION:PT2H\r\n",
                OverlapCondition::TodoStartDuration,
            ),
        ] {
            let data = event_data(&format!("{series}{}", todo(occurrence)));
            assert_eq!(
                conditions(&data, 1),
                [OverlapCondition::TodoStartDue],
                "{occurrence}"
            );
            assert_eq!(
                conditions(&data, 2),
                [expected],
                "RFC 4791 Section 9.9: the server infers the effective DTSTART, DURATION and DUE of an instance from the recurrence pattern and its overrides\n{occurrence}"
            );
        }

        let data = event_data(&format!(
            "{}{}",
            todo("DUE:20250106T170000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n"),
            todo("RECURRENCE-ID:20250107T170000Z\r\nSUMMARY:Renamed\r\n")
        ));
        assert_eq!(conditions(&data, 2), [OverlapCondition::TodoDue]);

        let data = event_data(&format!(
            "{}{}",
            todo("DTSTART:20250106T090000Z\r\nDUE:20250106T170000Z\r\n"),
            todo("RECURRENCE-ID:20250106T090000Z\r\nSUMMARY:Renamed\r\n")
        ));
        assert_eq!(
            conditions(&data, 2),
            [OverlapCondition::TodoStart],
            "an override of a component that does not recur has no series length to inherit"
        );
    }

    #[test]
    fn a_period_gives_a_todo_with_only_dtstart_an_effective_duration() {
        let data = event_data(&todo(
            "DTSTART:20250106T090000Z\r\nRDATE;VALUE=PERIOD:20250108T090000Z/PT3H\r\n",
        ));
        let found = conditions(&data, 1);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found.contains(&OverlapCondition::TodoStart)
                && found.contains(&OverlapCondition::TodoStartDuration),
            "RFC 5545 Section 3.8.5.2: the PERIOD sets the length of its instance\n{found:?}"
        );
    }

    #[test]
    fn todos_without_a_bounded_condition_are_flagged() {
        for (components, expected) in [
            (todo("CREATED:20250101T090000Z\r\n"), true),
            (todo("SUMMARY:Someday\r\n"), true),
            (todo("DUE:20250106T170000Z\r\n"), false),
            (
                todo("COMPLETED:20250107T090000Z\r\nCREATED:20250101T090000Z\r\n"),
                false,
            ),
            (
                "BEGIN:VEVENT\r\nUID:event\r\nDTSTART:20250106T090000Z\r\nEND:VEVENT\r\n"
                    .to_string(),
                false,
            ),
        ] {
            assert_eq!(
                event_data(&components).has_unbounded_todo(),
                expected,
                "RFC 4791 Section 9.9: (end > CREATED) and TRUE have no lower bound\n{components}"
            );
        }
    }

    #[test]
    fn rfc4791_9_9_caldav_uses_the_todo_conditions_and_jmap_the_overlap() {
        let utc = |hour: i8| {
            DateTime::new(2025, 1, 6, hour, 0, 0, 0)
                .expect("valid date")
                .naive_timestamp()
        };
        let range = TimeRange::new(utc(9), utc(10));
        for (component, caldav) in [
            (todo("DUE:20250106T090000Z\r\n"), false),
            (todo("DUE:20250106T100000Z\r\n"), true),
            (todo("COMPLETED:20250106T100000Z\r\n"), true),
            (todo("CREATED:20240101T000000Z\r\n"), true),
            (
                todo("DTSTART:20250106T080000Z\r\nDURATION:PT1H\r\n"),
                true,
            ),
            (
                todo("DTSTART:20250106T080000Z\r\nDUE:20250106T090000Z\r\n"),
                false,
            ),
            (todo("DTSTART:20250106T100000Z\r\n"), false),
            (
                "BEGIN:VEVENT\r\nUID:event\r\nDTSTART:20250106T080000Z\r\nDURATION:PT1H\r\nEND:VEVENT\r\n"
                    .to_string(),
                false,
            ),
            (
                "BEGIN:VEVENT\r\nUID:event\r\nDTSTART:20250106T090000Z\r\nEND:VEVENT\r\n"
                    .to_string(),
                true,
            ),
        ] {
            let bytes =
                rkyv::to_bytes::<rkyv::rancor::Error>(&event_data(&component)).expect("archive");
            let archived = rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&bytes)
                .expect("access");
            for (rule, expected) in [(OverlapRule::CalDav, caldav), (OverlapRule::Jmap, false)] {
                assert_eq!(
                    !archived
                        .expand(Tz::UTC, range, rule)
                        .expect("expansion")
                        .is_empty(),
                    expected,
                    "RFC 4791 Section 9.9 and draft-ietf-jmap-calendars-29 Section 2.2 ({rule:?}): {component}"
                );
            }
        }
    }
}
