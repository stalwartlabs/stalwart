/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS, EVENT_INVITE_SELF, compare::ComparisonScope,
    expand::ComponentRecurrenceId,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty, ICalendarValue,
    },
};

pub const SCHEDULING_EVENT_FLAGS: u16 =
    EVENT_INVITE_SELF | EVENT_INVITE_OTHERS | EVENT_HIDE_ATTENDEES;

pub trait ICalendarSequence {
    fn has_scheduling_changes(&self, previous: &ICalendar) -> bool;

    fn increment_sequence(&mut self, previous: &ICalendar);
}

impl ICalendarSequence for ICalendar {
    fn has_scheduling_changes(&self, previous: &ICalendar) -> bool {
        !ComparisonScope::SchedulingData.component_eq(self, 0, previous, 0)
            || PreviousSequences::new(previous).are_lowered_by(self)
    }

    fn increment_sequence(&mut self, previous: &ICalendar) {
        let previous = PreviousSequences::new(previous);
        for component in self
            .components
            .iter_mut()
            .filter(|component| component.component_type.is_scheduling_object())
        {
            let previous_sequence = previous.of(component);
            if component.sequence().unwrap_or_default() <= previous_sequence {
                component.set_sequence(previous_sequence + 1);
            }
        }
    }
}

struct PreviousSequences<'x> {
    series: Option<i64>,
    components: Vec<(&'x ICalendarComponentType, Option<i64>, Option<i64>)>,
}

impl<'x> PreviousSequences<'x> {
    fn new(ical: &'x ICalendar) -> Self {
        let components = ical
            .components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .map(|component| {
                (
                    &component.component_type,
                    component.recurrence_instant(),
                    component.sequence(),
                )
            })
            .collect::<Vec<_>>();
        PreviousSequences {
            series: ical
                .components
                .iter()
                .find(|component| {
                    component.component_type.is_scheduling_object()
                        && !component.is_recurrence_override()
                })
                .and_then(ComponentSequence::sequence),
            components,
        }
    }

    fn are_lowered_by(&self, ical: &ICalendar) -> bool {
        ical.components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .any(|component| component.sequence().unwrap_or_default() < self.of(component))
    }

    fn of(&self, component: &ICalendarComponent) -> i64 {
        let recurrence_instant = component.recurrence_instant();
        self.components
            .iter()
            .find(|(component_type, instant, _)| {
                **component_type == component.component_type && *instant == recurrence_instant
            })
            .map_or(self.series, |(_, _, sequence)| *sequence)
            .unwrap_or_default()
    }
}

trait ComponentSequence {
    fn sequence(&self) -> Option<i64>;

    fn set_sequence(&mut self, sequence: i64);

    fn recurrence_instant(&self) -> Option<i64>;
}

impl ComponentSequence for ICalendarComponent {
    fn sequence(&self) -> Option<i64> {
        self.property(&ICalendarProperty::Sequence)
            .and_then(|entry| entry.values.first())
            .and_then(ICalendarValue::as_integer)
    }

    fn recurrence_instant(&self) -> Option<i64> {
        self.recurrence_id(Tz::Floating).map(|id| id.utc)
    }

    fn set_sequence(&mut self, sequence: i64) {
        match self
            .entries
            .iter_mut()
            .find(|entry| entry.name == ICalendarProperty::Sequence)
        {
            Some(entry) => entry.values = vec![ICalendarValue::Integer(sequence)],
            None => self.add_sequence(sequence),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "DTSTAMP:20240101T000000Z\r\n",
        "DTSTART:20240101T100000Z\r\n",
        "DURATION:PT1H\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\n",
        "SEQUENCE:2\r\n",
        "SUMMARY:Standup\r\n",
        "COLOR:red\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "RECURRENCE-ID:20240102T100000Z\r\n",
        "DTSTART:20240102T110000Z\r\n",
        "DURATION:PT1H\r\n",
        "SEQUENCE:4\r\n",
        "SUMMARY:Standup moved\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn parse(ical: &str) -> ICalendar {
        ICalendar::parse(ical).expect("valid iCalendar")
    }

    #[test]
    fn per_user_and_volatile_changes_are_ignored() {
        let previous = parse(EVENT);
        let current = parse(
            &EVENT
                .replace(
                    "COLOR:red",
                    "COLOR:blue\r\nCATEGORIES:Work\r\nTRANSP:TRANSPARENT",
                )
                .replace(
                    "DTSTAMP:20240101T000000Z",
                    "DTSTAMP:20250101T000000Z\r\nLAST-MODIFIED:20250101T000000Z",
                )
                .replace("SEQUENCE:2", "SEQUENCE:9")
                .replacen(
                    "END:VEVENT",
                    "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT",
                    1,
                ),
        );
        assert!(!current.has_scheduling_changes(&previous));
        assert!(
            parse(&EVENT.replace("SUMMARY:Standup\r\n", "SUMMARY:Retro\r\n"))
                .has_scheduling_changes(&previous)
        );
    }

    #[test]
    fn lowered_sequence_is_a_change() {
        let previous = parse(EVENT);
        for lowered in [
            EVENT.replace("SEQUENCE:2", "SEQUENCE:0"),
            EVENT.replace("SEQUENCE:4", "SEQUENCE:1"),
        ] {
            let mut current = parse(&lowered);
            assert!(current.has_scheduling_changes(&previous), "{lowered}");
            current.increment_sequence(&previous);
            let text = current.to_string();
            assert!(text.contains("SEQUENCE:3"), "{text}");
            assert!(text.contains("SEQUENCE:5"), "{text}");
        }
    }

    #[test]
    fn overrides_are_matched_by_recurrence_instant() {
        let stored = concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:test\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "DTSTART;TZID=Europe/Berlin:20260601T090000\r\n",
            "DURATION:PT1H\r\n",
            "RRULE:FREQ=DAILY;COUNT=5\r\n",
            "SEQUENCE:2\r\n",
            "SUMMARY:Standup\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "RECURRENCE-ID:20260602T070000Z\r\n",
            "DTSTART;TZID=Europe/Berlin:20260602T100000\r\n",
            "DURATION:PT1H\r\n",
            "SEQUENCE:4\r\n",
            "SUMMARY:Standup moved\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        );
        let previous = parse(stored);
        let mut current = parse(
            &stored
                .replace(
                    "RECURRENCE-ID:20260602T070000Z",
                    "RECURRENCE-ID;TZID=Europe/Berlin:20260602T090000",
                )
                .replace(
                    "DTSTART;TZID=Europe/Berlin:20260602T100000",
                    "DTSTART;TZID=Europe/Berlin:20260602T110000",
                ),
        );
        assert!(current.has_scheduling_changes(&previous));
        current.increment_sequence(&previous);
        let text = current.to_string();
        assert!(text.contains("SEQUENCE:3"), "{text}");
        assert!(text.contains("SEQUENCE:5"), "{text}");
    }

    #[test]
    fn increments_each_component_unless_raised() {
        let previous = parse(EVENT);
        let mut current = parse(
            &EVENT
                .replace("SUMMARY:Standup\r\n", "SUMMARY:Retro\r\n")
                .replace("SEQUENCE:4", "SEQUENCE:7"),
        );
        current.increment_sequence(&previous);
        let text = current.to_string();
        assert!(text.contains("SEQUENCE:3"), "{text}");
        assert!(text.contains("SEQUENCE:7"), "{text}");
    }
}
