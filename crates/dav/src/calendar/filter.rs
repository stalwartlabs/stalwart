/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    query::{CalendarQueryHandler, EventTimeRange},
    view::{AlarmView, CalendarView, ChildIdView, ComponentView, EntryView, ParameterView},
};
use crate::common::{
    EventContent,
    search::{Candidates, IndexedText, QueryScope, TextIndex},
};
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
};
use common::storage::dav::MAX_CACHED_UID_LEN;
use dav_proto::schema::request::{
    CalendarPropFilter, CalendarPropMatch, CompFilter, CompFilterMatch, ParamFilter, Presence,
    PropValueMatch,
};
use groupware::calendar::{EVENT_HAS_ALARMS, EVENT_HAS_UNBOUNDED_TODO};
use store::search::{CalendarSearchField, SearchField};
use types::TimeRange;

pub(crate) trait CalendarFilterPlan {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates;
    fn time_ranges(&self) -> FilterTimeRanges;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FilterTimeRanges {
    pub range: Option<TimeRange>,
    pub has_alarms: bool,
}

const ALARM_EXPANSION_SLACK: i64 = 86_400;

trait AlarmReach {
    fn widen_for_alarms(&self, range: TimeRange) -> TimeRange;
}

trait PropFilterPlan {
    fn candidates(
        &self,
        component: &ICalendarComponentType,
        scope: &QueryScope<'_>,
        index: TextIndex<'_>,
    ) -> Candidates;
}

trait CalendarIndexField {
    fn search_field(&self) -> Option<(SearchField, IndexedText)>;
}

trait EntryFilter: EntryView {
    fn matches_prop(&self, test: &CalendarPropMatch, default_tz: Tz) -> bool;
    fn matches_param(&self, filter: &ParamFilter<ICalendarParameterName>) -> bool;
}

impl CalendarQueryHandler {
    pub fn matches_content(&self, content: &EventContent<'_>, filter: &CompFilter) -> bool {
        match content.view() {
            Some(view) => self.matches(view, filter),
            None => self.matches(content.stored(), filter),
        }
    }

    pub fn matches<V: CalendarView>(&self, event: &V, filter: &CompFilter) -> bool {
        match (&filter.test, event.components().first()) {
            (Presence::IsDefined(test), Some(root)) if root.component_type() == &filter.name => {
                self.component_matches(event, 0, root, test)
            }
            _ => false,
        }
    }

    fn component_matches<V: CalendarView>(
        &self,
        event: &V,
        comp_id: u32,
        component: &V::Component,
        test: &CompFilterMatch,
    ) -> bool {
        test.time_range
            .as_ref()
            .is_none_or(|range| self.component_in_range(event, comp_id, component, range))
            && test.prop_filters.iter().all(|filter| {
                let mut entries = component
                    .entries()
                    .iter()
                    .filter(|entry| entry.is_named(&filter.name))
                    .peekable();
                match &filter.test {
                    Presence::IsNotDefined => entries.peek().is_none(),
                    Presence::IsDefined(test) if entries.peek().is_some() => {
                        entries.any(|entry| entry.matches_prop(test, self.default_tz))
                    }
                    Presence::IsDefined(test) => {
                        test.param_filters.is_empty()
                            && matches!(&test.value, Some(PropValueMatch::TimeRange(range))
                            if component
                                .effective_end(&filter.name, self.default_tz)
                                .is_some_and(|timestamp| {
                                    range.start <= timestamp && range.end > timestamp
                                }))
                    }
                }
            })
            && test
                .comp_filters
                .iter()
                .all(|filter| self.child_filter_matches(event, component, filter))
    }

    fn child_filter_matches<V: CalendarView>(
        &self,
        event: &V,
        parent: &V::Component,
        filter: &CompFilter,
    ) -> bool {
        let components = event.components();
        let mut children = parent.child_ids().iter().filter_map(|child_id| {
            let child_id = child_id.child_id();
            components
                .get(child_id as usize)
                .filter(|child| child.component_type() == &filter.name)
                .map(|child| (child_id, child))
        });

        match &filter.test {
            Presence::IsNotDefined => children.next().is_none(),
            Presence::IsDefined(test) => children
                .any(|(child_id, child)| self.component_matches(event, child_id, child, test)),
        }
    }

    fn component_in_range<V: CalendarView>(
        &self,
        event: &V,
        comp_id: u32,
        component: &V::Component,
        range: &TimeRange,
    ) -> bool {
        if component.is_type(ICalendarComponentType::VAlarm) {
            let repetition = component.alarm_repetition();
            event
                .alarms()
                .iter()
                .filter(|alarm| alarm.id() == comp_id)
                .any(
                    |alarm| match alarm.delta().fixed_timestamp(self.default_tz) {
                        Some(timestamp) => repetition.triggers_in(timestamp, range),
                        None => self
                            .expansions_of(alarm.parent_id())
                            .iter()
                            .any(|expansion| {
                                alarm.timestamp(expansion, self.default_tz).is_some_and(
                                    |timestamp| repetition.triggers_in(timestamp, range),
                                )
                            }),
                    },
                )
        } else if component.is_type(ICalendarComponentType::VCalendar) {
            !self.undated_todos.is_empty()
                || self.expanded_times.iter().any(|expansion| {
                    range.is_in_range(expansion.flags.condition(), expansion.start, expansion.end)
                })
        } else {
            self.undated_todos.contains(&comp_id)
                || (self.dateless_events_match
                    && component.is_type(ICalendarComponentType::VEvent)
                    && !component
                        .entries()
                        .iter()
                        .any(|entry| entry.is_named(&ICalendarProperty::Dtstart)))
                || self.expansions_of(comp_id).iter().any(|expansion| {
                    range.is_in_range(expansion.flags.condition(), expansion.start, expansion.end)
                })
        }
    }
}

impl<E: EntryView> EntryFilter for E {
    fn matches_prop(&self, test: &CalendarPropMatch, default_tz: Tz) -> bool {
        test.value.as_ref().is_none_or(|value| match value {
            PropValueMatch::TimeRange(range) => self
                .date_time_timestamp(default_tz)
                .is_some_and(|timestamp| range.start <= timestamp && range.end > timestamp),
            PropValueMatch::Text(text_match) => text_match.is_match_any(self.text_values()),
        }) && test
            .param_filters
            .iter()
            .all(|filter| self.matches_param(filter))
    }

    fn matches_param(&self, filter: &ParamFilter<ICalendarParameterName>) -> bool {
        let mut params = self
            .params()
            .iter()
            .filter(|param| param.is_named(&filter.name))
            .peekable();
        match &filter.test {
            Presence::IsNotDefined => params.peek().is_none(),
            Presence::IsDefined(None) => params.peek().is_some(),
            Presence::IsDefined(Some(text_match)) => {
                params.peek().is_some()
                    && text_match.is_match_any(params.filter_map(|param| param.text()))
            }
        }
    }
}

impl CalendarFilterPlan for CompFilter {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates {
        let Presence::IsDefined(test) = &self.test else {
            return Candidates::All;
        };

        let time_range = test.time_range.as_ref().map(|range| match self.name {
            ICalendarComponentType::VEvent
            | ICalendarComponentType::VJournal
            | ICalendarComponentType::VFreebusy => {
                scope.matching(|resource| resource.resource.is_in_time_range(range))
            }
            ICalendarComponentType::VTodo | ICalendarComponentType::VCalendar => {
                scope.matching(|resource| {
                    resource.resource.is_in_time_range(range)
                        || resource
                            .event_flags()
                            .is_some_and(|flags| flags & EVENT_HAS_UNBOUNDED_TODO != 0)
                })
            }
            ICalendarComponentType::VAlarm => scope.matching(|resource| {
                resource
                    .event_flags()
                    .is_some_and(|flags| flags & EVENT_HAS_ALARMS != 0)
            }),
            _ => Candidates::All,
        });

        Candidates::and(
            time_range
                .into_iter()
                .chain(
                    test.prop_filters
                        .iter()
                        .map(|filter| filter.candidates(&self.name, scope, index)),
                )
                .chain(
                    test.comp_filters
                        .iter()
                        .map(|filter| filter.candidates(scope, index)),
                ),
        )
    }

    fn time_ranges(&self) -> FilterTimeRanges {
        let Presence::IsDefined(test) = &self.test else {
            return FilterTimeRanges::default();
        };
        test.comp_filters.iter().map(CompFilter::time_ranges).fold(
            FilterTimeRanges {
                range: test.time_range,
                has_alarms: test.time_range.is_some()
                    && self.name == ICalendarComponentType::VAlarm,
            },
            FilterTimeRanges::union,
        )
    }
}

impl FilterTimeRanges {
    pub fn union(self, other: FilterTimeRanges) -> Self {
        FilterTimeRanges {
            range: match (self.range, other.range) {
                (Some(range), Some(other)) => Some(range.union(other)),
                (range, other) => range.or(other),
            },
            has_alarms: self.has_alarms || other.has_alarms,
        }
    }

    pub fn expansion_range<V: CalendarView>(&self, event: &V) -> Option<TimeRange> {
        self.range.map(|range| {
            if self.has_alarms {
                event.widen_for_alarms(range)
            } else {
                range
            }
        })
    }
}

impl<V: CalendarView> AlarmReach for V {
    fn widen_for_alarms(&self, range: TimeRange) -> TimeRange {
        let components = self.components();
        let margin = self
            .alarms()
            .iter()
            .filter_map(|alarm| {
                let repetition = components
                    .get(alarm.id() as usize)
                    .map(ComponentView::alarm_repetition)
                    .unwrap_or_default();
                alarm
                    .trigger_offset()
                    .map(|offset| offset.saturating_add(repetition.span()))
            })
            .max()
            .unwrap_or_default()
            .saturating_add(ALARM_EXPANSION_SLACK);
        TimeRange {
            start: range.start.saturating_sub(margin),
            end: range.end.saturating_add(margin),
        }
    }
}

impl PropFilterPlan for CalendarPropFilter {
    fn candidates(
        &self,
        component: &ICalendarComponentType,
        scope: &QueryScope<'_>,
        index: TextIndex<'_>,
    ) -> Candidates {
        let Presence::IsDefined(CalendarPropMatch {
            value: Some(PropValueMatch::Text(text_match)),
            ..
        }) = &self.test
        else {
            return Candidates::All;
        };
        if text_match.negate {
            return Candidates::All;
        }

        match &self.name {
            ICalendarProperty::Uid
                if component.is_scheduling_object()
                    || *component == ICalendarComponentType::VAvailability =>
            {
                scope.matching(|resource| {
                    resource.uid().is_none_or(|uid| {
                        uid.is_empty()
                            || uid.len() >= MAX_CACHED_UID_LEN
                            || text_match.is_match(uid)
                    })
                })
            }
            name if component.is_scheduling_object() => match name.search_field() {
                Some((field, text)) => index.candidates(field, text, text_match),
                None => Candidates::All,
            },
            _ => Candidates::All,
        }
    }
}

impl CalendarIndexField for ICalendarProperty {
    fn search_field(&self) -> Option<(SearchField, IndexedText)> {
        let (field, text) = match self {
            ICalendarProperty::Summary => (CalendarSearchField::Title, IndexedText::Stemmed),
            ICalendarProperty::Description => {
                (CalendarSearchField::Description, IndexedText::Stemmed)
            }
            ICalendarProperty::Location => (CalendarSearchField::Location, IndexedText::Plain),
            ICalendarProperty::Organizer => (CalendarSearchField::Owner, IndexedText::Identifier),
            ICalendarProperty::Attendee => (CalendarSearchField::Attendee, IndexedText::Identifier),
            _ => return None,
        };
        Some((field.into(), text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::icalendar::ICalendar;
    use dav_proto::{
        parser::{DavParser, tokenizer::Tokenizer},
        schema::request::Report,
    };
    use groupware::calendar::{CalendarEventContent, CalendarEventData};

    const RECURRING_EVENT: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:test
BEGIN:VEVENT
UID:weekly
DTSTAMP:20240101T000000Z
DTSTART:20240110T100000Z
DTEND:20240110T110000Z
RRULE:FREQ=WEEKLY;COUNT=3
SUMMARY:Board meeting
LOCATION:HQ
ORGANIZER:mailto:jane@example.com
ATTENDEE;PARTSTAT=ACCEPTED:mailto:lisa@example.com
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.com
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Reminder
TRIGGER:-P7D
END:VALARM
END:VEVENT
BEGIN:VEVENT
UID:weekly
DTSTAMP:20240101T000000Z
RECURRENCE-ID:20240117T100000Z
DTSTART:20240117T100000Z
DTEND:20240117T110000Z
SUMMARY:Standup
LOCATION:Room 1
END:VEVENT
END:VCALENDAR
";

    const TODOS: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:test
BEGIN:VTODO
UID:todo
DTSTAMP:20240101T000000Z
DUE:20240120T100000Z
COMPLETED:20240105T120000Z
STATUS:COMPLETED
PRIORITY:1
SUMMARY:File taxes
END:VTODO
END:VCALENDAR
";

    const UNDATED_TODO: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:test
BEGIN:VTODO
UID:someday
DTSTAMP:20240101T000000Z
STATUS:NEEDS-ACTION
SUMMARY:Someday
END:VTODO
END:VCALENDAR
";

    const REPEATING_ALARM: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:test
BEGIN:VEVENT
UID:repeating-alarm
DTSTAMP:20240101T000000Z
DTSTART:20240110T100000Z
DTEND:20240110T110000Z
SUMMARY:Renewal
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Reminder
TRIGGER:-PT1H
REPEAT:3
DURATION:P2D
END:VALARM
END:VEVENT
END:VCALENDAR
";

    const REPLY: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:test
METHOD:REPLY
BEGIN:VEVENT
UID:reply
DTSTAMP:20240101T000000Z
ORGANIZER:mailto:jane@example.com
ATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.com
END:VEVENT
END:VCALENDAR
";

    fn parse_filter(filter: &str) -> CompFilter {
        let xml = format!(
            "<C:calendar-query xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><C:filter>{filter}</C:filter></C:calendar-query>"
        );
        match Report::parse(&mut Tokenizer::new(xml.as_bytes())) {
            Ok(Report::CalendarQuery(query)) => query.filter.expect("a filter"),
            other => panic!("unexpected parse result {other:?}"),
        }
    }

    fn matches_with(ical: &str, filter: &str, dateless_events_match: bool) -> bool {
        let filter = parse_filter(filter);
        let content = CalendarEventContent {
            data: CalendarEventData::new(
                ICalendar::parse(ical.replace('\n', "\r\n")).expect("valid iCalendar"),
                Tz::UTC,
                1000,
            ),
            ..Default::default()
        };
        let mut handler =
            CalendarQueryHandler::for_event_data(&content, filter.time_ranges(), Tz::UTC);
        handler.dateless_events_match = dateless_events_match;
        handler.matches(&content, &filter)
    }

    fn matches(ical: &str, filter: &str) -> bool {
        matches_with(ical, filter, false)
    }

    fn in_event(body: &str) -> String {
        format!(
            "<C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\">{body}</C:comp-filter></C:comp-filter>"
        )
    }

    fn in_todo(body: &str) -> String {
        format!(
            "<C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VTODO\">{body}</C:comp-filter></C:comp-filter>"
        )
    }

    #[test]
    fn text_and_parameters_match_the_same_property() {
        let attendee = |address: &str| {
            in_event(&format!(
                "<C:prop-filter name=\"ATTENDEE\"><C:text-match>{address}</C:text-match><C:param-filter name=\"PARTSTAT\"><C:text-match>NEEDS-ACTION</C:text-match></C:param-filter></C:prop-filter>"
            ))
        };
        assert!(!matches(
            RECURRING_EVENT,
            &attendee("mailto:lisa@example.com")
        ));
        assert!(matches(
            RECURRING_EVENT,
            &attendee("mailto:bob@example.com")
        ));
    }

    #[test]
    fn conditions_apply_to_a_single_component() {
        let filter = |summary: &str| {
            in_event(&format!(
                "<C:prop-filter name=\"SUMMARY\"><C:text-match>{summary}</C:text-match></C:prop-filter><C:prop-filter name=\"LOCATION\"><C:text-match>room</C:text-match></C:prop-filter>"
            ))
        };
        assert!(!matches(RECURRING_EVENT, &filter("board")));
        assert!(matches(RECURRING_EVENT, &filter("standup")));
    }

    #[test]
    fn time_ranges_apply_to_the_instances_of_the_matching_component() {
        let filter = |summary: &str| {
            in_event(&format!(
                "<C:time-range start=\"20240117T000000Z\" end=\"20240118T000000Z\"/><C:prop-filter name=\"SUMMARY\"><C:text-match>{summary}</C:text-match></C:prop-filter>"
            ))
        };
        assert!(!matches(RECURRING_EVENT, &filter("board")));
        assert!(matches(RECURRING_EVENT, &filter("standup")));
        assert!(matches(
            RECURRING_EVENT,
            &in_event("<C:time-range start=\"20240124T000000Z\" end=\"20240125T000000Z\"/>")
        ));
        assert!(!matches(
            RECURRING_EVENT,
            &in_event("<C:time-range start=\"20240201T000000Z\" end=\"20240301T000000Z\"/>")
        ));
    }

    #[test]
    fn alarm_time_ranges_look_beyond_the_query_window() {
        let alarm = |start: &str, end: &str| {
            in_event(&format!(
                "<C:comp-filter name=\"VALARM\"><C:time-range start=\"{start}\" end=\"{end}\"/></C:comp-filter>"
            ))
        };
        assert!(matches(
            RECURRING_EVENT,
            &alarm("20240103T000000Z", "20240104T000000Z")
        ));
        assert!(matches(
            RECURRING_EVENT,
            &alarm("20240117T000000Z", "20240118T000000Z")
        ));
        assert!(!matches(
            RECURRING_EVENT,
            &alarm("20240105T000000Z", "20240106T000000Z")
        ));
    }

    #[test]
    fn repeating_alarms_match_every_trigger() {
        let alarm = |start: &str, end: &str| {
            in_event(&format!(
                "<C:comp-filter name=\"VALARM\"><C:time-range start=\"{start}\" end=\"{end}\"/></C:comp-filter>"
            ))
        };
        for (start, end, expected) in [
            ("20240110T000000Z", "20240111T000000Z", true),
            ("20240114T000000Z", "20240115T000000Z", true),
            ("20240116T000000Z", "20240116T120000Z", true),
            ("20240116T090000Z", "20240116T090001Z", true),
            ("20240113T000000Z", "20240114T000000Z", false),
            ("20240115T000000Z", "20240116T090000Z", false),
            ("20240116T090001Z", "20240120T000000Z", false),
        ] {
            assert_eq!(
                matches(REPEATING_ALARM, &alarm(start, end)),
                expected,
                "{start} {end}"
            );
        }
    }

    #[test]
    fn property_tests_require_the_enclosing_component() {
        let filter =
            in_event("<C:prop-filter name=\"LOCATION\"><C:is-not-defined/></C:prop-filter>");
        assert!(!matches(TODOS, &filter));
        assert!(matches(
            TODOS,
            &in_todo("<C:prop-filter name=\"LOCATION\"><C:is-not-defined/></C:prop-filter>")
        ));
    }

    #[test]
    fn empty_filters_test_for_existence() {
        assert!(matches(
            RECURRING_EVENT,
            &in_event("<C:prop-filter name=\"LOCATION\"/>")
        ));
        assert!(!matches(
            RECURRING_EVENT,
            &in_event("<C:prop-filter name=\"GEO\"/>")
        ));
        assert!(matches(
            RECURRING_EVENT,
            &in_event(
                "<C:prop-filter name=\"ATTENDEE\"><C:param-filter name=\"PARTSTAT\"/></C:prop-filter>"
            )
        ));
        assert!(!matches(
            RECURRING_EVENT,
            &in_event(
                "<C:prop-filter name=\"ATTENDEE\"><C:param-filter name=\"DELEGATED-FROM\"/></C:prop-filter>"
            )
        ));
    }

    #[test]
    fn sibling_component_filters_are_all_required() {
        let filter = "<C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"/><C:comp-filter name=\"VTODO\"/></C:comp-filter>";
        assert!(!matches(RECURRING_EVENT, filter));
        assert!(!matches(TODOS, filter));
        assert!(matches(
            TODOS,
            "<C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"><C:is-not-defined/></C:comp-filter><C:comp-filter name=\"VTODO\"/></C:comp-filter>"
        ));
    }

    #[test]
    fn property_time_ranges_use_the_property_value() {
        let completed = |start: &str| {
            in_todo(&format!(
                "<C:prop-filter name=\"COMPLETED\"><C:time-range start=\"{start}\" end=\"20240106T000000Z\"/></C:prop-filter>"
            ))
        };
        assert!(matches(TODOS, &completed("20240105T000000Z")));
        assert!(!matches(TODOS, &completed("20240105T130000Z")));
    }

    #[test]
    fn negated_matches_and_undefined_properties() {
        let pending = in_todo(
            "<C:prop-filter name=\"COMPLETED\"><C:is-not-defined/></C:prop-filter><C:prop-filter name=\"STATUS\"><C:text-match negate-condition=\"yes\">CANCELLED</C:text-match></C:prop-filter>",
        );
        assert!(!matches(TODOS, &pending));
        assert!(matches(UNDATED_TODO, &pending));
    }

    #[test]
    fn text_matches_apply_to_non_text_values() {
        let priority = |text: &str, negate: &str| {
            in_todo(&format!(
                "<C:prop-filter name=\"PRIORITY\"><C:text-match negate-condition=\"{negate}\">{text}</C:text-match></C:prop-filter>"
            ))
        };
        assert!(matches(TODOS, &priority("1", "no")));
        assert!(!matches(TODOS, &priority("1", "yes")));
        assert!(matches(TODOS, &priority("2", "yes")));
        assert!(!matches(TODOS, &priority("2", "no")));
        assert!(matches(
            RECURRING_EVENT,
            &in_event(
                "<C:prop-filter name=\"RRULE\"><C:text-match>FREQ=WEEKLY</C:text-match></C:prop-filter>"
            )
        ));
        assert!(matches(
            RECURRING_EVENT,
            &in_event(
                "<C:prop-filter name=\"DTSTART\"><C:text-match>20240110T100000Z</C:text-match></C:prop-filter>"
            )
        ));
        assert!(!matches(
            RECURRING_EVENT,
            &in_event(
                "<C:prop-filter name=\"DTSTART\"><C:text-match negate-condition=\"yes\">20240110</C:text-match></C:prop-filter><C:prop-filter name=\"SUMMARY\"><C:text-match>board</C:text-match></C:prop-filter>"
            )
        ));
    }

    #[test]
    fn missing_end_properties_use_the_effective_value() {
        const DURATIONS: &str = "BEGIN:VCALENDAR
VERSION:2.0
PRODID:test
BEGIN:VEVENT
UID:effective-end
DTSTAMP:20240101T000000Z
DTSTART:20240110T100000Z
DURATION:PT2H
SUMMARY:Workshop
END:VEVENT
BEGIN:VTODO
UID:effective-due
DTSTAMP:20240101T000000Z
DTSTART:20240112T080000Z
DURATION:P1D
SUMMARY:Review
END:VTODO
END:VCALENDAR
";
        let end = |component: &str, property: &str, start: &str, end: &str| {
            format!(
                "<C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"{component}\"><C:prop-filter name=\"{property}\"><C:time-range start=\"{start}\" end=\"{end}\"/></C:prop-filter></C:comp-filter></C:comp-filter>"
            )
        };
        assert!(matches(
            DURATIONS,
            &end("VEVENT", "DTEND", "20240110T113000Z", "20240110T123000Z")
        ));
        assert!(!matches(
            DURATIONS,
            &end("VEVENT", "DTEND", "20240110T090000Z", "20240110T113000Z")
        ));
        assert!(matches(
            DURATIONS,
            &end("VTODO", "DUE", "20240113T000000Z", "20240114T000000Z")
        ));
        assert!(!matches(
            DURATIONS,
            &end("VTODO", "DTEND", "20240113T000000Z", "20240114T000000Z")
        ));
        assert!(matches(
            DURATIONS,
            "<C:comp-filter name=\"VCALENDAR\"><C:comp-filter name=\"VEVENT\"><C:prop-filter name=\"DTEND\"><C:is-not-defined/></C:prop-filter></C:comp-filter></C:comp-filter>"
        ));
    }

    #[test]
    fn undated_todos_match_any_time_range() {
        let filter = in_todo("<C:time-range start=\"20300101T000000Z\" end=\"20300102T000000Z\"/>");
        assert!(matches(UNDATED_TODO, &filter));
        assert!(!matches(TODOS, &filter));
    }

    #[test]
    fn dateless_events_match_time_ranges_in_the_scheduling_inbox() {
        let filter =
            in_event("<C:time-range start=\"20240101T000000Z\" end=\"20240102T000000Z\"/>");
        assert!(matches_with(REPLY, &filter, true));
        assert!(!matches_with(REPLY, &filter, false));
    }

    #[test]
    fn the_calendar_object_always_exists() {
        assert!(!matches(
            RECURRING_EVENT,
            "<C:comp-filter name=\"VCALENDAR\"><C:is-not-defined/></C:comp-filter>"
        ));
        assert!(matches(
            RECURRING_EVENT,
            "<C:comp-filter name=\"VCALENDAR\"/>"
        ));
    }
}
