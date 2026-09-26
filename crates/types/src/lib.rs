/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod blob;
pub mod blob_hash;
pub mod collection;
pub mod dead_property;
pub mod field;
pub mod id;
pub mod keyword;
pub mod media_type;
pub mod semver;
pub mod special_use;
pub mod text;
pub mod type_state;

pub type DocumentId = u32;
pub type ChangeId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeRange {
    pub start: i64,
    pub end: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapRule {
    CalDav,
    Jmap,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OverlapCondition {
    #[default]
    Event,
    TodoStartDuration,
    TodoStartDue,
    TodoStart,
    TodoDue,
    TodoCreatedCompleted,
    TodoCompleted,
    TodoCreated,
}

impl OverlapCondition {
    pub const ALL: [OverlapCondition; 8] = [
        OverlapCondition::Event,
        OverlapCondition::TodoStartDuration,
        OverlapCondition::TodoStartDue,
        OverlapCondition::TodoStart,
        OverlapCondition::TodoDue,
        OverlapCondition::TodoCreatedCompleted,
        OverlapCondition::TodoCompleted,
        OverlapCondition::TodoCreated,
    ];

    pub fn for_instance(self, start: i64, end: i64) -> Self {
        match self {
            OverlapCondition::TodoStart if start != end => OverlapCondition::TodoStartDuration,
            condition => condition,
        }
    }
}

impl TimeRange {
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    pub fn is_in_range(&self, condition: OverlapCondition, start: i64, end: i64) -> bool {
        match condition {
            OverlapCondition::Event if start == end => self.start <= start && self.end > start,
            // RFC4791#9.9: (start <  DTEND AND end > DTSTART)
            OverlapCondition::Event => self.start < end && self.end > start,
            OverlapCondition::TodoStartDuration => {
                self.start <= end && (self.end > start || self.end >= end)
            }
            // RFC4791#9.9: ((start <  DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE))
            OverlapCondition::TodoStartDue => {
                (self.start < end || self.start <= start) && (self.end > start || self.end >= end)
            }
            OverlapCondition::TodoStart => self.start <= start && self.end > start,
            OverlapCondition::TodoDue => self.start < start && self.end >= start,
            OverlapCondition::TodoCreatedCompleted => {
                (self.start <= start || self.start <= end) && (self.end >= start || self.end >= end)
            }
            OverlapCondition::TodoCompleted => self.start <= start && self.end >= start,
            OverlapCondition::TodoCreated => self.end > start,
        }
    }

    pub fn overlaps(&self, start: i64, end: i64) -> bool {
        self.start < end && self.end > start
    }

    pub fn union(self, other: TimeRange) -> Self {
        TimeRange {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    pub fn touches(&self, start: i64, end: i64) -> bool {
        self.start <= end && self.end >= start
    }

    pub fn matches(
        &self,
        rule: OverlapRule,
        condition: OverlapCondition,
        start: i64,
        end: i64,
    ) -> bool {
        match rule {
            OverlapRule::CalDav => self.is_in_range(condition, start, end),
            OverlapRule::Jmap => self.overlaps(start, end),
        }
    }
}

impl Default for TimeRange {
    fn default() -> Self {
        Self {
            start: i64::MIN,
            end: i64::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OverlapCondition, OverlapRule, TimeRange};

    const RANGE: TimeRange = TimeRange {
        start: 100,
        end: 200,
    };

    fn assert_condition(condition: OverlapCondition, rule: &str, cases: &[(i64, i64, bool)]) {
        for &(start, end, expected) in cases {
            assert_eq!(
                RANGE.is_in_range(condition, start, end),
                expected,
                "RFC 4791 Section 9.9 {rule}: instance {start}..{end} against the time range 100..200 ({condition:?})"
            );
        }
    }

    #[test]
    fn rfc4791_9_9_zero_length_events_are_points() {
        assert_condition(
            OverlapCondition::Event,
            "(start <= DTSTART AND end > DTSTART)",
            &[
                (99, 99, false),
                (100, 100, true),
                (150, 150, true),
                (199, 199, true),
                (200, 200, false),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_events_with_a_length_overlap_the_range() {
        assert_condition(
            OverlapCondition::Event,
            "(start < DTEND AND end > DTSTART)",
            &[
                (50, 100, false),
                (50, 101, true),
                (150, 160, true),
                (199, 250, true),
                (200, 250, false),
                (50, 250, true),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_dtstart_and_duration() {
        assert_condition(
            OverlapCondition::TodoStartDuration,
            "(start <= DTSTART+DURATION) AND ((end > DTSTART) OR (end >= DTSTART+DURATION))",
            &[
                (40, 99, false),
                (40, 100, true),
                (100, 100, true),
                (150, 160, true),
                (199, 250, true),
                (200, 200, true),
                (200, 250, false),
                (201, 201, false),
                (40, 250, true),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_dtstart_and_due() {
        assert_condition(
            OverlapCondition::TodoStartDue,
            "((start < DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE))",
            &[
                (40, 100, false),
                (40, 101, true),
                (99, 99, false),
                (100, 100, true),
                (199, 250, true),
                (200, 200, true),
                (200, 250, false),
                (40, 250, true),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_dtstart_only() {
        assert_condition(
            OverlapCondition::TodoStart,
            "(start <= DTSTART) AND (end > DTSTART)",
            &[
                (99, 99, false),
                (100, 100, true),
                (199, 199, true),
                (200, 200, false),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_due_only() {
        assert_condition(
            OverlapCondition::TodoDue,
            "(start < DUE) AND (end >= DUE)",
            &[
                (100, 100, false),
                (101, 101, true),
                (200, 200, true),
                (201, 201, false),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_completed_and_created() {
        assert_condition(
            OverlapCondition::TodoCreatedCompleted,
            "((start <= CREATED) OR (start <= COMPLETED)) AND ((end >= CREATED) OR (end >= COMPLETED))",
            &[
                (40, 99, false),
                (40, 100, true),
                (150, 160, true),
                (160, 150, true),
                (200, 250, true),
                (201, 250, false),
                (40, 250, true),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_completed_only() {
        assert_condition(
            OverlapCondition::TodoCompleted,
            "(start <= COMPLETED) AND (end >= COMPLETED)",
            &[
                (99, 99, false),
                (100, 100, true),
                (200, 200, true),
                (201, 201, false),
            ],
        );
    }

    #[test]
    fn rfc4791_9_9_todo_with_created_only() {
        assert_condition(
            OverlapCondition::TodoCreated,
            "(end > CREATED)",
            &[
                (i64::MIN, i64::MIN, true),
                (40, 40, true),
                (199, 199, true),
                (200, 200, false),
                (250, 250, false),
            ],
        );
    }

    #[test]
    fn a_todo_with_only_dtstart_and_a_period_has_an_effective_duration() {
        assert_eq!(
            OverlapCondition::TodoStart.for_instance(100, 100),
            OverlapCondition::TodoStart
        );
        assert_eq!(
            OverlapCondition::TodoStart.for_instance(40, 100),
            OverlapCondition::TodoStartDuration,
            "RFC 4791 Section 9.9: the server infers an effective DURATION for an instance from the recurrence pattern"
        );
        for condition in OverlapCondition::ALL
            .into_iter()
            .filter(|condition| *condition != OverlapCondition::TodoStart)
        {
            assert_eq!(condition.for_instance(40, 100), condition);
        }
    }

    #[test]
    fn the_closed_hull_of_an_instance_admits_every_bounded_match() {
        let instants = [40, 99, 100, 101, 150, 199, 200, 201, 250];
        for condition in OverlapCondition::ALL
            .into_iter()
            .filter(|condition| *condition != OverlapCondition::TodoCreated)
        {
            for (start, end) in instants
                .iter()
                .flat_map(|start| instants.iter().map(move |end| (*start, *end)))
            {
                for range in instants.iter().flat_map(|range_start| {
                    instants
                        .iter()
                        .filter(move |range_end| *range_end > range_start)
                        .map(move |range_end| TimeRange::new(*range_start, *range_end))
                }) {
                    assert!(
                        !range.is_in_range(condition, start, end)
                            || range.touches(start.min(end), start.max(end)),
                        "{condition:?} instance {start}..{end} matches {range:?} outside its closed hull"
                    );
                }
            }
        }
        assert!(
            RANGE.is_in_range(OverlapCondition::TodoCreated, 40, 40) && !RANGE.touches(40, 40),
            "RFC 4791 Section 9.9: (end > CREATED) has no lower bound"
        );
    }

    #[test]
    fn jmap_calendars_events_finish_after_the_start_and_start_before_the_end() {
        for (start, end, expected) in [
            (100, 100, false),
            (150, 150, true),
            (200, 200, false),
            (50, 100, false),
            (50, 101, true),
            (199, 250, true),
            (200, 250, false),
        ] {
            for condition in OverlapCondition::ALL {
                assert_eq!(
                    RANGE.matches(OverlapRule::Jmap, condition, start, end),
                    expected,
                    "draft-ietf-jmap-calendars-29 Section 2.2: {start}..{end}, {condition:?}"
                );
            }
        }
        assert!(RANGE.matches(OverlapRule::CalDav, OverlapCondition::Event, 100, 100));
        assert!(!RANGE.matches(OverlapRule::CalDav, OverlapCondition::TodoDue, 100, 100));
    }
}
