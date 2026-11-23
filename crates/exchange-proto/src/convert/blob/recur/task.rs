/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{common::timezone::Tz, datecalc::RRule, icalendar::ICalendarRecurrenceRule};
use jiff::civil::{Date, DateTime, Time};

use super::{
    RecurrencePattern,
    rrule::{RuleCount, UntilForm, is_representable, local_from_minutes, whole_minutes},
};
use crate::convert::BlobLimits;

const ALIGN_SCAN: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecur(RecurrencePattern);

#[derive(Debug, Clone, Copy)]
pub enum TaskAnchor {
    Date(Date),
    Local { start: DateTime, tz: Tz },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRecurError {
    Unmappable,
    Sliding,
    Invalid,
}

impl TaskRecur {
    pub fn decode(blob: &[u8], limits: &BlobLimits) -> Result<Self, TaskRecurError> {
        let pattern =
            RecurrencePattern::decode(blob, limits).map_err(|_| TaskRecurError::Invalid)?;
        if pattern.sliding_flag != 0 {
            Err(TaskRecurError::Sliding)
        } else if !pattern.deleted_instances.is_empty() || !pattern.modified_instances.is_empty() {
            Err(TaskRecurError::Invalid)
        } else if pattern.rrule(UntilForm::Date).is_none() {
            Err(TaskRecurError::Unmappable)
        } else {
            Ok(TaskRecur(pattern))
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }

    pub fn from_rrule(
        rule: &ICalendarRecurrenceRule,
        anchor: TaskAnchor,
    ) -> Result<Self, TaskRecurError> {
        Self::mapped(rule, anchor, RuleCount::Dtstart)
    }

    pub fn from_client_rrule(
        rule: &ICalendarRecurrenceRule,
        anchor: TaskAnchor,
    ) -> Result<Self, TaskRecurError> {
        Self::mapped(rule, anchor, RuleCount::Pattern)
    }

    fn mapped(
        rule: &ICalendarRecurrenceRule,
        anchor: TaskAnchor,
        count: RuleCount,
    ) -> Result<Self, TaskRecurError> {
        let (start, tz, is_date) = anchor.frame();
        if let Ok(pattern) = RecurrencePattern::from_rrule(rule, start, tz, count) {
            return Ok(TaskRecur(pattern));
        }
        if !is_representable(rule) {
            return Err(TaskRecurError::Unmappable);
        }
        let mut uncounted = rule.clone();
        uncounted.count = None;
        if RecurrencePattern::from_rrule(&uncounted, start, tz, RuleCount::Pattern).is_ok() {
            return Err(TaskRecurError::Unmappable);
        }
        let origin = tz.from_local(start).ok_or(TaskRecurError::Unmappable)?;
        let expanded = RRule::from_ical(&uncounted, origin, is_date)
            .map_err(|_| TaskRecurError::Unmappable)?;
        let realigned = match count {
            RuleCount::Dtstart | RuleCount::Realigned => RuleCount::Realigned,
            RuleCount::Pattern => RuleCount::Pattern,
        };
        expanded
            .iter()
            .take(ALIGN_SCAN)
            .map(|instance| whole_minutes(instance.naive_local()))
            .find(|occurrence| *occurrence > start)
            .and_then(|occurrence| {
                RecurrencePattern::from_rrule(rule, occurrence, tz, realigned).ok()
            })
            .map(TaskRecur)
            .ok_or(TaskRecurError::Unmappable)
    }

    pub fn to_rrule(&self, anchor: TaskAnchor) -> Result<ICalendarRecurrenceRule, TaskRecurError> {
        let until = match anchor {
            TaskAnchor::Date(_) => UntilForm::Date,
            TaskAnchor::Local { start, tz } => UntilForm::Local {
                time: Some(start.time()),
                tz,
            },
        };
        let mut rule = self.0.rrule(until).ok_or(TaskRecurError::Unmappable)?;
        anchor.count_start(&mut rule);
        Ok(rule)
    }

    pub fn pattern(&self) -> &RecurrencePattern {
        &self.0
    }
}

impl TaskAnchor {
    fn frame(self) -> (DateTime, Tz, bool) {
        match self {
            TaskAnchor::Date(date) => (date.to_datetime(Time::midnight()), Tz::Floating, true),
            TaskAnchor::Local { start, tz } => (whole_minutes(start), tz, false),
        }
    }

    pub(crate) fn count_start(self, rule: &mut ICalendarRecurrenceRule) {
        let Some(count) = rule.count else {
            return;
        };
        let (start, _, _) = self.frame();
        let off_start = TaskRecur::mapped(rule, self, RuleCount::Pattern)
            .ok()
            .and_then(|recur| local_from_minutes(recur.0.start_date))
            .is_some_and(|first| first.date() != start.date());
        if off_start {
            rule.count = Some(count.saturating_add(1));
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/blob/recur/task/tests.rs"]
mod tests;
