/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::icalendar::{
    ICalendarDay, ICalendarFrequency, ICalendarMonth, ICalendarRecurrenceRule, ICalendarWeekday,
};

use super::{LAST_DAY_OF_MONTH, recurrence_type};
use crate::{convert::ConvertError, eas::commands::appdata::TaskRecurrence};

static WEEKDAYS: [ICalendarWeekday; 7] = [
    ICalendarWeekday::Sunday,
    ICalendarWeekday::Monday,
    ICalendarWeekday::Tuesday,
    ICalendarWeekday::Wednesday,
    ICalendarWeekday::Thursday,
    ICalendarWeekday::Friday,
    ICalendarWeekday::Saturday,
];
const ALL_WEEKDAYS: u16 = 0x7F;
const LAST_WEEK_OF_MONTH: u8 = 5;
const MONTHS_PER_YEAR: u8 = 12;
const DAY_OF_MONTH_TYPES: [u8; 2] = [recurrence_type::MONTHLY, recurrence_type::YEARLY];
const DAY_OF_WEEK_TYPES: [u8; 4] = [
    recurrence_type::DAILY,
    recurrence_type::WEEKLY,
    recurrence_type::MONTHLY_NTH,
    recurrence_type::YEARLY_NTH,
];
const MONTH_OF_YEAR_TYPES: [u8; 2] = [recurrence_type::YEARLY, recurrence_type::YEARLY_NTH];
const WEEK_OF_MONTH_TYPES: [u8; 2] = [recurrence_type::MONTHLY_NTH, recurrence_type::YEARLY_NTH];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PatternEnd {
    Never,
    Count(u16),
    Until(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PatternKind {
    Daily,
    Weekly {
        days: Option<u16>,
    },
    Monthly {
        day: Option<u8>,
    },
    MonthlyNth {
        days: u16,
        week: u8,
    },
    Yearly {
        day: Option<u8>,
        month: Option<u8>,
    },
    YearlyNth {
        days: u16,
        week: u8,
        month: Option<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Pattern {
    pub kind: PatternKind,
    pub interval: u16,
    pub end: PatternEnd,
}

impl Pattern {
    pub fn from_task(recurrence: &TaskRecurrence) -> Result<Self, ConvertError> {
        let pattern_type = recurrence
            .recurrence_type
            .ok_or(ConvertError::Unsupported)?;
        let allowed = |present: bool, types: &[u8]| !present || types.contains(&pattern_type);
        if !(allowed(recurrence.day_of_month.is_some(), &DAY_OF_MONTH_TYPES)
            && allowed(recurrence.day_of_week.is_some(), &DAY_OF_WEEK_TYPES)
            && allowed(recurrence.month_of_year.is_some(), &MONTH_OF_YEAR_TYPES)
            && allowed(recurrence.week_of_month.is_some(), &WEEK_OF_MONTH_TYPES))
        {
            return Err(ConvertError::Unsupported);
        }
        let days = recurrence
            .day_of_week
            .filter(|days| *days != 0)
            .map(|days| {
                (days & !ALL_WEEKDAYS == 0)
                    .then_some(days)
                    .ok_or(ConvertError::Unsupported)
            })
            .transpose()?;
        let day = recurrence
            .day_of_month
            .map(|day| {
                (1..=LAST_DAY_OF_MONTH)
                    .contains(&day)
                    .then_some(day)
                    .ok_or(ConvertError::Unsupported)
            })
            .transpose()?;
        let month = recurrence
            .month_of_year
            .map(|month| {
                (1..=MONTHS_PER_YEAR)
                    .contains(&month)
                    .then_some(month)
                    .ok_or(ConvertError::Unsupported)
            })
            .transpose()?;
        let nth = || {
            let week = recurrence
                .week_of_month
                .filter(|week| (1..=LAST_WEEK_OF_MONTH).contains(week))
                .ok_or(ConvertError::Unsupported)?;
            Ok::<_, ConvertError>((days.ok_or(ConvertError::Unsupported)?, week))
        };
        let kind = match pattern_type {
            recurrence_type::DAILY if days.is_some() => PatternKind::Weekly { days },
            recurrence_type::DAILY => PatternKind::Daily,
            recurrence_type::WEEKLY => PatternKind::Weekly { days },
            recurrence_type::MONTHLY => PatternKind::Monthly { day },
            recurrence_type::MONTHLY_NTH => {
                let (days, week) = nth()?;
                PatternKind::MonthlyNth { days, week }
            }
            recurrence_type::YEARLY => PatternKind::Yearly { day, month },
            recurrence_type::YEARLY_NTH => {
                let (days, week) = nth()?;
                PatternKind::YearlyNth { days, week, month }
            }
            _ => return Err(ConvertError::Unsupported),
        };
        let end = match (recurrence.occurrences, recurrence.until) {
            (Some(count), _) if count > 0 => PatternEnd::Count(count),
            (_, Some(until)) => PatternEnd::Until(until.0.0),
            _ => PatternEnd::Never,
        };
        Ok(Pattern {
            kind,
            interval: recurrence.interval.unwrap_or(1).max(1),
            end,
        })
    }

    pub fn to_rule(self, first_day_of_week: Option<u8>) -> ICalendarRecurrenceRule {
        let mut rule = ICalendarRecurrenceRule {
            interval: (self.interval > 1).then_some(self.interval),
            wkst: first_day_of_week
                .and_then(|day| WEEKDAYS.get(usize::from(day)))
                .copied(),
            ..Default::default()
        };
        if let PatternEnd::Count(count) = self.end {
            rule.count = Some(u32::from(count));
        }
        match self.kind {
            PatternKind::Daily => rule.freq = ICalendarFrequency::Daily,
            PatternKind::Weekly { days } => {
                rule.freq = ICalendarFrequency::Weekly;
                rule.byday.extend(days.into_iter().flat_map(weekdays));
            }
            PatternKind::Monthly { day } => {
                rule.freq = ICalendarFrequency::Monthly;
                rule.bymonthday.extend(day.map(month_day));
            }
            PatternKind::MonthlyNth { days, week } => {
                rule.freq = ICalendarFrequency::Monthly;
                rule.byday.extend(weekdays(days));
                rule.bysetpos.push(set_position(week));
            }
            PatternKind::Yearly { day, month } => {
                rule.freq = ICalendarFrequency::Yearly;
                rule.bymonthday.extend(day.map(month_day));
                rule.bymonth
                    .extend(month.map(|month| ICalendarMonth::new(month, false)));
            }
            PatternKind::YearlyNth { days, week, month } => {
                rule.freq = ICalendarFrequency::Yearly;
                rule.byday.extend(weekdays(days));
                rule.bysetpos.push(set_position(week));
                rule.bymonth
                    .extend(month.map(|month| ICalendarMonth::new(month, false)));
            }
        }
        rule
    }
}

fn weekdays(days: u16) -> impl Iterator<Item = ICalendarDay> {
    WEEKDAYS
        .iter()
        .enumerate()
        .filter(move |(bit, _)| days & (1 << bit) != 0)
        .map(|(_, weekday)| ICalendarDay {
            ordwk: None,
            weekday: *weekday,
        })
}

fn month_day(day: u8) -> i8 {
    if day == LAST_DAY_OF_MONTH {
        -1
    } else {
        i8::try_from(day).unwrap_or(-1)
    }
}

fn set_position(week: u8) -> i32 {
    if week == LAST_WEEK_OF_MONTH {
        -1
    } else {
        i32::from(week)
    }
}
