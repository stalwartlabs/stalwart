/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    convert::blob::recur::{ALL_DAYS, WEEKDAYS, WEEKEND_DAYS, WORK_DAYS, clamped_month_day},
    ews::{
        schema::{DayOfWeek, DayOfWeekIndex, MonthName},
        types::recurrence::{DaysOfWeek, Recurrence, RecurrenceEnd, RecurrencePattern},
    },
    xml::value::XsDate,
};
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendarDay, ICalendarFrequency, ICalendarMonth, ICalendarRecurrenceRule, ICalendarWeekday,
    },
};
use jiff::civil::Date;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ews) enum RuleError {
    Invalid,
    Unsupported,
    NoOccurrence,
}

#[derive(Debug)]
pub(in crate::ews) struct SeriesRule {
    pub rule: ICalendarRecurrenceRule,
    pub first: Date,
}

pub(in crate::ews) fn rule_of(recurrence: &Recurrence) -> Result<SeriesRule, RuleError> {
    let mut rule = ICalendarRecurrenceRule::default();
    let interval = match recurrence.pattern {
        RecurrencePattern::Daily { interval } => {
            rule.freq = ICalendarFrequency::Daily;
            interval
        }
        RecurrencePattern::Weekly {
            interval,
            days_of_week,
            first_day_of_week,
        } => {
            rule.freq = ICalendarFrequency::Weekly;
            rule.byday = byday(days_of_week).ok_or(RuleError::Invalid)?;
            rule.wkst = match first_day_of_week {
                Some(day) => Some(weekday(day).ok_or(RuleError::Invalid)?),
                None => None,
            };
            interval
        }
        RecurrencePattern::AbsoluteMonthly {
            interval,
            day_of_month,
        } => {
            rule.freq = ICalendarFrequency::Monthly;
            month_day(&mut rule, day_of_month)?;
            interval
        }
        RecurrencePattern::RelativeMonthly {
            interval,
            days_of_week,
            index,
        } => {
            rule.freq = ICalendarFrequency::Monthly;
            rule.byday = byday(days_of_week).ok_or(RuleError::Invalid)?;
            rule.bysetpos = vec![set_position(index)];
            interval
        }
        RecurrencePattern::AbsoluteYearly {
            day_of_month,
            month,
        } => {
            rule.freq = ICalendarFrequency::Yearly;
            rule.bymonth = vec![month_of(month)];
            month_day(&mut rule, day_of_month)?;
            1
        }
        RecurrencePattern::RelativeYearly(yearly) => {
            rule.freq = ICalendarFrequency::Yearly;
            rule.bymonth = vec![month_of(yearly.month)];
            rule.byday = byday(yearly.days_of_week).ok_or(RuleError::Invalid)?;
            rule.bysetpos = vec![set_position(yearly.index)];
            1
        }
        RecurrencePattern::DailyRegeneration { .. }
        | RecurrencePattern::WeeklyRegeneration { .. }
        | RecurrencePattern::MonthlyRegeneration { .. }
        | RecurrencePattern::YearlyRegeneration { .. } => return Err(RuleError::Unsupported),
    };
    rule.interval = match u16::try_from(interval).map_err(|_| RuleError::Invalid)? {
        0 => return Err(RuleError::Invalid),
        1 => None,
        interval => Some(interval),
    };
    match recurrence.range.end {
        RecurrenceEnd::NoEnd => {}
        RecurrenceEnd::Numbered(count) => {
            rule.count = Some(
                u32::try_from(count)
                    .ok()
                    .filter(|count| *count > 0)
                    .ok_or(RuleError::Invalid)?,
            );
        }
        RecurrenceEnd::EndDate(date) => rule.until = Some(until_of(date)),
    }
    let first = date_of(recurrence.range.start).ok_or(RuleError::Invalid)?;
    if let RecurrenceEnd::EndDate(end) = recurrence.range.end
        && date_of(end).ok_or(RuleError::Invalid)? < first
    {
        return Err(RuleError::NoOccurrence);
    }
    Ok(SeriesRule { rule, first })
}

fn byday(days: DaysOfWeek) -> Option<Vec<ICalendarDay>> {
    let mask = days.iter().fold(0u8, |mask, day| mask | day_bits(day));
    (mask != 0).then(|| {
        WEEKDAYS
            .iter()
            .zip(0u32..)
            .filter(|(_, bit)| mask & (1 << bit) != 0)
            .map(|(weekday, _)| ICalendarDay {
                ordwk: None,
                weekday: *weekday,
            })
            .collect()
    })
}

fn day_bits(day: DayOfWeek) -> u8 {
    match day {
        DayOfWeek::Sunday => 1,
        DayOfWeek::Monday => 1 << 1,
        DayOfWeek::Tuesday => 1 << 2,
        DayOfWeek::Wednesday => 1 << 3,
        DayOfWeek::Thursday => 1 << 4,
        DayOfWeek::Friday => 1 << 5,
        DayOfWeek::Saturday => 1 << 6,
        DayOfWeek::Day => ALL_DAYS,
        DayOfWeek::Weekday => WORK_DAYS,
        DayOfWeek::WeekendDay => WEEKEND_DAYS,
    }
}

fn weekday(day: DayOfWeek) -> Option<ICalendarWeekday> {
    let bits = day_bits(day);
    bits.is_power_of_two()
        .then(|| {
            WEEKDAYS
                .get(usize::try_from(bits.trailing_zeros()).ok()?)
                .copied()
        })
        .flatten()
}

fn month_day(rule: &mut ICalendarRecurrenceRule, day: i32) -> Result<(), RuleError> {
    u8::try_from(day)
        .ok()
        .and_then(|day| clamped_month_day(rule, day))
        .ok_or(RuleError::Invalid)
}

fn set_position(index: DayOfWeekIndex) -> i32 {
    match index {
        DayOfWeekIndex::First => 1,
        DayOfWeekIndex::Second => 2,
        DayOfWeekIndex::Third => 3,
        DayOfWeekIndex::Fourth => 4,
        DayOfWeekIndex::Last => -1,
    }
}

fn month_of(month: MonthName) -> ICalendarMonth {
    ICalendarMonth::new(month as u8 + 1, false)
}

fn date_of(date: XsDate) -> Option<Date> {
    Date::new(
        i16::try_from(date.year).ok()?,
        i8::try_from(date.month).ok()?,
        i8::try_from(date.day).ok()?,
    )
    .ok()
}

fn until_of(date: XsDate) -> PartialDateTime {
    PartialDateTime {
        year: Some(date.year),
        month: Some(date.month),
        day: Some(date.day),
        ..PartialDateTime::default()
    }
}
