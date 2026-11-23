/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendarDay, ICalendarFrequency, ICalendarMonth, ICalendarRecurrenceRule, ICalendarWeekday,
    },
};
use jiff::{
    civil::{Date, DateTime, Time},
    tz::{Offset, TimeZone},
};

use super::{
    AppointmentRecur, NO_END_DATE, PatternType, RecurEnd, RecurFrequency, RecurrencePattern,
    WRITER_VERSION2,
};
use crate::convert::blob::goid::days_in_month;

const MINUTES_PER_DAY: i64 = 1440;
const MINUTES_PER_HOUR: u32 = 60;
const DAYS_PER_WEEK: i32 = 7;
const MONTHS_PER_YEAR: i32 = 12;
const EPOCH_YEAR: i32 = 1601;
const EPOCH_WEEKDAY: i32 = 1;
const CUTOFF_DAY: i32 = days_from_civil(4501, 1, 1);
const MAX_COUNT: u32 = 999;
const MAX_DAILY_INTERVAL: u16 = 999;
const MAX_WEEKLY_INTERVAL: u16 = 99;
const MAX_MONTHLY_INTERVAL: u16 = 99;
const MAX_YEARLY_INTERVAL: u16 = 8;
const INFINITE_OCCURRENCES: u32 = 10;
const LAST_WEEK: u8 = 5;
const DEFAULT_FIRST_DOW: u8 = 1;
pub(crate) const ALL_DAYS: u8 = 0x7F;
pub(crate) const WORK_DAYS: u8 = 0x3E;
pub(crate) const WEEKEND_DAYS: u8 = 0x41;
const CLAMP_FLOOR: i8 = 28;
const MONTH_END: u8 = 31;
const CALENDAR_DEFAULT: u16 = 0;
const CALENDAR_GREGORIAN: u16 = 1;
const SHORTEST_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
pub(crate) const WEEKDAYS: [ICalendarWeekday; 7] = [
    ICalendarWeekday::Sunday,
    ICalendarWeekday::Monday,
    ICalendarWeekday::Tuesday,
    ICalendarWeekday::Wednesday,
    ICalendarWeekday::Thursday,
    ICalendarWeekday::Friday,
    ICalendarWeekday::Saturday,
];

#[derive(Debug, Clone, Copy)]
pub struct RecurAnchor {
    pub start: DateTime,
    pub duration_minutes: u32,
    pub tz: Tz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmappable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleCount {
    Dtstart,
    Realigned,
    Pattern,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum UntilForm {
    Date,
    Local { time: Option<Time>, tz: Tz },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Day,
    Week { mask: u8 },
    Month { day: u8 },
    MonthNth { mask: u8, n: u8 },
}

#[derive(Debug, Clone, Copy)]
struct Series {
    shape: Shape,
    period: i32,
    start: i32,
    origin: i32,
}

struct End {
    kind: RecurEnd,
    count: u32,
    date: u32,
}

impl AppointmentRecur {
    pub fn from_rrule(
        rule: &ICalendarRecurrenceRule,
        anchor: RecurAnchor,
    ) -> Result<Self, Unmappable> {
        appointment_from_rrule(rule, &anchor, RuleCount::Dtstart).ok_or(Unmappable)
    }

    pub fn from_client_rrule(
        rule: &ICalendarRecurrenceRule,
        anchor: RecurAnchor,
    ) -> Result<Self, Unmappable> {
        appointment_from_rrule(rule, &anchor, RuleCount::Pattern).ok_or(Unmappable)
    }

    pub fn to_rrule(&self, tz: Tz) -> Result<ICalendarRecurrenceRule, Unmappable> {
        let time = offset_time(self.start_time_offset);
        self.pattern
            .rrule(UntilForm::Local { time, tz })
            .ok_or(Unmappable)
    }
}

impl RecurrencePattern {
    pub(crate) fn from_rrule(
        rule: &ICalendarRecurrenceRule,
        start: DateTime,
        tz: Tz,
        count: RuleCount,
    ) -> Result<Self, Unmappable> {
        pattern_from_rrule(rule, start, tz, count).ok_or(Unmappable)
    }

    pub(crate) fn rrule(&self, until: UntilForm) -> Option<ICalendarRecurrenceRule> {
        if !matches!(self.calendar_type, CALENDAR_DEFAULT | CALENDAR_GREGORIAN) {
            return None;
        }
        let mut rule = ICalendarRecurrenceRule::default();
        let interval = match self.pattern {
            PatternType::Day => {
                rule.freq = ICalendarFrequency::Daily;
                let period = i64::from(self.period);
                (period % MINUTES_PER_DAY == 0)
                    .then_some(period / MINUTES_PER_DAY)
                    .and_then(|days| u32::try_from(days).ok())?
            }
            PatternType::Week { days } => {
                rule.freq = ICalendarFrequency::Weekly;
                rule.byday = weekday_list(day_mask(days)?);
                if self.period > 1 {
                    rule.wkst = Some(*WEEKDAYS.get(usize::try_from(self.first_dow).ok()?)?);
                }
                self.period
            }
            PatternType::Month { day } => self.month_rule(&mut rule, MonthRule::Day(day))?,
            PatternType::MonthEnd { .. } => {
                self.month_rule(&mut rule, MonthRule::Day(u32::from(MONTH_END)))?
            }
            PatternType::MonthNth { days, n } => {
                self.month_rule(&mut rule, MonthRule::Nth(days, n))?
            }
            PatternType::HjMonth { .. }
            | PatternType::HjMonthNth { .. }
            | PatternType::HjMonthEnd { .. } => return None,
        };
        if interval == 0 {
            return None;
        }
        if rule.wkst.is_none() && self.first_dow != u32::from(DEFAULT_FIRST_DOW) {
            rule.wkst = usize::try_from(self.first_dow)
                .ok()
                .and_then(|day| WEEKDAYS.get(day))
                .copied();
        }
        rule.interval = if interval == 1 {
            None
        } else {
            Some(u16::try_from(interval).ok()?)
        };
        match self.end {
            RecurEnd::AfterCount => {
                rule.count = Some(self.occurrence_count).filter(|count| *count > 0);
                rule.count?;
            }
            RecurEnd::ByDate if self.end_date < NO_END_DATE => {
                rule.until = Some(until.value(self.end_date)?);
            }
            RecurEnd::ByDate | RecurEnd::Never | RecurEnd::NeverLegacy => {}
        }
        Some(rule)
    }

    fn month_rule(&self, rule: &mut ICalendarRecurrenceRule, kind: MonthRule) -> Option<u32> {
        let period = self.period;
        let first_month = month_index(self.first_date_time)?;
        let yearly = period.is_multiple_of(12);
        let months = i32::try_from(period).ok().filter(|months| *months > 0)?;
        if yearly {
            rule.freq = ICalendarFrequency::Yearly;
            let month = first_month.rem_euclid(MONTHS_PER_YEAR).checked_add(1)?;
            rule.bymonth = vec![ICalendarMonth::new(u8::try_from(month).ok()?, false)];
        } else {
            rule.freq = ICalendarFrequency::Monthly;
        }
        match kind {
            MonthRule::Day(day) => {
                let day = u8::try_from(day)
                    .ok()
                    .filter(|day| (1..=MONTH_END).contains(day))?;
                if day != MONTH_END && months_fit(first_month, months, day) {
                    rule.bymonthday = vec![i8::try_from(day).ok()?];
                } else {
                    clamped_month_day(rule, day)?;
                }
            }
            MonthRule::Nth(days, n) => {
                rule.byday = weekday_list(day_mask(days)?);
                let n = u8::try_from(n)
                    .ok()
                    .filter(|n| (1..=LAST_WEEK).contains(n))?;
                rule.bysetpos = vec![if n == LAST_WEEK { -1 } else { i32::from(n) }];
            }
        }
        Some(if yearly { period / 12 } else { period })
    }
}

enum MonthRule {
    Day(u32),
    Nth(u32, u32),
}

fn appointment_from_rrule(
    rule: &ICalendarRecurrenceRule,
    anchor: &RecurAnchor,
    count: RuleCount,
) -> Option<AppointmentRecur> {
    let start_time_offset = local_time_offset(anchor.start)?;
    Some(AppointmentRecur {
        pattern: pattern_from_rrule(rule, anchor.start, anchor.tz, count)?,
        writer_version2: WRITER_VERSION2,
        start_time_offset,
        end_time_offset: start_time_offset.checked_add(anchor.duration_minutes)?,
        exceptions: Vec::new(),
    })
}

fn offset_time(offset: u32) -> Option<Time> {
    Time::new(
        i8::try_from(offset / MINUTES_PER_HOUR).ok()?,
        i8::try_from(offset % MINUTES_PER_HOUR).ok()?,
        0,
        0,
    )
    .ok()
}

fn local_time_offset(start: DateTime) -> Option<u32> {
    u32::try_from(start.hour())
        .ok()?
        .checked_mul(MINUTES_PER_HOUR)?
        .checked_add(u32::try_from(start.minute()).ok()?)
}

pub(super) fn is_representable(rule: &ICalendarRecurrenceRule) -> bool {
    rule.rscale.is_none()
        && rule.skip.is_none()
        && rule.bysecond.is_empty()
        && rule.byyearday.is_empty()
        && rule.byweekno.is_empty()
        && (rule.count.is_none() || rule.until.is_none())
        && matches!(
            rule.freq,
            ICalendarFrequency::Daily
                | ICalendarFrequency::Weekly
                | ICalendarFrequency::Monthly
                | ICalendarFrequency::Yearly
        )
}

fn pattern_from_rrule(
    rule: &ICalendarRecurrenceRule,
    start: DateTime,
    tz: Tz,
    count: RuleCount,
) -> Option<RecurrencePattern> {
    let hour = u8::try_from(start.hour()).ok()?;
    let minute = u8::try_from(start.minute()).ok()?;
    if !is_representable(rule)
        || !matches_single(&rule.byhour, hour)
        || !matches_single(&rule.byminute, minute)
    {
        return None;
    }
    let interval = rule.interval.unwrap_or(1);
    let first_dow = rule.wkst.map_or(DEFAULT_FIRST_DOW, weekday_index);
    let start_day = day_number(start.date()).filter(|day| (0..CUTOFF_DAY).contains(day))?;
    let start_weekday = weekday(start_day);
    let (frequency, shape, max_interval) = match rule.freq {
        ICalendarFrequency::Daily => {
            if !rule.bymonth.is_empty() || !rule.bymonthday.is_empty() || !rule.bysetpos.is_empty()
            {
                return None;
            }
            if rule.byday.is_empty() {
                (RecurFrequency::Daily, Shape::Day, MAX_DAILY_INTERVAL)
            } else if interval == 1 {
                let mask = plain_mask(&rule.byday)?;
                (RecurFrequency::Weekly, Shape::Week { mask }, 1)
            } else {
                return None;
            }
        }
        ICalendarFrequency::Weekly => {
            if !rule.bymonth.is_empty() || !rule.bymonthday.is_empty() || !rule.bysetpos.is_empty()
            {
                return None;
            }
            let mask = if rule.byday.is_empty() {
                1u8.checked_shl(u32::from(start_weekday))?
            } else {
                plain_mask(&rule.byday)?
            };
            (
                RecurFrequency::Weekly,
                Shape::Week { mask },
                MAX_WEEKLY_INTERVAL,
            )
        }
        ICalendarFrequency::Monthly => {
            if !rule.bymonth.is_empty() {
                return None;
            }
            (
                RecurFrequency::Monthly,
                month_shape(rule, start.date())?,
                MAX_MONTHLY_INTERVAL,
            )
        }
        ICalendarFrequency::Yearly => {
            match rule.bymonth.as_slice() {
                [] if rule.bymonthday.is_empty()
                    && rule.byday.is_empty()
                    && rule.bysetpos.is_empty() => {}
                [month]
                    if !month.is_leap() && i8::try_from(month.month()).ok()? == start.month() => {}
                _ => return None,
            }
            (
                RecurFrequency::Yearly,
                month_shape(rule, start.date())?,
                MAX_YEARLY_INTERVAL,
            )
        }
        ICalendarFrequency::Hourly
        | ICalendarFrequency::Minutely
        | ICalendarFrequency::Secondly => {
            return None;
        }
    };
    if interval == 0 || interval > max_interval {
        return None;
    }
    let period = match (rule.freq, shape) {
        (ICalendarFrequency::Yearly, _) => i32::from(interval).checked_mul(MONTHS_PER_YEAR)?,
        _ => i32::from(interval),
    };
    let series = Series::new(shape, period, first_dow, start_day)?;
    if let Shape::Month { day } = shape
        && !series.month_day_is_exact(rule, day)
    {
        return None;
    }
    let first = series.occurrences().next()?;
    let taken = match count {
        RuleCount::Dtstart => u32::from(first != start_day),
        RuleCount::Realigned => 1,
        RuleCount::Pattern => 0,
    };
    let end = series
        .end(rule, start, tz, taken)
        .filter(|end| end.count > 0)?;
    Some(RecurrencePattern {
        frequency,
        pattern: shape.pattern_type(),
        calendar_type: CALENDAR_DEFAULT,
        first_date_time: series.first_date_time()?,
        period: series.blob_period()?,
        sliding_flag: 0,
        end: end.kind,
        occurrence_count: end.count,
        first_dow: u32::from(first_dow),
        deleted_instances: Vec::new(),
        modified_instances: Vec::new(),
        start_date: day_minutes(first)?,
        end_date: end.date,
    })
}

fn month_shape(rule: &ICalendarRecurrenceRule, start: Date) -> Option<Shape> {
    if !rule.byday.is_empty() {
        if !rule.bymonthday.is_empty() {
            return None;
        }
        return match (rule.byday.as_slice(), rule.bysetpos.as_slice()) {
            (
                [
                    ICalendarDay {
                        ordwk: Some(ordinal),
                        weekday,
                    },
                ],
                [],
            ) => Some(Shape::MonthNth {
                mask: 1u8.checked_shl(u32::from(weekday_index(*weekday)))?,
                n: set_position(i32::from(*ordinal))?,
            }),
            (days, [position]) => Some(Shape::MonthNth {
                mask: plain_mask(days)?,
                n: set_position(*position)?,
            }),
            _ => None,
        };
    }
    let day = match (rule.bymonthday.as_slice(), rule.bysetpos.as_slice()) {
        ([], []) => u8::try_from(start.day()).ok()?,
        ([-1], []) => MONTH_END,
        ([day], []) => u8::try_from(*day).ok()?,
        (days, [-1]) => clamp_day(days)?,
        _ => return None,
    };
    (1..=MONTH_END)
        .contains(&day)
        .then_some(Shape::Month { day })
}

fn clamp_day(days: &[i8]) -> Option<u8> {
    let last = CLAMP_FLOOR
        .checked_add(i8::try_from(days.len()).ok()?)?
        .checked_sub(1)?;
    let mut seen = 0u8;
    for day in days {
        let bit = day
            .checked_sub(CLAMP_FLOOR)
            .and_then(|offset| u32::try_from(offset).ok())?;
        seen |= 1u8.checked_shl(bit)?;
    }
    let expected = 1u8
        .checked_shl(u32::try_from(days.len()).ok()?)?
        .checked_sub(1)?;
    (seen == expected && last > CLAMP_FLOOR && last <= MONTH_END as i8)
        .then(|| u8::try_from(last).ok())
        .flatten()
}

fn set_position(position: i32) -> Option<u8> {
    match position {
        -1 => Some(LAST_WEEK),
        1..=4 => u8::try_from(position).ok(),
        _ => None,
    }
}

fn matches_single(values: &[u8], expected: u8) -> bool {
    match values {
        [] => true,
        [value] => *value == expected,
        _ => false,
    }
}

fn plain_mask(days: &[ICalendarDay]) -> Option<u8> {
    days.iter().try_fold(0u8, |mask, day| {
        day.ordwk
            .is_none()
            .then(|| 1u8.checked_shl(u32::from(weekday_index(day.weekday))))
            .flatten()
            .map(|bit| mask | bit)
    })
}

fn day_mask(days: u32) -> Option<u8> {
    u8::try_from(days)
        .ok()
        .filter(|mask| *mask != 0 && *mask & !ALL_DAYS == 0)
}

fn weekday_list(mask: u8) -> Vec<ICalendarDay> {
    WEEKDAYS
        .iter()
        .zip(0u32..)
        .filter(|(_, bit)| mask & 1u8.checked_shl(*bit).unwrap_or(0) != 0)
        .map(|(weekday, _)| ICalendarDay {
            ordwk: None,
            weekday: *weekday,
        })
        .collect()
}

fn weekday_index(weekday: ICalendarWeekday) -> u8 {
    match weekday {
        ICalendarWeekday::Sunday => 0,
        ICalendarWeekday::Monday => 1,
        ICalendarWeekday::Tuesday => 2,
        ICalendarWeekday::Wednesday => 3,
        ICalendarWeekday::Thursday => 4,
        ICalendarWeekday::Friday => 5,
        ICalendarWeekday::Saturday => 6,
    }
}

pub(crate) fn clamped_month_day(rule: &mut ICalendarRecurrenceRule, day: u8) -> Option<()> {
    let last = i8::try_from(day)
        .ok()
        .filter(|_| (1..=MONTH_END).contains(&day))?;
    if day == MONTH_END {
        rule.bymonthday = vec![-1];
    } else if last <= CLAMP_FLOOR {
        rule.bymonthday = vec![last];
    } else {
        rule.bymonthday = (CLAMP_FLOOR..=last).collect();
        rule.bysetpos = vec![-1];
    }
    Some(())
}

fn months_fit(first_month: i32, period: i32, day: u8) -> bool {
    (0..MONTHS_PER_YEAR).all(|step| {
        step.checked_mul(period)
            .and_then(|offset| offset.checked_add(first_month))
            .and_then(|month| usize::try_from(month.rem_euclid(MONTHS_PER_YEAR)).ok())
            .and_then(|month| SHORTEST_MONTH.get(month))
            .is_some_and(|shortest| *shortest >= day)
    })
}

impl UntilForm {
    fn value(self, end_date: u32) -> Option<PartialDateTime> {
        let (year, month, day) =
            civil_from_days(i32::try_from(i64::from(end_date) / MINUTES_PER_DAY).ok()?);
        let date = Date::new(
            i16::try_from(year).ok()?,
            i8::try_from(month).ok()?,
            i8::try_from(day).ok()?,
        )
        .ok()?;
        match self {
            UntilForm::Date => Some(PartialDateTime {
                year: u16::try_from(year).ok(),
                month: Some(month),
                day: Some(day),
                ..Default::default()
            }),
            UntilForm::Local { time, tz } => until_local(date.to_datetime(time?), tz),
        }
    }
}

fn until_local(local: DateTime, tz: Tz) -> Option<PartialDateTime> {
    let (value, utc) = if tz.is_floating() {
        (local, None)
    } else {
        let timestamp = tz.from_local(local)?.to_timestamp();
        (TimeZone::UTC.to_datetime(timestamp), Some(0))
    };
    Some(PartialDateTime {
        year: u16::try_from(value.year()).ok(),
        month: u8::try_from(value.month()).ok(),
        day: u8::try_from(value.day()).ok(),
        hour: u8::try_from(value.hour()).ok(),
        minute: u8::try_from(value.minute()).ok(),
        second: u8::try_from(value.second()).ok(),
        tz_hour: utc,
        tz_minute: utc,
        tz_minus: false,
    })
}

fn until_limit(until: &PartialDateTime, start: DateTime, tz: Tz) -> Option<i32> {
    let date = Date::new(
        i16::try_from(until.year?).ok()?,
        i8::try_from(until.month?).ok()?,
        i8::try_from(until.day?).ok()?,
    )
    .ok()?;
    if !until.has_time() {
        return day_number(date);
    }
    let local = date.to_datetime(
        Time::new(
            i8::try_from(until.hour?).ok()?,
            i8::try_from(until.minute?).ok()?,
            i8::try_from(until.second.unwrap_or(0)).ok()?,
            0,
        )
        .ok()?,
    );
    let local = match until.tz_hour {
        Some(hours) if !tz.is_floating() => {
            let seconds = i32::from(hours)
                .checked_mul(3600)?
                .checked_add(i32::from(until.tz_minute.unwrap_or(0)).checked_mul(60)?)?;
            let seconds = if until.tz_minus {
                seconds.checked_neg()?
            } else {
                seconds
            };
            let timestamp = Offset::from_seconds(seconds)
                .ok()?
                .to_timestamp(local)
                .ok()?;
            tz.from_timestamp(timestamp).naive_local()
        }
        _ => local,
    };
    let day = day_number(local.date())?;
    if local.time() < start.time() {
        day.checked_sub(1)
    } else {
        Some(day)
    }
}

impl Shape {
    fn pattern_type(self) -> PatternType {
        match self {
            Shape::Day => PatternType::Day,
            Shape::Week { mask } => PatternType::Week {
                days: u32::from(mask),
            },
            Shape::Month { day } => PatternType::Month {
                day: u32::from(day),
            },
            Shape::MonthNth { mask, n } => PatternType::MonthNth {
                days: u32::from(mask),
                n: u32::from(n),
            },
        }
    }
}

impl Series {
    fn month_day_is_exact(&self, rule: &ICalendarRecurrenceRule, day: u8) -> bool {
        let clamped = rule.bymonthday.as_slice() == [-1] || !rule.bysetpos.is_empty();
        clamped || months_fit(self.origin, self.period, day)
    }

    fn new(shape: Shape, period: i32, first_dow: u8, start: i32) -> Option<Self> {
        let origin = match shape {
            Shape::Day => start,
            Shape::Week { .. } => {
                let back = i32::from(weekday(start))
                    .checked_sub(i32::from(first_dow))?
                    .rem_euclid(DAYS_PER_WEEK);
                start.checked_sub(back)?
            }
            Shape::Month { .. } | Shape::MonthNth { .. } => month_of_day(start)?,
        };
        Some(Series {
            shape,
            period,
            start,
            origin,
        })
    }

    fn block(&self, index: i32) -> Option<i32> {
        match self.shape {
            Shape::Day | Shape::Month { .. } | Shape::MonthNth { .. } => {
                index.checked_mul(self.period)?.checked_add(self.origin)
            }
            Shape::Week { .. } => index
                .checked_mul(self.period)?
                .checked_mul(DAYS_PER_WEEK)?
                .checked_add(self.origin),
        }
    }

    fn day_in_block(&self, block: i32, offset: i32) -> Option<i32> {
        match self.shape {
            Shape::Day => Some(block),
            Shape::Week { mask } => {
                let weekday = u32::from(weekday(block.checked_add(offset)?));
                (mask & 1u8.checked_shl(weekday)? != 0).then(|| block.checked_add(offset))?
            }
            Shape::Month { day } => {
                let (first, length) = month_bounds(block)?;
                first
                    .checked_add(i32::from(day.min(length)))?
                    .checked_sub(1)
            }
            Shape::MonthNth { mask, n } => {
                let (first, length) = month_bounds(block)?;
                let mut matching = (0..i32::from(length)).filter(|offset| {
                    first
                        .checked_add(*offset)
                        .and_then(|day| 1u8.checked_shl(u32::from(weekday(day))))
                        .is_some_and(|bit| mask & bit != 0)
                });
                let offset = if n == LAST_WEEK {
                    matching.next_back()
                } else {
                    matching.nth(usize::from(n.checked_sub(1)?))
                }?;
                first.checked_add(offset)
            }
        }
    }

    fn occurrences(&self) -> impl Iterator<Item = i32> {
        let span = match self.shape {
            Shape::Week { .. } => DAYS_PER_WEEK,
            _ => 1,
        };
        let series = *self;
        (0..)
            .map_while(move |index| series.block(index))
            .take_while(|block| *block < CUTOFF_DAY)
            .flat_map(move |block| {
                (0..span).filter_map(move |offset| series.day_in_block(block, offset))
            })
            .skip_while(move |day| *day < series.start)
            .take_while(|day| *day < CUTOFF_DAY)
    }

    fn end(
        &self,
        rule: &ICalendarRecurrenceRule,
        start: DateTime,
        tz: Tz,
        taken: u32,
    ) -> Option<End> {
        let infinite = End {
            kind: RecurEnd::Never,
            count: INFINITE_OCCURRENCES,
            date: NO_END_DATE,
        };
        match (rule.count, rule.until.as_ref()) {
            (Some(count), _) => {
                let count = count
                    .checked_sub(taken)
                    .filter(|count| (1..=MAX_COUNT).contains(count))?;
                match self
                    .occurrences()
                    .nth(usize::try_from(count.checked_sub(1)?).ok()?)
                {
                    Some(last) => Some(End {
                        kind: RecurEnd::AfterCount,
                        count,
                        date: day_minutes(last)?,
                    }),
                    None => Some(infinite),
                }
            }
            (None, Some(until)) => {
                let limit = until_limit(until, start, tz)?;
                if limit < self.start {
                    return None;
                }
                if limit >= CUTOFF_DAY {
                    return Some(infinite);
                }
                let (count, last) = self.count_until(limit)?;
                Some(End {
                    kind: RecurEnd::ByDate,
                    count,
                    date: day_minutes(last)?,
                })
            }
            (None, None) => Some(infinite),
        }
    }

    fn count_until(&self, limit: i32) -> Option<(u32, i32)> {
        if self.shape == Shape::Day {
            let steps = limit.checked_sub(self.start)?.checked_div(self.period)?;
            let last = steps.checked_mul(self.period)?.checked_add(self.start)?;
            return Some((u32::try_from(steps).ok()?.checked_add(1)?, last));
        }
        self.occurrences()
            .take_while(|day| *day <= limit)
            .try_fold((0u32, self.start), |(count, _), day| {
                Some((count.checked_add(1)?, day))
            })
    }

    fn blob_period(&self) -> Option<u32> {
        let period = u32::try_from(self.period).ok()?;
        match self.shape {
            Shape::Day => period.checked_mul(u32::try_from(MINUTES_PER_DAY).ok()?),
            _ => Some(period),
        }
    }

    fn first_date_time(&self) -> Option<u32> {
        match self.shape {
            Shape::Day => day_minutes(self.origin.checked_rem(self.period)?),
            Shape::Week { .. } => day_minutes(
                self.origin
                    .checked_rem(self.period.checked_mul(DAYS_PER_WEEK)?)?,
            ),
            Shape::Month { .. } | Shape::MonthNth { .. } => {
                let month = self.origin.checked_rem(self.period)?;
                day_minutes(month_bounds(month)?.0)
            }
        }
    }
}

pub(crate) fn whole_minutes(local: DateTime) -> DateTime {
    local
        .with()
        .second(0)
        .subsec_nanosecond(0)
        .build()
        .unwrap_or(local)
}

pub(crate) fn with_seconds_of(local: DateTime, start: DateTime) -> DateTime {
    local
        .with()
        .second(start.second())
        .subsec_nanosecond(0)
        .build()
        .unwrap_or(local)
}

pub(crate) fn local_minutes(local: DateTime) -> Option<u32> {
    let day = day_number(local.date())?;
    let minutes = i64::from(local.hour())
        .checked_mul(i64::from(MINUTES_PER_HOUR))?
        .checked_add(i64::from(local.minute()))?;
    u32::try_from(
        i64::from(day)
            .checked_mul(MINUTES_PER_DAY)?
            .checked_add(minutes)?,
    )
    .ok()
}

pub(crate) fn local_from_minutes(minutes: u32) -> Option<DateTime> {
    let (year, month, day) =
        civil_from_days(i32::try_from(i64::from(minutes) / MINUTES_PER_DAY).ok()?);
    let of_day = u32::try_from(i64::from(minutes).rem_euclid(MINUTES_PER_DAY)).ok()?;
    Some(
        Date::new(
            i16::try_from(year).ok()?,
            i8::try_from(month).ok()?,
            i8::try_from(day).ok()?,
        )
        .ok()?
        .to_datetime(
            Time::new(
                i8::try_from(of_day / MINUTES_PER_HOUR).ok()?,
                i8::try_from(of_day % MINUTES_PER_HOUR).ok()?,
                0,
                0,
            )
            .ok()?,
        ),
    )
}

fn weekday(day: i32) -> u8 {
    u8::try_from(day.wrapping_add(EPOCH_WEEKDAY).rem_euclid(DAYS_PER_WEEK)).unwrap_or(0)
}

fn day_minutes(day: i32) -> Option<u32> {
    u32::try_from(i64::from(day).checked_mul(MINUTES_PER_DAY)?).ok()
}

fn day_number(date: Date) -> Option<i32> {
    Some(days_from_civil(
        i32::from(date.year()),
        u8::try_from(date.month()).ok()?,
        u8::try_from(date.day()).ok()?,
    ))
}

fn month_index(minutes: u32) -> Option<i32> {
    month_of_day(i32::try_from(i64::from(minutes) / MINUTES_PER_DAY).ok()?)
}

fn month_of_day(day: i32) -> Option<i32> {
    let (year, month, _) = civil_from_days(day);
    year.checked_sub(EPOCH_YEAR)?
        .checked_mul(MONTHS_PER_YEAR)?
        .checked_add(i32::from(month))?
        .checked_sub(1)
}

fn month_bounds(month_index: i32) -> Option<(i32, u8)> {
    let year = month_index
        .checked_div(MONTHS_PER_YEAR)?
        .checked_add(EPOCH_YEAR)?;
    let month = u8::try_from(month_index.checked_rem(MONTHS_PER_YEAR)?.checked_add(1)?).ok()?;
    let length = days_in_month(u16::try_from(year).ok()?, month);
    Some((days_from_civil(year, month, 1), length))
}

#[allow(clippy::arithmetic_side_effects)]
const fn days_from_civil(year: i32, month: u8, day: u8) -> i32 {
    let month = month as i32;
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 584_694
}

#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
fn civil_from_days(day: i32) -> (i32, u8, u8) {
    let day = i64::from(day) + 584_694;
    let era = day.div_euclid(146_097);
    let day_of_era = day - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_from_march + 2) / 5 + 1) as u8;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    } as u8;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year as i32, month, day)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/blob/recur/rrule/tests.rs"]
mod tests;
