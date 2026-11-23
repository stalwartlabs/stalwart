/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::{EwsValue, T, enum_set, ews_fields};
use crate::{
    common::XsDateTime,
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{DayOfWeek, DayOfWeekIndex, MonthName},
    },
    xml::{
        Attrs, XmlWriter,
        value::{XmlValue, XsDate},
    },
};
use std::borrow::Cow;

enum_set!(pub struct DaysOfWeek(DayOfWeek) list "DaysOfWeek");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelativeYearly {
    pub days_of_week: DaysOfWeek,
    pub index: DayOfWeekIndex,
    pub month: MonthName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurrencePattern {
    RelativeYearly(RelativeYearly),
    AbsoluteYearly {
        day_of_month: i32,
        month: MonthName,
    },
    RelativeMonthly {
        interval: i32,
        days_of_week: DaysOfWeek,
        index: DayOfWeekIndex,
    },
    AbsoluteMonthly {
        interval: i32,
        day_of_month: i32,
    },
    Weekly {
        interval: i32,
        days_of_week: DaysOfWeek,
        first_day_of_week: Option<DayOfWeek>,
    },
    Daily {
        interval: i32,
    },
    DailyRegeneration {
        interval: i32,
    },
    WeeklyRegeneration {
        interval: i32,
    },
    MonthlyRegeneration {
        interval: i32,
    },
    YearlyRegeneration {
        interval: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecurrenceRange {
    pub start: XsDate,
    pub end: RecurrenceEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurrenceEnd {
    NoEnd,
    EndDate(XsDate),
    Numbered(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recurrence {
    pub pattern: RecurrencePattern,
    pub range: RecurrenceRange,
}

#[derive(Clone, Copy)]
enum PatternKind {
    RelativeYearly,
    AbsoluteYearly,
    RelativeMonthly,
    AbsoluteMonthly,
    Weekly,
    Daily,
    DailyRegeneration,
    WeeklyRegeneration,
    MonthlyRegeneration,
    YearlyRegeneration,
}

fn pattern_kind(local: &str) -> Option<PatternKind> {
    hashify::map!(local.as_bytes(), PatternKind,
        "RelativeYearlyRecurrence" => PatternKind::RelativeYearly,
        "AbsoluteYearlyRecurrence" => PatternKind::AbsoluteYearly,
        "RelativeMonthlyRecurrence" => PatternKind::RelativeMonthly,
        "AbsoluteMonthlyRecurrence" => PatternKind::AbsoluteMonthly,
        "WeeklyRecurrence" => PatternKind::Weekly,
        "DailyRecurrence" => PatternKind::Daily,
        "DailyRegeneration" => PatternKind::DailyRegeneration,
        "WeeklyRegeneration" => PatternKind::WeeklyRegeneration,
        "MonthlyRegeneration" => PatternKind::MonthlyRegeneration,
        "YearlyRegeneration" => PatternKind::YearlyRegeneration,
    )
    .copied()
}

#[derive(Clone, Copy)]
enum RangeKind {
    NoEnd,
    EndDate,
    Numbered,
}

fn range_kind(local: &str) -> Option<RangeKind> {
    hashify::map!(local.as_bytes(), RangeKind,
        "NoEndRecurrence" => RangeKind::NoEnd,
        "EndDateRecurrence" => RangeKind::EndDate,
        "NumberedRecurrence" => RangeKind::Numbered,
    )
    .copied()
}

ews_fields! {
    struct PatternScratch {
        interval: "Interval" => i32,
        days_of_week: "DaysOfWeek" => DaysOfWeek,
        day_of_week_index: "DayOfWeekIndex" => DayOfWeekIndex,
        day_of_month: "DayOfMonth" => i32,
        month: "Month" => MonthName,
        first_day_of_week: "FirstDayOfWeek" => DayOfWeek,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct RangeDate(XsDate);

impl XmlValue<'_> for RangeDate {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        let text = text.trim_ascii().as_bytes();
        XsDate::parse(text)
            .or_else(|| {
                XsDateTime::parse(text).map(|parsed| XsDate {
                    year: parsed.local.year,
                    month: parsed.local.month,
                    day: parsed.local.day,
                    zone: parsed.zone,
                })
            })
            .map(RangeDate)
    }
}

impl<'x> EwsValue<'x> for RangeDate {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.value("date")
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        EwsValue::write(&self.0, w, local);
    }
}

ews_fields! {
    struct RangeScratch {
        start_date: "StartDate" => RangeDate,
        end_date: "EndDate" => RangeDate,
        number_of_occurrences: "NumberOfOccurrences" => i32,
    }
}

pub fn required<T>(p: &Parser<'_>, value: Option<T>, name: &'static str) -> Result<T> {
    value.ok_or_else(|| p.error(ParseErrorKind::MissingElement(name)))
}

impl RelativeYearly {
    pub fn parse_fields(p: &mut Parser<'_>) -> Result<Self> {
        let mut scratch = PatternScratch::default();
        while let Some(child) = p.child()? {
            if !scratch.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Self::from_scratch(p, &scratch)
    }

    fn from_scratch(p: &Parser<'_>, scratch: &PatternScratch) -> Result<Self> {
        Ok(RelativeYearly {
            days_of_week: required(p, scratch.days_of_week, "DaysOfWeek")?,
            index: required(p, scratch.day_of_week_index, "DayOfWeekIndex")?,
            month: required(p, scratch.month, "Month")?,
        })
    }

    pub fn write_fields(&self, w: &mut XmlWriter<'_>) {
        self.days_of_week.write(w, "DaysOfWeek");
        self.index.write(w, "DayOfWeekIndex");
        self.month.write(w, "Month");
    }
}

impl RecurrencePattern {
    fn parse(p: &mut Parser<'_>, kind: PatternKind) -> Result<Self> {
        let mut scratch = PatternScratch::default();
        while let Some(child) = p.child()? {
            if !scratch.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        let interval = || required(p, scratch.interval, "Interval");
        Ok(match kind {
            PatternKind::RelativeYearly => {
                RecurrencePattern::RelativeYearly(RelativeYearly::from_scratch(p, &scratch)?)
            }
            PatternKind::AbsoluteYearly => RecurrencePattern::AbsoluteYearly {
                day_of_month: required(p, scratch.day_of_month, "DayOfMonth")?,
                month: required(p, scratch.month, "Month")?,
            },
            PatternKind::RelativeMonthly => RecurrencePattern::RelativeMonthly {
                interval: interval()?,
                days_of_week: required(p, scratch.days_of_week, "DaysOfWeek")?,
                index: required(p, scratch.day_of_week_index, "DayOfWeekIndex")?,
            },
            PatternKind::AbsoluteMonthly => RecurrencePattern::AbsoluteMonthly {
                interval: interval()?,
                day_of_month: required(p, scratch.day_of_month, "DayOfMonth")?,
            },
            PatternKind::Weekly => RecurrencePattern::Weekly {
                interval: interval()?,
                days_of_week: required(p, scratch.days_of_week, "DaysOfWeek")?,
                first_day_of_week: scratch.first_day_of_week,
            },
            PatternKind::Daily => RecurrencePattern::Daily {
                interval: interval()?,
            },
            PatternKind::DailyRegeneration => RecurrencePattern::DailyRegeneration {
                interval: interval()?,
            },
            PatternKind::WeeklyRegeneration => RecurrencePattern::WeeklyRegeneration {
                interval: interval()?,
            },
            PatternKind::MonthlyRegeneration => RecurrencePattern::MonthlyRegeneration {
                interval: interval()?,
            },
            PatternKind::YearlyRegeneration => RecurrencePattern::YearlyRegeneration {
                interval: interval()?,
            },
        })
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        let (name, interval) = match self {
            RecurrencePattern::RelativeYearly(_) => ("RelativeYearlyRecurrence", None),
            RecurrencePattern::AbsoluteYearly { .. } => ("AbsoluteYearlyRecurrence", None),
            RecurrencePattern::RelativeMonthly { interval, .. } => {
                ("RelativeMonthlyRecurrence", Some(*interval))
            }
            RecurrencePattern::AbsoluteMonthly { interval, .. } => {
                ("AbsoluteMonthlyRecurrence", Some(*interval))
            }
            RecurrencePattern::Weekly { interval, .. } => ("WeeklyRecurrence", Some(*interval)),
            RecurrencePattern::Daily { interval } => ("DailyRecurrence", Some(*interval)),
            RecurrencePattern::DailyRegeneration { interval } => {
                ("DailyRegeneration", Some(*interval))
            }
            RecurrencePattern::WeeklyRegeneration { interval } => {
                ("WeeklyRegeneration", Some(*interval))
            }
            RecurrencePattern::MonthlyRegeneration { interval } => {
                ("MonthlyRegeneration", Some(*interval))
            }
            RecurrencePattern::YearlyRegeneration { interval } => {
                ("YearlyRegeneration", Some(*interval))
            }
        };
        w.start(T, name);
        if let Some(interval) = interval {
            interval.write(w, "Interval");
        }
        match self {
            RecurrencePattern::RelativeYearly(yearly) => yearly.write_fields(w),
            RecurrencePattern::AbsoluteYearly {
                day_of_month,
                month,
            } => {
                day_of_month.write(w, "DayOfMonth");
                month.write(w, "Month");
            }
            RecurrencePattern::RelativeMonthly {
                days_of_week,
                index,
                ..
            } => {
                days_of_week.write(w, "DaysOfWeek");
                index.write(w, "DayOfWeekIndex");
            }
            RecurrencePattern::AbsoluteMonthly { day_of_month, .. } => {
                day_of_month.write(w, "DayOfMonth");
            }
            RecurrencePattern::Weekly {
                days_of_week,
                first_day_of_week,
                ..
            } => {
                days_of_week.write(w, "DaysOfWeek");
                if let Some(first) = first_day_of_week {
                    first.write(w, "FirstDayOfWeek");
                }
            }
            _ => {}
        }
        w.end(T, name);
    }
}

impl RecurrenceRange {
    fn parse(p: &mut Parser<'_>, kind: RangeKind) -> Result<Self> {
        let mut scratch = RangeScratch::default();
        while let Some(child) = p.child()? {
            if !scratch.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Ok(RecurrenceRange {
            start: required(p, scratch.start_date, "StartDate")?.0,
            end: match kind {
                RangeKind::NoEnd => RecurrenceEnd::NoEnd,
                RangeKind::EndDate => {
                    RecurrenceEnd::EndDate(required(p, scratch.end_date, "EndDate")?.0)
                }
                RangeKind::Numbered => RecurrenceEnd::Numbered(required(
                    p,
                    scratch.number_of_occurrences,
                    "NumberOfOccurrences",
                )?),
            },
        })
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        let name = match self.end {
            RecurrenceEnd::NoEnd => "NoEndRecurrence",
            RecurrenceEnd::EndDate(_) => "EndDateRecurrence",
            RecurrenceEnd::Numbered(_) => "NumberedRecurrence",
        };
        w.start(T, name);
        EwsValue::write(&self.start, w, "StartDate");
        match &self.end {
            RecurrenceEnd::NoEnd => {}
            RecurrenceEnd::EndDate(date) => EwsValue::write(date, w, "EndDate"),
            RecurrenceEnd::Numbered(count) => count.write(w, "NumberOfOccurrences"),
        }
        w.end(T, name);
    }
}

impl<'x> EwsValue<'x> for Recurrence {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut pattern = None;
        let mut range = None;
        while let Some(child) = p.child()? {
            if let Some(kind) = pattern_kind(child.local) {
                p.expect_types(&child)?;
                pattern = Some(RecurrencePattern::parse(p, kind)?);
            } else if let Some(kind) = range_kind(child.local) {
                p.expect_types(&child)?;
                range = Some(RecurrenceRange::parse(p, kind)?);
            } else {
                p.skip()?;
            }
        }
        Ok(Recurrence {
            pattern: required(p, pattern, "RecurrencePattern")?,
            range: required(p, range, "RecurrenceRange")?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.pattern.write(w);
        self.range.write(w);
        w.end(T, local);
    }
}
