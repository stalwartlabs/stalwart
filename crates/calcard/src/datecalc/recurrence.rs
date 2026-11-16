/*
 * SPDX-FileCopyrightText: 2025 Andrew Gallant <jamslam@gmail.com> (https://github.com/BurntSushi/bttf)
 *
 * SPDX-License-Identifier: Unlicense OR MIT
 */

//! The RFC 5545 recurrence rule engine.
//!
//! Ported from [`bttf`](https://github.com/BurntSushi/bttf) by Andrew Gallant,
//! with these changes:
//!
//! * `anyhow` errors became [`ValidationError`], so the crate stays free of an
//!   error reporting dependency and a bad rule is reported the way the rest of
//!   calcard reports one.
//! * Instants are [`ZonedDateTime`] rather than [`jiff::Zoned`], because
//!   RFC 5545 has floating values, which carry no zone, and because a
//!   `ZonedDateTime` is `Copy` and so costs no reference counting per instance.
//! * Ambiguous wall clock readings follow RFC 5545 section 3.3.5 through
//!   [`Tz::from_local`]; see [`RecurrenceSet::pop_civil`].
//! * COUNT and an iteration budget were added, neither of which `bttf` needs.

use super::error::ValidationError;
use crate::common::timezone::{Tz, ZonedDateTime};
use crate::datecalc::weekdate::{WeekDate, first_of_week, last_of_week, weeks_in_year};
use crate::icalendar::ICalendarFrequency;
use jiff::{
    SignedDuration, Span, Timestamp, ToSpan,
    civil::{DateTime, Time, Weekday},
};
use std::{
    cmp::Ordering,
    ops::{Range, RangeInclusive},
    sync::Arc,
};

/// Stops an expansion that keeps finding nothing.
///
/// A rule such as `FREQ=SECONDLY;BYMONTH=2;BYMONTHDAY=31` matches no date at
/// all, so without a bound the iterator would step one second at a time up to
/// the year 9999. The budget counts attempts that yield no instance and is
/// reset whenever one is produced, so a long but productive series is never
/// cut short.
pub const MAX_ITER_LOOP: u32 = 100_000;

pub const MAX_PERIOD_CANDIDATES: usize = 100_000;

pub const MAX_EXPANSION_WORK: usize = 10_000_000;

pub const MAX_UNPRODUCTIVE_WORK: usize = 1_000_000;

const ALL_WEEKDAYS: u8 = 0b111_1111;

/// The RFC 5545 recurrence rule implementation.
#[derive(Clone, Debug)]
pub struct RecurrenceRule {
    inner: Arc<RecurrenceRuleInner>,
}

#[derive(Debug)]
struct RecurrenceRuleInner {
    freq: ICalendarFrequency,
    start: ZonedDateTime,
    civil_start: DateTime,
    until: Option<ZonedDateTime>,
    count: Option<u32>,
    interval: Span,
    by_month: Box<[i8]>,
    // can be negative
    by_week: Box<[i8]>,
    // can be negative
    by_year_day: Box<[i16]>,
    // can be negative
    by_month_day: Box<[i8]>,
    // can be negative
    by_week_day: Box<[ByWeekday]>,
    by_hour: Box<[i8]>,
    by_minute: Box<[i8]>,
    by_second: Box<[i8]>,
    // can be negative
    by_set_pos: Box<[i32]>,
    week_start: Weekday,
}

impl RecurrenceRule {
    /// Returns a builder for constructing a `RecurrenceRule`.
    ///
    /// The frequency and the starting point are the only two things required
    /// to create a rule.
    pub fn builder(freq: ICalendarFrequency, start: ZonedDateTime) -> RecurrenceRuleBuilder {
        RecurrenceRuleBuilder::new(freq, start)
    }

    /// Returns an iterator over all datetimes in this recurrence rule.
    ///
    /// Note that the iterator may be "infinite," in the sense that it returns
    /// datetimes all the way up to Jiff's supported maximum datetime. Callers
    /// should therefore either specify an `RecurrenceRuleBuilder::until` rule
    /// or call `take(N)` to limit the number of datetimes to `N`.
    pub fn iter(&self) -> RecurrenceIter<'_> {
        RecurrenceIter {
            rule: self,
            set: RecurrenceSet::new(),
            cur: Some((0, self.inner.civil_start)),
            remaining: self.inner.count,
            lead: Lead::Unchecked,
            budget: MAX_ITER_LOOP,
            work: MAX_EXPANSION_WORK,
            unproductive: usize::MAX,
            period_work: 0,
            exhausted: false,
            gap_instants: Vec::new(),
        }
    }

    /// Returns the time zone that datetimes emitted by this rule should be in.
    pub fn tz(&self) -> Tz {
        self.inner.start.timezone()
    }
}

impl<'r> IntoIterator for &'r RecurrenceRule {
    type IntoIter = RecurrenceIter<'r>;
    type Item = ZonedDateTime;

    fn into_iter(self) -> RecurrenceIter<'r> {
        self.iter()
    }
}

/// An expander for a single RFC 5545 recurrence rule and datetime.
#[derive(Clone, Debug)]
struct Expander<'a> {
    /// The rule we are expanding.
    rule: &'a RecurrenceRule,
    /// The "current" datetime we are expanding.
    ///
    /// How this datetime is used depends on the frequency we are expanding
    /// for.
    cur: DateTime,
}

impl<'a> Expander<'a> {
    /// Expand into the set provided.
    fn expand(&self, set: &mut RecurrenceSet) {
        set.begin_period(self.cur);
        match self.frequency() {
            ICalendarFrequency::Yearly => self.yearly(set),
            ICalendarFrequency::Monthly => self.monthly(set),
            ICalendarFrequency::Weekly => self.weekly(set),
            ICalendarFrequency::Daily => self.daily(set),
            ICalendarFrequency::Hourly => self.hourly(set),
            ICalendarFrequency::Minutely => self.minutely(set),
            ICalendarFrequency::Secondly => self.secondly(set),
        }
        set.canonicalize(self.rule());

        // When BYSETPOS is present, we need to convert all of our civil
        // datetimes to zoned datetimes, check them with our start/until rules
        // and put them into another set. Only when we do this can we process
        // the BYSETPOS rule. In particular, BYSETPOS may contain negative
        // values, which fundamentally requires knowing the length of the
        // recurrence set.
        //
        // We could in theory do better here in the case where BYSETPOS is only
        // positive values, but it seems like it's most commonly used with
        // negative values. Moreover, BYSETPOS is probably rare by itself,
        // so it's not clear that we need to care too much about this extra
        // shuffling.
        if self.has_by_set_pos() {
            set.select_positions(self.rule);
        } else {
            let start = self.rule().civil_start;
            set.seek(self.rule(), start.checked_sub(1.day()).unwrap_or(start));
        }
    }

    /// Populate `set` with datetimes according to this rule at a YEARLY
    /// frequency.
    fn yearly(&self, set: &mut RecurrenceSet) {
        set.insert(self.cur);
        if self.has_by_week_day() {
            if self.has_by_week() {
                self.expand_by_week(set);
                self.limit_by_month(set);
            } else if self.has_by_month() {
                self.expand_by_month(set);
                self.expand_by_week_day_monthly(set);
            } else {
                self.expand_by_week_day_yearly(set);
            }
            self.limit_by_year_day(set);
            self.limit_by_month_day(set);
        } else if self.has_by_week() {
            self.expand_by_week(set);
            // Note that we use slightly different expansionary
            // behavior here for `by_week` than for other things[1].
            // For example, at YEARLY frequency with BYMONTH={2,5},
            // you'll get two datetimes in February and May with the
            // day and time of the starting point. You don't get every
            // day in the specified months. But when `by_week` is
            // present, you get every day in each week specified.
            //
            // This is... somewhat odd. But I guess makes sense for
            // certain kinds of expressions. And it's also what
            // Python's `dateutil` does. So we do the same.
            //
            // [1]: https://stackoverflow.com/questions/48064349
            self.limit_by_month(set);
            self.limit_by_year_day(set);
            self.limit_by_month_day(set);
        } else if self.has_by_month() && (self.has_by_month_day() || !self.has_by_year_day()) {
            self.expand_by_month(set);
            self.expand_by_month_day(set);
            self.limit_by_year_day(set);
        } else if self.has_by_month() {
            self.expand_by_year_day(set);
            self.limit_by_month(set);
        } else if self.has_by_month_day() {
            set.expand(|dt| {
                (1..=12).filter_map(move |month| dt.with().month(month).day(1).build().ok())
            });
            self.expand_by_month_day(set);
            self.limit_by_year_day(set);
        } else if self.has_by_year_day() {
            self.expand_by_year_day(set);
        }
        self.expand_by_hour(set);
        self.expand_by_minute(set);
        self.expand_by_second(set);
    }

    /// Populate `set` with datetimes according to this rule at a MONTHLY
    /// frequency.
    fn monthly(&self, set: &mut RecurrenceSet) {
        // N.B. BYWEEKNO and BYYEARDAY are not allowed here.
        if !self.satisfies_by_month(self.cur) {
            return;
        }

        set.insert(self.cur);
        if self.has_by_week_day() {
            self.expand_by_week_day_monthly(set);
            self.limit_by_month_day(set);
        } else {
            self.expand_by_month_day(set);
        }
        self.expand_by_hour(set);
        self.expand_by_minute(set);
        self.expand_by_second(set);
    }

    /// Populate `set` with datetimes according to this rule at a WEEKLY
    /// frequency.
    fn weekly(&self, set: &mut RecurrenceSet) {
        // N.B. BYWEEKNO, BYYEARDAY and BYMONTHDAY are not allowed here. Also,
        // BYDAY cannot have a numeric weekday.
        set.insert(self.cur);
        self.expand_by_week_day_weekly(set);
        // BYMONTH limits each day the week expands to, not the day the week
        // is anchored on. A week runs across a month boundary often enough
        // that testing the anchor instead would both admit days outside the
        // requested months and discard days inside them.
        self.limit_by_month(set);
        self.expand_by_hour(set);
        self.expand_by_minute(set);
        self.expand_by_second(set);
    }

    /// Populate `set` with datetimes according to this rule at a DAILY
    /// frequency.
    fn daily(&self, set: &mut RecurrenceSet) {
        // N.B. BYWEEKNO and BYYEARDAY are not allowed here. Also, BYDAY
        // cannot have a numeric weekday. I get the restriction on BYDAY, but
        // it seems like BYWEEKNO and BYYEARDAY could be trivially supported
        // in exactly the same way that BYMONTH and BYMONTHDAY are supported
        // below.
        //
        // This is just so deliciously easy compared to YEARLY...
        if !self.satisfies_by_month(self.cur) {
            return;
        }
        if !self.satisfies_by_month_day(self.cur) {
            return;
        }
        if !self.satisfies_by_week_day(self.cur) {
            return;
        }
        set.insert(self.cur);
        self.expand_by_hour(set);
        self.expand_by_minute(set);
        self.expand_by_second(set);
    }

    /// Populate `set` with datetimes according to this rule at a HOURLY
    /// frequency.
    fn hourly(&self, set: &mut RecurrenceSet) {
        // N.B. BYWEEKNOis not allowed here. Also, BYDAY cannot have a numeric
        // weekday.
        if !self.satisfies_by_month(self.cur) {
            return;
        }
        if !self.satisfies_by_year_day(self.cur) {
            return;
        }
        if !self.satisfies_by_month_day(self.cur) {
            return;
        }
        if !self.satisfies_by_week_day(self.cur) {
            return;
        }
        if !self.satisfies_by_hour(self.cur) {
            return;
        }
        set.insert(self.cur);
        self.expand_by_minute(set);
        self.expand_by_second(set);
    }

    /// Populate `set` with datetimes according to this rule at a MINUTELY
    /// frequency.
    fn minutely(&self, set: &mut RecurrenceSet) {
        // N.B. BYWEEKNOis not allowed here. Also, BYDAY cannot have a numeric
        // weekday.
        if !self.satisfies_by_month(self.cur) {
            return;
        }
        if !self.satisfies_by_year_day(self.cur) {
            return;
        }
        if !self.satisfies_by_month_day(self.cur) {
            return;
        }
        if !self.satisfies_by_week_day(self.cur) {
            return;
        }
        if !self.satisfies_by_hour(self.cur) {
            return;
        }
        if !self.satisfies_by_minute(self.cur) {
            return;
        }
        set.insert(self.cur);
        self.expand_by_second(set);
    }

    /// Populate `set` with datetimes according to this rule at a SECONDLY
    /// frequency.
    fn secondly(&self, set: &mut RecurrenceSet) {
        // N.B. BYWEEKNOis not allowed here. Also, BYDAY cannot have a numeric
        // weekday.
        if !self.satisfies_by_month(self.cur) {
            return;
        }
        if !self.satisfies_by_year_day(self.cur) {
            return;
        }
        if !self.satisfies_by_month_day(self.cur) {
            return;
        }
        if !self.satisfies_by_week_day(self.cur) {
            return;
        }
        if !self.satisfies_by_hour(self.cur) {
            return;
        }
        if !self.satisfies_by_minute(self.cur) {
            return;
        }
        if !self.satisfies_by_second(self.cur) {
            return;
        }
        set.insert(self.cur);
    }

    /// Returns true if there is at least one BYMONTH value.
    fn has_by_month(&self) -> bool {
        !self.rule().by_month.is_empty()
    }

    /// Returns true if there is at least one BYWEEKNO value.
    fn has_by_week(&self) -> bool {
        !self.rule().by_week.is_empty()
    }

    /// Returns true if there is at least one BYYEARDAY value.
    fn has_by_year_day(&self) -> bool {
        !self.rule().by_year_day.is_empty()
    }

    /// Returns true if there is at least one BYMONTHDAY value.
    fn has_by_month_day(&self) -> bool {
        !self.rule().by_month_day.is_empty()
    }

    /// Returns true if there is at least one BYDAY value.
    fn has_by_week_day(&self) -> bool {
        !self.rule().by_week_day.is_empty()
    }

    /// Returns true if there is at least one BYHOUR value.
    fn has_by_hour(&self) -> bool {
        !self.rule().by_hour.is_empty()
    }

    /// Returns true if there is at least one BYMINUTE value.
    fn has_by_minute(&self) -> bool {
        !self.rule().by_minute.is_empty()
    }

    /// Returns true if there is at least one BYSECOND value.
    fn has_by_second(&self) -> bool {
        !self.rule().by_second.is_empty()
    }

    /// Returns true if there is at least one BYSETPOS value.
    fn has_by_set_pos(&self) -> bool {
        !self.rule().by_set_pos.is_empty()
    }

    /// Returns true if and only if the given datetime satisfies the
    /// BYMONTH rule.
    fn satisfies_by_month(&self, dt: DateTime) -> bool {
        !self.has_by_month() || self.rule().by_month.contains(&dt.month())
    }

    /// Returns true if and only if the given datetime satisfies the
    /// BYYEARDAY rule.
    fn satisfies_by_year_day(&self, dt: DateTime) -> bool {
        if !self.has_by_year_day() {
            return true;
        }
        let positive = dt.day_of_year();
        // Minus 1 because -1 is the last day of the year, and the days of the
        // year are 1-indexed.
        let negative = positive - 1 - dt.days_in_year();
        self.rule().by_year_day.binary_search(&positive).is_ok()
            || self.rule().by_year_day.binary_search(&negative).is_ok()
    }

    /// Returns true if and only if the given datetime satisfies the
    /// BYMONTHDAY rule.
    fn satisfies_by_month_day(&self, dt: DateTime) -> bool {
        if !self.has_by_month_day() {
            return true;
        }
        let positive = dt.day();
        // Minus 1 because -1 is the last day of month, and the days of the
        // month are 1-indexed.
        let negative = positive - 1 - dt.days_in_month();
        self.rule().by_month_day.binary_search(&positive).is_ok()
            || self.rule().by_month_day.binary_search(&negative).is_ok()
    }

    /// Returns true only if the weekday for the given datetime is allowed by
    /// this recurrence rule.
    ///
    /// # Panics
    ///
    /// This panics when this is a numbered weekday. In effect, this shouldn't
    /// be used in contexts where BYDAY can contain numbered weekdays. That
    /// limits this to YEARLY and MONTHLY frequencies (and in the YEARLY case,
    /// only when BYWEEKNO is not used).
    fn satisfies_by_week_day(&self, dt: DateTime) -> bool {
        if !self.has_by_week_day() {
            return true;
        }
        let wd = dt.weekday();
        self.rule().by_week_day.iter().any(|bywd| bywd.is_match(wd))
    }

    /// Returns true if and only if the given datetime satisfies the
    /// BYHOUR rule.
    fn satisfies_by_hour(&self, dt: DateTime) -> bool {
        !self.has_by_hour() || self.rule().by_hour.contains(&dt.hour())
    }

    /// Returns true if and only if the given datetime satisfies the
    /// BYMINUTE rule.
    fn satisfies_by_minute(&self, dt: DateTime) -> bool {
        !self.has_by_minute() || self.rule().by_minute.contains(&dt.minute())
    }

    /// Returns true if and only if the given datetime satisfies the
    /// BYSECOND rule.
    fn satisfies_by_second(&self, dt: DateTime) -> bool {
        !self.has_by_second() || self.rule().by_second.contains(&dt.second())
    }

    /// Removes any element in the given set whose month is
    /// inconsistent with the BYMONTH rule.
    ///
    /// If the BYMONTH rule is empty, then this is a no-op.
    fn limit_by_month(&self, set: &mut RecurrenceSet) {
        if !self.has_by_month() {
            return;
        }
        set.retain(|dt| self.satisfies_by_month(*dt));
    }

    /// Removes any element in the given set whose day of the year is
    /// inconsistent with the BYYEARDAY rule.
    ///
    /// If the BYYEARDAY rule is empty, then this is a no-op.
    fn limit_by_year_day(&self, set: &mut RecurrenceSet) {
        if !self.has_by_year_day() {
            return;
        }
        set.retain(|dt| self.satisfies_by_year_day(*dt));
    }

    /// Removes any element in the given set whose day of the month is
    /// inconsistent with the BYMONTHDAY rule.
    ///
    /// If the BYMONTHDAY rule is empty, then this is a no-op.
    fn limit_by_month_day(&self, set: &mut RecurrenceSet) {
        if !self.has_by_month_day() {
            return;
        }
        set.retain(|dt| self.satisfies_by_month_day(*dt));
    }

    /// When the rule has a non-empty number of BYMONTH values, then this
    /// expands every datetime in the given set with the corresponding
    /// months.
    fn expand_by_month(&self, set: &mut RecurrenceSet) {
        if !self.has_by_month() {
            return;
        }
        set.expand(|dt| self.iter_by_month(dt))
    }

    /// When the rule has a non-empty number of BYWEEKNO values, then this
    /// expands every datetime in the given set with the corresponding
    /// week numbers.
    fn expand_by_week(&self, set: &mut RecurrenceSet) {
        if !self.has_by_week() {
            return;
        }
        set.expand(|dt| self.iter_by_week(dt))
    }

    /// When the rule has a non-empty number of BYYEARDAY values, then this
    /// expands every datetime in the given set with the corresponding
    /// year days.
    fn expand_by_year_day(&self, set: &mut RecurrenceSet) {
        if !self.has_by_year_day() {
            return;
        }
        set.expand(|dt| self.iter_by_year_day(dt))
    }

    /// When the rule has a non-empty number of BYMONTHDAY values, then this
    /// expands every datetime in the given set with the corresponding
    /// month days.
    fn expand_by_month_day(&self, set: &mut RecurrenceSet) {
        if !self.has_by_month_day() {
            return;
        }
        set.expand(|dt| self.iter_by_month_day(dt))
    }

    /// When the rule has a non-empty number of BYDAY values, then this
    /// expands every datetime in the given set with the corresponding
    /// BYDAY rules at a YEARLY frequency.
    fn expand_by_week_day_yearly(&self, set: &mut RecurrenceSet) {
        if !self.has_by_week_day() {
            return;
        }
        set.expand(|dt| self.iter_by_week_day_yearly(dt))
    }

    /// When the rule has a non-empty number of BYDAY values, then this
    /// expands every datetime in the given set with the corresponding
    /// BYDAY rules at a MONTHLY frequency.
    fn expand_by_week_day_monthly(&self, set: &mut RecurrenceSet) {
        if !self.has_by_week_day() {
            return;
        }
        set.expand(|dt| self.iter_by_week_day_monthly(dt))
    }

    /// When the rule has a non-empty number of BYDAY values, then this
    /// expands every datetime in the given set with the corresponding
    /// BYDAY rules at a WEEKLY frequency.
    ///
    /// # Panics
    ///
    /// When any `ByWeekday` is `Numbered`. RFC 5545 doesn't permit that
    /// construction at anything other than YEARLY and MONTHLY frequency.
    fn expand_by_week_day_weekly(&self, set: &mut RecurrenceSet) {
        if !self.has_by_week_day() {
            return;
        }
        set.expand(|dt| self.iter_by_week_day_weekly(dt))
    }

    /// When the rule has a non-empty number of BYHOUR values, then this
    /// expands every datetime in the given set with the corresponding
    /// hours.
    fn expand_by_hour(&self, set: &mut RecurrenceSet) {
        if self.has_by_hour() {
            set.hours = Axis::Rule;
        }
    }

    /// When the rule has a non-empty number of BYMINUTE values, then this
    /// expands every datetime in the given set with the corresponding
    /// minutes.
    fn expand_by_minute(&self, set: &mut RecurrenceSet) {
        if self.has_by_minute() {
            set.minutes = Axis::Rule;
        }
    }

    /// When the rule has a non-empty number of BYSECOND values, then this
    /// expands every datetime in the given set with the corresponding
    /// seconds.
    fn expand_by_second(&self, set: &mut RecurrenceSet) {
        if self.has_by_second() {
            set.seconds = Axis::Rule;
        }
    }

    /// Returns an iterator over the BYMONTH values in this recurrence rule.
    ///
    /// The values returned are datetimes with each of the corresponding
    /// months. The other parts of the datetime are copied from `dt`.
    ///
    /// If there are no month values, then this iterator does not yield
    /// any items.
    fn iter_by_month(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        let day = self.rule().civil_start.day();
        // BYMONTH is always followed here by a rule that sets the day of the
        // month, so when the starting point's day does not exist in a month
        // the month itself must still be kept: `DTSTART` on October 31 with
        // `BYMONTH=11;BYDAY=4SU` means the fourth Sunday of November, not
        // nothing at all. Only the month is carried in that case.
        let day_is_replaced = self.has_by_week_day() || self.has_by_month_day();
        self.rule()
            .by_month
            .iter()
            .copied()
            .filter_map(move |month| {
                // This is subtle, but in the case where BYMONTHDAY is set, the
                // starting point is Feb 29 and all other date modifying rules are
                // empty, then the day here could have been constrained to Feb 28.
                // In which case, we really should pull the day from the actual
                // starting point.
                //
                // (I kinda wonder if we should do this more broadly, but it
                // doesn't appear necessary.)
                dt.with().month(month).day(day).build().ok().or_else(|| {
                    day_is_replaced
                        .then(|| dt.with().month(month).day(1).build().ok())
                        .flatten()
                })
            })
    }

    /// Returns an iterator over the BYWEEKNO values in this recurrence rule.
    ///
    /// The values returned are the days of the year of `dt` whose week number,
    /// in the week year the day belongs to, matches a BYWEEKNO value, limited
    /// to the BYDAY weekdays when there are any. The time is copied from `dt`.
    ///
    /// If there are no week number values, then this iterator does not yield
    /// any items.
    fn iter_by_week(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        let rule = self.rule();
        let week_start = rule.week_start;
        let year = dt.year();
        let time = dt.time();
        let offsets = match rule.by_week_day.iter().fold(0u8, |mask, weekday| {
            mask | (1 << weekday.weekday().since(week_start))
        }) {
            0 => ALL_WEEKDAYS,
            mask => mask,
        };
        let first_offset = i64::from(offsets.trailing_zeros());
        let last_offset = i64::from(u8::BITS - 1 - offsets.leading_zeros());
        [year.saturating_sub(1), year, year.saturating_add(1)]
            .into_iter()
            .flat_map(move |week_year| {
                let weeks_in_year = weeks_in_year(week_start, week_year);
                rule.by_week.iter().filter_map(move |&week| {
                    let week = if week.is_negative() {
                        weeks_in_year.checked_add(week + 1)?
                    } else {
                        week
                    };
                    if (week_year < year && week != weeks_in_year)
                        || (week_year > year && week != 1)
                    {
                        return None;
                    }
                    WeekDate::new(week_start, week_year, week, week_start)?.date()
                })
            })
            .filter_map(move |first_day| match first_offset {
                0 => Some(first_day),
                offset => first_day.checked_add(offset.days()).ok(),
            })
            .flat_map(move |first_match| {
                (first_offset..=last_offset)
                    .zip(std::iter::successors(Some(first_match), |day| {
                        day.tomorrow().ok()
                    }))
                    .filter(move |(offset, day)| offsets & (1 << offset) != 0 && day.year() == year)
                    .map(move |(_, day)| day.to_datetime(time))
            })
    }

    /// Returns an iterator over the BYYEARDAY values in this recurrence rule.
    ///
    /// The values returned are datetimes with each of the corresponding
    /// days of the year. The other parts of the datetime are copied from `dt`.
    ///
    /// This handles any negative day of the year values according to the
    /// number of days of the year in `dt`.
    ///
    /// If there are no day of the year values, then this iterator does not
    /// yield any items.
    fn iter_by_year_day(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        let days_in_year = dt.days_in_year();
        self.rule()
            .by_year_day
            .iter()
            .copied()
            .filter_map(move |mut day| {
                if day.is_negative() {
                    // Add 1 because -1 is the last day of the year, and the days
                    // of the year are 1-indexed.
                    day = days_in_year.checked_add(day + 1)?;
                }
                dt.with().day_of_year(day).build().ok()
            })
    }

    /// Returns an iterator over the BYMONTHDAY values in this recurrence rule.
    ///
    /// The values returned are datetimes with each of the corresponding
    /// month days. The other parts of the datetime are copied from `dt`.
    ///
    /// This handles any negative month day values according to the number of
    /// days of the month in `dt`.
    ///
    /// If there are no month day values, then this iterator does not yield
    /// any items.
    fn iter_by_month_day(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        let days_in_month = dt.days_in_month();
        self.rule()
            .by_month_day
            .iter()
            .copied()
            .filter_map(move |mut day| {
                if day.is_negative() {
                    // Add 1 because -1 is the last day of month, and the days of
                    // the month are 1-indexed.
                    day = days_in_month.checked_add(day + 1)?;
                }
                dt.with().day(day).build().ok()
            })
    }

    /// Returns an iterator over the BYDAY values in this recurrence rule at
    /// a YEARLY frequency.
    ///
    /// The values returned are datetimes with each of the corresponding
    /// weekdays. The other parts of the datetime are copied from `dt`.
    ///
    /// This handles any negative numbered weekday values. Negative values are
    /// interpreted with respect to the end of the year. Where as positive
    /// values are interpreted with respect to the beginning of the year.
    /// (Where the year is taken from `dt`.)
    ///
    /// If there are no week day values, then this iterator does not yield
    /// any items.
    fn iter_by_week_day_yearly(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        let start = dt.first_of_year();
        let end = dt.last_of_year();
        self.rule()
            .by_week_day
            .iter()
            .copied()
            .flat_map(move |weekday| weekday.iter_yearly(start, end))
    }

    /// Returns an iterator over the BYDAY values in this recurrence rule at
    /// a MONTHLY frequency.
    ///
    /// The values returned are datetimes with each of the corresponding
    /// weekdays. The other parts of the datetime are copied from `dt`.
    ///
    /// This handles any negative numbered weekday values. Negative values are
    /// interpreted with respect to the end of the month. Where as positive
    /// values are interpreted with respect to the beginning of the month.
    /// (Where the month is taken from `dt`.)
    ///
    /// If there are no week day values, then this iterator does not yield
    /// any items.
    fn iter_by_week_day_monthly(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        let start = dt.first_of_month();
        let end = dt.last_of_month();
        self.rule()
            .by_week_day
            .iter()
            .copied()
            .flat_map(move |weekday| weekday.iter_monthly(start, end))
    }

    /// Returns an iterator over the BYDAY values in this recurrence rule at
    /// a WEEKLY frequency.
    ///
    /// The values returned are datetimes with each of the corresponding
    /// weekdays. The other parts of the datetime are copied from `dt`.
    ///
    /// If there are no week day values, then this iterator does not yield
    /// any items.
    ///
    /// # Panics
    ///
    /// When any `ByWeekday` is `Numbered`. RFC 5545 doesn't permit that
    /// construction at anything other than YEARLY and MONTHLY frequency.
    fn iter_by_week_day_weekly(&self, dt: DateTime) -> impl Iterator<Item = DateTime> {
        // I tried writing this as one iterator chain, but it was a complex
        // mess. Since I already defined `Either` for other uses, I felt it
        // was simpler to just use it here.
        let Some(start) = first_of_week(self.rule().week_start, dt.date()) else {
            return Either::Left(std::iter::empty());
        };
        let Some(end) = last_of_week(self.rule().week_start, dt.date()) else {
            return Either::Left(std::iter::empty());
        };
        let Ok(start) = dt.with().date(start).build() else {
            return Either::Left(std::iter::empty());
        };
        let Ok(end) = dt.with().date(end).build() else {
            return Either::Left(std::iter::empty());
        };

        Either::Right(
            self.rule()
                .by_week_day
                .iter()
                .copied()
                .flat_map(move |weekday| weekday.iter_weekly(start, end)),
        )
    }

    /// Returns the frequency at which we are generating datetimes.
    ///
    /// The frequency determines how we interpret the `by_*` data in our rule
    /// to generate datetimes.
    fn frequency(&self) -> ICalendarFrequency {
        self.rule().freq
    }

    /// Returns the "inner" rule associated with this expander.
    ///
    /// This is somewhat of a misnomer, since `self.rule` is the actual
    /// rule, but this returns the "inner" rule. But the "inner" rule is
    /// where all the goods are.
    fn rule(&self) -> &RecurrenceRuleInner {
        &self.rule.inner
    }
}

#[derive(Clone, Copy, Debug)]
enum Lead {
    Unchecked,
    Held(ZonedDateTime),
    Done,
}

#[derive(Clone, Debug)]
pub struct RecurrenceIter<'r> {
    /// The recurrence rule that we're generating zoned datetimes for.
    rule: &'r RecurrenceRule,
    /// The set of datetimes that we should drain and emit before
    /// incrementing by our interval and refilling the set.
    set: RecurrenceSet,
    /// The interval index along with the current datetime.
    ///
    /// In order to get the next datetime, the interval index should be
    /// incremented by one and then multiplied by the frequency `Span`. This
    /// is done instead of just adding to the previous datetime to avoid
    /// cases where we go from 2025-03-31 -> 2025-04-30 -> 2025-05-30 instead
    /// of 2025-03-31 -> 2025-04-30 -> 2025-05-31.
    ///
    /// When this is `None`, iteration has ceased.
    cur: Option<(i64, DateTime)>,
    /// Instances left to emit under COUNT, if the rule sets one.
    remaining: Option<u32>,
    lead: Lead,
    /// Attempts left before the expansion gives up; see [`MAX_ITER_LOOP`].
    budget: u32,
    work: usize,
    unproductive: usize,
    period_work: usize,
    /// Whether the budget ran out with the rule still unfinished.
    exhausted: bool,
    gap_instants: Vec<Timestamp>,
}

impl<'r> RecurrenceIter<'r> {
    fn expand(&mut self) {
        let Some((_, cur)) = self.cur else { return };
        Expander {
            rule: self.rule,
            cur,
        }
        .expand(&mut self.set);
    }

    fn is_done(&self) -> bool {
        self.cur.is_none() && self.set.is_empty()
    }

    /// Returns whether iteration stopped at the budget rather than at the end
    /// of the rule, so the caller can tell a truncated series from a finished
    /// one.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn with_unproductive_budget(mut self, units: usize) -> Self {
        self.unproductive = units;
        self
    }

    pub fn unproductive_budget(&self) -> usize {
        self.unproductive.saturating_sub(self.set.spent)
    }

    fn period_start(&self, dt: DateTime) -> Option<DateTime> {
        let rule = &self.rule.inner;
        match rule.freq {
            ICalendarFrequency::Yearly => Some(dt.first_of_year().start_of_day()),
            ICalendarFrequency::Monthly => Some(dt.first_of_month().start_of_day()),
            ICalendarFrequency::Weekly => {
                first_of_week(rule.week_start, dt.date()).map(|date| date.to_datetime(Time::MIN))
            }
            ICalendarFrequency::Daily => Some(dt.start_of_day()),
            ICalendarFrequency::Hourly => dt.with().minute(0).second(0).build().ok(),
            ICalendarFrequency::Minutely => dt.with().second(0).build().ok(),
            ICalendarFrequency::Secondly => Some(dt),
        }
    }

    fn skip_ahead(&self, attempt: i64, next: DateTime) -> Option<(i64, DateTime)> {
        let rule = &self.rule.inner;
        if !matches!(
            rule.freq,
            ICalendarFrequency::Hourly
                | ICalendarFrequency::Minutely
                | ICalendarFrequency::Secondly
        ) {
            return None;
        }
        let expander = Expander {
            rule: self.rule,
            cur: next,
        };
        let boundary = if !expander.satisfies_by_month(next)
            || !expander.satisfies_by_year_day(next)
            || !expander.satisfies_by_month_day(next)
            || !expander.satisfies_by_week_day(next)
        {
            next.date().tomorrow().ok()?.to_datetime(Time::MIN)
        } else if rule.freq != ICalendarFrequency::Hourly && !expander.satisfies_by_hour(next) {
            next.with()
                .minute(0)
                .second(0)
                .build()
                .ok()?
                .checked_add(1.hour())
                .ok()?
        } else if rule.freq == ICalendarFrequency::Secondly && !expander.satisfies_by_minute(next) {
            next.with()
                .second(0)
                .build()
                .ok()?
                .checked_add(1.minute())
                .ok()?
        } else {
            return None;
        };
        let step = SignedDuration::try_from(rule.interval).ok()?.as_secs();
        let elapsed = rule.civil_start.duration_until(boundary).as_secs();
        let skipped = attempt.max(elapsed.checked_add(step - 1)? / step);
        let anchor = rule
            .civil_start
            .checked_add(rule.interval.checked_mul(skipped).ok()?)
            .ok()?;
        Some((skipped, anchor))
    }

    fn increment(&self) -> Option<(i64, DateTime)> {
        let (mut attempt, orig) = self.cur?;
        let interval = self.rule.inner.interval;
        loop {
            attempt = attempt.checked_add(1)?;
            let interval = interval.checked_mul(attempt).ok()?;
            let mut next = self.rule.inner.civil_start.checked_add(interval).ok()?;
            if let Some((skipped, anchor)) = self.skip_ahead(attempt, next) {
                attempt = skipped;
                next = anchor;
            }
            // Subtle, but this is not technically required for correctness,
            // since we filter based on `until` when we pop from the
            // recurrence set. The reason we do this is for cases where the
            // recurrence set is always empty (or nearly always). Namely, this
            // lets us "bound" our work even if we aren't visibly producing
            // anything.
            //
            // It is somewhat unfortunate that in order to do this, we need
            // to convert our next datetime to a physical instant. Perhaps
            // we can avoid doing this when the previous size of the recurrence
            // set is non-empty. Why? Because if the recurrence set is getting
            // datetimes in it, then filtering can be applied when we pop from
            // it and this optimization ends up not being necessary.
            //
            // I think one tricky thing here is that just because a recurrence
            // set is empty after expansion for a single interval, that doesn't
            // mean iteration can stop. Because a subsequent interval might
            // generate a non-empty recurrence set.
            if let Some(ref until) = self.rule.inner.until
                && self
                    .rule
                    .tz()
                    .from_local(self.period_start(next).unwrap_or(next))
                    .is_none_or(|start| &start > until)
            {
                return None;
            }
            // In cases where we add N years or N months, the day number can
            // change. For example, in Jiff, 2024-02-29 + 1 year = 2025-02-28.
            // But RFC 5545 wants us to treat it like 2025-02-29, which
            // is invalid and thus ignore such things. So we assume the
            // "constraining" behavior of Jiff (as Temporal calls it) occurs
            // when the result's day number is not equal to the one we started
            // with.
            //
            // When constraining behavior happens, we just continue on and try
            // the next point by adding our interval again. We do this *not*
            // by just continually adding our interval to an ever increasing
            // datetime, which is the natural thing to do. The problem is that
            // constraining behavior is infectious. Once you get, for example,
            // 2025-02-28, adding 3 years will give you 2028-02-28 and so on.
            // You'll never get back to a leap day. So instead, we track our
            // number of attempts and multiply our `Span` as we go.
            //
            // This doesn't account for the other way to get invalid datetimes,
            // which is to end up at a time that is invalid for the given time
            // zone. We handle that when we pop datetimes from the set.
            //
            // This is pretty tricky, but there is an exception to skipping
            // invalid datetimes here. When expansion rules are set that choose
            // the date (instead of using it from the start date), then we DO
            // need to consider the interval instead of skipping over it. This
            // works because if a date-setting expansion rule is present, then
            // the constrained datetime should not remain as part of the set,
            // unless the rule would have otherwise selected it.
            let r = &self.rule.inner;
            match r.freq {
                ICalendarFrequency::Yearly if next.day() != orig.day() => {
                    if r.by_month.is_empty()
                        && r.by_week.is_empty()
                        && r.by_year_day.is_empty()
                        && r.by_month_day.is_empty()
                        && r.by_week_day.is_empty()
                    {
                        continue;
                    }
                }
                ICalendarFrequency::Monthly
                    if next.day() != orig.day()
                        && r.by_week_day.is_empty()
                        && r.by_month_day.is_empty() =>
                {
                    continue;
                }
                _ => {}
            }
            return Some((attempt, next));
        }
    }
}

impl<'r> Iterator for RecurrenceIter<'r> {
    type Item = ZonedDateTime;

    fn next(&mut self) -> Option<ZonedDateTime> {
        match self.lead {
            Lead::Done => self.next_rule(),
            Lead::Held(next) => {
                self.lead = Lead::Done;
                Some(next)
            }
            Lead::Unchecked => {
                self.lead = Lead::Done;
                self.next_lead()
            }
        }
    }
}

impl<'r> RecurrenceIter<'r> {
    fn next_lead(&mut self) -> Option<ZonedDateTime> {
        if self.remaining == Some(0) {
            return None;
        }
        let start = self.rule.inner.start;
        match self.next_rule() {
            Some(first) if first == start || self.yields_start_after(first) => Some(first),
            Some(first) => {
                match self.remaining {
                    Some(0) => {}
                    remaining => {
                        self.remaining = remaining.map(|count| count - 1);
                        self.lead = Lead::Held(first);
                    }
                }
                Some(start)
            }
            None => Some(start),
        }
    }

    fn yields_start_after(&self, first: ZonedDateTime) -> bool {
        let start = self.rule.inner.start;
        let civil_start = self.rule.inner.civil_start;
        if first.naive_local() >= civil_start {
            return false;
        }
        let mut rest = self.clone();
        rest.remaining = None;
        rest.find(|next| *next == start || next.naive_local() >= civil_start) == Some(start)
    }

    fn next_rule(&mut self) -> Option<ZonedDateTime> {
        if self.remaining == Some(0) {
            return None;
        }
        while !self.is_done() {
            if let Some((zdt, in_gap)) = self.set.pop(self.rule) {
                let instant = zdt.to_timestamp();
                if in_gap {
                    self.gap_instants.push(instant);
                } else if self.gap_instants.binary_search(&instant).is_ok() {
                    continue;
                } else if self.gap_instants.last().is_some_and(|last| *last < instant) {
                    self.gap_instants.clear();
                }
                // Producing an instance means the rule is making progress, so
                // the budget starts over.
                self.budget = MAX_ITER_LOOP;
                self.unproductive += std::mem::take(&mut self.period_work);
                self.remaining = self.remaining.map(|count| count - 1);
                return Some(zdt);
            }
            let discarded = self.set.take_spent();
            self.work = self.work.saturating_sub(discarded);
            self.unproductive = self.unproductive.saturating_sub(discarded);
            let Some(budget) = self.budget.checked_sub(1).filter(|_| self.unproductive > 0) else {
                self.exhausted = true;
                return None;
            };
            self.budget = budget;
            self.expand();
            let spent = self.set.take_spent() + 1;
            self.work = self.work.saturating_sub(spent);
            self.period_work = spent.min(self.unproductive);
            self.unproductive -= self.period_work;
            if self.set.overflowed || self.work == 0 {
                self.set.clear();
                self.cur = None;
                self.exhausted = true;
                return None;
            }
            self.cur = self.increment();
        }
        None
    }
}

impl<'r> std::iter::FusedIterator for RecurrenceIter<'r> {}

/// A builder for constructing a valid recurrence rule.
#[derive(Clone, Debug)]
pub struct RecurrenceRuleBuilder {
    freq: ICalendarFrequency,
    start: ZonedDateTime,
    until: Option<ZonedDateTime>,
    count: Option<u32>,
    interval: i32,
    by_month: Vec<i8>,
    by_week: Vec<i8>,
    by_year_day: Vec<i16>,
    by_month_day: Vec<i8>,
    by_week_day: Vec<ByWeekday>,
    by_hour: Vec<i8>,
    by_minute: Vec<i8>,
    by_second: Vec<i8>,
    by_set_pos: Vec<i32>,
    week_start: Weekday,
}

impl RecurrenceRuleBuilder {
    fn new(freq: ICalendarFrequency, start: ZonedDateTime) -> RecurrenceRuleBuilder {
        RecurrenceRuleBuilder {
            freq,
            start,
            until: None,
            count: None,
            interval: 1,
            by_month: vec![],
            by_week: vec![],
            by_year_day: vec![],
            by_month_day: vec![],
            by_week_day: vec![],
            by_hour: vec![],
            by_minute: vec![],
            by_second: vec![],
            by_set_pos: vec![],
            week_start: Weekday::Monday,
        }
    }

    pub fn build(&self) -> Result<RecurrenceRule, ValidationError> {
        fn sort_and_dedup<T: Clone + Ord>(slice: &[T]) -> Box<[T]> {
            let mut vec = slice.to_vec();
            vec.sort();
            vec.dedup();
            vec.into_boxed_slice()
        }

        fn range<T: std::fmt::Display>(
            field: &str,
            value: T,
            start_idx: &str,
            end_idx: &str,
        ) -> ValidationError {
            ValidationError::InvalidFieldValueRange {
                field: field.to_string(),
                value: value.to_string(),
                start_idx: start_idx.to_string(),
                end_idx: end_idx.to_string(),
            }
        }

        if self.interval < 1 {
            return Err(ValidationError::InvalidFieldValue {
                field: "INTERVAL".to_string(),
                value: self.interval.to_string(),
            });
        }
        for &v in self.by_month.iter() {
            if !(1..=12).contains(&v) {
                return Err(range("BYMONTH", v, "1", "12"));
            }
        }
        for &v in self.by_week.iter() {
            if !((-53..=-1).contains(&v) || (1..=53).contains(&v)) {
                return Err(range("BYWEEKNO", v, "-53", "53"));
            }
        }
        for &v in self.by_year_day.iter() {
            if !((-366..=-1).contains(&v) || (1..=366).contains(&v)) {
                return Err(range("BYYEARDAY", v, "-366", "366"));
            }
        }
        for &v in self.by_month_day.iter() {
            if !((-31..=-1).contains(&v) || (1..=31).contains(&v)) {
                return Err(range("BYMONTHDAY", v, "-31", "31"));
            }
        }
        for &v in self.by_week_day.iter() {
            let nth = match v {
                ByWeekday::Any(_) => continue,
                ByWeekday::Numbered { nth, .. } => nth,
            };
            // Firstly, numbered weekdays are only allowed for YEARLY or
            // MONTHLY frequencies, and at YEARLY only when BYWEEKNO is unset.
            if !matches!(
                self.freq,
                ICalendarFrequency::Yearly | ICalendarFrequency::Monthly
            ) || (matches!(self.freq, ICalendarFrequency::Yearly) && !self.by_week.is_empty())
            {
                return Err(ValidationError::InvalidByRuleAndFrequency {
                    by_rule: "BYDAY".to_string(),
                    freq: self.freq,
                });
            }
            // Secondly, check the bounds on `nth`. It's yearly when the
            // frequency is yearly and BYMONTH isn't set. Otherwise, it's
            // monthly.
            let (lo, hi) =
                if matches!(self.freq, ICalendarFrequency::Yearly) && self.by_month.is_empty() {
                    (53, "53")
                } else {
                    (5, "5")
                };
            if !((-lo..=-1).contains(&nth) || (1..=lo).contains(&nth)) {
                return Err(ValidationError::InvalidFieldValueRangeWithFreq {
                    field: "BYDAY".to_string(),
                    value: v.to_string(),
                    freq: self.freq,
                    start_idx: format!("-{hi}"),
                    end_idx: hi.to_string(),
                });
            }
        }
        for &v in self.by_hour.iter() {
            if !(0..=23).contains(&v) {
                return Err(range("BYHOUR", v, "0", "23"));
            }
        }
        for &v in self.by_minute.iter() {
            if !(0..=59).contains(&v) {
                return Err(range("BYMINUTE", v, "0", "59"));
            }
        }
        for &v in self.by_second.iter() {
            // RFC 5545 technically allows a value of `60` here, presumably
            // for leap seconds. Jiff doesn't support leap seconds outside of
            // parsing, in which case, Jiff just clamps the value. Clamping
            // doesn't really make sense here, so just reject it. This is also
            // what `python-dateutil` does.
            if !(0..=59).contains(&v) {
                return Err(range("BYSECOND", v, "0", "59"));
            }
        }
        for &v in self.by_set_pos.iter() {
            if !((-366..=-1).contains(&v) || (1..=366).contains(&v)) {
                return Err(range("BYSETPOS", v, "-366", "366"));
            }
        }

        // Some additional frequency-specific errors.
        let by_rule_freq = |by_rule: &str| ValidationError::InvalidByRuleAndFrequency {
            by_rule: by_rule.to_string(),
            freq: self.freq,
        };
        if !self.by_week.is_empty() && !matches!(self.freq, ICalendarFrequency::Yearly) {
            return Err(by_rule_freq("BYWEEKNO"));
        }
        if !self.by_year_day.is_empty()
            && matches!(
                self.freq,
                ICalendarFrequency::Monthly
                    | ICalendarFrequency::Weekly
                    | ICalendarFrequency::Daily
            )
        {
            return Err(by_rule_freq("BYYEARDAY"));
        }
        if !self.by_month_day.is_empty() && matches!(self.freq, ICalendarFrequency::Weekly) {
            return Err(by_rule_freq("BYMONTHDAY"));
        }

        // A BYSETPOS specific error is that, if it's given, then there MUST
        // be another BY* rule.
        if !self.by_set_pos.is_empty()
            && self.by_month.is_empty()
            && self.by_week.is_empty()
            && self.by_year_day.is_empty()
            && self.by_month_day.is_empty()
            && self.by_week_day.is_empty()
            && self.by_hour.is_empty()
            && self.by_minute.is_empty()
            && self.by_second.is_empty()
        {
            return Err(ValidationError::BySetPosWithoutByRule);
        }

        let interval = freq_to_span(self.freq, self.interval)
            .ok_or(ValidationError::TooBigInterval(self.interval as u16))?;
        let inner = Arc::new(RecurrenceRuleInner {
            freq: self.freq,
            start: self.start,
            civil_start: self.start.naive_local(),
            until: self.until,
            count: self.count,
            interval,
            by_month: sort_and_dedup(&self.by_month),
            by_week: sort_and_dedup(&self.by_week),
            by_year_day: sort_and_dedup(&self.by_year_day),
            by_month_day: sort_and_dedup(&self.by_month_day),
            by_week_day: sort_and_dedup(&self.by_week_day),
            by_hour: sort_and_dedup(&self.by_hour),
            by_minute: sort_and_dedup(&self.by_minute),
            by_second: sort_and_dedup(&self.by_second),
            by_set_pos: sort_and_dedup(&self.by_set_pos),
            week_start: self.week_start,
        });
        Ok(RecurrenceRule { inner })
    }

    pub fn until(&mut self, until: ZonedDateTime) -> &mut RecurrenceRuleBuilder {
        self.until = Some(until);
        self
    }

    /// Limits the rule to a number of instances.
    ///
    /// RFC 5545 counts instances generated by the rule itself, so dates added
    /// by RDATE do not consume the count and dates removed by EXDATE do.
    pub fn count(&mut self, count: u32) -> &mut RecurrenceRuleBuilder {
        self.count = Some(count);
        self
    }

    pub fn interval(&mut self, increment: i32) -> &mut RecurrenceRuleBuilder {
        self.interval = increment;
        self
    }

    pub fn by_month<I: IntoI8Iter>(&mut self, months: I) -> &mut RecurrenceRuleBuilder {
        self.by_month.extend(months.into_i8_iter());
        self
    }

    pub fn by_week<I: IntoI8Iter>(&mut self, weeks: I) -> &mut RecurrenceRuleBuilder {
        self.by_week.extend(weeks.into_i8_iter());
        self
    }

    pub fn by_year_day<I: IntoI16Iter>(&mut self, days: I) -> &mut RecurrenceRuleBuilder {
        self.by_year_day.extend(days.into_i16_iter());
        self
    }

    pub fn by_month_day<I: IntoI8Iter>(&mut self, days: I) -> &mut RecurrenceRuleBuilder {
        self.by_month_day.extend(days.into_i8_iter());
        self
    }

    pub fn by_week_day<I: IntoByWeekdayIter>(
        &mut self,
        week_days: I,
    ) -> &mut RecurrenceRuleBuilder {
        self.by_week_day.extend(week_days.into_by_weekday_iter());
        self
    }

    pub fn by_hour<I: IntoI8Iter>(&mut self, hours: I) -> &mut RecurrenceRuleBuilder {
        self.by_hour.extend(hours.into_i8_iter());
        self
    }

    pub fn by_minute<I: IntoI8Iter>(&mut self, minutes: I) -> &mut RecurrenceRuleBuilder {
        self.by_minute.extend(minutes.into_i8_iter());
        self
    }

    pub fn by_second<I: IntoI8Iter>(&mut self, seconds: I) -> &mut RecurrenceRuleBuilder {
        self.by_second.extend(seconds.into_i8_iter());
        self
    }

    pub fn by_set_position<I: IntoI32Iter>(&mut self, positions: I) -> &mut RecurrenceRuleBuilder {
        self.by_set_pos.extend(positions.into_i32_iter());
        self
    }

    pub fn week_start(&mut self, weekday: Weekday) -> &mut RecurrenceRuleBuilder {
        self.week_start = weekday;
        self
    }
}

#[derive(Clone, Debug)]
struct RecurrenceSet {
    civil: Vec<DateTime>,
    /// A set of *zoned* datetimes that we use exactly like `set`, but only
    /// when BYSETPOS has a non-zero number of values.
    ///
    /// Basically, when BYSETPOS is used, `set` is drained into `zoned_set`,
    /// `zoned_set` is then filtered according to BYSETPOS and the iterator
    /// pops from `zoned_set` instead of `set`.
    ///
    /// Otherwise, this is totally ignored and no allocation is done.
    ///
    /// Generally speaking, this isn't really managed by the methods on
    /// `RecurrenceSet`. The abstraction somewhat sucks. If this needed to be
    /// a public API, we'd probably use more type machinery. But in practice,
    /// this is mostly treated as scratch space by `Expander`.
    zoned: Vec<(ZonedDateTime, bool)>,
    hours: Axis,
    minutes: Axis,
    seconds: Axis,
    cursor: usize,
    len: usize,
    spent: usize,
    overflowed: bool,
}

#[derive(Clone, Copy, Debug)]
enum Axis {
    Fixed(i8),
    Rule,
}

impl Axis {
    fn values<'a>(&'a self, rule: &'a [i8]) -> &'a [i8] {
        match self {
            Axis::Fixed(value) => std::slice::from_ref(value),
            Axis::Rule => rule,
        }
    }
}

impl RecurrenceSet {
    fn new() -> RecurrenceSet {
        RecurrenceSet {
            civil: vec![],
            zoned: vec![],
            hours: Axis::Fixed(0),
            minutes: Axis::Fixed(0),
            seconds: Axis::Fixed(0),
            cursor: 0,
            len: 0,
            spent: 0,
            overflowed: false,
        }
    }

    fn take_spent(&mut self) -> usize {
        std::mem::take(&mut self.spent)
    }

    fn is_empty(&self) -> bool {
        self.cursor >= self.len && self.zoned.is_empty()
    }

    fn begin_period(&mut self, cur: DateTime) {
        self.civil.clear();
        self.zoned.clear();
        self.hours = Axis::Fixed(cur.hour());
        self.minutes = Axis::Fixed(cur.minute());
        self.seconds = Axis::Fixed(cur.second());
        self.cursor = 0;
        self.len = 0;
    }

    fn candidate(&self, rule: &RecurrenceRuleInner, index: usize) -> Option<DateTime> {
        let hours = self.hours.values(&rule.by_hour);
        let minutes = self.minutes.values(&rule.by_minute);
        let seconds = self.seconds.values(&rule.by_second);
        let per_hour = minutes.len() * seconds.len();
        let per_date = hours.len() * per_hour;
        let date = self.civil.get(index.checked_div(per_date)?)?;
        let time = index % per_date;
        date.with()
            .hour(*hours.get(time / per_hour)?)
            .minute(*minutes.get(time / seconds.len() % minutes.len())?)
            .second(*seconds.get(time % seconds.len())?)
            .build()
            .ok()
    }

    fn seek(&mut self, rule: &RecurrenceRuleInner, start: DateTime) {
        let (mut low, mut high) = (0, self.len);
        while low < high {
            let middle = low + (high - low) / 2;
            if self
                .candidate(rule, middle)
                .is_some_and(|candidate| candidate < start)
            {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        self.cursor = low;
    }

    fn select_positions(&mut self, rule: &RecurrenceRule) {
        self.spent += rule.inner.by_set_pos.len();
        let len = self.len;
        let mut indices = rule
            .inner
            .by_set_pos
            .iter()
            .filter_map(|position| {
                let offset = usize::try_from(position.unsigned_abs()).ok()?;
                if *position > 0 {
                    offset.checked_sub(1).filter(|index| *index < len)
                } else {
                    len.checked_sub(offset)
                }
            })
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();
        let tz = rule.tz();
        let selected = indices
            .into_iter()
            .filter_map(|index| tz.interpret_local(self.candidate(&rule.inner, index)?))
            .collect::<Vec<_>>();
        self.zoned = selected;
        self.cursor = self.len;
        self.zoned.sort_by_key(|(zdt, _)| *zdt);
        self.zoned.dedup_by_key(|(zdt, _)| *zdt);
        self.zoned.reverse();
    }

    fn insert(&mut self, dt: DateTime) {
        self.spent += 1;
        self.civil.push(dt);
    }

    fn clear(&mut self) {
        self.civil.clear();
        self.zoned.clear();
        self.cursor = 0;
        self.len = 0;
    }

    fn retain(&mut self, predicate: impl FnMut(&mut DateTime) -> bool) {
        self.civil.retain_mut(predicate);
    }

    fn expand<E, I>(&mut self, expand: E)
    where
        E: Fn(DateTime) -> I,
        I: Iterator<Item = DateTime>,
    {
        // We're going to replace every datetime in the set at this point
        // with its expansion provided by the closure. So record how many
        // datetimes we have now. At the end, we'll drain them in one swoop.
        let len = self.civil.len();
        for i in 0..len {
            self.civil.extend(expand(self.civil[i]));
            if self.civil.len() > MAX_PERIOD_CANDIDATES {
                self.overflowed = true;
                self.civil.clear();
                return;
            }
        }
        self.spent += self.civil.len() - len;
        self.civil.drain(..len);
    }

    fn canonicalize(&mut self, rule: &RecurrenceRuleInner) {
        self.civil.sort();
        self.civil.dedup();
        let per_date = self.hours.values(&rule.by_hour).len()
            * self.minutes.values(&rule.by_minute).len()
            * self.seconds.values(&rule.by_second).len();
        match self.civil.len().checked_mul(per_date) {
            Some(len) => self.len = len,
            None => {
                self.overflowed = true;
                self.clear();
            }
        }
    }

    fn pop(&mut self, rule: &RecurrenceRule) -> Option<(ZonedDateTime, bool)> {
        loop {
            let (next, in_gap) = self.zoned.pop().or_else(|| self.pop_civil(rule))?;
            // For simplicity of implementation, the recurrence rule
            // generator may create datetimes before our starting point. Since
            // this can generally only happen on the first "iteration," we
            // don't worry about it too much and just filter them here.
            //
            // Ideally we would do this even earlier, and that might make the
            // BYSETPOS implementation simpler. But the starting point is a
            // zoned datetime and this is the earliest that we convert a
            // datetime from our buffered set to a zoned datetime.
            if next < rule.inner.start {
                self.spent += 1;
                continue;
            }
            // For similar reasons, we handle our "until" constraint here too.
            if let Some(ref until) = rule.inner.until
                && &next > until
            {
                // Since we always move forward in time, if we reach
                // this point, we'll never be able to return any other
                // datetime. So we can drain the rest of the set and
                // bail.
                self.clear();
                return None;
            }
            return Some((next, in_gap));
        }
    }

    fn pop_civil(&mut self, rule: &RecurrenceRule) -> Option<(ZonedDateTime, bool)> {
        let tz = rule.tz();
        while self.cursor < self.len {
            let index = self.cursor;
            self.cursor += 1;
            let Some(dt) = self.candidate(&rule.inner, index) else {
                continue;
            };
            // RFC 5545 section 3.3.5 settles what an ambiguous wall clock
            // reading means: a reading that occurs twice means its first
            // occurrence, and a reading that does not occur is interpreted
            // with the offset in effect before the gap, which moves it
            // forward by the length of the gap. `Tz::from_local` applies
            // exactly that rule, so an instance around a daylight saving
            // transition is neither dropped nor duplicated.
            let Some(next) = tz.interpret_local(dt) else {
                continue;
            };
            // N.B. We don't check if the civil datetime is before our starting
            // point or after our `until` here because BYSETPOS wants those
            // included in the recurrence set when resolving indices. They
            // will get filtered out later in `pop()`.
            return Some(next);
        }
        None
    }
}

/// A trait that permits flexibly specifying a sequence of `i8` integers.
///
/// This trait is used for builder methods on `RecurrenceRuleBuilder`. It
/// permits callers to provide integers in a number of flexible ways:
///
/// * A single integer: `5`
/// * An array of integers: `[1, 3, 5]`.
/// * A single range of integers: `5..8` or `5..=8`.
/// * An array of ranges of integers: `[5..=10, 15..=20]`.
///
/// # Design
///
/// The reason this trait _and_ `IntoI16Iter` exists is to make specifying a
/// sequence more ergonomic. In particular, an alternative design is:
///
/// ```ignore
/// pub trait IntoIntegerIter {
///     type Integer;
///     fn into_integer_iter(self) -> impl Iterator<Item = Self::Integer>;
/// }
/// ```
///
/// But since this would be implemented for both `i8` and `i16`, this
/// means that `builder.by_month(5)` cannot have the type of `5` inferred
/// unambiguously.
// N.B. If we end up copying this design into Jiff, we should make this
// trait sealed so that people downstream can't add trait impls and fuck up
// inference.
pub trait IntoI8Iter {
    /// Creates an iterator over all integers in this sequence.
    fn into_i8_iter(self) -> impl Iterator<Item = i8>;
}

/// A trait that permits flexibly specifying a sequence of `i16` integers.
///
/// This trait is used for builder methods on `RecurrenceRuleBuilder`. It
/// permits callers to provide integers in a number of flexible ways:
///
/// * A single integer: `5`
/// * An array of integers: `[1, 3, 5]`.
/// * A single range of integers: `5..8` or `5..=8`.
/// * An array of ranges of integers: `[5..=10, 15..=20]`.
///
/// # Design
///
/// The reason this trait _and_ `IntoI8Iter` exists is to make specifying a
/// sequence more ergonomic. In particular, an alternative design is:
///
/// ```ignore
/// pub trait IntoIntegerIter {
///     type Integer;
///     fn into_integer_iter(self) -> impl Iterator<Item = Self::Integer>;
/// }
/// ```
///
/// But since this would be implemented for both `i8` and `i16`, this
/// means that `builder.by_month(5)` cannot have the type of `5` inferred
/// unambiguously.
pub trait IntoI16Iter {
    /// Creates an iterator over all integers in this sequence.
    fn into_i16_iter(self) -> impl Iterator<Item = i16>;
}

/// A trait that permits flexibly specifying a sequence of `i32` integers.
///
/// This trait is used for builder methods on `RecurrenceRuleBuilder`. It
/// permits callers to provide integers in a number of flexible ways:
///
/// * A single integer: `5`
/// * An array of integers: `[1, 3, 5]`.
/// * A single range of integers: `5..8` or `5..=8`.
/// * An array of ranges of integers: `[5..=10, 15..=20]`.
///
/// # Design
///
/// The reason this trait, `IntoI8Iter` _and_ `IntoI16Iter` exists is to make
/// specifying a sequence more ergonomic. In particular, an alternative design
/// is:
///
/// ```ignore
/// pub trait IntoIntegerIter {
///     type Integer;
///     fn into_integer_iter(self) -> impl Iterator<Item = Self::Integer>;
/// }
/// ```
///
/// But since this would be implemented for `i8`, `i16` and `i32`, this
/// means that `builder.by_month(5)` cannot have the type of `5` inferred
/// unambiguously.
pub trait IntoI32Iter {
    /// Creates an iterator over all integers in this sequence.
    fn into_i32_iter(self) -> impl Iterator<Item = i32>;
}

impl IntoI8Iter for Vec<i8> {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.into_iter()
    }
}

impl IntoI8Iter for &[i8] {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.iter().copied()
    }
}

impl IntoI16Iter for &[i16] {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        self.iter().copied()
    }
}

impl IntoI32Iter for &[i32] {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        self.iter().copied()
    }
}

impl IntoByWeekdayIter for Vec<ByWeekday> {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        self.into_iter()
    }
}

impl IntoI8Iter for i8 {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        std::iter::once(self)
    }
}

impl IntoI16Iter for i16 {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        std::iter::once(self)
    }
}

impl IntoI32Iter for i32 {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        std::iter::once(self)
    }
}

impl IntoI8Iter for Range<i8> {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.into_iter()
    }
}

impl IntoI16Iter for Range<i16> {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        self.into_iter()
    }
}

impl IntoI32Iter for Range<i32> {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        self.into_iter()
    }
}

impl IntoI8Iter for RangeInclusive<i8> {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.into_iter()
    }
}

impl IntoI16Iter for RangeInclusive<i16> {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        self.into_iter()
    }
}

impl IntoI32Iter for RangeInclusive<i32> {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        self.into_iter()
    }
}

impl<const N: usize> IntoI8Iter for [i8; N] {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.into_iter()
    }
}

impl<const N: usize> IntoI16Iter for [i16; N] {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        self.into_iter()
    }
}

impl<const N: usize> IntoI32Iter for [i32; N] {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        self.into_iter()
    }
}

impl<const N: usize> IntoI8Iter for [Range<i8>; N] {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.into_iter().flatten()
    }
}

impl<const N: usize> IntoI16Iter for [Range<i16>; N] {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        self.into_iter().flatten()
    }
}

impl<const N: usize> IntoI32Iter for [Range<i32>; N] {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        self.into_iter().flatten()
    }
}

impl<const N: usize> IntoI8Iter for [RangeInclusive<i8>; N] {
    fn into_i8_iter(self) -> impl Iterator<Item = i8> {
        self.into_iter().flatten()
    }
}

impl<const N: usize> IntoI16Iter for [RangeInclusive<i16>; N] {
    fn into_i16_iter(self) -> impl Iterator<Item = i16> {
        self.into_iter().flatten()
    }
}

impl<const N: usize> IntoI32Iter for [RangeInclusive<i32>; N] {
    fn into_i32_iter(self) -> impl Iterator<Item = i32> {
        self.into_iter().flatten()
    }
}

/// A trait that permits flexibly specifying a sequence of weekdays.
///
/// Each weekday can just mean "any" weekday (e.g., `Weekday::Saturday`), or
/// it can mean a numbered weekday. For example, when the frequency for a
/// recurrence rule is yearly, then `(3, Weekday::Saturday)` corresponds to the
/// third Saturday of the year.
///
/// This trait is primarily used for the `RecurrenceRuleBuilder::by_week_day`
/// builder methods. It permits callers to provide weekdays in a number of
/// flexible ways:
///
/// * Directly via `ByWeekday::Numbered { nth: 3, weekday: Weekday::Monday }`.
/// * As just any weekday via `Weekday::Monday`.
/// * As a range of weekdays via `Weekday::Monday..=Weekday::Wednesday`.
/// * As an array of weekdays via `[Weekday::Monday, Weekday::Friday]`.
/// * As an array of numbered weekdays via
///   `[(2, Weekday::Monday), (1, Weekday::Friday)]`.
pub trait IntoByWeekdayIter {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday>;
}

impl IntoByWeekdayIter for ByWeekday {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        std::iter::once(self)
    }
}

impl IntoByWeekdayIter for Weekday {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        std::iter::once(ByWeekday::Any(self))
    }
}

impl IntoByWeekdayIter for (i8, Weekday) {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        let (nth, weekday) = self;
        std::iter::once(ByWeekday::Numbered { nth, weekday })
    }
}

impl IntoByWeekdayIter for RangeInclusive<Weekday> {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        let (start, end) = (*self.start(), *self.end());
        // OK because `Weekday::until` guarantees `0..=6`.
        // And add `1` because this is an inclusive range.
        let count =
            1 + usize::try_from(start.until(end)).expect("Weekday::until is always within 0..=6");
        start.cycle_forward().take(count).map(ByWeekday::Any)
    }
}

impl<const N: usize> IntoByWeekdayIter for [ByWeekday; N] {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        self.into_iter()
    }
}

impl<const N: usize> IntoByWeekdayIter for [Weekday; N] {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        self.into_iter().flat_map(|any| any.into_by_weekday_iter())
    }
}

impl<const N: usize> IntoByWeekdayIter for [(i8, Weekday); N] {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        self.into_iter()
            .flat_map(|numbered| numbered.into_by_weekday_iter())
    }
}

impl<const N: usize> IntoByWeekdayIter for [RangeInclusive<Weekday>; N] {
    fn into_by_weekday_iter(self) -> impl Iterator<Item = ByWeekday> {
        self.into_iter().flat_map(|any| any.into_by_weekday_iter())
    }
}

/// Converts a frequency and interval into the span one step advances by.
///
/// Returns `None` when the interval is too large for a span to hold.
fn freq_to_span(freq: ICalendarFrequency, interval: i32) -> Option<Span> {
    let base = match freq {
        ICalendarFrequency::Yearly => 1.year(),
        ICalendarFrequency::Monthly => 1.month(),
        ICalendarFrequency::Weekly => 1.week(),
        ICalendarFrequency::Daily => 1.day(),
        ICalendarFrequency::Hourly => 1.hour(),
        ICalendarFrequency::Minutely => 1.minute(),
        ICalendarFrequency::Secondly => 1.second(),
    };
    base.checked_mul(i64::from(interval)).ok()
}

/// A type describing "day of week" inputs.
///
/// This implements `Ord` even though the actual order of weekdays cannot be
/// determined unless the _start_ of the week is known (which is commonly
/// either or Sunday or Monday, but RFC 5545 lets any day be the start).
/// However, we implement `Ord` to make it easy to sort and de-duplicate
/// collections containing a `ByWeekday`. We never actually rely on its
/// ordering for generating datetimes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByWeekday {
    Any(Weekday),
    Numbered { nth: i8, weekday: Weekday },
}

impl ByWeekday {
    fn weekday(&self) -> Weekday {
        match *self {
            ByWeekday::Any(weekday) | ByWeekday::Numbered { weekday, .. } => weekday,
        }
    }

    /// Returns true if and only if the given weekday matches this one.
    ///
    /// # Panics
    ///
    /// This panics when this is a numbered weekday. In effect, this shouldn't
    /// be used in contexts where BYDAY can contain numbered weekdays. That
    /// limits this to YEARLY and MONTHLY frequencies (and in the YEARLY case,
    /// only when BYWEEKNO is not used).
    fn is_match(&self, wd: Weekday) -> bool {
        match *self {
            ByWeekday::Any(weekday) => weekday == wd,
            _ => unreachable!(),
        }
    }

    /// Return an iterator of weekdays, at yearly frequency, within the given
    /// range of datetimes.
    ///
    /// Generally speaking, `start` should be the first day of a year and `end`
    /// should be the last day of that same year.
    ///
    /// When this is a numbered weekday, then a positive number is interpreted
    /// relative to the start and a negative number is interpreted relative to
    /// the end. Either way, the iterator returned yields at most one element
    /// (but may yield zero).
    ///
    /// When this is "any" weekday, then every date with that weekday between
    /// `start` and `end` (inclusive) is returned.
    fn iter_yearly(
        &self,
        start: DateTime,
        end: DateTime,
    ) -> impl Iterator<Item = DateTime> + use<> {
        match *self {
            ByWeekday::Any(weekday) => Either::Left(iter_weekdays_between(weekday, start, end)),
            ByWeekday::Numbered { nth, weekday } => {
                let from = if nth < 0 { end } else { start };
                let nth = if from.weekday() != weekday {
                    nth
                } else if nth.abs() == 1 {
                    return Either::Right(Some(from).into_iter());
                } else {
                    nth - nth.signum()
                };
                Either::Right(
                    from.nth_weekday(i32::from(nth), weekday)
                        .ok()
                        .filter(|dt| (start..=end).contains(dt))
                        .into_iter(),
                )
            }
        }
    }

    /// Return an iterator of weekdays, at monthly frequency, within the given
    /// range of datetimes.
    ///
    /// Generally speaking, `start` should be the first day of a month and
    /// `end` should be the last day of that same month.
    ///
    /// When this is a numbered weekday, then a positive number is interpreted
    /// relative to the start and a negative number is interpreted relative to
    /// the end. Either way, the iterator returned yields at most one element
    /// (but may yield zero).
    ///
    /// When this is "any" weekday, then every date with that weekday between
    /// `start` and `end` (inclusive) is returned.
    fn iter_monthly(
        &self,
        start: DateTime,
        end: DateTime,
    ) -> impl Iterator<Item = DateTime> + use<> {
        match *self {
            ByWeekday::Any(weekday) => Either::Left(iter_weekdays_between(weekday, start, end)),
            ByWeekday::Numbered { nth, weekday } => {
                Either::Right(start.nth_weekday_of_month(nth, weekday).ok().into_iter())
            }
        }
    }

    /// Return an iterator of weekdays, at weekly frequency, within the given
    /// range of datetimes.
    ///
    /// Generally speaking, `start` should be the first day of a week and
    /// `end` should be the last day of that same week.
    ///
    /// When this is "any" weekday, then every date with that weekday between
    /// `start` and `end` (inclusive) is returned.
    ///
    /// # Panics
    ///
    /// When this `ByWeekday` is `Numbered`. RFC 5545 doesn't permit that
    /// construction at anything other than YEARLY and MONTHLY frequency.
    fn iter_weekly(
        &self,
        start: DateTime,
        end: DateTime,
    ) -> impl Iterator<Item = DateTime> + use<> {
        match *self {
            ByWeekday::Any(weekday) => iter_weekdays_between(weekday, start, end),
            // Not allowed according to RFC 5545. This case should be prevented
            // by recurrence rule construction.
            ByWeekday::Numbered { .. } => unreachable!(),
        }
    }
}

impl Ord for ByWeekday {
    fn cmp(&self, rhs: &ByWeekday) -> Ordering {
        match (*self, *rhs) {
            (ByWeekday::Any(lhs), ByWeekday::Any(rhs)) => {
                lhs.to_monday_one_offset().cmp(&rhs.to_monday_one_offset())
            }
            (
                ByWeekday::Numbered {
                    nth: lhs_nth,
                    weekday: lhs_weekday,
                },
                ByWeekday::Numbered {
                    nth: rhs_nth,
                    weekday: rhs_weekday,
                },
            ) => {
                let lhs = (lhs_nth, lhs_weekday.to_monday_one_offset());
                let rhs = (rhs_nth, rhs_weekday.to_monday_one_offset());
                lhs.cmp(&rhs)
            }
            (ByWeekday::Any(_), ByWeekday::Numbered { .. }) => Ordering::Less,
            (ByWeekday::Numbered { .. }, ByWeekday::Any(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for ByWeekday {
    fn partial_cmp(&self, rhs: &ByWeekday) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl std::fmt::Display for ByWeekday {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn fmt_weekday(wd: Weekday, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match wd {
                Weekday::Sunday => write!(f, "Sun"),
                Weekday::Monday => write!(f, "Mon"),
                Weekday::Tuesday => write!(f, "Tue"),
                Weekday::Wednesday => write!(f, "Wed"),
                Weekday::Thursday => write!(f, "Thu"),
                Weekday::Friday => write!(f, "Fri"),
                Weekday::Saturday => write!(f, "Sat"),
            }
        }

        match *self {
            ByWeekday::Any(weekday) => fmt_weekday(weekday, f),
            ByWeekday::Numbered { nth, weekday } => {
                write!(f, "{nth}-")?;
                fmt_weekday(weekday, f)
            }
        }
    }
}

/// A simple `Either` type for easy construction of `impl Iterator`.
///
/// Specifically, this is useful when it's supremely annoying to write a
/// single iterator chain when it would be more naturally written using case
/// analysis.
enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R, I> Iterator for Either<L, R>
where
    L: Iterator<Item = I>,
    R: Iterator<Item = I>,
{
    type Item = I;

    fn next(&mut self) -> Option<I> {
        match *self {
            Either::Left(ref mut it) => it.next(),
            Either::Right(ref mut it) => it.next(),
        }
    }
}

/// Returns an iterator for every weekday between `start` and `end` (inclusive).
fn iter_weekdays_between(
    weekday: Weekday,
    start: DateTime,
    end: DateTime,
) -> impl Iterator<Item = DateTime> {
    (start.weekday() == weekday)
        .then_some(start)
        .into_iter()
        .chain({
            let mut cur = start.nth_weekday(1, weekday).ok();
            std::iter::from_fn(move || {
                let next = cur.take()?;
                if next > end {
                    return None;
                }
                cur = next.nth_weekday(1, weekday).ok();
                Some(next)
            })
        })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/datecalc/recurrence/tests.rs"]
mod tests;
