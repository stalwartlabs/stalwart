/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jiff::{
    SignedDuration, Span, ToSpan, Zoned,
    civil::{Date, Time},
};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleCron {
    Day { hour: u32, minute: u32 },
    Week { day: u32, hour: u32, minute: u32 },
    Hour { minute: u32 },
}

impl SimpleCron {
    pub fn time_to_next(&self) -> Duration {
        let now = Zoned::now();
        self.next_after(&now)
            .and_then(|next| Duration::try_from(now.duration_until(&next)).ok())
            .unwrap_or_else(|| self.as_duration())
    }

    fn next_after(&self, now: &Zoned) -> Option<Zoned> {
        match *self {
            SimpleCron::Hour { minute } => {
                let next = now
                    .with()
                    .minute(i8::try_from(minute).ok()?)
                    .second(0)
                    .subsec_nanosecond(0)
                    .build()
                    .ok()?;
                if next > *now {
                    Some(next)
                } else {
                    next.checked_add(SignedDuration::from_hours(1)).ok()
                }
            }
            SimpleCron::Day { hour, minute } => {
                Self::next_local_time(now, 0, 1.day(), hour, minute)
            }
            SimpleCron::Week { day, hour, minute } => Self::next_local_time(
                now,
                (i64::from(day) - i64::from(now.weekday().to_sunday_zero_offset())).rem_euclid(7),
                1.week(),
                hour,
                minute,
            ),
        }
    }

    fn next_local_time(
        now: &Zoned,
        days_ahead: i64,
        period: Span,
        hour: u32,
        minute: u32,
    ) -> Option<Zoned> {
        let time = Time::new(i8::try_from(hour).ok()?, i8::try_from(minute).ok()?, 0, 0).ok()?;
        let date = now.date().checked_add(days_ahead.days()).ok()?;
        let at = |date: Date| {
            date.to_datetime(time)
                .to_zoned(now.time_zone().clone())
                .ok()
        };
        let next = at(date)?;
        if next > *now {
            Some(next)
        } else {
            at(date.checked_add(period).ok()?)
        }
    }

    pub fn as_duration(&self) -> Duration {
        match self {
            SimpleCron::Day { .. } => Duration::from_secs(24 * 60 * 60),
            SimpleCron::Week { .. } => Duration::from_secs(7 * 24 * 60 * 60),
            SimpleCron::Hour { .. } => Duration::from_secs(60 * 60),
        }
    }
}

impl Default for SimpleCron {
    fn default() -> Self {
        SimpleCron::Hour { minute: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::SimpleCron;
    use jiff::{Zoned, civil::date, tz::TimeZone};

    fn new_york() -> TimeZone {
        TimeZone::posix("EST5EDT,M3.2.0,M11.1.0").expect("valid POSIX time zone")
    }

    fn local(tz: &TimeZone, year: i16, month: i8, day: i8, hour: i8, minute: i8) -> Zoned {
        date(year, month, day)
            .at(hour, minute, 0, 0)
            .to_zoned(tz.clone())
            .expect("representable local time")
    }

    #[test]
    fn weekly_runs_on_the_next_matching_weekday_with_sunday_as_zero() {
        let utc = TimeZone::UTC;
        let tuesday = local(&utc, 2026, 9, 22, 10, 0);
        for (day, hour, expected) in [
            (3, 9, local(&utc, 2026, 9, 23, 9, 0)),
            (2, 11, local(&utc, 2026, 9, 22, 11, 0)),
            (2, 10, local(&utc, 2026, 9, 29, 10, 0)),
            (2, 9, local(&utc, 2026, 9, 29, 9, 0)),
            (1, 11, local(&utc, 2026, 9, 28, 11, 0)),
            (0, 9, local(&utc, 2026, 9, 27, 9, 0)),
            (6, 23, local(&utc, 2026, 9, 26, 23, 0)),
        ] {
            assert_eq!(
                SimpleCron::Week {
                    day,
                    hour,
                    minute: 0
                }
                .next_after(&tuesday),
                Some(expected),
                "day {day} at {hour}:00"
            );
        }
    }

    #[test]
    fn daily_keeps_its_wall_clock_time_across_daylight_saving_changes() {
        let tz = new_york();
        let cron = SimpleCron::Day { hour: 9, minute: 0 };
        for (now, expected, hours) in [
            (
                local(&tz, 2026, 3, 7, 10, 0),
                local(&tz, 2026, 3, 8, 9, 0),
                22,
            ),
            (
                local(&tz, 2026, 10, 31, 10, 0),
                local(&tz, 2026, 11, 1, 9, 0),
                24,
            ),
            (
                local(&tz, 2026, 3, 8, 8, 0),
                local(&tz, 2026, 3, 8, 9, 0),
                1,
            ),
        ] {
            let next = cron.next_after(&now).expect("next run");
            assert_eq!(next, expected);
            assert_eq!(now.duration_until(&next).as_hours(), hours);
        }
    }

    #[test]
    fn daily_time_inside_a_gap_runs_once_after_the_gap() {
        let tz = new_york();
        let next = SimpleCron::Day {
            hour: 2,
            minute: 30,
        }
        .next_after(&local(&tz, 2026, 3, 8, 1, 0))
        .expect("next run");
        assert_eq!(next, local(&tz, 2026, 3, 8, 3, 30));
    }

    #[test]
    fn hourly_counts_elapsed_hours_through_a_repeated_hour() {
        let tz = new_york();
        let first_pass = local(&tz, 2026, 11, 1, 1, 30);
        let next = SimpleCron::Hour { minute: 15 }
            .next_after(&first_pass)
            .expect("next run");
        assert_eq!(first_pass.duration_until(&next).as_mins(), 45);
        assert_eq!(
            SimpleCron::Hour { minute: 45 }.next_after(&first_pass),
            Some(local(&tz, 2026, 11, 1, 1, 45))
        );
    }
}
