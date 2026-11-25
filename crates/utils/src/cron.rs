/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jiff::{
    SignedDuration, Span, ToSpan, ZonedDateTime,
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
        let now = ZonedDateTime::now();
        self.next_after(&now)
            .and_then(|next| Duration::try_from(now.duration_until(&next)).ok())
            .unwrap_or_else(|| self.as_duration())
    }

    fn next_after(&self, now: &ZonedDateTime) -> Option<ZonedDateTime> {
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
        now: &ZonedDateTime,
        days_ahead: i64,
        period: Span,
        hour: u32,
        minute: u32,
    ) -> Option<ZonedDateTime> {
        let time = Time::new(i8::try_from(hour).ok()?, i8::try_from(minute).ok()?, 0, 0).ok()?;
        let date = now.date().checked_add(days_ahead.days()).ok()?;
        let at = |date: Date| {
            date.to_datetime(time)
                .to_zoned_datetime(now.time_zone().clone())
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/utils/src/cron/tests.rs"]
mod tests;
