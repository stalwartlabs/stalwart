/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Write;

const SECONDS_PER_DAY: i64 = 86_400;
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
pub(crate) const FILETIME_TICKS_PER_MINUTE: u64 = FILETIME_TICKS_PER_SECOND * 60;
#[cfg(feature = "convert")]
pub(crate) const FILETIME_NO_DATE: u64 = 0x5AE9_80E0 * FILETIME_TICKS_PER_MINUTE;
const FILETIME_UNIX_OFFSET: i64 = 11_644_473_600;
const OA_DATE_UNIX_OFFSET: i64 = -2_209_161_600;
const OA_DATE_MAX_DAYS: f64 = 2_958_466.0;
const OA_DATE_MIN_DAYS: f64 = -657_435.0;
const WEEKDAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileTime(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub millis: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcSeconds(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanos: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XsZone {
    Utc,
    OffsetMinutes(i16),
    Floating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XsDateTime {
    pub local: LocalDateTime,
    pub zone: XsZone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XsDuration {
    pub negative: bool,
    pub seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    Seconds,
    Millis(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XsForm {
    Utc,
    Floating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasDateForm {
    Punctuated,
    Compact,
}

impl FileTime {
    pub fn from_utc(t: UtcSeconds, nanos: u32) -> Self {
        let seconds = u64::try_from(t.0.saturating_add(FILETIME_UNIX_OFFSET)).unwrap_or(0);
        FileTime(
            seconds
                .saturating_mul(FILETIME_TICKS_PER_SECOND)
                .saturating_add(u64::from(nanos.min(999_999_999) / 100)),
        )
    }

    pub fn whole_minute(self) -> Self {
        FileTime(self.0.saturating_sub(self.0 % FILETIME_TICKS_PER_MINUTE))
    }

    pub fn to_utc(self) -> (UtcSeconds, u32) {
        let seconds = i64::try_from(self.0 / FILETIME_TICKS_PER_SECOND).unwrap_or(i64::MAX);
        let ticks = u32::try_from(self.0 % FILETIME_TICKS_PER_SECOND).unwrap_or(0);
        (
            UtcSeconds(seconds.saturating_sub(FILETIME_UNIX_OFFSET)),
            ticks.saturating_mul(100),
        )
    }
}

impl LocalDateTime {
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanos: u32,
    ) -> Option<Self> {
        ((1..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month)
            && hour < 24
            && minute < 60
            && second < 60
            && nanos < 1_000_000_000)
            .then_some(LocalDateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanos,
            })
    }

    pub fn to_unix_seconds(&self) -> UtcSeconds {
        let days = days_from_civil(
            i64::from(self.year),
            i64::from(self.month),
            i64::from(self.day),
        );
        let time = i64::from(self.hour)
            .saturating_mul(3600)
            .saturating_add(i64::from(self.minute).saturating_mul(60))
            .saturating_add(i64::from(self.second));
        UtcSeconds(days.saturating_mul(SECONDS_PER_DAY).saturating_add(time))
    }
}

impl XsDateTime {
    pub fn parse(s: &[u8]) -> Option<Self> {
        let [
            y0,
            y1,
            y2,
            y3,
            b'-',
            mo0,
            mo1,
            b'-',
            d0,
            d1,
            b'T',
            h0,
            h1,
            b':',
            mi0,
            mi1,
            b':',
            s0,
            s1,
            rest @ ..,
        ] = s
        else {
            return None;
        };
        let year = u16::from(digits2(*y0, *y1)?)
            .saturating_mul(100)
            .saturating_add(u16::from(digits2(*y2, *y3)?));
        let (nanos, rest) = match rest.strip_prefix(b".") {
            Some(fraction) => parse_fraction(fraction)?,
            None => (0, rest),
        };
        let zone = match rest {
            [] => XsZone::Floating,
            [b'Z'] => XsZone::Utc,
            [sign @ (b'+' | b'-'), oh0, oh1, b':', om0, om1] => {
                let hours = digits2(*oh0, *oh1)?;
                let minutes = digits2(*om0, *om1)?;
                if hours > 14 || minutes > 59 || (hours == 14 && minutes > 0) {
                    return None;
                }
                let total = i16::from(hours)
                    .saturating_mul(60)
                    .saturating_add(i16::from(minutes));
                XsZone::OffsetMinutes(if *sign == b'-' {
                    total.saturating_neg()
                } else {
                    total
                })
            }
            _ => return None,
        };
        Some(XsDateTime {
            local: LocalDateTime::new(
                year,
                digits2(*mo0, *mo1)?,
                digits2(*d0, *d1)?,
                digits2(*h0, *h1)?,
                digits2(*mi0, *mi1)?,
                digits2(*s0, *s1)?,
                nanos,
            )?,
            zone,
        })
    }

    pub fn to_utc(&self) -> Option<UtcSeconds> {
        let local = self.local.to_unix_seconds();
        match self.zone {
            XsZone::Utc => Some(local),
            XsZone::OffsetMinutes(minutes) => Some(UtcSeconds(
                local
                    .0
                    .saturating_sub(i64::from(minutes).saturating_mul(60)),
            )),
            XsZone::Floating => None,
        }
    }
}

impl UtcSeconds {
    fn split(&self) -> (LocalDateTime, u8) {
        let days = self.0.div_euclid(SECONDS_PER_DAY);
        let time = self.0.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let weekday = u8::try_from(days.saturating_add(4).rem_euclid(7)).unwrap_or(0);
        (
            LocalDateTime {
                year,
                month,
                day,
                hour: u8::try_from(time / 3600).unwrap_or(0),
                minute: u8::try_from(time % 3600 / 60).unwrap_or(0),
                second: u8::try_from(time % 60).unwrap_or(0),
                nanos: 0,
            },
            weekday,
        )
    }

    pub fn write_xs(&self, out: &mut Vec<u8>, precision: Precision) {
        self.write_xs_form(out, precision, XsForm::Utc);
    }

    pub fn write_xs_form(&self, out: &mut Vec<u8>, precision: Precision, form: XsForm) {
        let (t, _) = self.split();
        write_date(out, &t, true);
        out.push(b'T');
        write_time(out, &t, true);
        if let Precision::Millis(millis) = precision {
            out.push(b'.');
            push_digits(out, u32::from(millis.min(999)), 3);
        }
        if form == XsForm::Utc {
            out.push(b'Z');
        }
    }

    pub fn write_eas(&self, out: &mut Vec<u8>, form: EasDateForm) {
        let (t, _) = self.split();
        let punctuated = form == EasDateForm::Punctuated;
        write_date(out, &t, punctuated);
        out.push(b'T');
        write_time(out, &t, punctuated);
        if punctuated {
            out.extend_from_slice(b".000");
        }
        out.push(b'Z');
    }

    pub fn write_http_date(&self, out: &mut Vec<u8>) {
        let (t, weekday) = self.split();
        if let Some(name) = WEEKDAYS.get(usize::from(weekday)) {
            out.extend_from_slice(*name);
        }
        out.extend_from_slice(b", ");
        push_digits(out, u32::from(t.day), 2);
        out.push(b' ');
        if let Some(name) = MONTHS.get(usize::from(t.month.saturating_sub(1))) {
            out.extend_from_slice(*name);
        }
        out.push(b' ');
        push_digits(out, u32::from(t.year), 4);
        out.push(b' ');
        write_time(out, &t, true);
        out.extend_from_slice(b" GMT");
    }
}

impl XsDuration {
    pub fn parse(s: &[u8]) -> Option<Self> {
        let (negative, s) = match s.strip_prefix(b"-") {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let mut rest = s.strip_prefix(b"P")?;
        let mut seconds: u64 = 0;
        let mut in_time = false;
        let mut components = 0u8;
        let mut last_rank = 0u8;
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix(b"T") {
                if in_time {
                    return None;
                }
                in_time = true;
                rest = after;
                if rest.is_empty() {
                    return None;
                }
                continue;
            }
            let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
            let (number, after) = rest.split_at_checked(digits)?;
            if number.is_empty() {
                return None;
            }
            let value = parse_u64(number)?;
            let (unit, after) = after.split_first()?;
            let (unit, after) = if *unit == b'.' {
                let (_, after) = parse_fraction(after)?;
                let (unit, after) = after.split_first()?;
                if !in_time || *unit != b'S' {
                    return None;
                }
                (b'S', after)
            } else {
                (*unit, after)
            };
            let (rank, multiplier) = match (in_time, unit) {
                (false, b'Y') => (1, None),
                (false, b'M') => (2, None),
                (false, b'D') => (3, Some(86_400)),
                (true, b'H') => (4, Some(3_600)),
                (true, b'M') => (5, Some(60)),
                (true, b'S') => (6, Some(1)),
                _ => return None,
            };
            if rank <= last_rank {
                return None;
            }
            last_rank = rank;
            components = components.saturating_add(1);
            match multiplier {
                Some(multiplier) => {
                    seconds = seconds.checked_add(value.checked_mul(multiplier)?)?;
                }
                None if value == 0 => {}
                None => return None,
            }
            rest = after;
        }
        (components > 0).then_some(XsDuration { negative, seconds })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        if self.negative && self.seconds > 0 {
            out.push(b'-');
        }
        out.extend_from_slice(b"PT");
        let hours = self.seconds / 3600;
        let minutes = self.seconds % 3600 / 60;
        let seconds = self.seconds % 60;
        if hours > 0 {
            push_u64(out, hours);
            out.push(b'H');
        }
        if minutes > 0 {
            push_u64(out, minutes);
            out.push(b'M');
        }
        if seconds > 0 || self.seconds == 0 {
            push_u64(out, seconds);
            out.push(b'S');
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
pub fn oa_date_to_utc(days: f64) -> Option<UtcSeconds> {
    if !days.is_finite() || !(OA_DATE_MIN_DAYS..=OA_DATE_MAX_DAYS).contains(&days) {
        return None;
    }
    let whole = days.trunc();
    let fraction = (days - whole).abs();
    let seconds = (whole * 86_400.0 + (fraction * 86_400.0).round()) as i64;
    Some(UtcSeconds(seconds.saturating_add(OA_DATE_UNIX_OFFSET)))
}

fn is_leap(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 {
        year.wrapping_sub(1)
    } else {
        year
    };
    let era = y.div_euclid(400);
    let year_of_era = y.wrapping_sub(era.wrapping_mul(400));
    let shifted_month = month.wrapping_add(9).rem_euclid(12);
    let day_of_year = shifted_month
        .wrapping_mul(153)
        .wrapping_add(2)
        .div_euclid(5)
        .wrapping_add(day)
        .wrapping_sub(1);
    let day_of_era = year_of_era
        .wrapping_mul(365)
        .wrapping_add(year_of_era.div_euclid(4))
        .wrapping_sub(year_of_era.div_euclid(100))
        .wrapping_add(day_of_year);
    era.wrapping_mul(146_097)
        .wrapping_add(day_of_era)
        .wrapping_sub(719_468)
}

fn civil_from_days(days: i64) -> (u16, u8, u8) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let day_of_era = z.wrapping_sub(era.wrapping_mul(146_097));
    let year_of_era = day_of_era
        .wrapping_sub(day_of_era.div_euclid(1_460))
        .wrapping_add(day_of_era.div_euclid(36_524))
        .wrapping_sub(day_of_era.div_euclid(146_096))
        .div_euclid(365);
    let day_of_year = day_of_era.wrapping_sub(
        year_of_era
            .wrapping_mul(365)
            .wrapping_add(year_of_era.div_euclid(4))
            .wrapping_sub(year_of_era.div_euclid(100)),
    );
    let shifted_month = day_of_year.wrapping_mul(5).wrapping_add(2).div_euclid(153);
    let day = day_of_year
        .wrapping_sub(
            shifted_month
                .wrapping_mul(153)
                .wrapping_add(2)
                .div_euclid(5),
        )
        .wrapping_add(1);
    let month = if shifted_month < 10 {
        shifted_month.wrapping_add(3)
    } else {
        shifted_month.wrapping_sub(9)
    };
    let year = year_of_era
        .wrapping_add(era.wrapping_mul(400))
        .wrapping_add(i64::from(month <= 2));
    (
        u16::try_from(year.clamp(0, 9999)).unwrap_or(0),
        u8::try_from(month).unwrap_or(1),
        u8::try_from(day).unwrap_or(1),
    )
}

fn digits2(hi: u8, lo: u8) -> Option<u8> {
    (hi.is_ascii_digit() && lo.is_ascii_digit()).then(|| {
        hi.wrapping_sub(b'0')
            .wrapping_mul(10)
            .wrapping_add(lo.wrapping_sub(b'0'))
    })
}

fn parse_u64(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |acc, b| {
        acc.checked_mul(10)?
            .checked_add(u64::from(b.wrapping_sub(b'0')))
    })
}

fn parse_fraction(s: &[u8]) -> Option<(u32, &[u8])> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    let (fraction, rest) = s.split_at_checked(digits)?;
    if fraction.is_empty() {
        return None;
    }
    let mut nanos: u32 = 0;
    let mut scale: u32 = 100_000_000;
    for digit in fraction.iter().take(9) {
        nanos = nanos.saturating_add(u32::from(digit.wrapping_sub(b'0')).saturating_mul(scale));
        scale /= 10;
    }
    Some((nanos, rest))
}

fn push_digits(out: &mut Vec<u8>, value: u32, width: u32) {
    let mut divisor = 10u32.saturating_pow(width.saturating_sub(1));
    while divisor > 0 {
        let digit = u8::try_from(value.checked_div(divisor).unwrap_or(0) % 10).unwrap_or(0);
        out.push(b'0'.wrapping_add(digit));
        divisor /= 10;
    }
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    let _ = write!(out, "{value}");
}

fn write_date(out: &mut Vec<u8>, t: &LocalDateTime, separators: bool) {
    push_digits(out, u32::from(t.year), 4);
    if separators {
        out.push(b'-');
    }
    push_digits(out, u32::from(t.month), 2);
    if separators {
        out.push(b'-');
    }
    push_digits(out, u32::from(t.day), 2);
}

fn write_time(out: &mut Vec<u8>, t: &LocalDateTime, separators: bool) {
    push_digits(out, u32::from(t.hour), 2);
    if separators {
        out.push(b':');
    }
    push_digits(out, u32::from(t.minute), 2);
    if separators {
        out.push(b':');
    }
    push_digits(out, u32::from(t.second), 2);
}
