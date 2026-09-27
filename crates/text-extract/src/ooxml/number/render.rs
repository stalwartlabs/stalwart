/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DateSystem, NumberFormat, SIGNIFICANT_DIGITS, push_exact, push_integer};
use crate::{output::Output, xml::Text};
use std::fmt::{self, Write};

const SECONDS_PER_DAY: u32 = 86_400;
const MAX_SERIAL: f64 = 2_958_466.0;
const LEAP_DAY_SERIAL: i64 = 60;
const DAYS_1899_12_30_TO_UNIX: i64 = -25_569;
const DAYS_1899_12_31_TO_UNIX: i64 = -25_568;
const DAYS_1904_01_01_TO_UNIX: i64 = -24_107;
const MIN_PLAIN: f64 = 1e-9;
const MAX_PLAIN: f64 = 1e15;
const RENDER_CAPACITY: usize = 64;
const MAX_SERIAL_DAYS: i64 = 2_958_466;
const MAX_UNIX_DAYS: i64 = 2_932_896;
const MAX_SERIAL_DIGITS: usize = 7;

struct Rendered {
    bytes: [u8; RENDER_CAPACITY],
    len: usize,
}

impl Rendered {
    fn new() -> Self {
        Rendered {
            bytes: [0; RENDER_CAPACITY],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.bytes.get(..self.len).unwrap_or_default()).unwrap_or_default()
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    fn push_digits(&mut self, value: u64, width: usize) -> fmt::Result {
        let mut digits = [b'0'; 20];
        let mut remaining = value;
        let mut used = 0;
        for slot in digits.iter_mut().rev() {
            *slot = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            used += 1;
            if remaining == 0 && used >= width {
                break;
            }
        }
        let start = digits.len() - used;
        let text =
            std::str::from_utf8(digits.get(start..).unwrap_or_default()).map_err(|_| fmt::Error)?;
        self.write_str(text)
    }
}

impl Write for Rendered {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub(crate) fn push_boolean(raw: &[u8], out: &mut Output<'_>) {
    match raw.trim_ascii() {
        b"1" => out.push_str("TRUE"),
        b"0" => out.push_str("FALSE"),
        other => out.push_utf8(other),
    }
}

pub(crate) fn push_number(
    raw: &[u8],
    format: NumberFormat,
    dates: DateSystem,
    out: &mut Output<'_>,
) {
    let trimmed = raw.trim_ascii();
    if push_integer(Text::raw(trimmed), format, out) || push_exact(Text::raw(trimmed), format, out)
    {
        return;
    }
    let mut rendered = Rendered::new();
    if matches!(format, NumberFormat::Date | NumberFormat::DateTime)
        && let Some(moment) = whole_days(trimmed).and_then(|days| Moment::from_days(days, 0, dates))
        && render_moment(&moment, format, &mut rendered).is_ok()
    {
        out.push_str(rendered.as_str());
        return;
    }
    let Some(value) = std::str::from_utf8(trimmed)
        .ok()
        .and_then(|text| text.parse::<f64>().ok())
        .filter(|value| value.is_finite())
    else {
        out.push_utf8(trimmed);
        return;
    };
    rendered.clear();
    if render(value, format, dates, &mut rendered, out).is_ok() {
        out.push_str(rendered.as_str());
    } else {
        out.push_utf8(trimmed);
    }
}

fn render(
    value: f64,
    format: NumberFormat,
    dates: DateSystem,
    rendered: &mut Rendered,
    out: &mut Output<'_>,
) -> fmt::Result {
    match format {
        NumberFormat::General | NumberFormat::Text => {
            if write!(rendered, "{value}").is_ok()
                && push_exact(Text::raw(rendered.bytes()), format, out)
            {
                rendered.clear();
                return Ok(());
            }
            rendered.clear();
            write_general(value, rendered)
        }
        NumberFormat::Fixed(_) | NumberFormat::Percent(_) => {
            write!(rendered, "{value}")?;
            if push_exact(Text::raw(rendered.bytes()), format, out) {
                rendered.clear();
                Ok(())
            } else {
                Err(fmt::Error)
            }
        }
        NumberFormat::Date | NumberFormat::DateTime | NumberFormat::Time => {
            let moment = Moment::from_serial(value, dates).ok_or(fmt::Error)?;
            render_moment(&moment, format, rendered)
        }
        NumberFormat::ElapsedTime => {
            let seconds = (value.abs() * f64::from(SECONDS_PER_DAY)).round();
            if seconds >= MAX_SERIAL * f64::from(SECONDS_PER_DAY) {
                return Err(fmt::Error);
            }
            let seconds = seconds as u64;
            if value < 0.0 && seconds > 0 {
                rendered.write_char('-')?;
            }
            rendered.push_digits(seconds / 3600, 1)?;
            rendered.write_char(':')?;
            rendered.push_digits(seconds / 60 % 60, 2)?;
            rendered.write_char(':')?;
            rendered.push_digits(seconds % 60, 2)
        }
    }
}

fn render_moment(moment: &Moment, format: NumberFormat, rendered: &mut Rendered) -> fmt::Result {
    match format {
        NumberFormat::Date => moment.write_date(rendered),
        NumberFormat::DateTime => {
            moment.write_date(rendered)?;
            rendered.write_char(' ')?;
            moment.write_time(rendered)
        }
        _ => moment.write_time(rendered),
    }
}

fn whole_days(raw: &[u8]) -> Option<i64> {
    if raw.is_empty() || raw.len() > MAX_SERIAL_DIGITS {
        return None;
    }
    raw.iter().try_fold(0i64, |days, &digit| {
        Some(days * 10 + i64::from(digit.checked_sub(b'0').filter(|value| *value < 10)?))
    })
}

fn write_general(value: f64, rendered: &mut Rendered) -> fmt::Result {
    write!(rendered, "{:.*e}", SIGNIFICANT_DIGITS - 1, value)?;
    let rounded = rendered.as_str().parse::<f64>().map_err(|_| fmt::Error)?;
    rendered.clear();
    if rounded == 0.0 {
        rendered.write_char('0')
    } else if (MIN_PLAIN..MAX_PLAIN).contains(&rounded.abs()) {
        write!(rendered, "{rounded}")
    } else {
        write!(rendered, "{rounded:e}")
    }
}

struct Moment {
    year: i64,
    month: u32,
    day: u32,
    seconds: u32,
}

impl Moment {
    fn from_serial(serial: f64, dates: DateSystem) -> Option<Moment> {
        if !(0.0..MAX_SERIAL).contains(&serial) {
            return None;
        }
        let whole = serial.floor();
        let mut days = whole as i64;
        let mut seconds = ((serial - whole) * f64::from(SECONDS_PER_DAY)).round() as u32;
        if seconds >= SECONDS_PER_DAY {
            days += 1;
            seconds -= SECONDS_PER_DAY;
        }
        Moment::from_days(days, seconds, dates)
    }

    fn from_days(days: i64, seconds: u32, dates: DateSystem) -> Option<Moment> {
        if !(0..MAX_SERIAL_DAYS).contains(&days) {
            return None;
        }
        let unix_days = match dates {
            DateSystem::Epoch1904 => days + DAYS_1904_01_01_TO_UNIX,
            DateSystem::Epoch1900 if days == LEAP_DAY_SERIAL => {
                return Some(Moment {
                    year: 1900,
                    month: 2,
                    day: 29,
                    seconds,
                });
            }
            DateSystem::Epoch1900 if days < LEAP_DAY_SERIAL => days + DAYS_1899_12_31_TO_UNIX,
            DateSystem::Epoch1900 => days + DAYS_1899_12_30_TO_UNIX,
        };
        if unix_days > MAX_UNIX_DAYS {
            return None;
        }
        let (year, month, day) = civil_from_days(unix_days);
        Some(Moment {
            year,
            month,
            day,
            seconds,
        })
    }

    fn write_date(&self, rendered: &mut Rendered) -> fmt::Result {
        rendered.push_digits(u64::try_from(self.year).map_err(|_| fmt::Error)?, 4)?;
        rendered.write_char('-')?;
        rendered.push_digits(u64::from(self.month), 2)?;
        rendered.write_char('-')?;
        rendered.push_digits(u64::from(self.day), 2)
    }

    fn write_time(&self, rendered: &mut Rendered) -> fmt::Result {
        rendered.push_digits(u64::from(self.seconds / 3600), 2)?;
        rendered.write_char(':')?;
        rendered.push_digits(u64::from(self.seconds / 60 % 60), 2)?;
        rendered.write_char(':')?;
        rendered.push_digits(u64::from(self.seconds % 60), 2)
    }
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}
