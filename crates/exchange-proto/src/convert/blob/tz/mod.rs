/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod windows;

use std::ops::RangeInclusive;

use jiff::{
    SignedDuration, Timestamp,
    civil::{Date, DateTime},
    tz::{Offset, TimeZone},
};

pub use windows::{TERRITORY_ZONES, iana_to_windows};

use crate::{
    common::{
        reader::LeReader,
        time::{LocalDateTime, SystemTime},
        utf16::Utf16Le,
        writer::LeWriter,
    },
    convert::{BlobKind, BlobLimits, ConvertError, blob::goid::days_in_month},
};

const MAJOR_VERSION: u8 = 0x02;
const MINOR_VERSION: u8 = 0x01;
const TZDEF_RESERVED: u16 = 0x0002;
const TZRULE_RESERVED: u16 = 0x003E;
const TZRULE_UNUSED_LEN: usize = 14;
const MAX_RULES: u16 = 1024;
const MAX_KEY_NAME_UNITS: u16 = 260;
const MAX_TRANSITIONS_PER_YEAR: usize = 16;
const LAST_WEEK: u16 = 5;
const DAYS_PER_WEEK: u16 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TzRule {
    pub year: u16,
    pub flags: u16,
    pub bias: i32,
    pub standard_bias: i32,
    pub daylight_bias: i32,
    pub standard_date: SystemTime,
    pub daylight_date: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TzDefinition {
    pub key_name: Box<str>,
    pub rules: Vec<TzRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TzStruct {
    pub bias: i32,
    pub standard_bias: i32,
    pub daylight_bias: i32,
    pub standard_year: u16,
    pub standard_date: SystemTime,
    pub daylight_year: u16,
    pub daylight_date: SystemTime,
}

impl TzRule {
    pub const FLAG_RECUR_CURRENT: u16 = 0x1;
    pub const FLAG_EFFECTIVE: u16 = 0x2;

    pub fn has_daylight(&self) -> bool {
        self.standard_date.month != 0 && self.daylight_date.month != 0
    }

    pub fn utc_offset_minutes(&self, local: LocalDateTime) -> i32 {
        let daylight = self.has_daylight() && {
            let at = (
                local.month,
                local.day,
                local.hour,
                local.minute,
                local.second,
            );
            let year = local.year;
            match (
                transition_in_year(&self.daylight_date, year),
                transition_in_year(&self.standard_date, year),
            ) {
                (Some(start), Some(end)) if start <= end => at >= start && at < end,
                (Some(start), Some(end)) => at >= start || at < end,
                _ => false,
            }
        };
        let extra = if daylight {
            self.daylight_bias
        } else {
            self.standard_bias
        };
        self.bias.saturating_add(extra).saturating_neg()
    }

    fn decode(reader: &mut LeReader<'_>) -> Option<Self> {
        let major = reader.u8().ok()?;
        let _minor = reader.u8().ok()?;
        let _reserved = reader.u16().ok()?;
        let flags = reader.u16().ok()?;
        let year = reader.u16().ok()?;
        reader.skip(TZRULE_UNUSED_LEN).ok()?;
        let rule = TzRule {
            year,
            flags,
            bias: reader.i32().ok()?,
            standard_bias: reader.i32().ok()?,
            daylight_bias: reader.i32().ok()?,
            standard_date: read_system_time(reader)?,
            daylight_date: read_system_time(reader)?,
        };
        (major == MAJOR_VERSION).then_some(rule)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(MAJOR_VERSION);
        out.put_u8(MINOR_VERSION);
        out.put_u16(TZRULE_RESERVED);
        out.put_u16(self.flags);
        out.put_u16(self.year);
        out.extend_from_slice(&[0u8; TZRULE_UNUSED_LEN]);
        out.put_i32(self.bias);
        out.put_i32(self.standard_bias);
        out.put_i32(self.daylight_bias);
        write_system_time(&self.standard_date, out);
        write_system_time(&self.daylight_date, out);
    }

    pub(crate) fn same_zone(&self, other: &TzRule) -> bool {
        self.bias == other.bias
            && self.standard_bias == other.standard_bias
            && self.daylight_bias == other.daylight_bias
            && self.standard_date == other.standard_date
            && self.daylight_date == other.daylight_date
    }

    fn from_year(tz: &TimeZone, year: i16) -> Option<Self> {
        let start = year_start(year)?;
        let end = year.checked_add(1).and_then(year_start)?;
        let mut daylight_start = None;
        let mut standard_start = None;
        for transition in tz
            .following(start)
            .take_while(|t| t.timestamp() < end)
            .take(MAX_TRANSITIONS_PER_YEAR)
        {
            let at = transition.timestamp();
            let before = tz.to_offset(at.checked_sub(SignedDuration::from_secs(1)).ok()?);
            let local = before.to_datetime(at);
            if transition.dst().is_dst() {
                daylight_start = Some((local, transition.offset()));
            } else {
                standard_start = Some((local, transition.offset()));
            }
        }
        let rule = match (daylight_start, standard_start) {
            (Some((daylight_at, daylight)), Some((standard_at, standard))) => {
                let bias = offset_bias(standard);
                TzRule {
                    year: u16::try_from(year).ok()?,
                    flags: 0,
                    bias,
                    standard_bias: 0,
                    daylight_bias: offset_bias(daylight).saturating_sub(bias),
                    standard_date: relative_date(standard_at),
                    daylight_date: relative_date(daylight_at),
                }
            }
            _ => TzRule {
                year: u16::try_from(year).ok()?,
                bias: offset_bias(
                    tz.to_offset(end.checked_sub(SignedDuration::from_secs(1)).ok()?),
                ),
                ..TzRule::default()
            },
        };
        Some(rule)
    }
}

impl TzDefinition {
    pub fn decode(b: &[u8], _limits: &BlobLimits) -> Result<Self, ConvertError> {
        let mut reader = LeReader::new(b);
        let bad = |reader: &LeReader<'_>| ConvertError::BadBlob {
            what: BlobKind::TimeZoneDefinition,
            offset: u32::try_from(reader.offset()).unwrap_or(u32::MAX),
        };
        let header = (|| {
            let major = reader.u8().ok()?;
            let _minor = reader.u8().ok()?;
            let header_len = reader.u16().ok()?;
            let _reserved = reader.u16().ok()?;
            let key_units = reader.u16().ok()?;
            if major != MAJOR_VERSION || key_units > MAX_KEY_NAME_UNITS {
                return None;
            }
            let key_name =
                Utf16Le::new(reader.bytes(usize::from(key_units).checked_mul(2)?).ok()?)?;
            let rule_count = reader.u16().ok()?;
            let expected_len = u32::from(key_units).checked_mul(2)?.checked_add(6)?;
            if u32::from(header_len) != expected_len || rule_count == 0 || rule_count > MAX_RULES {
                return None;
            }
            let mut name = String::with_capacity(usize::from(key_units));
            key_name.to_string_lossy(&mut name);
            Some((name.into_boxed_str(), rule_count))
        })();
        let Some((key_name, rule_count)) = header else {
            return Err(bad(&reader));
        };
        let mut rules = Vec::with_capacity(usize::from(rule_count));
        for _ in 0..rule_count {
            let rule = TzRule::decode(&mut reader).ok_or_else(|| bad(&reader))?;
            rules.push(rule);
        }
        Ok(TzDefinition { key_name, rules })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let key_units = u16::try_from(self.key_name.encode_utf16().count())
            .unwrap_or(MAX_KEY_NAME_UNITS)
            .min(MAX_KEY_NAME_UNITS);
        let rule_count = u16::try_from(self.rules.len())
            .unwrap_or(MAX_RULES)
            .min(MAX_RULES);
        out.put_u8(MAJOR_VERSION);
        out.put_u8(MINOR_VERSION);
        out.put_u16(key_units.saturating_mul(2).saturating_add(6));
        out.put_u16(TZDEF_RESERVED);
        out.put_u16(key_units);
        for unit in self.key_name.encode_utf16().take(usize::from(key_units)) {
            out.put_u16(unit);
        }
        out.put_u16(rule_count);
        for rule in self.rules.iter().take(usize::from(rule_count)) {
            rule.encode(out);
        }
    }

    pub fn effective(&self) -> Option<&TzRule> {
        self.rules
            .iter()
            .find(|rule| rule.flags & TzRule::FLAG_EFFECTIVE != 0)
            .or_else(|| self.rules.last())
    }

    pub fn from_time_zone(key_name: &str, tz: &TimeZone, years: RangeInclusive<i16>) -> Self {
        let first_year = *years.start();
        let mut rules: Vec<TzRule> = Vec::new();
        for year in years {
            let Some(rule) = TzRule::from_year(tz, year) else {
                continue;
            };
            if rules.last().is_none_or(|last| !last.same_zone(&rule)) {
                rules.push(rule);
            }
            if rules.len() >= usize::from(MAX_RULES) {
                break;
            }
        }
        let effective = rules
            .iter()
            .rposition(|rule| i32::from(rule.year) <= i32::from(first_year))
            .unwrap_or_default();
        if let Some(rule) = rules.get_mut(effective) {
            rule.flags = TzRule::FLAG_RECUR_CURRENT | TzRule::FLAG_EFFECTIVE;
        }
        TzDefinition {
            key_name: key_name.into(),
            rules,
        }
    }
}

impl TzStruct {
    pub fn decode(b: &[u8]) -> Result<Self, ConvertError> {
        let mut reader = LeReader::new(b);
        let decoded = (|| {
            Some(TzStruct {
                bias: reader.i32().ok()?,
                standard_bias: reader.i32().ok()?,
                daylight_bias: reader.i32().ok()?,
                standard_year: reader.u16().ok()?,
                standard_date: read_system_time(&mut reader)?,
                daylight_year: reader.u16().ok()?,
                daylight_date: read_system_time(&mut reader)?,
            })
        })();
        decoded.ok_or(ConvertError::BadBlob {
            what: BlobKind::TimeZoneStruct,
            offset: u32::try_from(reader.offset()).unwrap_or(u32::MAX),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_i32(self.bias);
        out.put_i32(self.standard_bias);
        out.put_i32(self.daylight_bias);
        out.put_u16(self.standard_year);
        write_system_time(&self.standard_date, out);
        out.put_u16(self.daylight_year);
        write_system_time(&self.daylight_date, out);
    }

    pub fn from_rule(rule: &TzRule) -> Self {
        TzStruct {
            bias: rule.bias,
            standard_bias: rule.standard_bias,
            daylight_bias: rule.daylight_bias,
            standard_year: rule.standard_date.year,
            standard_date: rule.standard_date,
            daylight_year: rule.daylight_date.year,
            daylight_date: rule.daylight_date,
        }
    }

    pub fn matches(&self, rule: &TzRule) -> bool {
        self.bias == rule.bias
            && self.standard_bias == rule.standard_bias
            && self.daylight_bias == rule.daylight_bias
            && self.standard_date == rule.standard_date
            && self.daylight_date == rule.daylight_date
    }

    pub fn to_rule(&self) -> TzRule {
        TzRule {
            year: 0,
            flags: TzRule::FLAG_RECUR_CURRENT | TzRule::FLAG_EFFECTIVE,
            bias: self.bias,
            standard_bias: self.standard_bias,
            daylight_bias: self.daylight_bias,
            standard_date: self.standard_date,
            daylight_date: self.daylight_date,
        }
    }
}

fn read_system_time(reader: &mut LeReader<'_>) -> Option<SystemTime> {
    Some(SystemTime {
        year: reader.u16().ok()?,
        month: reader.u16().ok()?,
        day_of_week: reader.u16().ok()?,
        day: reader.u16().ok()?,
        hour: reader.u16().ok()?,
        minute: reader.u16().ok()?,
        second: reader.u16().ok()?,
        millis: reader.u16().ok()?,
    })
}

fn write_system_time(time: &SystemTime, out: &mut Vec<u8>) {
    for field in [
        time.year,
        time.month,
        time.day_of_week,
        time.day,
        time.hour,
        time.minute,
        time.second,
        time.millis,
    ] {
        out.put_u16(field);
    }
}

fn transition_in_year(date: &SystemTime, year: u16) -> Option<(u8, u8, u8, u8, u8)> {
    let month = u8::try_from(date.month)
        .ok()
        .filter(|m| (1..=12).contains(m))?;
    let day = if date.year != 0 {
        u8::try_from(date.day).ok()?
    } else {
        let last = days_in_month(year, month);
        let first_weekday = weekday(year, month, 1);
        let target = date.day_of_week % DAYS_PER_WEEK;
        let first = target
            .wrapping_add(DAYS_PER_WEEK)
            .wrapping_sub(first_weekday)
            .wrapping_rem(DAYS_PER_WEEK)
            .wrapping_add(1);
        let week = date.day.clamp(1, LAST_WEEK);
        let mut day = first.wrapping_add(week.wrapping_sub(1).wrapping_mul(DAYS_PER_WEEK));
        while day > u16::from(last) {
            day = day.saturating_sub(DAYS_PER_WEEK);
        }
        u8::try_from(day).ok()?
    };
    Some((
        month,
        day,
        u8::try_from(date.hour).ok()?,
        u8::try_from(date.minute).ok()?,
        u8::try_from(date.second).ok()?,
    ))
}

pub(crate) fn weekday(year: u16, month: u8, day: u8) -> u16 {
    const OFFSETS: [u16; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let year = if month < 3 {
        year.saturating_sub(1)
    } else {
        year
    };
    let offset = OFFSETS
        .get(usize::from(month.saturating_sub(1)))
        .copied()
        .unwrap_or_default();
    let sum = u32::from(year)
        .wrapping_add(u32::from(year / 4))
        .wrapping_sub(u32::from(year / 100))
        .wrapping_add(u32::from(year / 400))
        .wrapping_add(u32::from(offset))
        .wrapping_add(u32::from(day));
    u16::try_from(sum % 7).unwrap_or_default()
}

fn year_start(year: i16) -> Option<Timestamp> {
    Offset::UTC
        .to_timestamp(
            Date::new(year, 1, 1)
                .ok()?
                .to_datetime(jiff::civil::Time::midnight()),
        )
        .ok()
}

fn offset_bias(offset: Offset) -> i32 {
    (offset.seconds() / 60).saturating_neg()
}

fn relative_date(local: DateTime) -> SystemTime {
    let day = u16::try_from(local.day()).unwrap_or_default();
    let last = local.days_in_month();
    let week = if local.day().saturating_add(7) > last {
        LAST_WEEK
    } else {
        (day.saturating_sub(1) / DAYS_PER_WEEK).saturating_add(1)
    };
    SystemTime {
        year: 0,
        month: u16::try_from(local.month()).unwrap_or_default(),
        day_of_week: u16::from(local.weekday().to_sunday_zero_offset().unsigned_abs()),
        day: week,
        hour: u16::try_from(local.hour()).unwrap_or_default(),
        minute: u16::try_from(local.minute()).unwrap_or_default(),
        second: u16::try_from(local.second()).unwrap_or_default(),
        millis: 0,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/blob/tz/tests.rs"]
mod tests;
