/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonPatch,
    },
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};
use std::{fmt::Display, str::FromStr};

const MINUTES_PER_DAY: u16 = 24 * 60;
const DAYS_FROM_CIVIL_EPOCH: i64 = 719_468;
const DAYS_PER_ERA: i64 = 146_097;
const MIN_YEAR: i64 = 1;
const MAX_YEAR: i64 = 9999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct LocalTime(u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct LocalDate(i32);

impl LocalTime {
    pub const fn from_minutes(minutes: u16) -> Self {
        LocalTime(minutes)
    }

    #[inline(always)]
    pub fn minutes(&self) -> u16 {
        self.0
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.0 <= MINUTES_PER_DAY
    }
}

impl LocalDate {
    pub const fn from_days(days: i32) -> Self {
        LocalDate(days)
    }

    #[inline(always)]
    pub fn days(&self) -> i32 {
        self.0
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        (MIN_YEAR..=MAX_YEAR).contains(&self.civil().0)
    }

    fn from_civil(year: i64, month: i64, day: i64) -> Option<Self> {
        let year = year - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let yoe = year - era * 400;
        let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        i32::try_from(era * DAYS_PER_ERA + doe - DAYS_FROM_CIVIL_EPOCH)
            .ok()
            .map(LocalDate)
    }

    fn civil(&self) -> (i64, i64, i64) {
        let z = i64::from(self.0) + DAYS_FROM_CIVIL_EPOCH;
        let era = z.div_euclid(DAYS_PER_ERA);
        let doe = z - era * DAYS_PER_ERA;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        (yoe + era * 400 + i64::from(month <= 2), month, day)
    }
}

fn is_digits(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit())
}

impl FromStr for LocalTime {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hour, minute) = s
            .split_once(':')
            .filter(|(hour, minute)| {
                hour.len() == 2 && minute.len() == 2 && is_digits(hour) && is_digits(minute)
            })
            .ok_or(())?;
        match (hour.parse::<u16>(), minute.parse::<u16>()) {
            (Ok(hour @ 0..=23), Ok(minute @ 0..=59)) => Ok(LocalTime(hour * 60 + minute)),
            (Ok(24), Ok(0)) => Ok(LocalTime(MINUTES_PER_DAY)),
            _ => Err(()),
        }
    }
}

impl FromStr for LocalDate {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '-');
        let (Some(year), Some(month), Some(day)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(());
        };
        if year.len() != 4
            || month.len() != 2
            || day.len() != 2
            || !is_digits(year)
            || !is_digits(month)
            || !is_digits(day)
        {
            return Err(());
        }
        let (Ok(year), Ok(month @ 1..=12), Ok(day @ 1..=31)) = (
            year.parse::<i64>(),
            month.parse::<i64>(),
            day.parse::<i64>(),
        ) else {
            return Err(());
        };
        LocalDate::from_civil(year, month, day)
            .filter(|date| date.civil() == (year, month, day))
            .ok_or(())
    }
}

impl Display for LocalTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02}:{:02}", self.0 / 60, self.0 % 60)
    }
}

impl Display for LocalDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (year, month, day) = self.civil();
        write!(f, "{year:04}-{month:02}-{day:02}")
    }
}

impl serde::Serialize for LocalTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl serde::Serialize for LocalDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for LocalTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        LocalTime::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid LocalTime"))
    }
}

impl<'de> serde::Deserialize<'de> for LocalDate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        LocalDate::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid LocalDate"))
    }
}

impl Pickle for LocalTime {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        data.read_array::<2>()
            .map(|bytes| LocalTime(u16::from_le_bytes(bytes)))
    }
}

impl Pickle for LocalDate {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        data.read_array::<4>()
            .map(|bytes| LocalDate(i32::from_le_bytes(bytes)))
    }
}

impl RegistryJsonPatch for LocalTime {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Str(value), None) => {
                *self = LocalTime::from_str(value.as_ref()).map_err(|_| {
                    PatchError::new(pointer, "Failed to parse LocalTime, expected HH:MM")
                })?;
                Ok(MaybeUnpatched::Patched)
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for LocalTime, expected a string value",
            )),
        }
    }
}

impl RegistryJsonPatch for LocalDate {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Str(value), None) => {
                *self = LocalDate::from_str(value.as_ref()).map_err(|_| {
                    PatchError::new(pointer, "Failed to parse LocalDate, expected YYYY-MM-DD")
                })?;
                Ok(MaybeUnpatched::Patched)
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for LocalDate, expected a string value",
            )),
        }
    }
}

impl IntoValue for LocalTime {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.to_string().into())
    }
}

impl IntoValue for LocalDate {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.to_string().into())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/registry/src/types/localtime/tests.rs"]
mod tests;
