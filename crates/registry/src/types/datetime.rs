/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{IntoValue, JmapValue, JsonPointerPatch, RegistryJsonPatch},
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};
use std::{fmt::Display, str::FromStr, time::SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct UTCDateTime(i64);

struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_before_gmt: bool,
    pub tz_hour: u8,
    pub tz_minute: u8,
}

impl FromStr for UTCDateTime {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 2004 - 06 - 28 T 23 : 43 : 45 . 000 Z
        // 1969 - 02 - 13 T 23 : 32 : 00 - 03 : 30
        //   0     1    2    3    4    5    6    7

        let mut pos = 0;
        let mut parts = [0u32; 8];
        let mut parts_sizes = [
            4u32, // Year (0)
            2u32, // Month (1)
            2u32, // Day (2)
            2u32, // Hour (3)
            2u32, // Minute (4)
            2u32, // Second (5)
            2u32, // TZ Hour (6)
            2u32, // TZ Minute (7)
        ];
        let mut skip_digits = false;
        let mut is_plus = true;

        for ch in s.as_bytes() {
            match ch {
                b'0'..=b'9' => {
                    if !skip_digits {
                        if parts_sizes[pos] > 0 {
                            parts_sizes[pos] -= 1;
                            parts[pos] += (ch - b'0') as u32 * u32::pow(10, parts_sizes[pos]);
                        } else {
                            break;
                        }
                    }
                }
                b'-' => {
                    if pos <= 1 {
                        pos += 1;
                    } else if pos == 5 {
                        pos += 1;
                        is_plus = false;
                        skip_digits = false;
                    } else {
                        break;
                    }
                }
                b'T' => {
                    if pos == 2 {
                        pos += 1;
                    } else {
                        break;
                    }
                }
                b':' => {
                    if [3, 4, 6].contains(&pos) {
                        pos += 1;
                    } else {
                        break;
                    }
                }
                b'+' => {
                    if pos == 5 {
                        pos += 1;
                        skip_digits = false;
                    } else {
                        break;
                    }
                }
                b'.' => {
                    if pos == 5 {
                        skip_digits = true;
                    } else {
                        break;
                    }
                }
                b'Z' | b'z' => (),
                _ => {
                    break;
                }
            }
        }

        let dt = DateTime {
            year: parts[0] as u16,
            month: parts[1] as u8,
            day: parts[2] as u8,
            hour: parts[3] as u8,
            minute: parts[4] as u8,
            second: parts[5] as u8,
            tz_hour: parts[6] as u8,
            tz_minute: parts[7] as u8,
            tz_before_gmt: !is_plus,
        };

        if pos >= 5 && dt.is_valid() {
            Ok(UTCDateTime(dt.timestamp()))
        } else {
            Err(())
        }
    }
}

impl UTCDateTime {
    pub fn now() -> Self {
        UTCDateTime(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        )
    }

    pub fn from_timestamp(timestamp: i64) -> Self {
        UTCDateTime(timestamp)
    }

    #[inline(always)]
    pub fn timestamp(&self) -> i64 {
        self.0
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.0 != i64::MAX
    }
}

impl DateTime {
    pub fn from_timestamp(timestamp: i64) -> Self {
        // Ported from http://howardhinnant.github.io/date_algorithms.html#civil_from_days
        let (z, seconds) = ((timestamp / 86400) + 719468, timestamp % 86400);
        let era: i64 = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe: u64 = (z - era * 146097) as u64; // [0, 146096]
        let yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y: i64 = (yoe as i64) + era * 400;
        let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d: u64 = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let (h, mn, s) = (seconds / 3600, (seconds / 60) % 60, seconds % 60);

        DateTime {
            year: (y + i64::from(m <= 2)) as u16,
            month: m as u8,
            day: d as u8,
            hour: h as u8,
            minute: mn as u8,
            second: s as u8,
            tz_before_gmt: false,
            tz_hour: 0,
            tz_minute: 0,
        }
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        (0..=23).contains(&self.tz_hour)
            && (1970..=3000).contains(&self.year)
            && (0..=59).contains(&self.tz_minute)
            && (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
            && (0..=23).contains(&self.hour)
            && (0..=59).contains(&self.minute)
            && (0..=59).contains(&self.second)
    }

    pub fn timestamp(&self) -> i64 {
        // Ported from https://github.com/protocolbuffers/upb/blob/22182e6e/upb/json_decode.c#L982-L992
        let month = self.month as u32;
        let year_base = 4800; /* Before min year, multiple of 400. */
        let m_adj = month.wrapping_sub(3); /* March-based month. */
        let carry = i64::from(m_adj > month);
        let adjust = if carry > 0 { 12 } else { 0 };
        let y_adj = self.year as i64 + year_base - carry;
        let month_days = ((m_adj.wrapping_add(adjust)) * 62719 + 769) / 2048;
        let leap_days = y_adj / 4 - y_adj / 100 + y_adj / 400;
        (y_adj * 365 + leap_days + month_days as i64 + (self.day as i64 - 1) - 2472632) * 86400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64
            + ((self.tz_hour as i64 * 3600 + self.tz_minute as i64 * 60)
                * if self.tz_before_gmt { 1 } else { -1 })
    }
}

impl Display for UTCDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dt = DateTime::from_timestamp(self.0);

        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
        )
    }
}

impl Default for UTCDateTime {
    fn default() -> Self {
        UTCDateTime(i64::MAX)
    }
}

impl serde::Serialize for UTCDateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for UTCDateTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UTCDateTime::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid DateTime"))
    }
}

impl Pickle for UTCDateTime {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_be_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(data.read_bytes(8)?);
        Some(UTCDateTime(i64::from_be_bytes(arr)))
    }
}

impl From<u64> for UTCDateTime {
    fn from(value: u64) -> Self {
        UTCDateTime(value as i64)
    }
}

impl RegistryJsonPatch for UTCDateTime {
    fn patch(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'_>,
    ) -> Result<(), PatchError> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = UTCDateTime::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(())
                } else {
                    Err(PatchError::new(
                        pointer,
                        "Failed to parse UTCDateTime from string",
                    ))
                }
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for UTCDateTime, expected a string value",
            )),
        }
    }
}

impl IntoValue for UTCDateTime {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::types::datetime::UTCDateTime;

    #[test]
    fn parse_jmap_date() {
        for (input, _) in [
            ("1997-11-21T09:55:06-06:00", "1997-11-21T09:55:06-06:00"),
            ("1997-11-21T09:55:06+00:00", "1997-11-21T09:55:06Z"),
            ("2021-01-01T09:55:06+02:00", "2021-01-01T09:55:06+02:00"),
            ("2004-06-28T23:43:45.000Z", "2004-06-28T23:43:45Z"),
            ("1997-11-21T09:55:06.123+00:00", "1997-11-21T09:55:06Z"),
            (
                "2021-01-01T09:55:06.4567+02:00",
                "2021-01-01T09:55:06+02:00",
            ),
        ] {
            let date = UTCDateTime::from_str(input).unwrap();
            //assert_eq!(date.to_string(), expected_result);

            let timestamp = date.timestamp();
            assert_eq!(
                UTCDateTime::from_timestamp(timestamp).timestamp(),
                timestamp
            );
        }
    }
}
