/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    str::{FromStr, from_utf8},
};

#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[rkyv(derive(Debug), compare(PartialEq))]
pub struct UTCDate {
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

impl FromStr for UTCDate {
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
                b'T' if pos == 2 => {
                    pos += 1;
                }
                b':' if [3, 4, 6].contains(&pos) => {
                    pos += 1;
                }
                b'+' if pos == 5 => {
                    pos += 1;
                    skip_digits = false;
                }
                b'.' if pos == 5 => {
                    skip_digits = true;
                }
                b'Z' | b'z' => (),
                _ => {
                    break;
                }
            }
        }

        if pos >= 5 {
            Ok(UTCDate {
                year: parts[0] as u16,
                month: parts[1] as u8,
                day: parts[2] as u8,
                hour: parts[3] as u8,
                minute: parts[4] as u8,
                second: parts[5] as u8,
                tz_hour: parts[6] as u8,
                tz_minute: parts[7] as u8,
                tz_before_gmt: !is_plus,
            })
        } else {
            Err(())
        }
    }
}

impl UTCDate {
    fn text(&self) -> DateText {
        let mut text = DateText {
            bytes: [0; DATE_TEXT_CAPACITY],
            len: 0,
        };
        text.push_number(self.year, 4);
        text.push(b'-');
        text.push_number(self.month.into(), 2);
        text.push(b'-');
        text.push_number(self.day.into(), 2);
        text.push(b'T');
        text.push_number(self.hour.into(), 2);
        text.push(b':');
        text.push_number(self.minute.into(), 2);
        text.push(b':');
        text.push_number(self.second.into(), 2);
        if self.tz_hour != 0 || self.tz_minute != 0 {
            text.push(
                if self.tz_before_gmt && (self.tz_hour > 0 || self.tz_minute > 0) {
                    b'-'
                } else {
                    b'+'
                },
            );
            text.push_number(self.tz_hour.into(), 2);
            text.push(b':');
            text.push_number(self.tz_minute.into(), 2);
        } else {
            text.push(b'Z');
        }
        text
    }

    pub fn from_timestamp(timestamp: i64) -> Self {
        // Ported from http://howardhinnant.github.io/date_algorithms.html#civil_from_days
        let (z, seconds) = (
            timestamp.div_euclid(86400) + 719468,
            timestamp.rem_euclid(86400),
        );
        let era: i64 = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe: u64 = (z - era * 146097) as u64; // [0, 146096]
        let yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y: i64 = (yoe as i64) + era * 400;
        let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d: u64 = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let (h, mn, s) = (seconds / 3600, (seconds / 60) % 60, seconds % 60);

        UTCDate {
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

impl From<&ArchivedUTCDate> for UTCDate {
    fn from(value: &ArchivedUTCDate) -> Self {
        UTCDate {
            year: value.year.to_native(),
            month: value.month,
            day: value.day,
            hour: value.hour,
            minute: value.minute,
            second: value.second,
            tz_before_gmt: value.tz_before_gmt,
            tz_hour: value.tz_hour,
            tz_minute: value.tz_minute,
        }
    }
}

const DATE_TEXT_CAPACITY: usize = 40;
const MAX_DIGITS: usize = 5;

struct DateText {
    bytes: [u8; DATE_TEXT_CAPACITY],
    len: usize,
}

impl DateText {
    fn push(&mut self, byte: u8) {
        if let Some(slot) = self.bytes.get_mut(self.len) {
            *slot = byte;
            self.len += 1;
        }
    }

    fn push_number(&mut self, value: u16, width: usize) {
        let mut digits = [0u8; MAX_DIGITS];
        let mut rest = value;
        let mut count = 0;
        for digit in digits.iter_mut().rev() {
            *digit = b'0' + (rest % 10) as u8;
            rest /= 10;
            count += 1;
            if rest == 0 {
                break;
            }
        }
        (count..width).for_each(|_| self.push(b'0'));
        if let Some((_, significant)) = digits.split_at_checked(MAX_DIGITS - count) {
            significant.iter().for_each(|&digit| self.push(digit));
        }
    }

    fn as_str(&self) -> &str {
        self.bytes
            .get(..self.len)
            .and_then(|bytes| from_utf8(bytes).ok())
            .unwrap_or_default()
    }
}

impl Display for UTCDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text().as_str())
    }
}

impl serde::Serialize for UTCDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.text().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for UTCDate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UTCDate::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid JMAP UTCDate"))
    }
}

impl From<UTCDate> for u64 {
    fn from(value: UTCDate) -> Self {
        value.timestamp() as u64
    }
}

impl From<u64> for UTCDate {
    fn from(value: u64) -> Self {
        UTCDate::from_timestamp(value as i64)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::date::UTCDate;
    use std::str::FromStr;

    #[test]
    fn display_renders_padded_fields() {
        let date =
            |year, month, day, hour, minute, second, tz_before_gmt, tz_hour, tz_minute| UTCDate {
                year,
                month,
                day,
                hour,
                minute,
                second,
                tz_before_gmt,
                tz_hour,
                tz_minute,
            };
        for (value, text) in [
            (UTCDate::from_timestamp(0), "1970-01-01T00:00:00Z"),
            (
                UTCDate::from_timestamp(1_738_598_445),
                "2025-02-03T16:00:45Z",
            ),
            (
                date(2025, 2, 3, 16, 0, 45, false, 5, 30),
                "2025-02-03T16:00:45+05:30",
            ),
            (
                date(2025, 2, 3, 16, 0, 45, true, 8, 0),
                "2025-02-03T16:00:45-08:00",
            ),
            (
                date(2025, 2, 3, 16, 0, 45, true, 0, 0),
                "2025-02-03T16:00:45Z",
            ),
            (
                date(2025, 2, 3, 16, 0, 45, true, 0, 30),
                "2025-02-03T16:00:45-00:30",
            ),
            (date(7, 1, 1, 0, 0, 0, false, 0, 0), "0007-01-01T00:00:00Z"),
            (
                date(12345, 12, 31, 23, 59, 59, false, 0, 0),
                "12345-12-31T23:59:59Z",
            ),
            (
                date(2024, 100, 9, 1, 2, 3, false, 14, 0),
                "2024-100-09T01:02:03+14:00",
            ),
            (
                date(65535, 255, 255, 255, 255, 255, true, 255, 255),
                "65535-255-255T255:255:255-255:255",
            ),
        ] {
            assert_eq!(value.to_string(), text);
            assert_eq!(format!("{value:>40}"), text);
        }
    }

    #[test]
    fn parse_jmap_date() {
        for (input, expected_result) in [
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
            let date = UTCDate::from_str(input).unwrap();
            assert_eq!(date.to_string(), expected_result);

            let timestamp = date.timestamp();
            assert_eq!(UTCDate::from_timestamp(timestamp).timestamp(), timestamp);
        }
    }

    #[test]
    fn jmap_date_from_timestamp_before_epoch() {
        for (timestamp, expected_result) in [
            (0, "1970-01-01T00:00:00Z"),
            (-1, "1969-12-31T23:59:59Z"),
            (-3600, "1969-12-31T23:00:00Z"),
            (-86400, "1969-12-31T00:00:00Z"),
            (-86401, "1969-12-30T23:59:59Z"),
            (-2208988800, "1900-01-01T00:00:00Z"),
            (-2208945600, "1900-01-01T12:00:00Z"),
            (-62135596800, "0001-01-01T00:00:00Z"),
        ] {
            let date = UTCDate::from_timestamp(timestamp);
            assert_eq!(date.to_string(), expected_result, "{timestamp}");
            assert_eq!(date.timestamp(), timestamp, "{timestamp}");
        }
    }
}
