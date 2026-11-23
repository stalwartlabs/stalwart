/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::{Guid, XsDateTime, XsDuration, XsZone};
use std::borrow::Cow;

pub trait XmlValue<'a>: Sized {
    fn parse_value(text: Cow<'a, str>) -> Option<Self>;
}

impl<'a> XmlValue<'a> for Cow<'a, str> {
    fn parse_value(text: Cow<'a, str>) -> Option<Self> {
        Some(text)
    }
}

impl XmlValue<'_> for bool {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        parse_bool(&text)
    }
}

macro_rules! int_value {
    ($($ty:ty),+) => {
        $(impl XmlValue<'_> for $ty {
            fn parse_value(text: Cow<'_, str>) -> Option<Self> {
                text.trim_ascii().parse().ok()
            }
        })+
    };
}

int_value!(u8, u16, u32, u64, i16, i32, i64);

impl XmlValue<'_> for f64 {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        parse_f64(&text)
    }
}

impl XmlValue<'_> for XsDateTime {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        XsDateTime::parse(text.trim_ascii().as_bytes())
    }
}

impl XmlValue<'_> for XsDuration {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        XsDuration::parse(text.trim_ascii().as_bytes())
    }
}

impl XmlValue<'_> for Guid {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        Guid::parse_text(text.trim_ascii().as_bytes())
    }
}

pub fn parse_bool(text: &str) -> Option<bool> {
    hashify::map!(
        text.trim_ascii().as_bytes(),
        bool,
        "true" => true,
        "false" => false,
        "1" => true,
        "0" => false,
    )
    .copied()
}

pub fn parse_f64(text: &str) -> Option<f64> {
    let text = text.trim_ascii();
    hashify::fnc_map!(text.as_bytes(),
        "INF" => { return Some(f64::INFINITY); },
        "-INF" => { return Some(f64::NEG_INFINITY); },
        "NaN" => { return Some(f64::NAN); },
        _ => {}
    );
    if text
        .bytes()
        .any(|b| b.is_ascii_alphabetic() && b != b'e' && b != b'E')
    {
        return None;
    }
    text.parse().ok()
}

pub fn parse_hex_or_decimal(text: &str) -> Option<u64> {
    let text = text.trim_ascii();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) if !hex.is_empty() && hex.len() <= 16 => u64::from_str_radix(hex, 16).ok(),
        Some(_) => None,
        None => text.parse().ok(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XsDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub zone: XsZone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XsTime {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanos: u32,
    pub zone: XsZone,
}

const XS_DATE_LEN: usize = 10;
const XS_TIME_MAX_LEN: usize = 48;
const MIDNIGHT: &[u8] = b"T00:00:00";
const EPOCH_DATE: &[u8] = b"2000-01-01T";

fn join_parse(head: &[u8], middle: &[u8], tail: &[u8]) -> Option<XsDateTime> {
    let mut buf = [0u8; EPOCH_DATE.len() + XS_TIME_MAX_LEN];
    let total = head.len() + middle.len() + tail.len();
    let out = buf.get_mut(..total)?;
    let (a, rest) = out.split_at_mut(head.len());
    let (b, c) = rest.split_at_mut(middle.len());
    a.copy_from_slice(head);
    b.copy_from_slice(middle);
    c.copy_from_slice(tail);
    XsDateTime::parse(out)
}

impl XsDate {
    pub fn parse(s: &[u8]) -> Option<Self> {
        let (date, zone) = s.split_at_checked(XS_DATE_LEN)?;
        let parsed = join_parse(date, MIDNIGHT, zone)?;
        Some(XsDate {
            year: parsed.local.year,
            month: parsed.local.month,
            day: parsed.local.day,
            zone: parsed.zone,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        push_padded(out, u32::from(self.year), 4);
        out.push(b'-');
        push_padded(out, u32::from(self.month), 2);
        out.push(b'-');
        push_padded(out, u32::from(self.day), 2);
        write_zone(out, self.zone);
    }
}

impl XsTime {
    pub fn parse(s: &[u8]) -> Option<Self> {
        if s.len() > XS_TIME_MAX_LEN {
            return None;
        }
        let parsed = join_parse(EPOCH_DATE, s, b"")?;
        Some(XsTime {
            hour: parsed.local.hour,
            minute: parsed.local.minute,
            second: parsed.local.second,
            nanos: parsed.local.nanos,
            zone: parsed.zone,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        push_padded(out, u32::from(self.hour), 2);
        out.push(b':');
        push_padded(out, u32::from(self.minute), 2);
        out.push(b':');
        push_padded(out, u32::from(self.second), 2);
        if self.nanos > 0 {
            out.push(b'.');
            let mut nanos = self.nanos;
            let mut width = 9;
            while nanos.is_multiple_of(10) {
                nanos /= 10;
                width -= 1;
            }
            push_padded(out, nanos, width);
        }
        write_zone(out, self.zone);
    }
}

fn push_padded(out: &mut Vec<u8>, value: u32, width: u32) {
    for exp in (0..width).rev() {
        let digit = (value / 10u32.pow(exp)) % 10;
        out.push(b'0' + u8::try_from(digit).unwrap_or(0));
    }
}

fn write_zone(out: &mut Vec<u8>, zone: XsZone) {
    match zone {
        XsZone::Utc => out.push(b'Z'),
        XsZone::OffsetMinutes(minutes) => {
            out.push(if minutes < 0 { b'-' } else { b'+' });
            let minutes = u32::from(minutes.unsigned_abs());
            push_padded(out, minutes / 60, 2);
            out.push(b':');
            push_padded(out, minutes % 60, 2);
        }
        XsZone::Floating => {}
    }
}

impl XmlValue<'_> for XsDate {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        XsDate::parse(text.trim_ascii().as_bytes())
    }
}

impl XmlValue<'_> for XsTime {
    fn parse_value(text: Cow<'_, str>) -> Option<Self> {
        XsTime::parse(text.trim_ascii().as_bytes())
    }
}
