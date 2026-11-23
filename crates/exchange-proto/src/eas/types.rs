/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::{
    EasDateForm, LocalDateTime, Precision, SystemTime, UtcSeconds,
    base64::{Base64Mode, base64_decode_into, base64_encode_into},
    reader::LeReader,
    writer::LeWriter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EasDateTime(pub UtcSeconds, pub u16);

impl EasDateTime {
    pub fn parse(s: &[u8]) -> Option<Self> {
        let (date, time) = match s.split_once_byte(b'T') {
            Some((date, time)) => (date, Some(time)),
            None => (s, None),
        };
        let (year, month, day) = match *date {
            [y0, y1, y2, y3, b'-', m0, m1, b'-', d0, d1] | [y0, y1, y2, y3, m0, m1, d0, d1] => (
                u16::from(digits2(y0, y1)?)
                    .checked_mul(100)?
                    .checked_add(u16::from(digits2(y2, y3)?))?,
                digits2(m0, m1)?,
                digits2(d0, d1)?,
            ),
            _ => return None,
        };
        let (hour, minute, second, millis) = match time {
            None => (0, 0, 0, 0),
            Some(time) => {
                let time = time.strip_suffix(b"Z").unwrap_or(time);
                let (hms, fraction) = match time.split_once_byte(b'.') {
                    Some((hms, fraction)) => (hms, Some(fraction)),
                    None => (time, None),
                };
                let (h, m, s) = match *hms {
                    [h0, h1, b':', m0, m1, b':', s0, s1] | [h0, h1, m0, m1, s0, s1] => {
                        (digits2(h0, h1)?, digits2(m0, m1)?, digits2(s0, s1)?)
                    }
                    _ => return None,
                };
                (h, m, s, parse_millis(fraction)?)
            }
        };
        let local = LocalDateTime::new(year, month, day, hour, minute, second, 0)?;
        Some(EasDateTime(local.to_unix_seconds(), millis))
    }

    pub fn write(&self, out: &mut Vec<u8>, form: EasDateForm) {
        match form {
            EasDateForm::Punctuated if self.1 > 0 => {
                self.0.write_xs(out, Precision::Millis(self.1.min(999)))
            }
            _ => self.0.write_eas(out, form),
        }
    }
}

fn parse_millis(fraction: Option<&[u8]>) -> Option<u16> {
    let Some(fraction) = fraction else {
        return Some(0);
    };
    if fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut millis = 0u16;
    for (i, digit) in fraction.iter().take(3).enumerate() {
        let scale: u16 = match i {
            0 => 100,
            1 => 10,
            _ => 1,
        };
        millis = millis.saturating_add(u16::from(digit.wrapping_sub(b'0')).saturating_mul(scale));
    }
    Some(millis)
}

fn digits2(a: u8, b: u8) -> Option<u8> {
    if a.is_ascii_digit() && b.is_ascii_digit() {
        Some(
            a.wrapping_sub(b'0')
                .wrapping_mul(10)
                .wrapping_add(b.wrapping_sub(b'0')),
        )
    } else {
        None
    }
}

pub(crate) trait SplitOnceByte {
    fn split_once_byte(&self, byte: u8) -> Option<(&[u8], &[u8])>;
}

impl SplitOnceByte for [u8] {
    fn split_once_byte(&self, byte: u8) -> Option<(&[u8], &[u8])> {
        let mut parts = self.splitn(2, |b| *b == byte);
        let first = parts.next()?;
        parts.next().map(|rest| (first, rest))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTimeZone;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeZoneInformation {
    pub bias: i32,
    pub standard_name: [u16; 32],
    pub standard_date: SystemTime,
    pub standard_bias: i32,
    pub daylight_name: [u16; 32],
    pub daylight_date: SystemTime,
    pub daylight_bias: i32,
}

impl TimeZoneInformation {
    pub const WIRE_LEN: usize = 172;
    pub const NAME_UTF8_LEN: usize = 96;

    pub fn decode_base64(text: &[u8]) -> Result<Self, InvalidTimeZone> {
        let mut raw = Vec::with_capacity(Self::WIRE_LEN);
        base64_decode_into(text, &mut raw, Self::WIRE_LEN, Base64Mode::Lenient)
            .map_err(|_| InvalidTimeZone)?;
        Self::decode(&raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, InvalidTimeZone> {
        if raw.len() != Self::WIRE_LEN {
            return Err(InvalidTimeZone);
        }
        let mut reader = LeReader::new(raw);
        let mut tz = TimeZoneInformation {
            bias: reader.i32().map_err(|_| InvalidTimeZone)?,
            ..Default::default()
        };
        read_name(&mut reader, &mut tz.standard_name)?;
        tz.standard_date = read_system_time(&mut reader)?;
        tz.standard_bias = reader.i32().map_err(|_| InvalidTimeZone)?;
        read_name(&mut reader, &mut tz.daylight_name)?;
        tz.daylight_date = read_system_time(&mut reader)?;
        tz.daylight_bias = reader.i32().map_err(|_| InvalidTimeZone)?;
        Ok(tz)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(Self::WIRE_LEN);
        out.put_i32(self.bias);
        for unit in self.standard_name {
            out.put_u16(unit);
        }
        write_system_time(out, &self.standard_date);
        out.put_i32(self.standard_bias);
        for unit in self.daylight_name {
            out.put_u16(unit);
        }
        write_system_time(out, &self.daylight_date);
        out.put_i32(self.daylight_bias);
    }

    pub fn encode_base64(&self, out: &mut Vec<u8>) {
        let mut raw = Vec::with_capacity(Self::WIRE_LEN);
        self.encode(&mut raw);
        base64_encode_into(&raw, out);
    }

    pub fn standard_name<'b>(&self, buf: &'b mut [u8; Self::NAME_UTF8_LEN]) -> &'b str {
        let mut len = 0;
        for ch in char::decode_utf16(
            self.standard_name
                .iter()
                .copied()
                .take_while(|unit| *unit != 0),
        ) {
            let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
            let Some(slot) = buf.get_mut(len..len + ch.len_utf8()) else {
                break;
            };
            len += ch.encode_utf8(slot).len();
        }
        buf.get(..len)
            .and_then(|name| std::str::from_utf8(name).ok())
            .unwrap_or_default()
    }

    pub fn set_names(&mut self, standard: &str, daylight: &str) {
        fill_name(&mut self.standard_name, standard);
        fill_name(&mut self.daylight_name, daylight);
    }
}

fn fill_name(target: &mut [u16; 32], name: &str) {
    *target = [0; 32];
    for (slot, unit) in target.iter_mut().take(31).zip(name.encode_utf16()) {
        *slot = unit;
    }
}

fn read_name(reader: &mut LeReader<'_>, name: &mut [u16; 32]) -> Result<(), InvalidTimeZone> {
    for unit in name.iter_mut() {
        *unit = reader.u16().map_err(|_| InvalidTimeZone)?;
    }
    Ok(())
}

fn read_system_time(reader: &mut LeReader<'_>) -> Result<SystemTime, InvalidTimeZone> {
    let mut field = || reader.u16().map_err(|_| InvalidTimeZone);
    Ok(SystemTime {
        year: field()?,
        month: field()?,
        day_of_week: field()?,
        day: field()?,
        hour: field()?,
        minute: field()?,
        second: field()?,
        millis: field()?,
    })
}

fn write_system_time(out: &mut Vec<u8>, t: &SystemTime) {
    for value in [
        t.year,
        t.month,
        t.day_of_week,
        t.day,
        t.hour,
        t.minute,
        t.second,
        t.millis,
    ] {
        out.put_u16(value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyType {
    Plain = 1,
    Html = 2,
    Rtf = 3,
    Mime = 4,
}

impl BodyType {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(BodyType::Plain),
            2 => Some(BodyType::Html),
            3 => Some(BodyType::Rtf),
            4 => Some(BodyType::Mime),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyPreference {
    pub body_type: BodyType,
    pub truncation_size: Option<u32>,
    pub all_or_none: bool,
    pub preview: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Email,
    Calendar,
    Contacts,
    Tasks,
    Notes,
    Sms,
}

impl Class {
    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::map!(
            value,
            Class,
            "Email" => Class::Email,
            "Calendar" => Class::Calendar,
            "Contacts" => Class::Contacts,
            "Tasks" => Class::Tasks,
            "Notes" => Class::Notes,
            "SMS" => Class::Sms,
        )
        .copied()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Email => "Email",
            Class::Calendar => "Calendar",
            Class::Contacts => "Contacts",
            Class::Tasks => "Tasks",
            Class::Notes => "Notes",
            Class::Sms => "SMS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FolderType(pub u8);

impl FolderType {
    pub const GENERIC: Self = Self(1);
    pub const INBOX: Self = Self(2);
    pub const DRAFTS: Self = Self(3);
    pub const DELETED_ITEMS: Self = Self(4);
    pub const SENT_ITEMS: Self = Self(5);
    pub const OUTBOX: Self = Self(6);
    pub const TASKS: Self = Self(7);
    pub const CALENDAR: Self = Self(8);
    pub const CONTACTS: Self = Self(9);
    pub const NOTES: Self = Self(10);
    pub const JOURNAL: Self = Self(11);
    pub const USER_MAIL: Self = Self(12);
    pub const USER_CALENDAR: Self = Self(13);
    pub const USER_CONTACTS: Self = Self(14);
    pub const USER_TASKS: Self = Self(15);
    pub const USER_JOURNAL: Self = Self(16);
    pub const USER_NOTES: Self = Self(17);
    pub const UNKNOWN: Self = Self(18);
    pub const RECIPIENT_INFORMATION_CACHE: Self = Self(19);

    pub fn is_user_creatable(self) -> bool {
        matches!(self.0, 1 | 12..=17)
    }
}
