/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod rrule;
mod task;

use mail_parser::decoders::charsets::Charset;

use crate::{
    common::{reader::LeReader, utf16::Utf16Le, writer::LeWriter},
    convert::{BlobKind, BlobLimits, ConvertError},
};

pub(crate) use rrule::{
    ALL_DAYS, RuleCount, WEEKDAYS, WEEKEND_DAYS, WORK_DAYS, clamped_month_day, local_from_minutes,
    local_minutes, with_seconds_of,
};
pub use rrule::{RecurAnchor, Unmappable};
pub use task::{TaskAnchor, TaskRecur, TaskRecurError};

pub const RECUR_VERSION: u16 = 0x3004;
pub const READER_VERSION2: u32 = 0x3006;
pub const WRITER_VERSION2: u32 = 0x3009;
pub const WRITER_VERSION2_OUTLOOK_2003: u32 = 0x3008;
pub const NO_END_DATE: u32 = 0x5AE9_80DF;

const FREQ_DAILY: u16 = 0x200A;
const FREQ_WEEKLY: u16 = 0x200B;
const FREQ_MONTHLY: u16 = 0x200C;
const FREQ_YEARLY: u16 = 0x200D;
const END_BY_DATE: u32 = 0x2021;
const END_AFTER_COUNT: u32 = 0x2022;
const END_NEVER: u32 = 0x2023;
const END_NEVER_LEGACY: u32 = 0xFFFF_FFFF;
const CHANGE_HIGHLIGHT_VALUE_LEN: u32 = 4;

pub mod override_flags {
    pub const SUBJECT: u16 = 0x0001;
    pub const MEETING_TYPE: u16 = 0x0002;
    pub const REMINDER_DELTA: u16 = 0x0004;
    pub const REMINDER: u16 = 0x0008;
    pub const LOCATION: u16 = 0x0010;
    pub const BUSY_STATUS: u16 = 0x0020;
    pub const ATTACHMENT: u16 = 0x0040;
    pub const SUB_TYPE: u16 = 0x0080;
    pub const APPOINTMENT_COLOR: u16 = 0x0100;
    pub const EXCEPTIONAL_BODY: u16 = 0x0200;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurFrequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    Day,
    Week { days: u32 },
    Month { day: u32 },
    MonthNth { days: u32, n: u32 },
    MonthEnd { day: u32 },
    HjMonth { day: u32 },
    HjMonthNth { days: u32, n: u32 },
    HjMonthEnd { day: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurEnd {
    ByDate,
    AfterCount,
    Never,
    NeverLegacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecurrencePattern {
    pub frequency: RecurFrequency,
    pub pattern: PatternType,
    pub calendar_type: u16,
    pub first_date_time: u32,
    pub period: u32,
    pub sliding_flag: u32,
    pub end: RecurEnd,
    pub occurrence_count: u32,
    pub first_dow: u32,
    pub deleted_instances: Vec<u32>,
    pub modified_instances: Vec<u32>,
    pub start_date: u32,
    pub end_date: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExceptionInfo {
    pub start: u32,
    pub end: u32,
    pub original_start: u32,
    pub subject: Option<Box<str>>,
    pub meeting_type: Option<u32>,
    pub reminder_delta: Option<u32>,
    pub reminder_set: Option<u32>,
    pub location: Option<Box<str>>,
    pub busy_status: Option<u32>,
    pub attachment: Option<u32>,
    pub sub_type: Option<u32>,
    pub appointment_color: Option<u32>,
    pub exceptional_body: bool,
    pub change_highlight: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppointmentRecur {
    pub pattern: RecurrencePattern,
    pub writer_version2: u32,
    pub start_time_offset: u32,
    pub end_time_offset: u32,
    pub exceptions: Vec<ExceptionInfo>,
}

struct Decoder<'a, 'l> {
    reader: LeReader<'a>,
    limits: &'l BlobLimits,
}

impl ExceptionInfo {
    pub fn override_flags(&self) -> u16 {
        [
            (self.subject.is_some(), override_flags::SUBJECT),
            (self.meeting_type.is_some(), override_flags::MEETING_TYPE),
            (
                self.reminder_delta.is_some(),
                override_flags::REMINDER_DELTA,
            ),
            (self.reminder_set.is_some(), override_flags::REMINDER),
            (self.location.is_some(), override_flags::LOCATION),
            (self.busy_status.is_some(), override_flags::BUSY_STATUS),
            (self.attachment.is_some(), override_flags::ATTACHMENT),
            (self.sub_type.is_some(), override_flags::SUB_TYPE),
            (
                self.appointment_color.is_some(),
                override_flags::APPOINTMENT_COLOR,
            ),
            (self.exceptional_body, override_flags::EXCEPTIONAL_BODY),
        ]
        .iter()
        .filter(|(set, _)| *set)
        .fold(0, |flags, (_, flag)| flags | flag)
    }

    fn has_text(&self) -> bool {
        self.subject.is_some() || self.location.is_some()
    }
}

impl AppointmentRecur {
    pub fn decode(b: &[u8], limits: &BlobLimits) -> Result<Self, ConvertError> {
        let mut decoder = Decoder {
            reader: LeReader::new(b),
            limits,
        };
        decoder.recur().ok_or_else(|| ConvertError::BadBlob {
            what: BlobKind::Recurrence,
            offset: u32::try_from(decoder.reader.offset()).unwrap_or(u32::MAX),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        self.pattern.encode(out);
        out.put_u32(READER_VERSION2);
        out.put_u32(self.writer_version2);
        out.put_u32(self.start_time_offset);
        out.put_u32(self.end_time_offset);
        out.put_u16(u16::try_from(self.exceptions.len()).unwrap_or(u16::MAX));
        for exception in &self.exceptions {
            encode_exception_info(exception, out);
        }
        out.put_u32(0);
        for exception in &self.exceptions {
            self.encode_extended(exception, out);
        }
        out.put_u32(0);
    }

    fn encode_extended(&self, exception: &ExceptionInfo, out: &mut Vec<u8>) {
        if self.writer_version2 >= WRITER_VERSION2 {
            out.put_u32(CHANGE_HIGHLIGHT_VALUE_LEN);
            out.put_u32(exception.change_highlight.unwrap_or_default());
        }
        out.put_u32(0);
        if exception.has_text() {
            out.put_u32(exception.start);
            out.put_u32(exception.end);
            out.put_u32(exception.original_start);
            for text in [&exception.subject, &exception.location]
                .into_iter()
                .flatten()
            {
                let units = u16::try_from(text.encode_utf16().count()).unwrap_or(u16::MAX);
                out.put_u16(units);
                for unit in text.encode_utf16().take(usize::from(units)) {
                    out.put_u16(unit);
                }
            }
            out.put_u32(0);
        }
    }
}

impl RecurrencePattern {
    pub fn decode(b: &[u8], limits: &BlobLimits) -> Result<Self, ConvertError> {
        let mut decoder = Decoder {
            reader: LeReader::new(b),
            limits,
        };
        decoder.pattern().ok_or_else(|| ConvertError::BadBlob {
            what: BlobKind::Recurrence,
            offset: u32::try_from(decoder.reader.offset()).unwrap_or(u32::MAX),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(RECUR_VERSION);
        out.put_u16(RECUR_VERSION);
        out.put_u16(match self.frequency {
            RecurFrequency::Daily => FREQ_DAILY,
            RecurFrequency::Weekly => FREQ_WEEKLY,
            RecurFrequency::Monthly => FREQ_MONTHLY,
            RecurFrequency::Yearly => FREQ_YEARLY,
        });
        let (code, specific): (u16, &[u32]) = match &self.pattern {
            PatternType::Day => (0x0, &[]),
            PatternType::Week { days } => (0x1, std::slice::from_ref(days)),
            PatternType::Month { day } => (0x2, std::slice::from_ref(day)),
            PatternType::MonthNth { days, n } => (0x3, &[*days, *n]),
            PatternType::MonthEnd { day } => (0x4, std::slice::from_ref(day)),
            PatternType::HjMonth { day } => (0xA, std::slice::from_ref(day)),
            PatternType::HjMonthNth { days, n } => (0xB, &[*days, *n]),
            PatternType::HjMonthEnd { day } => (0xC, std::slice::from_ref(day)),
        };
        out.put_u16(code);
        out.put_u16(self.calendar_type);
        out.put_u32(self.first_date_time);
        out.put_u32(self.period);
        out.put_u32(self.sliding_flag);
        for value in specific {
            out.put_u32(*value);
        }
        out.put_u32(match self.end {
            RecurEnd::ByDate => END_BY_DATE,
            RecurEnd::AfterCount => END_AFTER_COUNT,
            RecurEnd::Never => END_NEVER,
            RecurEnd::NeverLegacy => END_NEVER_LEGACY,
        });
        out.put_u32(self.occurrence_count);
        out.put_u32(self.first_dow);
        for dates in [&self.deleted_instances, &self.modified_instances] {
            out.put_u32(u32::try_from(dates.len()).unwrap_or(u32::MAX));
            for date in dates {
                out.put_u32(*date);
            }
        }
        out.put_u32(self.start_date);
        out.put_u32(self.end_date);
    }
}

fn encode_exception_info(exception: &ExceptionInfo, out: &mut Vec<u8>) {
    out.put_u32(exception.start);
    out.put_u32(exception.end);
    out.put_u32(exception.original_start);
    out.put_u16(exception.override_flags());
    let ansi = |text: &str, out: &mut Vec<u8>| {
        let len = u16::try_from(text.chars().count()).unwrap_or(u16::MAX - 1);
        out.put_u16(len.saturating_add(1));
        out.put_u16(len);
        out.extend(
            text.chars()
                .take(usize::from(len))
                .map(|c| if c.is_ascii() { c as u8 } else { b'?' }),
        );
    };
    if let Some(subject) = &exception.subject {
        ansi(subject, out);
    }
    for value in [
        exception.meeting_type,
        exception.reminder_delta,
        exception.reminder_set,
    ]
    .into_iter()
    .flatten()
    {
        out.put_u32(value);
    }
    if let Some(location) = &exception.location {
        ansi(location, out);
    }
    for value in [
        exception.busy_status,
        exception.attachment,
        exception.sub_type,
        exception.appointment_color,
    ]
    .into_iter()
    .flatten()
    {
        out.put_u32(value);
    }
}

impl Decoder<'_, '_> {
    fn u16(&mut self) -> Option<u16> {
        self.reader.u16().ok()
    }

    fn u32(&mut self) -> Option<u32> {
        self.reader.u32().ok()
    }

    fn flagged(&mut self, flags: u16, flag: u16) -> Option<Option<u32>> {
        if flags & flag != 0 {
            self.u32().map(Some)
        } else {
            Some(None)
        }
    }

    fn dates(&mut self) -> Option<Vec<u32>> {
        let count = self.u32()?;
        if count > u32::from(self.limits.max_exceptions) {
            return None;
        }
        let mut dates = Vec::with_capacity(usize::try_from(count).ok()?);
        for _ in 0..count {
            dates.push(self.u32()?);
        }
        Some(dates)
    }

    fn sized_skip(&mut self) -> Option<()> {
        let len = self.u32()?;
        self.reader.skip(usize::try_from(len).ok()?).ok()
    }

    fn pattern(&mut self) -> Option<RecurrencePattern> {
        let reader_version = self.u16()?;
        let _writer_version = self.u16()?;
        let frequency = match self.u16()? {
            FREQ_DAILY => RecurFrequency::Daily,
            FREQ_WEEKLY => RecurFrequency::Weekly,
            FREQ_MONTHLY => RecurFrequency::Monthly,
            FREQ_YEARLY => RecurFrequency::Yearly,
            _ => return None,
        };
        let pattern_code = self.u16()?;
        let calendar_type = self.u16()?;
        let first_date_time = self.u32()?;
        let period = self.u32()?;
        let sliding_flag = self.u32()?;
        let pattern = match pattern_code {
            0x0 => PatternType::Day,
            0x1 => PatternType::Week { days: self.u32()? },
            0x2 => PatternType::Month { day: self.u32()? },
            0x3 => PatternType::MonthNth {
                days: self.u32()?,
                n: self.u32()?,
            },
            0x4 => PatternType::MonthEnd { day: self.u32()? },
            0xA => PatternType::HjMonth { day: self.u32()? },
            0xB => PatternType::HjMonthNth {
                days: self.u32()?,
                n: self.u32()?,
            },
            0xC => PatternType::HjMonthEnd { day: self.u32()? },
            _ => return None,
        };
        let end = match self.u32()? {
            END_BY_DATE => RecurEnd::ByDate,
            END_AFTER_COUNT => RecurEnd::AfterCount,
            END_NEVER => RecurEnd::Never,
            END_NEVER_LEGACY => RecurEnd::NeverLegacy,
            _ => return None,
        };
        let occurrence_count = self.u32()?;
        let first_dow = self.u32()?;
        let deleted_instances = self.dates()?;
        let modified_instances = self.dates()?;
        let start_date = self.u32()?;
        let end_date = self.u32()?;
        (reader_version == RECUR_VERSION && modified_instances.len() <= deleted_instances.len())
            .then_some(RecurrencePattern {
                frequency,
                pattern,
                calendar_type,
                first_date_time,
                period,
                sliding_flag,
                end,
                occurrence_count,
                first_dow,
                deleted_instances,
                modified_instances,
                start_date,
                end_date,
            })
    }

    fn recur(&mut self) -> Option<AppointmentRecur> {
        let pattern = self.pattern()?;
        if self.u32()? != READER_VERSION2 {
            return None;
        }
        let writer_version2 = self.u32()?;
        let start_time_offset = self.u32()?;
        let end_time_offset = self.u32()?;
        let count = self.u16()?;
        if usize::from(count) != pattern.modified_instances.len() {
            return None;
        }
        let mut exceptions = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            exceptions.push(self.exception_info()?);
        }
        self.sized_skip()?;
        for exception in &mut exceptions {
            self.extended(exception, writer_version2)?;
        }
        self.sized_skip()?;
        Some(AppointmentRecur {
            pattern,
            writer_version2,
            start_time_offset,
            end_time_offset,
            exceptions,
        })
    }

    fn ansi(&mut self) -> Option<Box<str>> {
        let _len_plus_one = self.u16()?;
        let len = self.u16()?;
        let bytes = self.reader.bytes(usize::from(len)).ok()?;
        Some(Charset::Windows1252.decode(bytes).into())
    }

    fn exception_info(&mut self) -> Option<ExceptionInfo> {
        use override_flags::*;
        let start = self.u32()?;
        let end = self.u32()?;
        let original_start = self.u32()?;
        let flags = self.u16()?;
        let subject = if flags & SUBJECT != 0 {
            Some(self.ansi()?)
        } else {
            None
        };
        let meeting_type = self.flagged(flags, MEETING_TYPE)?;
        let reminder_delta = self.flagged(flags, REMINDER_DELTA)?;
        let reminder_set = self.flagged(flags, REMINDER)?;
        let location = if flags & LOCATION != 0 {
            Some(self.ansi()?)
        } else {
            None
        };
        Some(ExceptionInfo {
            start,
            end,
            original_start,
            subject,
            meeting_type,
            reminder_delta,
            reminder_set,
            location,
            busy_status: self.flagged(flags, BUSY_STATUS)?,
            attachment: self.flagged(flags, ATTACHMENT)?,
            sub_type: self.flagged(flags, SUB_TYPE)?,
            appointment_color: self.flagged(flags, APPOINTMENT_COLOR)?,
            exceptional_body: flags & EXCEPTIONAL_BODY != 0,
            change_highlight: None,
        })
    }

    fn wide(&mut self) -> Option<Box<str>> {
        let units = self.u16()?;
        let bytes = self.reader.bytes(usize::from(units).checked_mul(2)?).ok()?;
        let mut text = String::new();
        Utf16Le::new(bytes)?.to_string_lossy(&mut text);
        Some(text.into_boxed_str())
    }

    fn extended(&mut self, exception: &mut ExceptionInfo, writer_version2: u32) -> Option<()> {
        if writer_version2 >= WRITER_VERSION2 {
            let size = self.u32()?;
            let value = self.reader.bytes(usize::try_from(size).ok()?).ok()?;
            exception.change_highlight = value
                .first_chunk::<4>()
                .map(|value| u32::from_le_bytes(*value));
        }
        self.sized_skip()?;
        if exception.has_text() {
            let _start = self.u32()?;
            let _end = self.u32()?;
            let _original = self.u32()?;
            if exception.subject.is_some() {
                exception.subject = Some(self.wide()?);
            }
            if exception.location.is_some() {
                exception.location = Some(self.wide()?);
            }
            self.sized_skip()?;
        }
        Some(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/blob/recur/tests.rs"]
mod tests;
