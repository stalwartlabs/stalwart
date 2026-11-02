/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PartialDateTime, VCard, VCardEntry, VCardValueType, VCardVersion};
use crate::{
    common::{
        IanaString,
        format::{AsciiPush, BufferedWrite},
        parser::Timestamp,
        writer::{
            DOCUMENT_BUFFER, ENTRY_BUFFER, FoldingWriter, LineWriter, NeedsQuotes, write_jscomps,
            write_param_value, write_text,
        },
    },
    vcard::{
        VCardParameterName, VCardParameterValue, VCardProperty, VCardValue, ValueSeparator,
        media_type::legacy_media_type,
    },
};
use std::fmt::{self, Display, Write};

pub(crate) const DATE_BUFFER: usize = 48;

impl VCardVersion {
    pub(crate) fn begin_and_version(self) -> &'static str {
        match self {
            VCardVersion::V2_0 => "BEGIN:VCARD\r\nVERSION:2.0\r\n",
            VCardVersion::V2_1 => "BEGIN:VCARD\r\nVERSION:2.1\r\n",
            VCardVersion::V3_0 => "BEGIN:VCARD\r\nVERSION:3.0\r\n",
            VCardVersion::V4_0 => "BEGIN:VCARD\r\nVERSION:4.0\r\n",
        }
    }
}

impl VCard {
    pub fn write_to(&self, out: &mut impl Write, version: VCardVersion) -> fmt::Result {
        out.write_buffered::<DOCUMENT_BUFFER>(|buf| {
            self.write_entries(&mut FoldingWriter::new(buf), version)
        })
    }

    fn write_entries<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
        version: VCardVersion,
    ) -> fmt::Result {
        out.write_raw(version.begin_and_version())?;
        for entry in &self.entries {
            if !matches!(
                entry.name,
                VCardProperty::Begin | VCardProperty::End | VCardProperty::Version
            ) {
                entry.write_line(out, version)?;
            }
        }
        out.write_raw("END:VCARD\r\n")
    }
}

impl VCardEntry {
    #[deprecated(since = "0.4.0", note = "use write_with_version")]
    pub fn write_to(&self, out: &mut impl Write, is_v4: bool) -> fmt::Result {
        self.write_with_version(
            out,
            if is_v4 {
                VCardVersion::V4_0
            } else {
                VCardVersion::V3_0
            },
        )
    }

    pub fn write_with_version(&self, out: &mut impl Write, version: VCardVersion) -> fmt::Result {
        out.write_buffered::<ENTRY_BUFFER>(|buf| {
            self.write_line(&mut FoldingWriter::new(buf), version)
        })
    }

    pub(crate) fn write_line<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
        version: VCardVersion,
    ) -> fmt::Result {
        let is_v4 = matches!(version, VCardVersion::V4_0);

        if let Some(group_name) = &self.group {
            out.write_atomic(group_name)?;
            out.write_atomic(".")?;
        }

        out.write_atomic(self.name.as_str())?;
        let mut types = None;
        let mut last_param: Option<&VCardParameterName> = None;
        let legacy_binary = if is_v4 {
            None
        } else {
            self.values.iter().find_map(|v| match v {
                VCardValue::Binary(data) => Some(data),
                _ => None,
            })
        };

        for param in &self.params {
            if !is_v4
                && match param.name {
                    VCardParameterName::PropId | VCardParameterName::Jscomps => true,
                    VCardParameterName::Mediatype => legacy_binary.is_some(),
                    _ => false,
                }
            {
                continue;
            }

            if last_param.is_some_and(|last_param| last_param == &param.name) {
                out.write_atomic(",")?;
            } else {
                out.write_atomic(";")?;
                out.write_atomic(param.name.as_str())?;
                if !matches!(param.value, VCardParameterValue::Null) {
                    out.write_atomic("=")?;
                }
                last_param = Some(&param.name);
            }

            match &param.value {
                VCardParameterValue::Text(v)
                    if param.name == VCardParameterName::Jsptr && !v.needs_quotes() =>
                {
                    out.write_atomic("\"")?;
                    write_param_value(out, v, is_v4)?;
                    out.write_atomic("\"")?;
                }
                VCardParameterValue::Text(v) => {
                    write_param_value(out, v, is_v4)?;
                }
                VCardParameterValue::Integer(i) => {
                    out.push_u64((*i).into())?;
                }
                VCardParameterValue::Timestamp(v) => {
                    Timestamp(*v).push_to(out)?;
                }
                VCardParameterValue::Bool(v) => {
                    out.write_atomic(if *v { "TRUE" } else { "FALSE" })?;
                }
                VCardParameterValue::ValueType(v) => {
                    if types.is_none() {
                        types = Some(v);
                    }
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                VCardParameterValue::Type(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                VCardParameterValue::Calscale(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                VCardParameterValue::Level(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                VCardParameterValue::Phonetic(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                VCardParameterValue::Jscomps(v) => {
                    out.write_atomic("\"")?;
                    write_jscomps(out, v)?;
                    out.write_atomic("\"")?;
                    last_param = None;
                }
                VCardParameterValue::Null => {
                    last_param = None;
                }
            }
        }

        let is_v21_base64 = matches!(version, VCardVersion::V2_1) && legacy_binary.is_some();
        let max_values = if is_v4 {
            usize::MAX
        } else {
            self.name.legacy_max_values()
        };

        if !is_v4 {
            if let Some(data) = legacy_binary {
                out.write_atomic(if is_v21_base64 {
                    ";ENCODING=BASE64"
                } else {
                    ";ENCODING=b"
                })?;

                if let Some(media_type) = data.content_type.as_deref()
                    && !self
                        .params
                        .iter()
                        .any(|param| param.name == VCardParameterName::Type)
                    && let Some(token) = legacy_media_type(self.name.as_str(), media_type)
                {
                    out.write_atomic(";TYPE=")?;
                    out.write_atomic(&token)?;
                }
            }

            if self.values.iter().take(max_values).any(|v| match v {
                VCardValue::Text(s) => !s.is_ascii(),
                VCardValue::Component(items) => items.iter().any(|s| !s.is_ascii()),
                _ => false,
            }) {
                out.write_atomic(";CHARSET=UTF-8")?;
            }
        }

        out.write_atomic(":")?;

        let (default_type, value_separator) = self.name.default_types();
        let default_type = default_type.unwrap_vcard();

        let mut separator = ";";
        let mut escape_semicolon = matches!(types.unwrap_or(&default_type), VCardValueType::Text);
        let mut escape_comma = escape_semicolon;

        match value_separator {
            ValueSeparator::Comma => {
                escape_comma = true;
                separator = ",";
            }
            ValueSeparator::Semicolon => escape_semicolon = true,
            ValueSeparator::SemicolonAndComma => {
                escape_semicolon = true;
                escape_comma = true;
            }
            _ => {}
        }

        for (pos, value) in self.values.iter().take(max_values).enumerate() {
            if pos > 0 {
                out.write_atomic(separator)?;
            }

            match value {
                VCardValue::Text(v) => {
                    write_text(out, v, escape_semicolon, escape_comma)?;
                }
                VCardValue::Component(v) => {
                    for (pos, item) in v.iter().enumerate() {
                        if pos > 0 {
                            out.write_atomic(",")?;
                        }
                        write_text(out, item, true, true)?;
                    }
                }
                VCardValue::Integer(v) => {
                    out.push_i64(*v)?;
                }
                VCardValue::Float(v) => {
                    write!(out, "{v}")?;
                }
                VCardValue::Boolean(v) => {
                    out.write_atomic(if *v { "TRUE" } else { "FALSE" })?;
                }
                VCardValue::PartialDateTime(v) => {
                    let typ = if pos == 0 {
                        types
                    } else {
                        self.parameters(&VCardParameterName::Value)
                            .nth(pos)
                            .and_then(|v| v.as_value_type())
                            .and_then(|v| v.iana().copied())
                    }
                    .unwrap_or(&default_type);
                    if is_v4 {
                        v.push_vcard(out, typ)?;
                    } else {
                        v.push_legacy_vcard(out, typ)?;
                    }
                }
                VCardValue::Binary(v) => {
                    if is_v4 {
                        let media_type = v.content_type.as_deref().unwrap_or_default();
                        out.write_str("data:")?;
                        out.write_str(media_type)?;
                        if escape_semicolon {
                            out.write_atomic("\\;")?;
                        } else {
                            out.write_str(";")?;
                        }
                        out.write_atomic("base64\\,")?;
                    }
                    out.write_base64(&v.data)?;
                }
                VCardValue::Sex(v) => {
                    out.write_atomic(v.as_str())?;
                }
                VCardValue::GramGender(v) => {
                    out.write_atomic(v.as_str())?;
                }
                VCardValue::Kind(v) => {
                    out.write_atomic(v.as_str())?;
                }
            }
        }

        out.end_line()?;
        if is_v21_base64 {
            out.end_line()?;
        }
        Ok(())
    }
}

impl PartialDateTime {
    pub fn format_as_vcard(&self, out: &mut impl Write, fmt: &VCardValueType) -> fmt::Result {
        out.write_buffered::<DATE_BUFFER>(|buf| self.push_vcard(buf, fmt))
    }

    pub fn format_as_legacy_vcard(
        &self,
        out: &mut impl Write,
        fmt: &VCardValueType,
    ) -> fmt::Result {
        out.write_buffered::<DATE_BUFFER>(|buf| self.push_legacy_vcard(buf, fmt))
    }

    pub(crate) fn push_vcard(&self, buf: &mut impl AsciiPush, fmt: &VCardValueType) -> fmt::Result {
        if matches!(fmt, VCardValueType::Timestamp) {
            buf.push_4_digits(self.year.unwrap_or_default())?;
            buf.push_2_digits(self.month.unwrap_or_default())?;
            buf.push_2_digits(self.day.unwrap_or_default())?;
            buf.push_byte(b'T')?;
            buf.push_2_digits(self.hour.unwrap_or_default())?;
            buf.push_2_digits(self.minute.unwrap_or_default())?;
            buf.push_2_digits(self.second.unwrap_or_default())?;
            return self.push_timestamp_zone(buf);
        }

        let missing_time = self.hour.is_none() && self.minute.is_none() && self.second.is_none();
        let missing_tz = self.tz_hour.is_none();

        if matches!(
            fmt,
            VCardValueType::Date | VCardValueType::DateAndOrTime | VCardValueType::DateTime
        ) {
            match (self.year, self.month, self.day) {
                (Some(year), Some(month), Some(day)) => {
                    buf.push_4_digits(year)?;
                    buf.push_2_digits(month)?;
                    buf.push_2_digits(day)?;
                }
                (Some(year), Some(month), None) => {
                    buf.push_4_digits(year)?;
                    if missing_time && missing_tz {
                        buf.push_byte(b'-')?;
                    }
                    buf.push_2_digits(month)?;
                }
                (None, Some(month), Some(day)) => {
                    buf.push_ascii(b"--")?;
                    buf.push_2_digits(month)?;
                    buf.push_2_digits(day)?;
                }
                (None, None, Some(day)) => {
                    buf.push_ascii(b"---")?;
                    buf.push_2_digits(day)?;
                }
                (Some(year), None, None) => {
                    buf.push_4_digits(year)?;
                }
                (None, Some(month), None) => {
                    buf.push_ascii(b"--")?;
                    buf.push_2_digits(month)?;
                }
                _ => {}
            }
        }

        if matches!(
            fmt,
            VCardValueType::DateAndOrTime | VCardValueType::DateTime | VCardValueType::Time
        ) && !missing_time
        {
            if matches!(
                fmt,
                VCardValueType::DateAndOrTime | VCardValueType::DateTime
            ) {
                buf.push_byte(b'T')?;
            }
            let mut last_is_some = false;
            for value in [self.hour, self.minute, self.second] {
                if let Some(value) = value {
                    buf.push_2_digits(value)?;
                    last_is_some = true;
                } else if !last_is_some {
                    buf.push_byte(b'-')?;
                }
            }
        }

        if matches!(
            fmt,
            VCardValueType::DateAndOrTime
                | VCardValueType::DateTime
                | VCardValueType::Time
                | VCardValueType::UtcOffset
        ) {
            match (self.tz_hour, self.tz_minute) {
                (Some(0), Some(0)) | (Some(0), _) => {
                    buf.push_byte(b'Z')?;
                }
                (Some(hour), Some(minute)) => {
                    buf.push_byte(if self.tz_minus { b'-' } else { b'+' })?;
                    buf.push_2_digits(hour)?;
                    buf.push_2_digits(minute)?;
                }
                (Some(hour), None) => {
                    buf.push_byte(if self.tz_minus { b'-' } else { b'+' })?;
                    buf.push_2_digits(hour)?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub(crate) fn push_legacy_vcard(
        &self,
        buf: &mut impl AsciiPush,
        fmt: &VCardValueType,
    ) -> fmt::Result {
        if matches!(fmt, VCardValueType::Timestamp) {
            buf.push_4_digits(self.year.unwrap_or_default())?;
            buf.push_2_digits(self.month.unwrap_or_default())?;
            buf.push_2_digits(self.day.unwrap_or_default())?;

            if self.hour.is_some() {
                buf.push_byte(b'T')?;
                buf.push_2_digits(self.hour.unwrap_or_default())?;
                buf.push_2_digits(self.minute.unwrap_or_default())?;
                buf.push_2_digits(self.second.unwrap_or_default())?;
            }

            return self.push_timestamp_zone(buf);
        }

        let missing_time = self.hour.is_none() && self.minute.is_none() && self.second.is_none();

        if matches!(
            fmt,
            VCardValueType::Date | VCardValueType::DateAndOrTime | VCardValueType::DateTime
        ) {
            match (self.year, self.month, self.day) {
                (Some(year), Some(month), Some(day)) => {
                    buf.push_4_digits(year)?;
                    buf.push_byte(b'-')?;
                    buf.push_2_digits(month)?;
                    buf.push_byte(b'-')?;
                    buf.push_2_digits(day)?;
                }
                (Some(year), Some(month), None) => {
                    buf.push_4_digits(year)?;
                    buf.push_byte(b'-')?;
                    buf.push_2_digits(month)?;
                }
                (None, Some(month), Some(day)) => {
                    buf.push_ascii(b"--")?;
                    buf.push_2_digits(month)?;
                    buf.push_byte(b'-')?;
                    buf.push_2_digits(day)?;
                }
                (None, None, Some(day)) => {
                    buf.push_ascii(b"---")?;
                    buf.push_2_digits(day)?;
                }
                (Some(year), None, None) => {
                    buf.push_4_digits(year)?;
                }
                (None, Some(month), None) => {
                    buf.push_ascii(b"--")?;
                    buf.push_2_digits(month)?;
                }
                _ => {}
            }
        }

        if matches!(
            fmt,
            VCardValueType::DateAndOrTime | VCardValueType::DateTime | VCardValueType::Time
        ) && !missing_time
        {
            if matches!(
                fmt,
                VCardValueType::DateAndOrTime | VCardValueType::DateTime
            ) {
                buf.push_byte(b'T')?;
            }
            let mut last_is_some = false;
            for value in [self.hour, self.minute, self.second] {
                if let Some(value) = value {
                    if last_is_some {
                        buf.push_byte(b':')?;
                    }
                    buf.push_2_digits(value)?;
                    last_is_some = true;
                } else if !last_is_some {
                    buf.push_byte(b'-')?;
                }
            }
        }

        if matches!(
            fmt,
            VCardValueType::DateAndOrTime
                | VCardValueType::DateTime
                | VCardValueType::Time
                | VCardValueType::UtcOffset
        ) {
            match (self.tz_hour, self.tz_minute) {
                (Some(0), Some(0)) | (Some(0), _) => {
                    buf.push_byte(b'Z')?;
                }
                (Some(hour), Some(minute)) => {
                    buf.push_byte(if self.tz_minus { b'-' } else { b'+' })?;
                    buf.push_2_digits(hour)?;
                    buf.push_byte(b':')?;
                    buf.push_2_digits(minute)?;
                }
                (Some(hour), None) => {
                    buf.push_byte(if self.tz_minus { b'-' } else { b'+' })?;
                    buf.push_2_digits(hour)?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn push_timestamp_zone(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        if let Some(tz_hour) = self.tz_hour {
            let tz_minute = self.tz_minute.unwrap_or_default();
            if tz_hour == 0 && tz_minute == 0 {
                buf.push_byte(b'Z')?;
            } else {
                buf.push_byte(if self.tz_minus { b'-' } else { b'+' })?;
                buf.push_2_digits(tz_hour)?;

                if let Some(tz_minute) = self.tz_minute {
                    buf.push_2_digits(tz_minute)?;
                }
            }
        }
        Ok(())
    }
}

impl Display for VCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f, self.version().unwrap_or_default())
    }
}

impl Display for VCardVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VCardVersion::V2_0 => "2.0",
            VCardVersion::V2_1 => "2.1",
            VCardVersion::V3_0 => "3.0",
            VCardVersion::V4_0 => "4.0",
        })
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/vcard/writer/tests.rs"]
mod tests;
