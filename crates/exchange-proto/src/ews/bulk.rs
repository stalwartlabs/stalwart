/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::xml::Base64Sink;

pub const MAGIC: &[u8; 4] = b"STBT";
pub const VERSION: u8 = 1;
pub const MAX_RECORD_KEYWORDS: usize = 256;
pub const MAX_RECORD_ENVELOPE: usize = 64 * 1024;
pub const MAX_RECORD_PROPERTIES: usize = 8192;
pub const MAX_RECORD_RECIPIENTS: usize = 2048;

const CRITICAL: u8 = 0x80;
const TAG_CONTENT: u8 = 0x81;
const TAG_RECEIVED_AT: u8 = 0x02;
const TAG_KEYWORD: u8 = 0x03;
const TAG_PROPERTY: u8 = 0x04;
const TAG_RECIPIENT: u8 = 0x05;
const LEB128_MAX: usize = 10;
const LEB128_BITS: u32 = 7;
const LEB128_MORE: u8 = 0x80;
const LEB128_VALUE: u8 = 0x7F;

const KIND_EMAIL: u8 = 1;
const KIND_EVENT: u8 = 2;
const KIND_TASK: u8 = 3;
const KIND_CONTACT: u8 = 4;
const KIND_ASSOCIATED: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Email,
    Event,
    Task,
    Contact,
    Associated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawProperty<'x> {
    pub key: &'x [u8],
    pub value: &'x [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkRecord<'x> {
    Email {
        raw: &'x [u8],
        received_at: Option<i64>,
        keywords: Vec<&'x str>,
        properties: Vec<RawProperty<'x>>,
    },
    Event {
        ical: &'x str,
    },
    Task {
        ical: &'x str,
    },
    Contact {
        vcard: &'x str,
    },
    Associated {
        message_class: &'x str,
        properties: Vec<RawProperty<'x>>,
        recipients: Vec<Vec<RawProperty<'x>>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    Magic,
    Version,
    Kind,
    Truncated,
    Length,
    UnknownTag(u8),
    Duplicate(u8),
    Missing,
    Utf8,
    Value,
    TooManyKeywords,
    TooManyProperties,
    TooManyRecipients,
}

pub trait RecordSink {
    fn push(&mut self, bytes: &[u8]);
}

impl RecordSink for Vec<u8> {
    fn push(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl RecordSink for Base64Sink<'_, '_> {
    fn push(&mut self, bytes: &[u8]) {
        Base64Sink::push(self, bytes);
    }
}

impl<'x> BulkRecord<'x> {
    pub fn kind(&self) -> RecordKind {
        match self {
            BulkRecord::Email { .. } => RecordKind::Email,
            BulkRecord::Event { .. } => RecordKind::Event,
            BulkRecord::Task { .. } => RecordKind::Task,
            BulkRecord::Contact { .. } => RecordKind::Contact,
            BulkRecord::Associated { .. } => RecordKind::Associated,
        }
    }

    pub fn decode(bytes: &'x [u8]) -> Result<Self, RecordError> {
        let (magic, rest) = bytes.split_first_chunk::<4>().ok_or(RecordError::Magic)?;
        if magic != MAGIC {
            return Err(RecordError::Magic);
        }
        let (&[version, kind], mut rest) = rest
            .split_first_chunk::<2>()
            .ok_or(RecordError::Truncated)?;
        if version != VERSION {
            return Err(RecordError::Version);
        }
        if !(KIND_EMAIL..=KIND_ASSOCIATED).contains(&kind) {
            return Err(RecordError::Kind);
        }
        let mut content = None;
        let mut received_at = None;
        let mut keywords = Vec::new();
        let mut properties = Vec::new();
        let mut recipients = Vec::new();
        let mut budget = PropertyBudget(MAX_RECORD_PROPERTIES);
        while let Some(Field { tag, value, tail }) = next_field(rest)? {
            rest = tail;
            match (kind, tag) {
                (_, TAG_CONTENT) => set_once(&mut content, tag, value)?,
                (KIND_EMAIL, TAG_RECEIVED_AT) => {
                    let seconds = value
                        .try_into()
                        .map(i64::from_le_bytes)
                        .map_err(|_| RecordError::Value)?;
                    if seconds < 0 {
                        return Err(RecordError::Value);
                    }
                    set_once(&mut received_at, tag, seconds)?;
                }
                (KIND_EMAIL, TAG_KEYWORD) => {
                    if keywords.len() == MAX_RECORD_KEYWORDS {
                        return Err(RecordError::TooManyKeywords);
                    }
                    let keyword = text(value)?;
                    if keyword.is_empty() {
                        return Err(RecordError::Value);
                    }
                    keywords.push(keyword);
                }
                (KIND_EMAIL | KIND_ASSOCIATED, TAG_PROPERTY) => {
                    budget.take()?;
                    properties.push(property(value)?);
                }
                (KIND_ASSOCIATED, TAG_RECIPIENT) => {
                    if recipients.len() == MAX_RECORD_RECIPIENTS {
                        return Err(RecordError::TooManyRecipients);
                    }
                    recipients.push(recipient(value, &mut budget)?);
                }
                (_, tag) if tag & CRITICAL != 0 => return Err(RecordError::UnknownTag(tag)),
                _ => {}
            }
        }
        let content = content.ok_or(RecordError::Missing)?;
        Ok(match kind {
            KIND_EMAIL => BulkRecord::Email {
                raw: content,
                received_at,
                keywords,
                properties,
            },
            KIND_EVENT => BulkRecord::Event {
                ical: text(content)?,
            },
            KIND_TASK => BulkRecord::Task {
                ical: text(content)?,
            },
            KIND_CONTACT => BulkRecord::Contact {
                vcard: text(content)?,
            },
            KIND_ASSOCIATED => BulkRecord::Associated {
                message_class: text(content)?,
                properties,
                recipients,
            },
            _ => return Err(RecordError::Kind),
        })
    }

    pub fn encode(&self, out: &mut impl RecordSink) {
        out.push(MAGIC);
        match self {
            BulkRecord::Email {
                raw,
                received_at,
                keywords,
                properties,
            } => {
                out.push(&[VERSION, KIND_EMAIL]);
                write_field(out, TAG_CONTENT, raw);
                if let Some(seconds) = received_at {
                    write_field(out, TAG_RECEIVED_AT, &seconds.to_le_bytes());
                }
                for keyword in keywords {
                    write_field(out, TAG_KEYWORD, keyword.as_bytes());
                }
                for property in properties {
                    write_property(out, property);
                }
            }
            BulkRecord::Event { ical } => {
                out.push(&[VERSION, KIND_EVENT]);
                write_field(out, TAG_CONTENT, ical.as_bytes());
            }
            BulkRecord::Task { ical } => {
                out.push(&[VERSION, KIND_TASK]);
                write_field(out, TAG_CONTENT, ical.as_bytes());
            }
            BulkRecord::Contact { vcard } => {
                out.push(&[VERSION, KIND_CONTACT]);
                write_field(out, TAG_CONTENT, vcard.as_bytes());
            }
            BulkRecord::Associated {
                message_class,
                properties,
                recipients,
            } => {
                out.push(&[VERSION, KIND_ASSOCIATED]);
                write_field(out, TAG_CONTENT, message_class.as_bytes());
                for property in properties {
                    write_property(out, property);
                }
                for recipient in recipients {
                    let len = recipient.iter().map(property_field_len).sum::<usize>();
                    write_header(out, TAG_RECIPIENT, len);
                    for property in recipient {
                        write_property(out, property);
                    }
                }
            }
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, tag: u8, value: T) -> Result<(), RecordError> {
    if slot.replace(value).is_some() {
        Err(RecordError::Duplicate(tag))
    } else {
        Ok(())
    }
}

fn text(bytes: &[u8]) -> Result<&str, RecordError> {
    simdutf8::basic::from_utf8(bytes).map_err(|_| RecordError::Utf8)
}

struct Field<'x> {
    tag: u8,
    value: &'x [u8],
    tail: &'x [u8],
}

fn next_field(bytes: &[u8]) -> Result<Option<Field<'_>>, RecordError> {
    let Some((&tag, rest)) = bytes.split_first() else {
        return Ok(None);
    };
    let (len, rest) = read_leb128(rest)?;
    let len = usize::try_from(len).map_err(|_| RecordError::Length)?;
    let (value, rest) = rest.split_at_checked(len).ok_or(RecordError::Length)?;
    Ok(Some(Field {
        tag,
        value,
        tail: rest,
    }))
}

fn read_leb128(bytes: &[u8]) -> Result<(u64, &[u8]), RecordError> {
    let mut value = 0u64;
    let mut rest = bytes;
    for index in 0..LEB128_MAX {
        let (&byte, tail) = rest.split_first().ok_or(RecordError::Truncated)?;
        rest = tail;
        let part = u64::from(byte & LEB128_VALUE);
        if index == LEB128_MAX - 1 && part > 1 {
            return Err(RecordError::Length);
        }
        value |= part << (LEB128_BITS * index as u32);
        if byte & LEB128_MORE == 0 {
            if index > 0 && byte == 0 {
                return Err(RecordError::Length);
            }
            return Ok((value, rest));
        }
    }
    Err(RecordError::Length)
}

fn property(value: &[u8]) -> Result<RawProperty<'_>, RecordError> {
    let (len, rest) = read_leb128(value)?;
    let len = usize::try_from(len).map_err(|_| RecordError::Length)?;
    let (key, value) = rest.split_at_checked(len).ok_or(RecordError::Length)?;
    Ok(RawProperty { key, value })
}

struct PropertyBudget(usize);

impl PropertyBudget {
    fn take(&mut self) -> Result<(), RecordError> {
        self.0 = self
            .0
            .checked_sub(1)
            .ok_or(RecordError::TooManyProperties)?;
        Ok(())
    }
}

fn recipient<'x>(
    mut value: &'x [u8],
    budget: &mut PropertyBudget,
) -> Result<Vec<RawProperty<'x>>, RecordError> {
    let mut properties = Vec::new();
    while let Some(field) = next_field(value)? {
        value = field.tail;
        if field.tag != TAG_PROPERTY {
            return Err(RecordError::UnknownTag(field.tag));
        }
        budget.take()?;
        properties.push(property(field.value)?);
    }
    Ok(properties)
}

fn leb128_len(value: usize) -> usize {
    let bits = usize::BITS - value.leading_zeros();
    bits.div_ceil(LEB128_BITS).max(1) as usize
}

fn write_leb128(out: &mut impl RecordSink, mut value: usize) {
    let mut buf = [0u8; LEB128_MAX];
    let mut len = 0;
    for slot in buf.iter_mut() {
        let byte = (value & usize::from(LEB128_VALUE)) as u8;
        value >>= LEB128_BITS;
        len += 1;
        if value == 0 {
            *slot = byte;
            break;
        }
        *slot = byte | LEB128_MORE;
    }
    out.push(buf.get(..len).unwrap_or_default());
}

fn write_header(out: &mut impl RecordSink, tag: u8, len: usize) {
    out.push(&[tag]);
    write_leb128(out, len);
}

fn write_field(out: &mut impl RecordSink, tag: u8, value: &[u8]) {
    write_header(out, tag, value.len());
    out.push(value);
}

fn property_value_len(property: &RawProperty<'_>) -> usize {
    leb128_len(property.key.len()) + property.key.len() + property.value.len()
}

fn property_field_len(property: &RawProperty<'_>) -> usize {
    let len = property_value_len(property);
    1 + leb128_len(len) + len
}

fn write_property(out: &mut impl RecordSink, property: &RawProperty<'_>) {
    write_header(out, TAG_PROPERTY, property_value_len(property));
    write_leb128(out, property.key.len());
    out.push(property.key);
    out.push(property.value);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ews/bulk/tests.rs"]
mod tests;
