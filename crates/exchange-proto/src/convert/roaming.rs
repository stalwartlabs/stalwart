/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        Precision, UtcSeconds, XsDateTime,
        base64::{Base64Text, base64_encode_into},
    },
    ews::{
        schema::UserConfigurationDictionaryObjectType as ObjectType,
        types::config::{Dictionary, DictionaryEntry, DictionaryObject},
    },
    xml::{Token, Tokenizer, XmlLimits, XmlWriter, tokenizer::NoName},
};
use std::{
    borrow::Cow,
    collections::HashSet,
    fmt::{Display, Write},
    mem, str,
};

pub const DATATYPE_XML: u32 = 0x2;
pub const DATATYPE_DICTIONARY: u32 = 0x4;
pub const DATATYPE_BINARY: u32 = 0x1;

const CODE_BOOLEAN: u8 = 3;
const CODE_BYTE: u8 = 6;
const CODE_INTEGER32: u8 = 9;
const CODE_UNSIGNED_INTEGER32: u8 = 10;
const CODE_INTEGER64: u8 = 11;
const CODE_UNSIGNED_INTEGER64: u8 = 12;
const CODE_DATETIME: u8 = 16;
const CODE_STRING: u8 = 18;
const CODE_BYTE_ARRAY: u8 = 106;
const CODE_STRING_ARRAY: u8 = 118;

const STORED_TRUE: &str = "True";
const STORED_FALSE: &str = "False";
const ARRAY_SEPARATOR: char = ';';
const ARRAY_ESCAPE: char = '\\';
pub(super) const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
const ROOT: &str = "UserConfiguration";
const NAMESPACE: &str = "dictionary.xsd";
const INFO_VERSION: &str = "Stalwart.1";
const ENTRY: &str = "e";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoamingError {
    InvalidValue(ObjectType),
    MultipleValues(ObjectType),
    DuplicateKey,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoamingValue<'x> {
    Boolean(bool),
    Byte(u8),
    Integer32(i32),
    UnsignedInteger32(u32),
    Integer64(i64),
    UnsignedInteger64(u64),
    DateTime(UtcSeconds),
    String(Cow<'x, str>),
    StringArray(Vec<Cow<'x, str>>),
    ByteArray(Vec<u8>),
}

impl<'x> RoamingValue<'x> {
    pub fn from_object(object: &DictionaryObject<'x>) -> Result<Self, RoamingError> {
        let kind = object.kind;
        if kind == ObjectType::StringArray {
            return Ok(RoamingValue::StringArray(object.values.clone()));
        }
        let [value] = object.values.as_slice() else {
            return Err(RoamingError::MultipleValues(kind));
        };
        let invalid = || RoamingError::InvalidValue(kind);
        let text = value.trim_ascii();
        Ok(match kind {
            ObjectType::Boolean => RoamingValue::Boolean(
                hashify::map_ignore_case!(text.as_bytes(), bool,
                    "true" => true,
                    "false" => false,
                    "1" => true,
                    "0" => false,
                )
                .copied()
                .ok_or_else(invalid)?,
            ),
            ObjectType::Byte => RoamingValue::Byte(text.parse().map_err(|_| invalid())?),
            ObjectType::Integer32 => RoamingValue::Integer32(text.parse().map_err(|_| invalid())?),
            ObjectType::UnsignedInteger32 => {
                RoamingValue::UnsignedInteger32(text.parse().map_err(|_| invalid())?)
            }
            ObjectType::Integer64 => RoamingValue::Integer64(text.parse().map_err(|_| invalid())?),
            ObjectType::UnsignedInteger64 => {
                RoamingValue::UnsignedInteger64(text.parse().map_err(|_| invalid())?)
            }
            ObjectType::DateTime => {
                RoamingValue::DateTime(parse_datetime(text).ok_or_else(invalid)?)
            }
            ObjectType::String => RoamingValue::String(value.clone()),
            ObjectType::ByteArray => {
                let encoded = Base64Text(Cow::Borrowed(text.as_bytes()));
                let mut bytes = Vec::with_capacity(encoded.decoded_len_max());
                encoded
                    .decode_into(&mut bytes, encoded.decoded_len_max())
                    .map_err(|_| invalid())?;
                RoamingValue::ByteArray(bytes)
            }
            ObjectType::StringArray => return Err(invalid()),
        })
    }

    pub fn into_object(self) -> DictionaryObject<'x> {
        let (kind, value) = match self {
            RoamingValue::Boolean(value) => (
                ObjectType::Boolean,
                Cow::Borrowed(if value { "true" } else { "false" }),
            ),
            RoamingValue::Byte(value) => (ObjectType::Byte, value.to_string().into()),
            RoamingValue::Integer32(value) => (ObjectType::Integer32, value.to_string().into()),
            RoamingValue::UnsignedInteger32(value) => {
                (ObjectType::UnsignedInteger32, value.to_string().into())
            }
            RoamingValue::Integer64(value) => (ObjectType::Integer64, value.to_string().into()),
            RoamingValue::UnsignedInteger64(value) => {
                (ObjectType::UnsignedInteger64, value.to_string().into())
            }
            RoamingValue::DateTime(value) => (ObjectType::DateTime, xs_datetime(value).into()),
            RoamingValue::String(value) => (ObjectType::String, value),
            RoamingValue::StringArray(values) => {
                return DictionaryObject {
                    kind: ObjectType::StringArray,
                    values,
                };
            }
            RoamingValue::ByteArray(value) => {
                let mut encoded = Vec::with_capacity(value.len().div_ceil(3).saturating_mul(4));
                base64_encode_into(&value, &mut encoded);
                (
                    ObjectType::ByteArray,
                    String::from_utf8(encoded).unwrap_or_default().into(),
                )
            }
        };
        DictionaryObject {
            kind,
            values: vec![value],
        }
    }

    fn write_stored(&self, out: &mut String) {
        out.clear();
        match self {
            RoamingValue::Boolean(value) => {
                push_code(out, CODE_BOOLEAN);
                out.push_str(if *value { STORED_TRUE } else { STORED_FALSE });
            }
            RoamingValue::Byte(value) => push_number(out, CODE_BYTE, *value),
            RoamingValue::Integer32(value) => push_number(out, CODE_INTEGER32, *value),
            RoamingValue::UnsignedInteger32(value) => {
                push_number(out, CODE_UNSIGNED_INTEGER32, *value)
            }
            RoamingValue::Integer64(value) => push_number(out, CODE_INTEGER64, *value),
            RoamingValue::UnsignedInteger64(value) => {
                push_number(out, CODE_UNSIGNED_INTEGER64, *value)
            }
            RoamingValue::DateTime(value) => {
                push_code(out, CODE_DATETIME);
                out.push_str(&xs_datetime(*value));
            }
            RoamingValue::String(value) => {
                push_code(out, CODE_STRING);
                out.push_str(value);
            }
            RoamingValue::StringArray(values) => {
                push_code(out, CODE_STRING_ARRAY);
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(ARRAY_SEPARATOR);
                    }
                    for ch in value.chars() {
                        if matches!(ch, ARRAY_SEPARATOR | ARRAY_ESCAPE) {
                            out.push(ARRAY_ESCAPE);
                        }
                        out.push(ch);
                    }
                }
            }
            RoamingValue::ByteArray(value) => {
                push_code(out, CODE_BYTE_ARRAY);
                let mut encoded = Vec::with_capacity(value.len().div_ceil(3).saturating_mul(4));
                base64_encode_into(value, &mut encoded);
                out.push_str(str::from_utf8(&encoded).unwrap_or_default());
            }
        }
    }

    fn parse_stored(stored: &str) -> Option<RoamingValue<'static>> {
        let (code, text) = stored.split_once('-')?;
        Some(match code.parse::<u8>().ok()? {
            CODE_BOOLEAN => {
                RoamingValue::Boolean(*hashify::map_ignore_case!(text.as_bytes(), bool,
                    "true" => true,
                    "false" => false,
                )?)
            }
            CODE_BYTE => RoamingValue::Byte(text.parse().ok()?),
            CODE_INTEGER32 => RoamingValue::Integer32(text.parse().ok()?),
            CODE_UNSIGNED_INTEGER32 => RoamingValue::UnsignedInteger32(text.parse().ok()?),
            CODE_INTEGER64 => RoamingValue::Integer64(text.parse().ok()?),
            CODE_UNSIGNED_INTEGER64 => RoamingValue::UnsignedInteger64(text.parse().ok()?),
            CODE_DATETIME => RoamingValue::DateTime(parse_datetime(text)?),
            CODE_STRING => RoamingValue::String(Cow::Owned(text.to_string())),
            CODE_STRING_ARRAY => RoamingValue::StringArray(split_array(text)),
            CODE_BYTE_ARRAY => {
                let encoded = Base64Text(Cow::Borrowed(text.as_bytes()));
                let mut bytes = Vec::with_capacity(encoded.decoded_len_max());
                encoded
                    .decode_into(&mut bytes, encoded.decoded_len_max())
                    .ok()?;
                RoamingValue::ByteArray(bytes)
            }
            _ => return None,
        })
    }
}

pub fn encode_dictionary(dictionary: &Dictionary<'_>) -> Result<Vec<u8>, RoamingError> {
    let mut out = Vec::with_capacity(128 + dictionary.0.len() * 64);
    let mut key = String::new();
    let mut value = String::new();
    let mut seen = HashSet::with_capacity(dictionary.0.len());
    let mut w = XmlWriter::new(&mut out);
    w.decl();
    w.start("", ROOT).attr("xmlns", NAMESPACE).close_start();
    w.start("", "Info").attr("version", INFO_VERSION).empty();
    w.start("", "Data").close_start();
    for entry in &dictionary.0 {
        RoamingValue::from_object(&entry.key)?.write_stored(&mut key);
        if seen.contains(key.as_str()) {
            return Err(RoamingError::DuplicateKey);
        }
        w.start("", ENTRY).attr("k", &key);
        seen.insert(mem::take(&mut key));
        if let Some(object) = &entry.value {
            RoamingValue::from_object(object)?.write_stored(&mut value);
            w.attr("v", &value);
        }
        w.empty();
    }
    w.end("", "Data");
    w.end("", ROOT);
    Ok(out)
}

pub fn decode_dictionary(stream: &[u8], max_entries: usize) -> Option<Dictionary<'static>> {
    let stream = stream.strip_prefix(UTF8_BOM).unwrap_or(stream);
    let mut tokenizer = Tokenizer::new(stream, &XmlLimits::DEFAULT);
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut canonical = String::new();
    loop {
        match tokenizer.next_token::<NoName>().ok()? {
            Token::Unknown { local, attrs, .. } if local == ENTRY => {
                if entries.len() >= max_entries {
                    break;
                }
                let key = attrs.get("k").ok()?;
                let value = attrs.get("v").ok()?;
                let Some(key) = key.as_deref().and_then(RoamingValue::parse_stored) else {
                    continue;
                };
                key.write_stored(&mut canonical);
                if seen.contains(canonical.as_str()) {
                    continue;
                }
                let value = match value.as_deref() {
                    Some(value) => match RoamingValue::parse_stored(value) {
                        Some(value) => Some(value.into_object()),
                        None => continue,
                    },
                    None => None,
                };
                seen.insert(mem::take(&mut canonical));
                entries.push(DictionaryEntry {
                    key: key.into_object(),
                    value,
                });
            }
            Token::Eof => break,
            Token::Start { .. } | Token::Unknown { .. } | Token::End | Token::Text => {}
        }
    }
    Some(Dictionary(entries))
}

fn push_code(out: &mut String, code: u8) {
    let _ = write!(out, "{code}-");
}

fn push_number(out: &mut String, code: u8, value: impl Display) {
    let _ = write!(out, "{code}-{value}");
}

fn parse_datetime(text: &str) -> Option<UtcSeconds> {
    let parsed = XsDateTime::parse(text.as_bytes())?;
    Some(
        parsed
            .to_utc()
            .unwrap_or_else(|| parsed.local.to_unix_seconds()),
    )
}

fn xs_datetime(value: UtcSeconds) -> String {
    let mut out = Vec::with_capacity(20);
    value.write_xs(&mut out, Precision::Seconds);
    String::from_utf8(out).unwrap_or_default()
}

fn split_array(text: &str) -> Vec<Cow<'static, str>> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            ARRAY_ESCAPE => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ARRAY_SEPARATOR => values.push(Cow::Owned(mem::take(&mut current))),
            _ => current.push(ch),
        }
    }
    values.push(Cow::Owned(current));
    values
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/convert/roaming/tests.rs"]
mod tests;
