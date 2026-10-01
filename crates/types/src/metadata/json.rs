/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::codec::{
    CheckedReader, MAX_NESTING, Reader, TrustedReader, bytes_len, varint_len, write_bytes,
    write_varint,
};
use jmap_tools::{Element, Key, Map, Property, Value};
use std::{borrow::Cow, slice};

const NULL: u8 = 0x00;
const FALSE: u8 = 0x01;
const TRUE: u8 = 0x02;
const UINT: u8 = 0x03;
const NEG_INT: u8 = 0x04;
const FLOAT: u8 = 0x05;
const STR: u8 = 0x06;
const ARRAY: u8 = 0x07;
const OBJECT: u8 = 0x08;
const SMALL_UINT: u8 = 0x40;
const SMALL_UINT_MAX: u64 = 0x3F;
const SHORT_STR: u8 = 0x80;
const SHORT_STR_MAX: usize = 0x7F;
const FLOAT_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonKind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonError {
    NotAnObject,
    ControlCharacter,
    NestingTooDeep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedJson {
    bytes: Vec<u8>,
    depth: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct JsonView<'x> {
    reader: TrustedReader<'x>,
}

#[derive(Debug, Clone)]
pub struct JsonMembers<'x> {
    reader: TrustedReader<'x>,
    remaining: usize,
}

#[derive(Debug, Clone)]
pub struct JsonItems<'x> {
    reader: TrustedReader<'x>,
    remaining: usize,
}

impl EncodedJson {
    pub fn encode_namespace<P: Property, E: Element<Property = P>>(
        value: &Value<'_, P, E>,
    ) -> Result<Self, JsonError> {
        if matches!(value, Value::Object(_)) {
            Self::encode(value)
        } else {
            Err(JsonError::NotAnObject)
        }
    }

    pub fn encode<P: Property, E: Element<Property = P>>(
        value: &Value<'_, P, E>,
    ) -> Result<Self, JsonError> {
        let mut sizes = Vec::new();
        let (len, depth) = measure(value, 0, &mut sizes)?;
        let mut bytes = Vec::with_capacity(len);
        write(value, &mut sizes.iter(), &mut bytes);
        debug_assert_eq!(bytes.len(), len, "measured and written JSON lengths differ");
        Ok(EncodedJson {
            bytes,
            depth: depth.max(1),
        })
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn view(&self) -> JsonView<'_> {
        JsonView {
            reader: unsafe { Reader::trusted(&self.bytes) },
        }
    }
}

fn is_control(byte: u8) -> bool {
    (byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r')) || byte == 0x7F
}

fn check_text(text: &str) -> Result<(), JsonError> {
    if text.bytes().any(is_control) {
        Err(JsonError::ControlCharacter)
    } else {
        Ok(())
    }
}

fn str_encoded_len(len: usize) -> usize {
    if len <= SHORT_STR_MAX {
        1 + len
    } else {
        1 + bytes_len(len)
    }
}

#[derive(Clone, Copy)]
enum NumberRepr {
    Small(u8),
    Unsigned(u64),
    Negative(u64),
    Float(f64),
}

impl NumberRepr {
    fn new(unsigned: Option<u64>, signed: Option<i64>, float: Option<f64>) -> Self {
        match (unsigned, signed) {
            (Some(value), _) if value <= SMALL_UINT_MAX => NumberRepr::Small(value as u8),
            (Some(value), _) => NumberRepr::Unsigned(value),
            (None, Some(value)) => NumberRepr::Negative(!value as u64),
            (None, None) => NumberRepr::Float(float.unwrap_or_default()),
        }
    }

    fn encoded_len(self) -> usize {
        match self {
            NumberRepr::Small(_) => 1,
            NumberRepr::Unsigned(value) | NumberRepr::Negative(value) => 1 + varint_len(value),
            NumberRepr::Float(_) => 1 + FLOAT_LEN,
        }
    }

    fn write(self, out: &mut Vec<u8>) {
        match self {
            NumberRepr::Small(value) => out.push(SMALL_UINT | value),
            NumberRepr::Unsigned(value) => {
                out.push(UINT);
                write_varint(out, value);
            }
            NumberRepr::Negative(value) => {
                out.push(NEG_INT);
                write_varint(out, value);
            }
            NumberRepr::Float(value) => {
                out.push(FLOAT);
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
}

fn measure<P: Property, E: Element<Property = P>>(
    value: &Value<'_, P, E>,
    nesting: u32,
    sizes: &mut Vec<usize>,
) -> Result<(usize, u32), JsonError> {
    match value {
        Value::Null | Value::Bool(_) => Ok((1, 0)),
        Value::Number(number) => Ok((
            NumberRepr::new(number.as_u64(), number.as_i64(), number.as_f64()).encoded_len(),
            0,
        )),
        Value::Str(text) => {
            check_text(text)?;
            Ok((str_encoded_len(text.len()), 0))
        }
        Value::Element(element) => {
            let text = element.to_cow();
            check_text(&text)?;
            Ok((str_encoded_len(text.len()), 0))
        }
        Value::Array(items) => {
            if nesting >= MAX_NESTING {
                return Err(JsonError::NestingTooDeep);
            }
            let slot = sizes.len();
            sizes.push(0);
            let mut body = varint_len(items.len() as u64);
            let mut depth = 0;
            for item in items {
                let (len, item_depth) = measure(item, nesting + 1, sizes)?;
                body += len;
                depth = depth.max(item_depth);
            }
            if let Some(size) = sizes.get_mut(slot) {
                *size = body;
            }
            Ok((1 + bytes_len(body), depth))
        }
        Value::Object(object) => {
            if nesting >= MAX_NESTING {
                return Err(JsonError::NestingTooDeep);
            }
            let slot = sizes.len();
            sizes.push(0);
            let mut body = varint_len(object.len() as u64);
            let mut depth = 0;
            for (key, item) in object.iter() {
                let key = key.to_string();
                check_text(&key)?;
                let (len, item_depth) = measure(item, nesting + 1, sizes)?;
                body += bytes_len(key.len()) + len;
                depth = depth.max(item_depth);
            }
            if let Some(size) = sizes.get_mut(slot) {
                *size = body;
            }
            Ok((1 + bytes_len(body), depth + 1))
        }
    }
}

fn write_str(out: &mut Vec<u8>, text: &str) {
    if text.len() <= SHORT_STR_MAX {
        out.push(SHORT_STR | text.len() as u8);
        out.extend_from_slice(text.as_bytes());
    } else {
        out.push(STR);
        write_bytes(out, text.as_bytes());
    }
}

fn write<P: Property, E: Element<Property = P>>(
    value: &Value<'_, P, E>,
    sizes: &mut slice::Iter<'_, usize>,
    out: &mut Vec<u8>,
) {
    match value {
        Value::Null => out.push(NULL),
        Value::Bool(false) => out.push(FALSE),
        Value::Bool(true) => out.push(TRUE),
        Value::Number(number) => {
            NumberRepr::new(number.as_u64(), number.as_i64(), number.as_f64()).write(out)
        }
        Value::Str(text) => write_str(out, text),
        Value::Element(element) => write_str(out, &element.to_cow()),
        Value::Array(items) => {
            out.push(ARRAY);
            write_varint(out, sizes.next().copied().unwrap_or_default() as u64);
            write_varint(out, items.len() as u64);
            for item in items {
                write(item, sizes, out);
            }
        }
        Value::Object(object) => {
            out.push(OBJECT);
            write_varint(out, sizes.next().copied().unwrap_or_default() as u64);
            write_varint(out, object.len() as u64);
            for (key, item) in object.iter() {
                write_bytes(out, key.to_string().as_bytes());
                write(item, sizes, out);
            }
        }
    }
}

pub(crate) fn skip_value<const TRUSTED: bool>(reader: &mut Reader<'_, TRUSTED>) -> Option<()> {
    match reader.u8()? {
        NULL | FALSE | TRUE => Some(()),
        UINT | NEG_INT => reader.varint().map(drop),
        FLOAT => reader.skip(FLOAT_LEN),
        STR | ARRAY | OBJECT => {
            let len = reader.len()?;
            reader.skip(len)
        }
        tag if tag >= SHORT_STR => reader.skip(usize::from(tag & !SHORT_STR)),
        tag if tag >= SMALL_UINT => Some(()),
        _ => None,
    }
}

pub(crate) fn value_span<'x, const TRUSTED: bool>(
    reader: &mut Reader<'x, TRUSTED>,
) -> Option<Reader<'x, TRUSTED>> {
    let start = *reader;
    skip_value(reader)?;
    reader.consumed_since(&start)
}

pub(crate) fn validate_value(reader: &mut CheckedReader<'_>, nesting: u32) -> Option<()> {
    match reader.u8()? {
        NULL | FALSE | TRUE => Some(()),
        UINT => reader.varint().map(drop),
        NEG_INT => reader
            .varint()
            .filter(|value| i64::try_from(*value).is_ok())
            .map(drop),
        FLOAT => reader.skip(FLOAT_LEN),
        STR => reader.str().map(drop),
        tag @ (ARRAY | OBJECT) => {
            if nesting >= MAX_NESTING {
                return None;
            }
            let len = reader.len()?;
            let mut body = reader.take_reader(len)?;
            let count = body.len()?;
            for _ in 0..count {
                if tag == OBJECT {
                    body.str()?;
                }
                validate_value(&mut body, nesting + 1)?;
            }
            body.is_empty().then_some(())
        }
        tag if tag >= SHORT_STR => reader.text(usize::from(tag & !SHORT_STR)).map(drop),
        tag if tag >= SMALL_UINT => Some(()),
        _ => None,
    }
}

pub(crate) fn validate_namespace_value(reader: &mut CheckedReader<'_>) -> Option<()> {
    (reader.peek()? == OBJECT).then_some(())?;
    validate_value(reader, 0)
}

impl<'x> JsonView<'x> {
    pub(crate) const fn new(reader: TrustedReader<'x>) -> Self {
        JsonView { reader }
    }

    pub fn as_bytes(&self) -> &'x [u8] {
        self.reader.remaining()
    }

    pub fn encoded_len(&self) -> usize {
        self.reader.remaining().len()
    }

    pub fn kind(&self) -> JsonKind {
        match self.reader.peek() {
            Some(FALSE | TRUE) => JsonKind::Bool,
            Some(UINT | NEG_INT | FLOAT) => JsonKind::Number,
            Some(STR) => JsonKind::String,
            Some(ARRAY) => JsonKind::Array,
            Some(OBJECT) => JsonKind::Object,
            Some(tag) if tag >= SHORT_STR => JsonKind::String,
            Some(tag) if tag >= SMALL_UINT => JsonKind::Number,
            _ => JsonKind::Null,
        }
    }

    pub fn is_null(&self) -> bool {
        self.kind() == JsonKind::Null
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self.reader.peek()? {
            FALSE => Some(false),
            TRUE => Some(true),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        let mut reader = self.reader;
        match reader.u8()? {
            UINT => reader.varint(),
            tag if (SMALL_UINT..SHORT_STR).contains(&tag) => Some(u64::from(tag & !SMALL_UINT)),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        let mut reader = self.reader;
        match reader.peek()? {
            NEG_INT => {
                reader.u8()?;
                reader.varint().map(|value| !(value as i64))
            }
            _ => self.as_u64().and_then(|value| i64::try_from(value).ok()),
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        let mut reader = self.reader;
        match reader.peek()? {
            FLOAT => {
                reader.u8()?;
                reader
                    .take(FLOAT_LEN)?
                    .try_into()
                    .ok()
                    .map(f64::from_le_bytes)
            }
            NEG_INT => self.as_i64().map(|value| value as f64),
            _ => self.as_u64().map(|value| value as f64),
        }
    }

    pub fn as_str(&self) -> Option<&'x str> {
        let mut reader = self.reader;
        match reader.u8()? {
            STR => reader.str(),
            tag if tag >= SHORT_STR => reader.text(usize::from(tag & !SHORT_STR)),
            _ => None,
        }
    }

    fn container(&self, tag: u8) -> Option<(TrustedReader<'x>, usize)> {
        let mut reader = self.reader;
        (reader.u8()? == tag).then_some(())?;
        let len = reader.len()?;
        let mut body = reader.take_reader(len)?;
        let count = body.len()?;
        Some((body, count))
    }

    pub fn len(&self) -> usize {
        self.container(OBJECT)
            .or_else(|| self.container(ARRAY))
            .map_or(0, |(_, count)| count)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_object(&self) -> bool {
        self.reader.peek() == Some(OBJECT)
    }

    pub fn is_empty_object(&self) -> bool {
        self.container(OBJECT).is_some_and(|(_, count)| count == 0)
    }

    pub fn members(&self) -> JsonMembers<'x> {
        let (reader, remaining) = self.container(OBJECT).unwrap_or((Reader::empty(), 0));
        JsonMembers { reader, remaining }
    }

    pub fn items(&self) -> JsonItems<'x> {
        let (reader, remaining) = self.container(ARRAY).unwrap_or((Reader::empty(), 0));
        JsonItems { reader, remaining }
    }

    pub fn get(&self, key: &str) -> Option<JsonView<'x>> {
        let (mut body, count) = self.container(OBJECT)?;
        let key = key.as_bytes();
        for _ in 0..count {
            if body.bytes()? == key {
                return value_span(&mut body).map(JsonView::new);
            }
            skip_value(&mut body)?;
        }
        None
    }

    pub fn to_value<P: Property, E: Element<Property = P>>(&self) -> Option<Value<'x, P, E>> {
        let mut reader = self.reader;
        decode(&mut reader, 0)
    }
}

fn decode<'x, P: Property, E: Element<Property = P>>(
    reader: &mut TrustedReader<'x>,
    nesting: u32,
) -> Option<Value<'x, P, E>> {
    Some(match reader.u8()? {
        NULL => Value::Null,
        FALSE => Value::Bool(false),
        TRUE => Value::Bool(true),
        UINT => Value::Number(reader.varint()?.into()),
        NEG_INT => Value::Number((!(reader.varint()? as i64)).into()),
        FLOAT => Value::Number(f64::from_le_bytes(reader.take(FLOAT_LEN)?.try_into().ok()?).into()),
        STR => Value::Str(Cow::Borrowed(reader.str()?)),
        ARRAY => {
            if nesting >= MAX_NESTING {
                return None;
            }
            let len = reader.len()?;
            let mut body = reader.take_reader(len)?;
            let count = body.len()?;
            let mut items = Vec::with_capacity(count.min(body.remaining().len()));
            for _ in 0..count {
                items.push(decode(&mut body, nesting + 1)?);
            }
            Value::Array(items)
        }
        OBJECT => {
            if nesting >= MAX_NESTING {
                return None;
            }
            let len = reader.len()?;
            let mut body = reader.take_reader(len)?;
            let count = body.len()?;
            let mut object = Map::with_capacity(count.min(body.remaining().len()));
            for _ in 0..count {
                let key = body.str()?;
                object.insert_unchecked(Key::Borrowed(key), decode(&mut body, nesting + 1)?);
            }
            Value::Object(object)
        }
        tag if tag >= SHORT_STR => {
            Value::Str(Cow::Borrowed(reader.text(usize::from(tag & !SHORT_STR))?))
        }
        tag if tag >= SMALL_UINT => Value::Number(u64::from(tag & !SMALL_UINT).into()),
        _ => return None,
    })
}

impl<'x> Iterator for JsonMembers<'x> {
    type Item = (&'x str, JsonView<'x>);

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        let key = self.reader.str()?;
        let value = value_span(&mut self.reader)?;
        Some((key, JsonView::new(value)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

impl<'x> Iterator for JsonItems<'x> {
    type Item = JsonView<'x>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        value_span(&mut self.reader).map(JsonView::new)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}
