/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::proto::{
    len_field_len, tag_len, varint_len,
    writer::{LenHint, ProtoWriter},
};
use std::fmt::Write;
use trc::{Key, Value, serializers::timestamp::write_rfc3339};

const KEY_VALUE_KEY: u32 = 1;
const KEY_VALUE_VALUE: u32 = 2;

const ANY_STRING: u32 = 1;
const ANY_BOOL: u32 = 2;
const ANY_INT: u32 = 3;
const ANY_DOUBLE: u32 = 4;
const ANY_ARRAY: u32 = 5;
const ANY_KVLIST: u32 = 6;
const ANY_BYTES: u32 = 7;

const ARRAY_VALUES: u32 = 1;
const KVLIST_VALUES: u32 = 1;

const MAX_DEPTH: u8 = 8;
const DEPTH_PLACEHOLDER: &str = "[max depth]";
const EVENT_NAME_KEY: &str = "eventName";

enum Scalar<'x> {
    Str(&'x [u8]),
    Int(i64),
    Double(f64),
    Bool(bool),
    Bytes(&'x [u8]),
}

#[derive(Default)]
pub struct ValueEncoder {
    scratch: String,
}

impl Scalar<'_> {
    #[inline(always)]
    fn encoded_len(&self) -> usize {
        match self {
            Scalar::Str(value) => len_field_len(ANY_STRING, value.len()),
            Scalar::Bytes(value) => len_field_len(ANY_BYTES, value.len()),
            Scalar::Int(value) => tag_len(ANY_INT) + varint_len(*value as u64),
            Scalar::Double(_) => tag_len(ANY_DOUBLE) + 8,
            Scalar::Bool(_) => tag_len(ANY_BOOL) + 1,
        }
    }

    #[inline(always)]
    fn write(&self, w: &mut ProtoWriter) {
        match self {
            Scalar::Str(value) => w.bytes_always(ANY_STRING, value),
            Scalar::Bytes(value) => w.bytes_always(ANY_BYTES, value),
            Scalar::Int(value) => w.int64_always(ANY_INT, *value),
            Scalar::Double(value) => w.double_always(ANY_DOUBLE, *value),
            Scalar::Bool(value) => w.bool_always(ANY_BOOL, *value),
        }
    }
}

#[inline(always)]
fn unsigned(value: u64, scratch: &mut String) -> Scalar<'_> {
    match i64::try_from(value) {
        Ok(value) => Scalar::Int(value),
        Err(_) => {
            scratch.clear();
            scratch.push_str(itoa::Buffer::new().format(value));
            Scalar::Str(scratch.as_bytes())
        }
    }
}

#[inline(always)]
fn scalar<'x>(value: &'x Value, scratch: &'x mut String) -> Option<Scalar<'x>> {
    let scalar = match value {
        Value::String(value) => Scalar::Str(value.as_bytes()),
        Value::UInt(value) | Value::Duration(value) => unsigned(*value, scratch),
        Value::Int(value) => Scalar::Int(*value),
        Value::Float(value) => Scalar::Double(*value),
        Value::Bool(value) => Scalar::Bool(*value),
        Value::Bytes(value) => Scalar::Bytes(value),
        Value::Timestamp(value) => {
            scratch.clear();
            write_rfc3339(scratch, *value);
            Scalar::Str(scratch.as_bytes())
        }
        Value::Ipv4(value) => {
            scratch.clear();
            let _ = write!(scratch, "{value}");
            Scalar::Str(scratch.as_bytes())
        }
        Value::Ipv6(value) => {
            scratch.clear();
            let _ = write!(scratch, "{value}");
            Scalar::Str(scratch.as_bytes())
        }
        Value::Event(_) | Value::Array(_) | Value::None => return None,
    };
    Some(scalar)
}

impl ValueEncoder {
    #[inline]
    pub fn key_value(&mut self, w: &mut ProtoWriter, field: u32, key: Key, value: &Value) {
        self.key_value_str(w, field, key.as_str(), value, 0);
    }

    fn key_value_str(
        &mut self,
        w: &mut ProtoWriter,
        field: u32,
        key: &str,
        value: &Value,
        depth: u8,
    ) {
        if let Some(scalar) = scalar(value, &mut self.scratch) {
            let any_len = scalar.encoded_len();
            w.len_prefix(
                field,
                len_field_len(KEY_VALUE_KEY, key.len()) + len_field_len(KEY_VALUE_VALUE, any_len),
            );
            w.bytes_always(KEY_VALUE_KEY, key.as_bytes());
            w.len_prefix(KEY_VALUE_VALUE, any_len);
            scalar.write(w);
        } else if !matches!(value, Value::None) {
            let kv = w.begin(field, LenHint::Small);
            w.bytes_always(KEY_VALUE_KEY, key.as_bytes());
            self.complex(w, KEY_VALUE_VALUE, value, depth);
            w.end(kv);
        }
    }

    pub fn string_key_value(&mut self, w: &mut ProtoWriter, field: u32, key: &str, value: &str) {
        let any_len = len_field_len(ANY_STRING, value.len());
        w.len_prefix(
            field,
            len_field_len(KEY_VALUE_KEY, key.len()) + len_field_len(KEY_VALUE_VALUE, any_len),
        );
        w.bytes_always(KEY_VALUE_KEY, key.as_bytes());
        w.len_prefix(KEY_VALUE_VALUE, any_len);
        w.bytes_always(ANY_STRING, value.as_bytes());
    }

    fn any_value(&mut self, w: &mut ProtoWriter, field: u32, value: &Value, depth: u8) {
        if let Some(scalar) = scalar(value, &mut self.scratch) {
            w.len_prefix(field, scalar.encoded_len());
            scalar.write(w);
        } else if matches!(value, Value::None) {
            w.len_prefix(field, 0);
        } else {
            self.complex(w, field, value, depth);
        }
    }

    fn complex(&mut self, w: &mut ProtoWriter, field: u32, value: &Value, depth: u8) {
        if depth >= MAX_DEPTH {
            w.len_prefix(field, len_field_len(ANY_STRING, DEPTH_PLACEHOLDER.len()));
            w.bytes_always(ANY_STRING, DEPTH_PLACEHOLDER.as_bytes());
            return;
        }
        let any = w.begin(field, LenHint::Small);
        match value {
            Value::Array(values) => {
                let array = w.begin(ANY_ARRAY, LenHint::Small);
                for value in values {
                    self.any_value(w, ARRAY_VALUES, value, depth + 1);
                }
                w.end(array);
            }
            Value::Event(event) => {
                let kvlist = w.begin(ANY_KVLIST, LenHint::Small);
                self.string_key_value(
                    w,
                    KVLIST_VALUES,
                    EVENT_NAME_KEY,
                    event.event_type().as_str(),
                );
                for (key, value) in event.keys() {
                    self.key_value_str(w, KVLIST_VALUES, key.as_str(), value, depth + 1);
                }
                w.end(kvlist);
            }
            _ => {}
        }
        w.end(any);
    }
}
