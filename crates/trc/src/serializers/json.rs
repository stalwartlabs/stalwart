/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Error, Event, EventDetails, EventType, Key, MetricType, Value, event::KeySet,
    serializers::timestamp::TimestampCache,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use std::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicU64, Ordering},
};

static EVENT_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct JsonEventSerializer<T> {
    inner: T,
    with_id: bool,
    with_spans: bool,
    with_description: bool,
}

struct Context {
    with_id: bool,
    with_spans: bool,
    with_description: bool,
    next_id: Cell<u64>,
    timestamps: RefCell<TimestampCache>,
    value_timestamps: RefCell<TimestampCache>,
}

struct Serialized<'x, T> {
    ctx: &'x Context,
    inner: T,
}

struct Keys<'x> {
    keys: &'x [(Key, Value)],
    span_keys: &'x [(Key, Value)],
}

impl<T> JsonEventSerializer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            with_id: false,
            with_spans: false,
            with_description: false,
        }
    }

    pub fn with_id(mut self) -> Self {
        self.with_id = true;
        self
    }

    pub fn with_spans(mut self) -> Self {
        self.with_spans = true;
        self
    }

    pub fn with_description(mut self) -> Self {
        self.with_description = true;
        self
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    fn context(&self, num_events: usize) -> Context {
        Context {
            with_id: self.with_id,
            with_spans: self.with_spans,
            with_description: self.with_description,
            next_id: Cell::new(if self.with_id {
                EVENT_ID_COUNTER.fetch_add(num_events as u64, Ordering::Relaxed)
            } else {
                0
            }),
            timestamps: RefCell::new(TimestampCache::new()),
            value_timestamps: RefCell::new(TimestampCache::new()),
        }
    }
}

impl<T: AsRef<Event<EventDetails>>> Serialize for JsonEventSerializer<Vec<T>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ctx = self.context(self.inner.len());
        let mut seq = serializer.serialize_seq(Some(self.inner.len()))?;
        for event in &self.inner {
            seq.serialize_element(&Serialized {
                ctx: &ctx,
                inner: event.as_ref(),
            })?;
        }
        seq.end()
    }
}

impl<T: AsRef<Event<EventDetails>>> Serialize for JsonEventSerializer<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialized {
            ctx: &self.context(1),
            inner: self.inner.as_ref(),
        }
        .serialize(serializer)
    }
}

impl Serialize for Serialized<'_, &Event<EventDetails>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let event = self.inner;
        let mut map = serializer.serialize_map(None)?;
        if self.ctx.with_id {
            let counter = self.ctx.next_id.get();
            self.ctx.next_id.set(counter.wrapping_add(1));
            let mut id = EventId::default();
            map.serialize_entry(
                "id",
                id.format(event.inner.timestamp, counter, event.inner.typ.to_id()),
            )?;
        }
        if self.ctx.with_description {
            map.serialize_entry("text", event.inner.typ.description())?;
        }
        map.serialize_entry(
            "createdAt",
            self.ctx.timestamps.borrow_mut().get(event.inner.timestamp),
        )?;
        map.serialize_entry("type", event.inner.typ.as_str())?;
        map.serialize_entry(
            "data",
            &Serialized {
                ctx: self.ctx,
                inner: Keys {
                    keys: event.keys.as_slice(),
                    span_keys: event
                        .inner
                        .span
                        .as_ref()
                        .map_or(&[][..], |span| span.keys.as_slice()),
                },
            },
        )?;
        map.end()
    }
}

impl Serialize for Serialized<'_, Keys<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let keys_len = self.inner.keys.len() + self.inner.span_keys.len();
        let mut seen_keys = KeySet::default();
        let mut keys = serializer.serialize_map(Some(keys_len))?;
        for (key, value) in self.inner.keys.iter().chain(self.inner.span_keys.iter()) {
            if !matches!(value, Value::None)
                && (self.ctx.with_spans || !matches!(key, Key::SpanId))
                && seen_keys.insert(*key)
            {
                keys.serialize_entry(
                    key.as_str(),
                    &Serialized {
                        ctx: self.ctx,
                        inner: value,
                    },
                )?;
            }
        }
        keys.end()
    }
}

impl Serialize for Serialized<'_, &Error> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", self.inner.0.inner.as_str())?;
        if self.ctx.with_description {
            map.serialize_entry("text", self.inner.0.inner.description())?;
        }
        map.serialize_entry(
            "data",
            &Serialized {
                ctx: self.ctx,
                inner: Keys {
                    keys: self.inner.0.keys.as_slice(),
                    span_keys: &[],
                },
            },
        )?;
        map.end()
    }
}

impl Serialize for Serialized<'_, &Value> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.inner {
            Value::String(value) => serializer.serialize_str(value.as_str()),
            Value::UInt(value) => serializer.serialize_u64(*value),
            Value::Int(value) => serializer.serialize_i64(*value),
            Value::Float(value) => serializer.serialize_f64(*value),
            Value::Timestamp(value) => {
                serializer.serialize_str(self.ctx.value_timestamps.borrow_mut().get(*value))
            }
            Value::Duration(value) => serializer.serialize_u64(*value),
            Value::Bytes(value) => serializer.serialize_str(&STANDARD.encode(value)),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Ipv4(value) => value.serialize(serializer),
            Value::Ipv6(value) => value.serialize(serializer),
            Value::Event(value) => Serialized {
                ctx: self.ctx,
                inner: value,
            }
            .serialize(serializer),
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&Serialized {
                        ctx: self.ctx,
                        inner: value,
                    })?;
                }
                seq.end()
            }
            Value::None => serializer.serialize_unit(),
        }
    }
}

struct EventId {
    buf: [u8; 64],
}

impl Default for EventId {
    fn default() -> Self {
        Self { buf: [0; 64] }
    }
}

impl EventId {
    fn format(&mut self, timestamp: u64, counter: u64, type_id: u16) -> &str {
        let mut len = 0;
        for part in [
            itoa::Buffer::new().format(timestamp).as_bytes(),
            itoa::Buffer::new().format(counter).as_bytes(),
            itoa::Buffer::new().format(type_id).as_bytes(),
        ] {
            self.buf[len..len + part.len()].copy_from_slice(part);
            len += part.len();
        }
        std::str::from_utf8(&self.buf[..len]).unwrap_or_default()
    }
}

impl serde::Serialize for EventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        Self::parse(s).ok_or_else(|| serde::de::Error::unknown_variant(s, &[]))
    }
}

impl serde::Serialize for MetricType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MetricType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        Self::parse(s).ok_or_else(|| serde::de::Error::unknown_variant(s, &[]))
    }
}

#[cfg(test)]
mod tests {
    use super::JsonEventSerializer;
    use crate::{Event, EventDetails, EventType, Key, Level, SmtpEvent, Value};
    use std::sync::Arc;

    fn event(keys: Vec<(Key, Value)>) -> Arc<Event<EventDetails>> {
        Arc::new(Event {
            inner: EventDetails {
                typ: EventType::Smtp(SmtpEvent::MailFrom),
                timestamp: 1_700_000_000,
                level: Level::Info,
                span: None,
            },
            keys,
        })
    }

    #[test]
    fn json_format() {
        let events = vec![
            event(vec![
                (Key::From, Value::from("a\"b")),
                (Key::Total, Value::Array(vec![Value::UInt(1), Value::None])),
                (Key::From, Value::from("duplicate")),
                (Key::Size, Value::None),
                (Key::Expires, Value::Timestamp(0)),
            ]),
            event(vec![]),
        ];

        let json =
            serde_json::to_value(JsonEventSerializer::new(events).with_id()).unwrap_or_default();
        let list = json.as_array().cloned().unwrap_or_default();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["createdAt"], "2023-11-14T22:13:20Z");
        assert_eq!(
            list[0]["data"],
            serde_json::json!({"from": "a\"b", "total": [1, null], "expires": "1970-01-01T00:00:00Z"})
        );

        let type_id = EventType::Smtp(SmtpEvent::MailFrom).to_id().to_string();
        let counter = |value: &serde_json::Value| {
            value
                .as_str()
                .and_then(|id| id.strip_prefix("1700000000"))
                .and_then(|id| id.strip_suffix(type_id.as_str()))
                .and_then(|id| id.parse::<u64>().ok())
        };
        let first = counter(&list[0]["id"]);
        assert!(first.is_some());
        assert_eq!(first.map(|id| id + 1), counter(&list[1]["id"]));
    }
}
