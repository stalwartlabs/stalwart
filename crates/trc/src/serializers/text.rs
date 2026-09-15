/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, io::Write};

use crate::{
    Error, Event, EventDetails, Key, Level, Value,
    event::KeySet,
    serializers::{
        escape::escape_into, timestamp::TimestampCache, write_base64, write_int, write_uint,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Default)]
pub struct FmtWriter {
    ansi: bool,
    multiline: bool,
    timestamps: TimestampCache,
    value_timestamps: TimestampCache,
}

#[allow(dead_code)]
enum Color {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
}

impl FmtWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ansi(self, ansi: bool) -> Self {
        Self { ansi, ..self }
    }

    pub fn with_multiline(self, multiline: bool) -> Self {
        Self { multiline, ..self }
    }

    pub fn write(&mut self, event: &Event<EventDetails>, out: &mut Vec<u8>) {
        let level_color = match event.inner.level {
            Level::Error => Color::Red,
            Level::Warn => Color::Yellow,
            Level::Info => Color::Green,
            Level::Debug => Color::Blue,
            Level::Trace => Color::Magenta,
            Level::Disable => return,
        };

        if self.ansi {
            out.extend_from_slice(Color::White.as_code().as_bytes());
        }
        out.extend_from_slice(self.timestamps.get(event.inner.timestamp).as_bytes());
        if self.ansi {
            out.extend_from_slice(Color::reset().as_bytes());
        }
        out.push(b' ');

        if self.ansi {
            out.extend_from_slice(level_color.as_code_bold().as_bytes());
        }
        out.extend_from_slice(event.inner.level.as_str().as_bytes());
        if self.ansi {
            out.extend_from_slice(Color::reset().as_bytes());
        }
        out.push(b' ');

        if self.ansi {
            out.extend_from_slice(Color::White.as_code_bold().as_bytes());
        }
        out.extend_from_slice(event.inner.typ.description().as_bytes());
        if self.ansi {
            out.extend_from_slice(Color::reset().as_bytes());
        }
        out.extend_from_slice(b" (");
        out.extend_from_slice(event.inner.typ.as_str().as_bytes());
        out.extend_from_slice(if self.multiline { b")\n" } else { b") " });

        let span_keys = event
            .inner
            .span
            .as_ref()
            .map_or(&[][..], |span| span.keys.as_slice());
        self.write_keys(out, span_keys, &event.keys, 1);

        if !self.multiline {
            out.push(b'\n');
        }
    }

    fn write_keys(
        &mut self,
        out: &mut Vec<u8>,
        span_keys: &[(Key, Value)],
        keys: &[(Key, Value)],
        indent: usize,
    ) {
        let mut event_keys = KeySet::default();
        if !span_keys.is_empty() {
            for (key, _) in keys {
                event_keys.insert(*key);
            }
        }

        let mut is_first = true;
        for (key, value) in span_keys
            .iter()
            .filter(|(key, _)| !event_keys.contains(*key))
            .chain(keys.iter())
        {
            if matches!(key, Key::SpanId) {
                continue;
            } else if is_first {
                is_first = false;
            } else if !self.multiline {
                out.extend_from_slice(b", ");
            }

            if self.multiline {
                out.resize(out.len() + indent, b'\t');
            }
            if self.ansi {
                out.extend_from_slice(Color::Cyan.as_code().as_bytes());
            }
            out.extend_from_slice(key.as_str().as_bytes());
            if self.ansi {
                out.extend_from_slice(Color::reset().as_bytes());
            }

            out.extend_from_slice(b" = ");
            self.write_value(out, value, indent);

            if self.multiline && !matches!(value, Value::Event(_)) {
                out.push(b'\n');
            }
        }
    }

    fn write_value(&mut self, out: &mut Vec<u8>, value: &Value, indent: usize) {
        match value {
            Value::String(v) => {
                out.push(b'"');
                escape_into(out, v.as_bytes());
                out.push(b'"');
            }
            Value::UInt(v) => write_uint(out, *v),
            Value::Int(v) => write_int(out, *v),
            Value::Float(v) => {
                let _ = write!(out, "{v}");
            }
            Value::Timestamp(v) => {
                out.extend_from_slice(self.value_timestamps.get(*v).as_bytes());
            }
            Value::Duration(v) => {
                write_uint(out, *v);
                out.extend_from_slice(b"ms");
            }
            Value::Bytes(bytes) => {
                out.extend_from_slice(b"base64:");
                write_base64(out, bytes);
            }
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Ipv4(v) => {
                let _ = write!(out, "{v}");
            }
            Value::Ipv6(v) => {
                let _ = write!(out, "{v}");
            }
            Value::Event(e) => {
                out.extend_from_slice(e.0.inner.description().as_bytes());
                out.extend_from_slice(b" (");
                out.extend_from_slice(e.0.inner.as_str().as_bytes());
                out.push(b')');
                if !e.0.keys.is_empty() {
                    out.extend_from_slice(if self.multiline { b"\n" } else { b" { " });
                    self.write_keys(out, &e.0.keys, &[], indent + 1);
                    if !self.multiline {
                        out.extend_from_slice(b" }");
                    }
                } else if self.multiline {
                    out.push(b'\n');
                }
            }
            Value::Array(arr) => {
                out.push(b'[');
                for (pos, value) in arr.iter().enumerate() {
                    if pos > 0 {
                        out.extend_from_slice(b", ");
                    }
                    self.write_value(out, value, indent);
                }
                out.push(b']');
            }
            Value::None => out.extend_from_slice(b"(null)"),
        }
    }
}

impl Color {
    pub fn as_code(&self) -> &'static str {
        match self {
            Color::Black => "\x1b[30m",
            Color::Red => "\x1b[31m",
            Color::Green => "\x1b[32m",
            Color::Yellow => "\x1b[33m",
            Color::Blue => "\x1b[34m",
            Color::Magenta => "\x1b[35m",
            Color::Cyan => "\x1b[36m",
            Color::White => "\x1b[37m",
        }
    }

    pub fn as_code_bold(&self) -> &'static str {
        match self {
            Color::Black => "\x1b[30;1m",
            Color::Red => "\x1b[31;1m",
            Color::Green => "\x1b[32;1m",
            Color::Yellow => "\x1b[33;1m",
            Color::Blue => "\x1b[34;1m",
            Color::Magenta => "\x1b[35;1m",
            Color::Cyan => "\x1b[36;1m",
            Color::White => "\x1b[37;1m",
        }
    }

    pub fn reset() -> &'static str {
        "\x1b[0m"
    }
}

impl Value {
    pub fn write_display(&self, out: &mut Vec<u8>) {
        match self {
            Value::String(value) => out.extend_from_slice(value.as_bytes()),
            Value::UInt(value) | Value::Timestamp(value) | Value::Duration(value) => {
                write_uint(out, *value)
            }
            Value::Int(value) => write_int(out, *value),
            Value::Float(value) => {
                let _ = write!(out, "{value}");
            }
            Value::Bytes(value) => write_base64(out, value),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Ipv4(value) => {
                let _ = write!(out, "{value}");
            }
            Value::Ipv6(value) => {
                let _ = write!(out, "{value}");
            }
            Value::Event(value) => {
                out.push(b'{');
                value.write_display(out);
                out.push(b'}');
            }
            Value::Array(values) => {
                out.push(b'[');
                for (pos, value) in values.iter().enumerate() {
                    if pos > 0 {
                        out.extend_from_slice(b", ");
                    }
                    value.write_display(out);
                }
                out.push(b']');
            }
            Value::None => out.extend_from_slice(b"(null)"),
        }
    }
}

impl Error {
    pub fn write_display(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.inner.description().as_bytes());
        out.extend_from_slice(b" (");
        out.extend_from_slice(self.0.inner.as_str().as_bytes());
        out.push(b')');

        if !self.0.keys.is_empty() {
            out.extend_from_slice(b": ");
            for (pos, (key, value)) in self.0.keys.iter().enumerate() {
                if pos > 0 {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(key.as_str().as_bytes());
                out.extend_from_slice(b" = ");
                value.write_display(out);
            }
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::String(value) => value.fmt(f),
            Value::UInt(value) => value.fmt(f),
            Value::Int(value) => value.fmt(f),
            Value::Float(value) => value.fmt(f),
            Value::Timestamp(value) => value.fmt(f),
            Value::Duration(value) => value.fmt(f),
            Value::Bytes(value) => STANDARD.encode(value).fmt(f),
            Value::Bool(value) => value.fmt(f),
            Value::Ipv4(value) => value.fmt(f),
            Value::Ipv6(value) => value.fmt(f),
            Value::Event(value) => {
                "{".fmt(f)?;
                value.fmt(f)?;
                "}".fmt(f)
            }
            Value::Array(value) => {
                f.write_str("[")?;
                for (i, value) in value.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    value.fmt(f)?;
                }
                f.write_str("]")
            }
            Value::None => "(null)".fmt(f),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.inner.description().fmt(f)?;
        " (".fmt(f)?;
        self.0.inner.as_str().fmt(f)?;
        ")".fmt(f)?;

        if !self.0.keys.is_empty() {
            f.write_str(": ")?;
            for (i, (key, value)) in self.0.keys.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                key.as_str().fmt(f)?;
                f.write_str(" = ")?;
                value.fmt(f)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FmtWriter;
    use crate::{Error, Event, EventDetails, EventType, Key, Level, SmtpEvent, StoreEvent, Value};
    use std::sync::Arc;

    fn event(
        level: Level,
        keys: Vec<(Key, Value)>,
        span: Option<Vec<(Key, Value)>>,
    ) -> Event<EventDetails> {
        Event {
            inner: EventDetails {
                typ: EventType::Smtp(SmtpEvent::MailFrom),
                timestamp: 1_700_000_000,
                level,
                span: span.map(|keys| {
                    Arc::new(Event {
                        inner: EventDetails {
                            typ: EventType::Smtp(SmtpEvent::ConnectionStart),
                            timestamp: 1_700_000_000,
                            level: Level::Info,
                            span: None,
                        },
                        keys,
                    })
                }),
            },
            keys,
        }
    }

    fn render(writer: &mut FmtWriter, event: &Event<EventDetails>) -> String {
        let mut out = Vec::new();
        writer.write(event, &mut out);
        String::from_utf8(out).unwrap_or_default()
    }

    #[test]
    fn text_format() {
        let mut writer = FmtWriter::new();
        let typ = EventType::Smtp(SmtpEvent::MailFrom);
        let prefix = format!(
            "2023-11-14T22:13:20Z INFO {} ({}) ",
            typ.description(),
            typ.as_str()
        );

        assert_eq!(
            render(
                &mut writer,
                &event(
                    Level::Info,
                    vec![
                        (Key::SpanId, Value::UInt(7)),
                        (Key::From, Value::from("a\", spanId = 999, x = \"b\r\n\x1b")),
                        (Key::Size, Value::UInt(1024)),
                        (Key::Elapsed, Value::Duration(15)),
                        (Key::Contents, Value::Bytes(b"hi!".to_vec())),
                        (Key::Code, Value::Int(-3)),
                        (
                            Key::Total,
                            Value::Array(vec![Value::Bool(true), Value::None])
                        ),
                        (Key::RemoteIp, Value::Ipv4([10, 0, 0, 1].into())),
                        (
                            Key::CausedBy,
                            Value::Event(
                                Error::new(EventType::Store(StoreEvent::DataCorruption))
                                    .ctx(Key::Reason, "bad"),
                            ),
                        ),
                    ],
                    Some(vec![
                        (Key::SpanId, Value::UInt(7)),
                        (Key::Hostname, Value::from("mx.example.org")),
                        (Key::From, Value::from("span-value")),
                    ]),
                ),
            ),
            format!(
                concat!(
                    "{}hostname = \"mx.example.org\", ",
                    "from = \"a\\\", spanId = 999, x = \\\"b\\r\\n\\x1b\", ",
                    "size = 1024, elapsed = 15ms, contents = base64:aGkh, code = -3, ",
                    "total = [true, (null)], remoteIp = 10.0.0.1, ",
                    "causedBy = {} ({}) {{ reason = \"bad\" }}\n"
                ),
                prefix,
                EventType::Store(StoreEvent::DataCorruption).description(),
                EventType::Store(StoreEvent::DataCorruption).as_str()
            )
        );

        assert_eq!(
            render(
                &mut writer,
                &event(Level::Disable, vec![(Key::Size, Value::UInt(1))], None)
            ),
            ""
        );
    }

    #[test]
    fn display_writer_matches_display() {
        for value in [
            Value::from("plain \"text\"\n"),
            Value::UInt(u64::MAX),
            Value::Int(i64::MIN),
            Value::Float(1.25),
            Value::Timestamp(1_700_000_000),
            Value::Duration(42),
            Value::Bytes(vec![0, 1, 2, 250]),
            Value::Bool(false),
            Value::Ipv4([192, 168, 0, 1].into()),
            Value::Ipv6(
                "2001:db8::1"
                    .parse()
                    .unwrap_or(std::net::Ipv6Addr::LOCALHOST),
            ),
            Value::Array(vec![Value::UInt(1), Value::from("x"), Value::None]),
            Value::Event(
                Error::new(EventType::Store(StoreEvent::DataCorruption))
                    .ctx(Key::Reason, "bad")
                    .ctx(Key::Size, 3u64),
            ),
            Value::None,
        ] {
            let mut out = Vec::new();
            value.write_display(&mut out);
            assert_eq!(
                String::from_utf8(out).unwrap_or_default(),
                value.to_string()
            );
        }
    }
}
