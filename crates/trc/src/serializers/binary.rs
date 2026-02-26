/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::*;
use compact_str::format_compact;
use std::net::{Ipv4Addr, Ipv6Addr};

const VERSION: u8 = 1;

pub fn serialize_events<'x>(
    events: impl IntoIterator<Item = &'x Event<EventDetails>>,
    num_events: usize,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(num_events * 64);
    buf.push(VERSION);
    leb128_write(&mut buf, num_events as u64);
    for event in events {
        event.serialize(&mut buf);
    }
    buf
}

pub fn deserialize_events(bytes: &[u8]) -> crate::Result<Vec<Event<EventDetails>>> {
    let mut iter = bytes.iter();
    if *iter.next().ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while reading version")
    })? != VERSION
    {
        crate::bail!(
            StoreEvent::DataCorruption
                .caused_by(crate::location!())
                .details("Invalid version")
        );
    }
    let len = leb128_read(&mut iter).ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while size")
    })? as usize;
    let mut events = Vec::with_capacity(len);
    for n in 0..len {
        events.push(Event::deserialize(&mut iter).ok_or_else(|| {
            StoreEvent::DataCorruption
                .caused_by(crate::location!())
                .details(format_compact!("Failed to deserialize event {n}"))
        })?);
    }
    Ok(events)
}

pub fn deserialize_single_event(bytes: &[u8]) -> crate::Result<Event<EventDetails>> {
    let mut iter = bytes.iter();
    if *iter.next().ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while reading version")
    })? != VERSION
    {
        crate::bail!(
            StoreEvent::DataCorruption
                .caused_by(crate::location!())
                .details("Invalid version")
        );
    }
    let _ = leb128_read(&mut iter).ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while size")
    })?;
    Event::deserialize(&mut iter).ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("Failed to deserialize event")
    })
}

impl Event<EventDetails> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        leb128_write(buf, self.inner.typ.to_id() as u64);
        buf.extend_from_slice(self.inner.timestamp.to_le_bytes().as_ref());
        leb128_write(buf, self.keys.len() as u64);
        for (k, v) in &self.keys {
            leb128_write(buf, k.code());
            v.serialize(buf);
        }
    }
    pub fn deserialize<'x>(iter: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let typ = EventType::from_id(leb128_read(iter)? as u16)?;
        let timestamp = u64::from_le_bytes([
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
        ]);
        let keys_len = leb128_read(iter)?;
        let mut keys = Vec::with_capacity(keys_len as usize);
        for _ in 0..keys_len {
            let key = Key::from_code(leb128_read(iter)?)?;
            let value = Value::deserialize(iter)?;
            keys.push((key, value));
        }
        Some(Event {
            inner: EventDetails {
                typ,
                timestamp,
                level: Level::Info,
                span: None,
            },
            keys,
        })
    }
}

impl Value {
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Value::String(v) => {
                buf.push(0u8);
                leb128_write(buf, v.len() as u64);
                buf.extend(v.as_bytes());
            }
            Value::UInt(v) => {
                buf.push(1u8);
                leb128_write(buf, *v);
            }
            Value::Int(v) => {
                buf.push(2u8);
                buf.extend(&v.to_le_bytes());
            }
            Value::Float(v) => {
                buf.push(3u8);
                buf.extend(&v.to_le_bytes());
            }
            Value::Timestamp(v) => {
                buf.push(4u8);
                buf.extend(&v.to_le_bytes());
            }
            Value::Duration(v) => {
                buf.push(5u8);
                leb128_write(buf, *v);
            }
            Value::Bytes(v) => {
                buf.push(6u8);
                leb128_write(buf, v.len() as u64);
                buf.extend(v);
            }
            Value::Bool(true) => {
                buf.push(7u8);
            }
            Value::Bool(false) => {
                buf.push(8u8);
            }
            Value::Ipv4(v) => {
                buf.push(9u8);
                buf.extend(&v.octets());
            }
            Value::Ipv6(v) => {
                buf.push(10u8);
                buf.extend(&v.octets());
            }
            Value::Event(v) => {
                buf.push(11u8);
                leb128_write(buf, v.0.inner.to_id() as u64);
                leb128_write(buf, v.0.keys.len() as u64);
                for (k, v) in &v.0.keys {
                    leb128_write(buf, k.code());
                    v.serialize(buf);
                }
            }
            Value::Array(v) => {
                buf.push(12u8);
                leb128_write(buf, v.len() as u64);
                for value in v {
                    value.serialize(buf);
                }
            }
            Value::None => {
                buf.push(13u8);
            }
        }
    }

    fn deserialize<'x>(iter: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        match iter.next()? {
            0 => {
                let mut buf = vec![0u8; leb128_read(iter)? as usize];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::String(CompactString::from_utf8(buf).ok()?))
            }
            1 => Some(Value::UInt(leb128_read(iter)?)),
            2 => {
                let mut buf = [0u8; std::mem::size_of::<i64>()];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Int(i64::from_le_bytes(buf)))
            }
            3 => {
                let mut buf = [0u8; std::mem::size_of::<f64>()];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Float(f64::from_le_bytes(buf)))
            }
            4 => {
                let mut buf = [0u8; std::mem::size_of::<u64>()];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Timestamp(u64::from_le_bytes(buf)))
            }
            5 => Some(Value::Duration(leb128_read(iter)?)),
            6 => {
                let mut buf = vec![0u8; leb128_read(iter)? as usize];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Bytes(buf))
            }
            7 => Some(Value::Bool(true)),
            8 => Some(Value::Bool(false)),
            9 => {
                let mut buf = [0u8; 4];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Ipv4(Ipv4Addr::from(buf)))
            }
            10 => {
                let mut buf = [0u8; 16];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Ipv6(Ipv6Addr::from(buf)))
            }
            11 => {
                let code = EventType::from_id(leb128_read(iter)? as u16)?;
                let keys_len = leb128_read(iter)?;
                let mut keys = Vec::with_capacity(keys_len as usize);
                for _ in 0..keys_len {
                    let key = Key::from_code(leb128_read(iter)?)?;
                    let value = Value::deserialize(iter)?;
                    keys.push((key, value));
                }
                Some(Value::Event(Error(
                    Event::with_keys(code, keys).into_boxed(),
                )))
            }
            12 => {
                let len = leb128_read(iter)?;
                let mut values = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    values.push(Value::deserialize(iter)?);
                }
                Some(Value::Array(values))
            }
            13 => Some(Value::None),
            _ => None,
        }
    }
}

fn leb128_write(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            buf.push(value as u8);
            break;
        } else {
            buf.push(((value & 0x7f) | 0x80) as u8);
            value >>= 7;
        }
    }
}

fn leb128_read<'x>(iter: &mut impl Iterator<Item = &'x u8>) -> Option<u64> {
    let mut result = 0;

    for shift in [0, 7, 14, 21, 28, 35, 42, 49, 56, 63] {
        let byte = iter.next()?;

        if (byte & 0x80) == 0 {
            result |= (*byte as u64) << shift;
            return Some(result);
        } else {
            result |= ((byte & 0x7F) as u64) << shift;
        }
    }

    None
}
