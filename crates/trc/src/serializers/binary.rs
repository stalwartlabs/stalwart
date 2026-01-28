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

impl Key {
    fn code(&self) -> u64 {
        match self {
            Key::AccountName => 0,
            Key::AccountId => 1,
            Key::BlobId => 2,
            Key::CausedBy => 3,
            Key::ChangeId => 4,
            Key::Code => 5,
            Key::Collection => 6,
            Key::Contents => 7,
            Key::Details => 8,
            Key::DkimFail => 9,
            Key::DkimNone => 10,
            Key::DkimPass => 11,
            Key::DmarcNone => 12,
            Key::DmarcPass => 13,
            Key::DmarcQuarantine => 14,
            Key::DmarcReject => 15,
            Key::DocumentId => 16,
            Key::Domain => 17,
            Key::Due => 18,
            Key::Elapsed => 19,
            Key::Expires => 20,
            Key::From => 21,
            Key::Hostname => 22,
            Key::Id => 23,
            Key::Key => 24,
            Key::Limit => 25,
            Key::ListenerId => 26,
            Key::LocalIp => 27,
            Key::LocalPort => 28,
            Key::MailboxName => 29,
            Key::MailboxId => 30,
            Key::MessageId => 31,
            Key::NextDsn => 32,
            Key::NextRetry => 33,
            Key::Path => 34,
            Key::Policy => 35,
            Key::QueueId => 36,
            Key::RangeFrom => 37,
            Key::RangeTo => 38,
            Key::Reason => 39,
            Key::RemoteIp => 40,
            Key::RemotePort => 41,
            Key::ReportId => 42,
            Key::Result => 43,
            Key::Size => 44,
            Key::Source => 45,
            Key::SpanId => 46,
            Key::SpfFail => 47,
            Key::SpfNone => 48,
            Key::SpfPass => 49,
            Key::Strict => 50,
            Key::Tls => 51,
            Key::To => 52,
            Key::Total => 53,
            Key::TotalFailures => 54,
            Key::TotalSuccesses => 55,
            Key::Type => 56,
            Key::Uid => 57,
            Key::UidNext => 58,
            Key::UidValidity => 59,
            Key::Url => 60,
            Key::ValidFrom => 61,
            Key::ValidTo => 62,
            Key::Value => 63,
            Key::Version => 64,
            Key::QueueName => 65,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Key::AccountName),
            1 => Some(Key::AccountId),
            2 => Some(Key::BlobId),
            3 => Some(Key::CausedBy),
            4 => Some(Key::ChangeId),
            5 => Some(Key::Code),
            6 => Some(Key::Collection),
            7 => Some(Key::Contents),
            8 => Some(Key::Details),
            9 => Some(Key::DkimFail),
            10 => Some(Key::DkimNone),
            11 => Some(Key::DkimPass),
            12 => Some(Key::DmarcNone),
            13 => Some(Key::DmarcPass),
            14 => Some(Key::DmarcQuarantine),
            15 => Some(Key::DmarcReject),
            16 => Some(Key::DocumentId),
            17 => Some(Key::Domain),
            18 => Some(Key::Due),
            19 => Some(Key::Elapsed),
            20 => Some(Key::Expires),
            21 => Some(Key::From),
            22 => Some(Key::Hostname),
            23 => Some(Key::Id),
            24 => Some(Key::Key),
            25 => Some(Key::Limit),
            26 => Some(Key::ListenerId),
            27 => Some(Key::LocalIp),
            28 => Some(Key::LocalPort),
            29 => Some(Key::MailboxName),
            30 => Some(Key::MailboxId),
            31 => Some(Key::MessageId),
            32 => Some(Key::NextDsn),
            33 => Some(Key::NextRetry),
            34 => Some(Key::Path),
            35 => Some(Key::Policy),
            36 => Some(Key::QueueId),
            37 => Some(Key::RangeFrom),
            38 => Some(Key::RangeTo),
            39 => Some(Key::Reason),
            40 => Some(Key::RemoteIp),
            41 => Some(Key::RemotePort),
            42 => Some(Key::ReportId),
            43 => Some(Key::Result),
            44 => Some(Key::Size),
            45 => Some(Key::Source),
            46 => Some(Key::SpanId),
            47 => Some(Key::SpfFail),
            48 => Some(Key::SpfNone),
            49 => Some(Key::SpfPass),
            50 => Some(Key::Strict),
            51 => Some(Key::Tls),
            52 => Some(Key::To),
            53 => Some(Key::Total),
            54 => Some(Key::TotalFailures),
            55 => Some(Key::TotalSuccesses),
            56 => Some(Key::Type),
            57 => Some(Key::Uid),
            58 => Some(Key::UidNext),
            59 => Some(Key::UidValidity),
            60 => Some(Key::Url),
            61 => Some(Key::ValidFrom),
            62 => Some(Key::ValidTo),
            63 => Some(Key::Value),
            64 => Some(Key::Version),
            65 => Some(Key::QueueName),
            _ => None,
        }
    }
}
