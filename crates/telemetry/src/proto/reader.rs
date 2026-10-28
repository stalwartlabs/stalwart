/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{WIRE_I32, WIRE_I64, WIRE_LEN, WIRE_VARINT};
use std::time::Duration;

const MAX_VARINT_LEN: usize = 10;
const MAX_LAST_VARINT_BYTE: u8 = 1;
const RETRY_INFO_TYPE_URL: &[u8] = b"type.googleapis.com/google.rpc.RetryInfo";
const MAX_RETRY_DELAY_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FieldValue<'x> {
    Varint(u64),
    I64(u64),
    Len(&'x [u8]),
    I32(u32),
}

pub struct ProtoReader<'x> {
    data: &'x [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PartialSuccess<'x> {
    pub rejected: i64,
    pub message: &'x [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RpcStatus<'x> {
    pub code: i32,
    pub message: &'x [u8],
    pub retry_delay: Option<Duration>,
}

impl<'x> ProtoReader<'x> {
    pub fn new(data: &'x [u8]) -> Self {
        Self { data }
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for (pos, byte) in self.data.iter().take(MAX_VARINT_LEN).enumerate() {
            if pos == MAX_VARINT_LEN - 1 && *byte > MAX_LAST_VARINT_BYTE {
                return Err(DecodeError);
            }
            value |= ((byte & 0x7f) as u64) << (pos * 7);
            if byte & 0x80 == 0 {
                self.data = self.data.get(pos + 1..).unwrap_or_default();
                return Ok(value);
            }
        }
        Err(DecodeError)
    }

    fn take(&mut self, len: usize) -> Result<&'x [u8], DecodeError> {
        let (head, tail) = self.data.split_at_checked(len).ok_or(DecodeError)?;
        self.data = tail;
        Ok(head)
    }

    pub fn next_field(&mut self) -> Option<Result<(u64, FieldValue<'x>), DecodeError>> {
        if self.data.is_empty() {
            return None;
        }
        Some(self.read_field())
    }

    fn read_field(&mut self) -> Result<(u64, FieldValue<'x>), DecodeError> {
        let key = self.varint()?;
        let field = key >> 3;
        if field == 0 {
            return Err(DecodeError);
        }
        let value = match (key & 0x07) as u8 {
            WIRE_VARINT => FieldValue::Varint(self.varint()?),
            WIRE_I64 => self
                .take(8)?
                .first_chunk::<8>()
                .map(|bytes| FieldValue::I64(u64::from_le_bytes(*bytes)))
                .ok_or(DecodeError)?,
            WIRE_LEN => {
                let len = usize::try_from(self.varint()?).map_err(|_| DecodeError)?;
                FieldValue::Len(self.take(len)?)
            }
            WIRE_I32 => self
                .take(4)?
                .first_chunk::<4>()
                .map(|bytes| FieldValue::I32(u32::from_le_bytes(*bytes)))
                .ok_or(DecodeError)?,
            _ => return Err(DecodeError),
        };
        Ok((field, value))
    }
}

impl<'x> PartialSuccess<'x> {
    pub fn parse(response: &'x [u8]) -> Result<Option<Self>, DecodeError> {
        let mut result = None;
        let mut reader = ProtoReader::new(response);
        while let Some(field) = reader.next_field() {
            if let (1, FieldValue::Len(bytes)) = field? {
                let partial = result.get_or_insert_with(PartialSuccess::default);
                let mut reader = ProtoReader::new(bytes);
                while let Some(field) = reader.next_field() {
                    match field? {
                        (1, FieldValue::Varint(value)) => partial.rejected = value as i64,
                        (2, FieldValue::Len(value)) => partial.message = value,
                        _ => {}
                    }
                }
            }
        }
        Ok(result)
    }
}

impl<'x> RpcStatus<'x> {
    pub fn parse(status: &'x [u8]) -> Result<Self, DecodeError> {
        let mut result = RpcStatus::default();
        let mut reader = ProtoReader::new(status);
        while let Some(field) = reader.next_field() {
            match field? {
                (1, FieldValue::Varint(value)) => result.code = value as i32,
                (2, FieldValue::Len(value)) => result.message = value,
                (3, FieldValue::Len(any)) => {
                    if let Some(delay) = parse_retry_info_any(any)? {
                        result.retry_delay = Some(delay);
                    }
                }
                _ => {}
            }
        }
        Ok(result)
    }
}

fn parse_retry_info_any(any: &[u8]) -> Result<Option<Duration>, DecodeError> {
    let mut type_url = &[][..];
    let mut value = &[][..];
    let mut reader = ProtoReader::new(any);
    while let Some(field) = reader.next_field() {
        match field? {
            (1, FieldValue::Len(bytes)) => type_url = bytes,
            (2, FieldValue::Len(bytes)) => value = bytes,
            _ => {}
        }
    }
    if type_url != RETRY_INFO_TYPE_URL {
        return Ok(None);
    }

    let mut delay = None;
    let mut reader = ProtoReader::new(value);
    while let Some(field) = reader.next_field() {
        if let (1, FieldValue::Len(duration)) = field? {
            delay = Some(parse_duration(duration)?);
        }
    }
    Ok(delay)
}

fn parse_duration(duration: &[u8]) -> Result<Duration, DecodeError> {
    let mut seconds = 0i64;
    let mut nanos = 0i32;
    let mut reader = ProtoReader::new(duration);
    while let Some(field) = reader.next_field() {
        match field? {
            (1, FieldValue::Varint(value)) => seconds = value as i64,
            (2, FieldValue::Varint(value)) => nanos = value as i32,
            _ => {}
        }
    }
    let seconds = u64::try_from(seconds)
        .unwrap_or(0)
        .min(MAX_RETRY_DELAY_SECS);
    let nanos = u32::try_from(nanos).unwrap_or(0).min(999_999_999);
    Ok(Duration::new(seconds, nanos))
}
