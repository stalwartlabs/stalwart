/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;

use crate::{
    common::{guid::Guid, time::FileTime, utf16::Utf16Le},
    convert::ConvertError,
    mapi::{
        ec::ErrorCode,
        prop::{OwnedPropValue, PropId, PropKey, PropType},
    },
};

const NAMED_KIND_ID: u32 = 0;
const NAMED_KIND_STRING: u32 = 1;
const ALIGN: usize = 4;
const MIN_VALUE_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TnefProps<'a> {
    attr: u32,
    cursor: Cursor<'a>,
    remaining: u32,
}

#[derive(Debug, Clone)]
pub struct TnefProp<'a> {
    pub key: PropKey,
    pub value: TnefValue<'a>,
}

#[derive(Debug, Clone)]
pub enum TnefValue<'a> {
    Value(OwnedPropValue),
    Object { iid: Guid, data: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TnefRecipients<'a> {
    cursor: Cursor<'a>,
    remaining: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    base: u32,
}

impl<'a> TnefProps<'a> {
    pub(super) fn new(data: &'a [u8], base: u32, attr: u32) -> Result<Self, ConvertError> {
        let mut cursor = Cursor { data, pos: 0, base };
        let remaining = cursor.u32()?;
        Ok(TnefProps {
            attr,
            cursor,
            remaining,
        })
    }

    pub fn attr(&self) -> u32 {
        self.attr
    }

    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<TnefProp<'a>>, ConvertError> {
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return Ok(None);
        };
        self.remaining = remaining;
        self.cursor.prop().map(Some)
    }
}

impl<'a> TnefRecipients<'a> {
    pub fn new(data: &'a [u8], base: u32) -> Result<Self, ConvertError> {
        let mut cursor = Cursor { data, pos: 0, base };
        let remaining = cursor.u32()?;
        Ok(TnefRecipients { cursor, remaining })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Vec<TnefProp<'a>>>, ConvertError> {
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return Ok(None);
        };
        self.remaining = remaining;
        let count = self.cursor.u32()?;
        let mut row = Vec::with_capacity(self.cursor.capacity_for(count));
        for _ in 0..count {
            row.push(self.cursor.prop()?);
        }
        Ok(Some(row))
    }
}

impl<'a> Cursor<'a> {
    fn error(&self) -> ConvertError {
        ConvertError::Tnef {
            offset: self
                .base
                .saturating_add(u32::try_from(self.pos).unwrap_or(u32::MAX)),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ConvertError> {
        let end = self.pos.checked_add(len).ok_or_else(|| self.error())?;
        let bytes = self.data.get(self.pos..end).ok_or_else(|| self.error())?;
        self.pos = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ConvertError> {
        let bytes = self.take(N)?;
        bytes
            .first_chunk::<N>()
            .copied()
            .ok_or_else(|| self.error())
    }

    fn u32(&mut self) -> Result<u32, ConvertError> {
        self.array().map(u32::from_le_bytes)
    }

    fn pad(&mut self, len: usize) {
        let pad = len.wrapping_neg() % ALIGN;
        self.pos = self.pos.saturating_add(pad).min(self.data.len());
    }

    fn capacity_for(&self, count: u32) -> usize {
        let left = self.data.len().saturating_sub(self.pos) / MIN_VALUE_LEN;
        usize::try_from(count).unwrap_or(usize::MAX).min(left)
    }

    fn sized(&mut self) -> Result<&'a [u8], ConvertError> {
        let len = usize::try_from(self.u32()?).map_err(|_| self.error())?;
        let bytes = self.take(len)?;
        self.pad(len);
        Ok(bytes)
    }

    fn scalar<const N: usize>(&mut self) -> Result<[u8; N], ConvertError> {
        let value = self.array::<N>()?;
        self.pad(N);
        Ok(value)
    }

    fn mv<T, const N: usize>(&mut self, f: fn([u8; N]) -> T) -> Result<Box<[T]>, ConvertError> {
        let count = self.u32()?;
        let mut values = Vec::with_capacity(self.capacity_for(count));
        for _ in 0..count {
            values.push(f(self.scalar::<N>()?));
        }
        Ok(values.into_boxed_slice())
    }

    fn mv_sized<T>(&mut self, f: fn(&[u8]) -> T) -> Result<Box<[T]>, ConvertError> {
        let count = self.u32()?;
        let mut values = Vec::with_capacity(self.capacity_for(count));
        for _ in 0..count {
            values.push(f(self.sized()?));
        }
        Ok(values.into_boxed_slice())
    }

    fn single_sized(&mut self) -> Result<&'a [u8], ConvertError> {
        if self.u32()? != 1 {
            return Err(self.error());
        }
        self.sized()
    }

    fn key(&mut self, id: u16) -> Result<PropKey, ConvertError> {
        if !PropId(id).is_named() {
            return Ok(PropKey::tag(PropId(id)));
        }
        let set = Guid::from_wire(self.array::<16>()?);
        match self.u32()? {
            NAMED_KIND_ID => Ok(PropKey::lid(set, self.u32()?)),
            NAMED_KIND_STRING => {
                let name = self.sized()?;
                Ok(PropKey::name(set, &utf16_string(name)))
            }
            _ => Err(self.error()),
        }
    }

    fn prop(&mut self) -> Result<TnefProp<'a>, ConvertError> {
        let start = self.error();
        let [t0, t1, i0, i1] = self.array::<4>()?;
        let ptype = PropType::from_code(u16::from_le_bytes([t0, t1]));
        let key = self.key(u16::from_le_bytes([i0, i1]))?;
        let value = match ptype {
            PropType::I16 => OwnedPropValue::I16(i16::from_le_bytes(self.scalar()?)),
            PropType::I32 => OwnedPropValue::I32(i32::from_le_bytes(self.scalar()?)),
            PropType::F32 => OwnedPropValue::F32(f32::from_le_bytes(self.scalar()?)),
            PropType::F64 => OwnedPropValue::F64(f64::from_le_bytes(self.scalar()?)),
            PropType::Currency => OwnedPropValue::Currency(i64::from_le_bytes(self.scalar()?)),
            PropType::AppTime => OwnedPropValue::AppTime(f64::from_le_bytes(self.scalar()?)),
            PropType::Error => OwnedPropValue::Error(ErrorCode(u32::from_le_bytes(self.scalar()?))),
            PropType::Bool => OwnedPropValue::Bool(u16::from_le_bytes(self.scalar()?) != 0),
            PropType::I64 => OwnedPropValue::I64(i64::from_le_bytes(self.scalar()?)),
            PropType::Time => OwnedPropValue::Time(FileTime(u64::from_le_bytes(self.scalar()?))),
            PropType::Guid => OwnedPropValue::Guid(Guid::from_wire(self.scalar()?)),
            PropType::String8 => OwnedPropValue::String8(trim_nul(self.single_sized()?).into()),
            PropType::Unicode => {
                OwnedPropValue::Unicode(utf16_string(self.single_sized()?).into_boxed_str())
            }
            PropType::Binary => {
                OwnedPropValue::Binary(Bytes::copy_from_slice(self.single_sized()?))
            }
            PropType::Object => {
                let (iid, data) = self
                    .single_sized()?
                    .split_first_chunk::<16>()
                    .ok_or(start)?;
                return Ok(TnefProp {
                    key,
                    value: TnefValue::Object {
                        iid: Guid::from_wire(*iid),
                        data,
                    },
                });
            }
            PropType::MvI16 => OwnedPropValue::MvI16(self.mv(i16::from_le_bytes)?),
            PropType::MvI32 => OwnedPropValue::MvI32(self.mv(i32::from_le_bytes)?),
            PropType::MvF32 => OwnedPropValue::MvF32(self.mv(f32::from_le_bytes)?),
            PropType::MvF64 => OwnedPropValue::MvF64(self.mv(f64::from_le_bytes)?),
            PropType::MvCurrency => OwnedPropValue::MvCurrency(self.mv(i64::from_le_bytes)?),
            PropType::MvAppTime => OwnedPropValue::MvAppTime(self.mv(f64::from_le_bytes)?),
            PropType::MvI64 => OwnedPropValue::MvI64(self.mv(i64::from_le_bytes)?),
            PropType::MvTime => {
                OwnedPropValue::MvTime(self.mv(|b: [u8; 8]| FileTime(u64::from_le_bytes(b)))?)
            }
            PropType::MvGuid => OwnedPropValue::MvGuid(self.mv(Guid::from_wire)?),
            PropType::MvString8 => {
                OwnedPropValue::MvString8(self.mv_sized(|b| trim_nul(b).into())?)
            }
            PropType::MvUnicode => {
                OwnedPropValue::MvUnicode(self.mv_sized(|b| utf16_string(b).into_boxed_str())?)
            }
            PropType::MvBinary => OwnedPropValue::MvBinary(self.mv_sized(Bytes::copy_from_slice)?),
            _ => return Err(start),
        };
        Ok(TnefProp {
            key,
            value: TnefValue::Value(value),
        })
    }
}

pub(super) fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| *b != 0)
        .map_or(0, |pos| pos.saturating_add(1));
    bytes.get(..end).unwrap_or_default()
}

fn utf16_string(bytes: &[u8]) -> String {
    let (units, _) = bytes.as_chunks::<2>();
    let len = units
        .iter()
        .rposition(|unit| *unit != [0, 0])
        .map_or(0, |pos| pos.saturating_add(1));
    let mut text = String::new();
    if let Some(units) = units
        .get(..len)
        .and_then(|units| Utf16Le::new(units.as_flattened()))
    {
        units.to_string_lossy(&mut text);
    }
    text
}
