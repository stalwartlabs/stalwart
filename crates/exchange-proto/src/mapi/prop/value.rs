/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;

use super::{owned::OwnedPropValue, tag::PropType};
use crate::{
    common::{FileTime, Guid, LeReader, Utf16Le},
    mapi::ec::ErrorCode,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PropValue<'a> {
    Null,
    I16(i16),
    I32(i32),
    F32(f32),
    F64(f64),
    Currency(i64),
    AppTime(f64),
    Error(ErrorCode),
    Bool(bool),
    I64(i64),
    Time(FileTime),
    Guid(&'a [u8; 16]),
    String8(&'a [u8]),
    Unicode(Utf16Le<'a>),
    Binary(&'a [u8]),
    ServerId(&'a [u8]),
    Restriction(&'a [u8]),
    RuleAction(&'a [u8]),
    Mv(MvView<'a>),
    Object,
}

const _: () = assert!(size_of::<PropValue<'_>>() <= 24);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountWidth {
    Rop,
    Wide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MvType {
    I16 = 0x1002,
    I32 = 0x1003,
    F32 = 0x1004,
    F64 = 0x1005,
    Currency = 0x1006,
    AppTime = 0x1007,
    I64 = 0x1014,
    String8 = 0x101E,
    Unicode = 0x101F,
    Time = 0x1040,
    Guid = 0x1048,
    Binary = 0x1102,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MvDialect {
    Rop,
    Wide,
    AddressBook,
    FastTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MvError {
    Truncated,
    TooMany,
    BadHasValue,
    Utf16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MvView<'a> {
    bytes: &'a [u8],
    count: u32,
    mv_type: MvType,
    dialect: MvDialect,
}

const _: () = assert!(size_of::<MvView<'_>>() <= 24);

#[derive(Debug, Clone)]
pub struct MvIter<'a> {
    reader: LeReader<'a>,
    remaining: u32,
    mv_type: MvType,
    dialect: MvDialect,
}

impl MvType {
    pub const fn prop_type(self) -> PropType {
        match self {
            MvType::I16 => PropType::MvI16,
            MvType::I32 => PropType::MvI32,
            MvType::F32 => PropType::MvF32,
            MvType::F64 => PropType::MvF64,
            MvType::Currency => PropType::MvCurrency,
            MvType::AppTime => PropType::MvAppTime,
            MvType::I64 => PropType::MvI64,
            MvType::String8 => PropType::MvString8,
            MvType::Unicode => PropType::MvUnicode,
            MvType::Time => PropType::MvTime,
            MvType::Guid => PropType::MvGuid,
            MvType::Binary => PropType::MvBinary,
        }
    }

    pub const fn element_type(self) -> PropType {
        match self {
            MvType::I16 => PropType::I16,
            MvType::I32 => PropType::I32,
            MvType::F32 => PropType::F32,
            MvType::F64 => PropType::F64,
            MvType::Currency => PropType::Currency,
            MvType::AppTime => PropType::AppTime,
            MvType::I64 => PropType::I64,
            MvType::String8 => PropType::String8,
            MvType::Unicode => PropType::Unicode,
            MvType::Time => PropType::Time,
            MvType::Guid => PropType::Guid,
            MvType::Binary => PropType::Binary,
        }
    }

    const fn element_size(self) -> Option<usize> {
        match self {
            MvType::I16 => Some(2),
            MvType::I32 | MvType::F32 => Some(4),
            MvType::F64 | MvType::Currency | MvType::AppTime | MvType::I64 | MvType::Time => {
                Some(8)
            }
            MvType::Guid => Some(16),
            MvType::String8 | MvType::Unicode | MvType::Binary => None,
        }
    }
}

impl<'a> MvView<'a> {
    pub fn parse(
        input: &'a [u8],
        mv_type: MvType,
        dialect: MvDialect,
        max_count: u32,
    ) -> Result<(Self, &'a [u8]), MvError> {
        let mut reader = LeReader::new(input);
        let count = reader.u32().map_err(|_| MvError::Truncated)?;
        if count > max_count {
            return Err(MvError::TooMany);
        }
        let body = reader.rest();
        let len = match mv_type.element_size() {
            Some(size) => usize::try_from(count)
                .ok()
                .and_then(|count| count.checked_mul(size))
                .ok_or(MvError::Truncated)?,
            None => {
                let mut elements = LeReader::new(body);
                for _ in 0..count {
                    read_element(&mut elements, mv_type, dialect)?;
                }
                elements.offset()
            }
        };
        let (bytes, rest) = body.split_at_checked(len).ok_or(MvError::Truncated)?;
        Ok((
            MvView {
                bytes,
                count,
                mv_type,
                dialect,
            },
            rest,
        ))
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn mv_type(&self) -> MvType {
        self.mv_type
    }

    pub fn dialect(&self) -> MvDialect {
        self.dialect
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn iter(&self) -> MvIter<'a> {
        MvIter {
            reader: LeReader::new(self.bytes),
            remaining: self.count,
            mv_type: self.mv_type,
            dialect: self.dialect,
        }
    }
}

impl<'a> Iterator for MvIter<'a> {
    type Item = PropValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        read_element(&mut self.reader, self.mv_type, self.dialect).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        (0, Some(remaining))
    }
}

fn read_element<'a>(
    r: &mut LeReader<'a>,
    mv_type: MvType,
    dialect: MvDialect,
) -> Result<PropValue<'a>, MvError> {
    if matches!(mv_type, MvType::String8 | MvType::Unicode | MvType::Binary)
        && dialect == MvDialect::AddressBook
    {
        match r.u8().map_err(|_| MvError::Truncated)? {
            0xFF => {}
            0x00 => return Ok(PropValue::Null),
            _ => return Err(MvError::BadHasValue),
        }
    }
    let value = match mv_type {
        MvType::I16 => PropValue::I16(i16::from_le_bytes(
            r.array().map_err(|_| MvError::Truncated)?,
        )),
        MvType::I32 => PropValue::I32(r.i32().map_err(|_| MvError::Truncated)?),
        MvType::F32 => PropValue::F32(f32::from_le_bytes(
            r.array().map_err(|_| MvError::Truncated)?,
        )),
        MvType::F64 => PropValue::F64(r.f64().map_err(|_| MvError::Truncated)?),
        MvType::Currency => PropValue::Currency(i64::from_le_bytes(
            r.array().map_err(|_| MvError::Truncated)?,
        )),
        MvType::AppTime => PropValue::AppTime(r.f64().map_err(|_| MvError::Truncated)?),
        MvType::I64 => PropValue::I64(i64::from_le_bytes(
            r.array().map_err(|_| MvError::Truncated)?,
        )),
        MvType::Time => PropValue::Time(FileTime(r.u64().map_err(|_| MvError::Truncated)?)),
        MvType::Guid => {
            let (guid, rest) = r
                .remaining()
                .split_first_chunk::<16>()
                .ok_or(MvError::Truncated)?;
            *r = LeReader::new(rest);
            PropValue::Guid(guid)
        }
        MvType::String8 => PropValue::String8(match dialect {
            MvDialect::FastTransfer => {
                let bytes = length_prefixed(r, CountWidth::Wide)?;
                bytes.strip_suffix(&[0]).unwrap_or(bytes)
            }
            _ => r.ascii_z().map_err(|_| MvError::Truncated)?,
        }),
        MvType::Unicode => PropValue::Unicode(match dialect {
            MvDialect::FastTransfer => {
                let bytes = length_prefixed(r, CountWidth::Wide)?;
                Utf16Le::new(bytes.strip_suffix(&[0, 0]).unwrap_or(bytes)).ok_or(MvError::Utf16)?
            }
            _ => r.utf16_z().map_err(|_| MvError::Truncated)?,
        }),
        MvType::Binary => PropValue::Binary(match dialect {
            MvDialect::Rop => length_prefixed(r, CountWidth::Rop)?,
            MvDialect::Wide | MvDialect::AddressBook | MvDialect::FastTransfer => {
                length_prefixed(r, CountWidth::Wide)?
            }
        }),
    };
    Ok(value)
}

fn length_prefixed<'a>(r: &mut LeReader<'a>, width: CountWidth) -> Result<&'a [u8], MvError> {
    let len = match width {
        CountWidth::Rop => usize::from(r.u16().map_err(|_| MvError::Truncated)?),
        CountWidth::Wide => usize::try_from(r.u32().map_err(|_| MvError::Truncated)?)
            .map_err(|_| MvError::Truncated)?,
    };
    r.bytes(len).map_err(|_| MvError::Truncated)
}

fn collect_mv<'a, T>(view: MvView<'a>, f: impl FnMut(PropValue<'a>) -> Option<T>) -> Box<[T]> {
    view.iter().filter_map(f).collect()
}

impl PropValue<'_> {
    pub fn ptype(&self) -> PropType {
        match self {
            PropValue::Null => PropType::Null,
            PropValue::I16(_) => PropType::I16,
            PropValue::I32(_) => PropType::I32,
            PropValue::F32(_) => PropType::F32,
            PropValue::F64(_) => PropType::F64,
            PropValue::Currency(_) => PropType::Currency,
            PropValue::AppTime(_) => PropType::AppTime,
            PropValue::Error(_) => PropType::Error,
            PropValue::Bool(_) => PropType::Bool,
            PropValue::I64(_) => PropType::I64,
            PropValue::Time(_) => PropType::Time,
            PropValue::Guid(_) => PropType::Guid,
            PropValue::String8(_) => PropType::String8,
            PropValue::Unicode(_) => PropType::Unicode,
            PropValue::Binary(_) => PropType::Binary,
            PropValue::ServerId(_) => PropType::ServerId,
            PropValue::Restriction(_) => PropType::Restriction,
            PropValue::RuleAction(_) => PropType::RuleAction,
            PropValue::Mv(view) => view.mv_type().prop_type(),
            PropValue::Object => PropType::Object,
        }
    }

    pub fn to_owned_value(&self) -> OwnedPropValue {
        match *self {
            PropValue::Null => OwnedPropValue::Null,
            PropValue::I16(v) => OwnedPropValue::I16(v),
            PropValue::I32(v) => OwnedPropValue::I32(v),
            PropValue::F32(v) => OwnedPropValue::F32(v),
            PropValue::F64(v) => OwnedPropValue::F64(v),
            PropValue::Currency(v) => OwnedPropValue::Currency(v),
            PropValue::AppTime(v) => OwnedPropValue::AppTime(v),
            PropValue::Error(v) => OwnedPropValue::Error(v),
            PropValue::Bool(v) => OwnedPropValue::Bool(v),
            PropValue::I64(v) => OwnedPropValue::I64(v),
            PropValue::Time(v) => OwnedPropValue::Time(v),
            PropValue::Guid(v) => OwnedPropValue::Guid(Guid(*v)),
            PropValue::String8(v) => OwnedPropValue::String8(v.into()),
            PropValue::Unicode(v) => OwnedPropValue::Unicode(utf16_to_box(v)),
            PropValue::Binary(v) => OwnedPropValue::Binary(Bytes::copy_from_slice(v)),
            PropValue::ServerId(v) => OwnedPropValue::ServerId(v.into()),
            PropValue::Restriction(v) => OwnedPropValue::Restriction(v.into()),
            PropValue::RuleAction(v) => OwnedPropValue::RuleAction(v.into()),
            PropValue::Object => OwnedPropValue::Object,
            PropValue::Mv(view) => match view.mv_type() {
                MvType::I16 => OwnedPropValue::MvI16(collect_mv(view, |item| match item {
                    PropValue::I16(v) => Some(v),
                    _ => None,
                })),
                MvType::I32 => OwnedPropValue::MvI32(collect_mv(view, |item| match item {
                    PropValue::I32(v) => Some(v),
                    _ => None,
                })),
                MvType::F32 => OwnedPropValue::MvF32(collect_mv(view, |item| match item {
                    PropValue::F32(v) => Some(v),
                    _ => None,
                })),
                MvType::F64 => OwnedPropValue::MvF64(collect_mv(view, |item| match item {
                    PropValue::F64(v) => Some(v),
                    _ => None,
                })),
                MvType::Currency => {
                    OwnedPropValue::MvCurrency(collect_mv(view, |item| match item {
                        PropValue::Currency(v) => Some(v),
                        _ => None,
                    }))
                }
                MvType::AppTime => OwnedPropValue::MvAppTime(collect_mv(view, |item| match item {
                    PropValue::AppTime(v) => Some(v),
                    _ => None,
                })),
                MvType::I64 => OwnedPropValue::MvI64(collect_mv(view, |item| match item {
                    PropValue::I64(v) => Some(v),
                    _ => None,
                })),
                MvType::Time => OwnedPropValue::MvTime(collect_mv(view, |item| match item {
                    PropValue::Time(v) => Some(v),
                    _ => None,
                })),
                MvType::Guid => OwnedPropValue::MvGuid(collect_mv(view, |item| match item {
                    PropValue::Guid(v) => Some(Guid(*v)),
                    _ => None,
                })),
                MvType::String8 => OwnedPropValue::MvString8(collect_mv(view, |item| match item {
                    PropValue::String8(v) => Some(v.into()),
                    _ => None,
                })),
                MvType::Unicode => OwnedPropValue::MvUnicode(collect_mv(view, |item| match item {
                    PropValue::Unicode(v) => Some(utf16_to_box(v)),
                    _ => None,
                })),
                MvType::Binary => OwnedPropValue::MvBinary(collect_mv(view, |item| match item {
                    PropValue::Binary(v) => Some(Bytes::copy_from_slice(v)),
                    _ => None,
                })),
            },
        }
    }
}

fn utf16_to_box(value: Utf16Le<'_>) -> Box<str> {
    let mut text = String::new();
    value.to_string_lossy(&mut text);
    text.into_boxed_str()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/value/tests.rs"]
mod tests;
