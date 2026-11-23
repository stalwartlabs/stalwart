/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    owned::OwnedPropValue,
    tag::PropType,
    value::{CountWidth, MvDialect, MvType, MvView, PropValue},
};
use crate::{
    common::{FileTime, LeReader},
    mapi::{ec::ErrorCode, emsmdb::MapiLimits, restriction::skip_restriction, rop::RopDecodeError},
};

const PRESENT: u8 = 0xFF;
const ABSENT: u8 = 0x00;
const MV_INSTANCE: u16 = 0x2000;
const MV_FLAG: u16 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueMode {
    Rop,
    Wide,
    AddressBook,
}

impl ValueMode {
    pub(crate) const fn width(self) -> CountWidth {
        match self {
            ValueMode::Rop => CountWidth::Rop,
            ValueMode::Wide | ValueMode::AddressBook => CountWidth::Wide,
        }
    }

    const fn dialect(self) -> MvDialect {
        match self {
            ValueMode::Rop => MvDialect::Rop,
            ValueMode::Wide => MvDialect::Wide,
            ValueMode::AddressBook => MvDialect::AddressBook,
        }
    }
}

impl From<CountWidth> for ValueMode {
    fn from(width: CountWidth) -> Self {
        match width {
            CountWidth::Rop => ValueMode::Rop,
            CountWidth::Wide => ValueMode::Wide,
        }
    }
}

pub fn decode_value<'a>(
    r: &mut LeReader<'a>,
    ptype: PropType,
    width: CountWidth,
    limits: &MapiLimits,
) -> Result<PropValue<'a>, RopDecodeError> {
    decode_value_in(r, ptype, width.into(), limits, limits.restriction_depth)
}

pub(crate) fn wire_type(code: u16) -> PropType {
    if code & (MV_INSTANCE | MV_FLAG) == (MV_INSTANCE | MV_FLAG) {
        PropType::from_code(code & !(MV_INSTANCE | MV_FLAG))
    } else {
        PropType::from_code(code)
    }
}

pub(crate) fn decode_value_in<'a>(
    r: &mut LeReader<'a>,
    ptype: PropType,
    mode: ValueMode,
    limits: &MapiLimits,
    depth: u8,
) -> Result<PropValue<'a>, RopDecodeError> {
    let start = r.offset();
    if mode == ValueMode::AddressBook && has_presence_byte(ptype) {
        match r.u8()? {
            PRESENT => {}
            ABSENT => return Ok(PropValue::Null),
            _ => {
                return Err(RopDecodeError::BadValue {
                    offset: RopDecodeError::at(start),
                });
            }
        }
    }
    let width = mode.width();
    let value = match ptype {
        PropType::Null => PropValue::Null,
        PropType::I16 => PropValue::I16(i16::from_le_bytes(r.array()?)),
        PropType::I32 => PropValue::I32(r.i32()?),
        PropType::F32 => PropValue::F32(f32::from_le_bytes(r.array()?)),
        PropType::F64 => PropValue::F64(r.f64()?),
        PropType::Currency => PropValue::Currency(i64::from_le_bytes(r.array()?)),
        PropType::AppTime => PropValue::AppTime(r.f64()?),
        PropType::Error => PropValue::Error(ErrorCode(r.u32()?)),
        PropType::Bool => PropValue::Bool(r.u8()? != 0),
        PropType::I64 => PropValue::I64(i64::from_le_bytes(r.array()?)),
        PropType::Time => PropValue::Time(FileTime(r.u64()?)),
        PropType::Guid => {
            let guid = r.remaining().first_chunk::<16>();
            r.skip(16)?;
            PropValue::Guid(guid.ok_or(RopDecodeError::Truncated {
                offset: RopDecodeError::at(start),
            })?)
        }
        PropType::String8 => PropValue::String8(r.ascii_z()?),
        PropType::Unicode => PropValue::Unicode(r.utf16_z()?),
        PropType::Binary => PropValue::Binary(counted(r, width)?),
        PropType::ServerId => PropValue::ServerId(counted(r, width)?),
        PropType::Object => match mode {
            ValueMode::AddressBook => PropValue::Object,
            ValueMode::Rop | ValueMode::Wide => {
                counted(r, width)?;
                PropValue::Object
            }
        },
        PropType::Restriction => {
            let body = r.remaining();
            let mut walker = r.clone();
            skip_restriction(&mut walker, ValueMode::Rop, limits, depth)?;
            let len = walker.offset().saturating_sub(r.offset());
            r.skip(len)?;
            PropValue::Restriction(body.get(..len).unwrap_or_default())
        }
        PropType::RuleAction => {
            let body = r.remaining();
            let before = r.offset();
            skip_rule_actions(r, CountWidth::Rop)?;
            let len = r.offset().saturating_sub(before);
            PropValue::RuleAction(body.get(..len).unwrap_or_default())
        }
        PropType::MvI16
        | PropType::MvI32
        | PropType::MvF32
        | PropType::MvF64
        | PropType::MvCurrency
        | PropType::MvAppTime
        | PropType::MvI64
        | PropType::MvString8
        | PropType::MvUnicode
        | PropType::MvTime
        | PropType::MvGuid
        | PropType::MvBinary => {
            let mv_type = ptype.mv_type().ok_or(RopDecodeError::BadType {
                offset: RopDecodeError::at(start),
                ptype: ptype.code(),
            })?;
            let offset = r.offset();
            let (view, rest) =
                MvView::parse(r.remaining(), mv_type, mode.dialect(), limits.mv_count_max)
                    .map_err(|err| RopDecodeError::from_mv(err, offset))?;
            *r = advance(r, rest)?;
            PropValue::Mv(view)
        }
        PropType::Unspecified | PropType::CodePageString(_) | PropType::Unknown(_) => {
            return Err(RopDecodeError::BadType {
                offset: RopDecodeError::at(start),
                ptype: ptype.code(),
            });
        }
    };
    Ok(value)
}

const fn has_presence_byte(ptype: PropType) -> bool {
    matches!(
        ptype,
        PropType::String8 | PropType::Unicode | PropType::Binary
    ) || ptype.is_multi()
}

fn advance<'a>(r: &LeReader<'a>, rest: &'a [u8]) -> Result<LeReader<'a>, RopDecodeError> {
    let consumed = r.remaining().len().saturating_sub(rest.len());
    let mut next = r.clone();
    next.skip(consumed)?;
    Ok(next)
}

fn counted<'a>(r: &mut LeReader<'a>, width: CountWidth) -> Result<&'a [u8], RopDecodeError> {
    let len = read_count(r, width)?;
    Ok(r.bytes(len)?)
}

pub(crate) fn read_count(r: &mut LeReader<'_>, width: CountWidth) -> Result<usize, RopDecodeError> {
    let offset = r.offset();
    let count = match width {
        CountWidth::Rop => u32::from(r.u16()?),
        CountWidth::Wide => r.u32()?,
    };
    usize::try_from(count).map_err(|_| RopDecodeError::TooMany {
        offset: RopDecodeError::at(offset),
    })
}

fn skip_rule_actions(r: &mut LeReader<'_>, width: CountWidth) -> Result<(), RopDecodeError> {
    let count = read_count(r, width)?;
    for _ in 0..count {
        let len = read_count(r, width)?;
        r.skip(len)?;
    }
    Ok(())
}

pub fn encode_value(out: &mut Vec<u8>, value: &PropValue<'_>, width: CountWidth) {
    encode_value_in(out, value, width.into());
}

pub(crate) fn encode_value_in(out: &mut Vec<u8>, value: &PropValue<'_>, mode: ValueMode) {
    let width = mode.width();
    if mode == ValueMode::AddressBook && has_presence_byte(value.ptype()) {
        out.push(PRESENT);
    }
    match value {
        PropValue::Null => {}
        PropValue::I16(v) => out.extend_from_slice(&v.to_le_bytes()),
        PropValue::I32(v) => out.extend_from_slice(&v.to_le_bytes()),
        PropValue::F32(v) => out.extend_from_slice(&v.to_le_bytes()),
        PropValue::F64(v) | PropValue::AppTime(v) => out.extend_from_slice(&v.to_le_bytes()),
        PropValue::Currency(v) | PropValue::I64(v) => out.extend_from_slice(&v.to_le_bytes()),
        PropValue::Error(code) => out.extend_from_slice(&code.0.to_le_bytes()),
        PropValue::Bool(v) => out.push(u8::from(*v)),
        PropValue::Time(t) => out.extend_from_slice(&t.0.to_le_bytes()),
        PropValue::Guid(g) => out.extend_from_slice(g.as_slice()),
        PropValue::String8(s) => write_string8(out, s),
        PropValue::Unicode(s) => write_utf16(out, s.as_bytes()),
        PropValue::Binary(b) | PropValue::ServerId(b) => write_counted(out, b, width),
        PropValue::Restriction(b) | PropValue::RuleAction(b) => out.extend_from_slice(b),
        PropValue::Object => {
            if mode != ValueMode::AddressBook {
                write_count(out, 0, width);
            }
        }
        PropValue::Mv(view) => encode_mv(out, view, mode),
    }
}

fn encode_mv(out: &mut Vec<u8>, view: &MvView<'_>, mode: ValueMode) {
    if view.dialect() == mode.dialect() {
        out.extend_from_slice(&view.count().to_le_bytes());
        out.extend_from_slice(view.as_bytes());
        return;
    }
    let count = if view.dialect() == MvDialect::AddressBook && mode != ValueMode::AddressBook {
        u32::try_from(
            view.iter()
                .filter(|item| !matches!(item, PropValue::Null))
                .count(),
        )
        .unwrap_or(u32::MAX)
    } else {
        view.count()
    };
    out.extend_from_slice(&count.to_le_bytes());
    let width = mode.width();
    let abk = mode == ValueMode::AddressBook && !is_fixed(view.mv_type());
    for item in view.iter() {
        if abk {
            if matches!(item, PropValue::Null) {
                out.push(ABSENT);
                continue;
            }
            out.push(PRESENT);
        }
        match item {
            PropValue::Binary(b) => write_counted(out, b, width),
            PropValue::Null => {}
            other => encode_value_in(out, &other, ValueMode::Rop),
        }
    }
}

const fn is_fixed(mv_type: MvType) -> bool {
    !matches!(mv_type, MvType::String8 | MvType::Unicode | MvType::Binary)
}

pub fn encode_owned(out: &mut Vec<u8>, value: &OwnedPropValue, width: CountWidth) {
    encode_owned_in(out, value, width.into());
}

pub(crate) fn encode_owned_in(out: &mut Vec<u8>, value: &OwnedPropValue, mode: ValueMode) {
    let width = mode.width();
    let abk = mode == ValueMode::AddressBook;
    if abk && has_presence_byte(value.ptype()) {
        out.push(PRESENT);
    }
    match value {
        OwnedPropValue::Null => {}
        OwnedPropValue::I16(v) => out.extend_from_slice(&v.to_le_bytes()),
        OwnedPropValue::I32(v) => out.extend_from_slice(&v.to_le_bytes()),
        OwnedPropValue::F32(v) => out.extend_from_slice(&v.to_le_bytes()),
        OwnedPropValue::F64(v) | OwnedPropValue::AppTime(v) => {
            out.extend_from_slice(&v.to_le_bytes())
        }
        OwnedPropValue::Currency(v) | OwnedPropValue::I64(v) => {
            out.extend_from_slice(&v.to_le_bytes())
        }
        OwnedPropValue::Error(code) => out.extend_from_slice(&code.0.to_le_bytes()),
        OwnedPropValue::Bool(v) => out.push(u8::from(*v)),
        OwnedPropValue::Time(t) => out.extend_from_slice(&t.0.to_le_bytes()),
        OwnedPropValue::Guid(g) => out.extend_from_slice(g.as_bytes()),
        OwnedPropValue::String8(s) => write_string8(out, s),
        OwnedPropValue::Unicode(s) => write_str_utf16(out, s),
        OwnedPropValue::Binary(b) => write_counted(out, b, width),
        OwnedPropValue::ServerId(b) => write_counted(out, b, width),
        OwnedPropValue::Restriction(b) | OwnedPropValue::RuleAction(b) => out.extend_from_slice(b),
        OwnedPropValue::Object => {
            if !abk {
                write_count(out, 0, width);
            }
        }
        OwnedPropValue::MvI16(items) => {
            write_fixed(out, items, |out, v| out.extend_from_slice(&v.to_le_bytes()))
        }
        OwnedPropValue::MvI32(items) => {
            write_fixed(out, items, |out, v| out.extend_from_slice(&v.to_le_bytes()))
        }
        OwnedPropValue::MvF32(items) => {
            write_fixed(out, items, |out, v| out.extend_from_slice(&v.to_le_bytes()))
        }
        OwnedPropValue::MvF64(items) | OwnedPropValue::MvAppTime(items) => {
            write_fixed(out, items, |out, v| out.extend_from_slice(&v.to_le_bytes()))
        }
        OwnedPropValue::MvCurrency(items) | OwnedPropValue::MvI64(items) => {
            write_fixed(out, items, |out, v| out.extend_from_slice(&v.to_le_bytes()))
        }
        OwnedPropValue::MvTime(items) => write_fixed(out, items, |out, v| {
            out.extend_from_slice(&v.0.to_le_bytes())
        }),
        OwnedPropValue::MvGuid(items) => {
            write_fixed(out, items, |out, v| out.extend_from_slice(v.as_bytes()))
        }
        OwnedPropValue::MvString8(items) => write_fixed(out, items, |out, v| {
            if abk {
                out.push(PRESENT);
            }
            write_string8(out, v)
        }),
        OwnedPropValue::MvUnicode(items) => write_fixed(out, items, |out, v| {
            if abk {
                out.push(PRESENT);
            }
            write_str_utf16(out, v)
        }),
        OwnedPropValue::MvBinary(items) => write_fixed(out, items, |out, v| {
            if abk {
                out.push(PRESENT);
            }
            write_counted(out, v, width)
        }),
    }
}

fn write_fixed<T>(out: &mut Vec<u8>, items: &[T], mut f: impl FnMut(&mut Vec<u8>, &T)) {
    write_count(out, items.len(), CountWidth::Wide);
    for item in items {
        f(out, item);
    }
}

pub(crate) fn write_count(out: &mut Vec<u8>, len: usize, width: CountWidth) {
    match width {
        CountWidth::Rop => out.extend_from_slice(&clamp_u16(len).to_le_bytes()),
        CountWidth::Wide => {
            out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes())
        }
    }
}

fn clamp_u16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

pub(crate) fn write_counted(out: &mut Vec<u8>, bytes: &[u8], width: CountWidth) {
    let bytes = match width {
        CountWidth::Rop => bytes.get(..usize::from(u16::MAX)).unwrap_or(bytes),
        CountWidth::Wide => bytes,
    };
    write_count(out, bytes.len(), width);
    out.extend_from_slice(bytes);
}

pub(crate) fn write_string8(out: &mut Vec<u8>, s: &[u8]) {
    let end = memchr::memchr(0, s).unwrap_or(s.len());
    out.extend_from_slice(s.get(..end).unwrap_or(s));
    out.push(0);
}

pub(crate) fn write_utf16(out: &mut Vec<u8>, units: &[u8]) {
    let end = units
        .as_chunks::<2>()
        .0
        .iter()
        .position(|unit| *unit == [0, 0])
        .and_then(|units| units.checked_mul(2))
        .unwrap_or(units.len());
    out.extend_from_slice(units.get(..end).unwrap_or(units));
    out.extend_from_slice(&[0, 0]);
}

pub(crate) fn write_str_utf16(out: &mut Vec<u8>, s: &str) {
    out.reserve(s.len().saturating_mul(2).saturating_add(2));
    for unit in s.encode_utf16().take_while(|unit| *unit != 0) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/codec/tests.rs"]
mod tests;
