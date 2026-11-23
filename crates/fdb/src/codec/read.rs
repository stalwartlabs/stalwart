/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Uid;

const OFFSET_LEN: usize = 4;
const VTABLE_HEADER: usize = 4;
const MIN_FIELD_OFFSET: usize = 4;
const TAG_ERROR: u8 = 1;
const TAG_VALUE: u8 = 2;
const TAG_PRESENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    OutOfBounds,
    InvalidVTable,
    FileIdentifier(u32),
    UnionTag(u8),
    Length,
    KeyRange,
    ErrorCode,
}

#[derive(Clone, Copy)]
pub struct Table<'a> {
    buf: &'a [u8],
    pos: usize,
    vtable: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct Alternative<'a> {
    buf: &'a [u8],
    pos: usize,
}

#[derive(Clone, Copy)]
pub struct Union<'a> {
    pub tag: u8,
    pub value: Option<Alternative<'a>>,
}

#[derive(Clone, Copy)]
pub struct Vector<'a> {
    buf: &'a [u8],
    start: usize,
    len: usize,
}

pub enum Reply<'a> {
    Value(Alternative<'a>),
    Error(u16),
}

#[cold]
#[inline(never)]
fn out_of_bounds() -> DecodeError {
    DecodeError::OutOfBounds
}

fn le<const N: usize>(buf: &[u8], pos: usize) -> Result<[u8; N], DecodeError> {
    buf.get(pos..)
        .and_then(|rest| rest.first_chunk::<N>())
        .copied()
        .ok_or_else(out_of_bounds)
}

fn le_u32(buf: &[u8], pos: usize) -> Result<usize, DecodeError> {
    le::<4>(buf, pos).map(|bytes| u32::from_le_bytes(bytes) as usize)
}

fn follow(buf: &[u8], pos: usize) -> Result<usize, DecodeError> {
    pos.checked_add(le_u32(buf, pos)?).ok_or_else(out_of_bounds)
}

fn dynamic(buf: &[u8], pos: usize) -> Result<&[u8], DecodeError> {
    let len = le_u32(buf, pos)?;
    let start = pos + OFFSET_LEN;
    start
        .checked_add(len)
        .and_then(|end| buf.get(start..end))
        .ok_or_else(out_of_bounds)
}

pub fn root(buf: &[u8], file_identifier: u32) -> Result<Table<'_>, DecodeError> {
    let root = le_u32(buf, 0)?;
    let found = u32::from_le_bytes(le::<4>(buf, OFFSET_LEN)?);
    if found != file_identifier {
        return Err(DecodeError::FileIdentifier(found));
    }
    Table::at(buf, root)
}

pub fn reply(buf: &[u8], file_identifier: u32) -> Result<Reply<'_>, DecodeError> {
    let union = root(buf, file_identifier)?.union(0)?;
    match (union.tag, union.value) {
        (TAG_VALUE, Some(value)) => Ok(Reply::Value(value)),
        (TAG_ERROR, Some(error)) => match error.table()?.u16(0)? {
            0 => Err(DecodeError::ErrorCode),
            code => Ok(Reply::Error(code)),
        },
        (tag, _) => Err(DecodeError::UnionTag(tag)),
    }
}

impl<'a> Table<'a> {
    pub const EMPTY: Table<'static> = Table {
        buf: &[],
        pos: 0,
        vtable: &[],
    };

    fn at(buf: &'a [u8], pos: usize) -> Result<Self, DecodeError> {
        let soffset = i32::from_le_bytes(le::<4>(buf, pos)?);
        let vtable_pos = isize::try_from(soffset)
            .ok()
            .and_then(isize::checked_neg)
            .and_then(|delta| pos.checked_add_signed(delta))
            .ok_or_else(out_of_bounds)?;
        let vtable_len = u16::from_le_bytes(le::<2>(buf, vtable_pos)?) as usize;
        if vtable_len < VTABLE_HEADER || !vtable_len.is_multiple_of(2) {
            return Err(DecodeError::InvalidVTable);
        }
        let vtable = buf
            .get(vtable_pos + VTABLE_HEADER..vtable_pos + vtable_len)
            .ok_or_else(out_of_bounds)?;
        Ok(Table { buf, pos, vtable })
    }

    fn field(&self, slot: usize) -> Option<usize> {
        let offset = self.vtable.get(slot * 2..)?.first_chunk::<2>()?;
        let offset = u16::from_le_bytes(*offset) as usize;
        (offset >= MIN_FIELD_OFFSET).then_some(self.pos + offset)
    }

    pub fn has(&self, slot: usize) -> bool {
        self.field(slot).is_some()
    }

    pub fn scalar<const N: usize>(&self, slot: usize) -> Result<[u8; N], DecodeError> {
        match self.field(slot) {
            Some(pos) => le::<N>(self.buf, pos),
            None => Ok([0; N]),
        }
    }

    pub fn u8(&self, slot: usize) -> Result<u8, DecodeError> {
        self.scalar::<1>(slot).map(u8::from_le_bytes)
    }

    pub fn bool(&self, slot: usize) -> Result<bool, DecodeError> {
        self.u8(slot).map(|value| value != 0)
    }

    pub fn i8(&self, slot: usize) -> Result<i8, DecodeError> {
        self.scalar::<1>(slot).map(i8::from_le_bytes)
    }

    pub fn u16(&self, slot: usize) -> Result<u16, DecodeError> {
        self.scalar::<2>(slot).map(u16::from_le_bytes)
    }

    pub fn i16(&self, slot: usize) -> Result<i16, DecodeError> {
        self.scalar::<2>(slot).map(i16::from_le_bytes)
    }

    pub fn u32(&self, slot: usize) -> Result<u32, DecodeError> {
        self.scalar::<4>(slot).map(u32::from_le_bytes)
    }

    pub fn i32(&self, slot: usize) -> Result<i32, DecodeError> {
        self.scalar::<4>(slot).map(i32::from_le_bytes)
    }

    pub fn u64(&self, slot: usize) -> Result<u64, DecodeError> {
        self.scalar::<8>(slot).map(u64::from_le_bytes)
    }

    pub fn i64(&self, slot: usize) -> Result<i64, DecodeError> {
        self.scalar::<8>(slot).map(i64::from_le_bytes)
    }

    pub fn f64(&self, slot: usize) -> Result<f64, DecodeError> {
        self.scalar::<8>(slot).map(f64::from_le_bytes)
    }

    pub fn uid(&self, slot: usize) -> Result<Uid, DecodeError> {
        self.scalar::<16>(slot).map(Uid::from_le_bytes)
    }

    pub fn bytes(&self, slot: usize) -> Result<&'a [u8], DecodeError> {
        self.blob(slot).map(Option::unwrap_or_default)
    }

    pub fn blob(&self, slot: usize) -> Result<Option<&'a [u8]>, DecodeError> {
        self.field(slot)
            .map(|pos| dynamic(self.buf, follow(self.buf, pos)?))
            .transpose()
    }

    pub fn table(&self, slot: usize) -> Result<Option<Table<'a>>, DecodeError> {
        match self.field(slot) {
            Some(pos) => Table::at(self.buf, follow(self.buf, pos)?).map(Some),
            None => Ok(None),
        }
    }

    pub fn union(&self, slot: usize) -> Result<Union<'a>, DecodeError> {
        let tag = self.u8(slot)?;
        let value = match (tag, self.field(slot + 1)) {
            (1.., Some(pos)) => Some(Alternative {
                buf: self.buf,
                pos: follow(self.buf, pos)?,
            }),
            _ => None,
        };
        Ok(Union { tag, value })
    }

    pub fn optional(&self, slot: usize) -> Result<Option<Alternative<'a>>, DecodeError> {
        self.union(slot)
            .map(|union| union.value.filter(|_| union.tag == TAG_PRESENT))
    }

    pub fn optional_table(&self, slot: usize) -> Result<Option<Table<'a>>, DecodeError> {
        self.optional(slot)?.map(|value| value.table()).transpose()
    }

    pub fn optional_bytes(&self, slot: usize) -> Result<Option<&'a [u8]>, DecodeError> {
        self.optional(slot)?.map(|value| value.bytes()).transpose()
    }

    pub fn optional_scalar<const N: usize>(
        &self,
        slot: usize,
    ) -> Result<Option<[u8; N]>, DecodeError> {
        self.optional(slot)?
            .map(|value| value.scalar::<N>())
            .transpose()
    }

    pub fn vector(&self, slot: usize) -> Result<Vector<'a>, DecodeError> {
        match self.field(slot) {
            Some(pos) => Alternative {
                buf: self.buf,
                pos: follow(self.buf, pos)?,
            }
            .vector(),
            None => Ok(Vector {
                buf: self.buf,
                start: 0,
                len: 0,
            }),
        }
    }

    pub fn scalar_vector<const N: usize>(&self, slot: usize) -> Result<&'a [[u8; N]], DecodeError> {
        match self.field(slot) {
            Some(pos) => Alternative {
                buf: self.buf,
                pos: follow(self.buf, pos)?,
            }
            .scalar_vector::<N>(),
            None => Ok(&[]),
        }
    }
}

impl<'a> Alternative<'a> {
    pub fn table(&self) -> Result<Table<'a>, DecodeError> {
        Table::at(self.buf, self.pos)
    }

    pub fn bytes(&self) -> Result<&'a [u8], DecodeError> {
        dynamic(self.buf, self.pos)
    }

    pub fn scalar<const N: usize>(&self) -> Result<[u8; N], DecodeError> {
        le::<N>(self.buf, self.pos)
    }

    pub fn vector(&self) -> Result<Vector<'a>, DecodeError> {
        let len = le_u32(self.buf, self.pos)?;
        let start = self.pos + OFFSET_LEN;
        let end = len
            .checked_mul(OFFSET_LEN)
            .and_then(|bytes| start.checked_add(bytes))
            .ok_or_else(out_of_bounds)?;
        if end > self.buf.len() {
            return Err(out_of_bounds());
        }
        Ok(Vector {
            buf: self.buf,
            start,
            len,
        })
    }

    pub fn scalar_vector<const N: usize>(&self) -> Result<&'a [[u8; N]], DecodeError> {
        let len = le_u32(self.buf, self.pos)?;
        let start = self.pos + OFFSET_LEN;
        let elements = len
            .checked_mul(N)
            .and_then(|bytes| start.checked_add(bytes))
            .and_then(|end| self.buf.get(start..end))
            .ok_or_else(out_of_bounds)?;
        Ok(elements.as_chunks::<N>().0)
    }
}

impl<'a> Vector<'a> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Result<Alternative<'a>, DecodeError> {
        if index >= self.len {
            return Err(out_of_bounds());
        }
        let pos = self.start + index * OFFSET_LEN;
        Ok(Alternative {
            buf: self.buf,
            pos: follow(self.buf, pos)?,
        })
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Result<Alternative<'a>, DecodeError>> + 'a {
        let vector = *self;
        (0..self.len).map(move |index| vector.get(index))
    }

    pub fn tables(&self) -> impl ExactSizeIterator<Item = Result<Table<'a>, DecodeError>> + 'a {
        self.iter().map(|item| item.and_then(|value| value.table()))
    }

    pub fn bytes(&self) -> impl ExactSizeIterator<Item = Result<&'a [u8], DecodeError>> + 'a {
        self.iter().map(|item| item.and_then(|value| value.bytes()))
    }
}
