/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) const MAX_NESTING: u32 = 128;

#[inline]
pub(crate) const fn varint_len(value: u64) -> usize {
    ((u64::BITS - (value | 1).leading_zeros()) as usize).div_ceil(7)
}

#[inline]
pub(crate) fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[inline]
pub(crate) const fn bytes_len(len: usize) -> usize {
    varint_len(len as u64) + len
}

#[inline]
pub(crate) fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'x, const TRUSTED: bool> {
    bytes: &'x [u8],
}

pub(crate) type TrustedReader<'x> = Reader<'x, true>;
pub(crate) type CheckedReader<'x> = Reader<'x, false>;

impl<'x> Reader<'x, true> {
    #[inline]
    pub(crate) const unsafe fn trusted(bytes: &'x [u8]) -> Self {
        Reader { bytes }
    }

    #[inline]
    pub(crate) const fn empty() -> Self {
        Reader { bytes: &[] }
    }
}

impl<'x> Reader<'x, false> {
    #[inline]
    pub(crate) const fn checked(bytes: &'x [u8]) -> Self {
        Reader { bytes }
    }
}

impl<'x, const TRUSTED: bool> Reader<'x, TRUSTED> {
    #[inline]
    pub(crate) const fn remaining(&self) -> &'x [u8] {
        self.bytes
    }

    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline]
    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    #[inline]
    pub(crate) fn u8(&mut self) -> Option<u8> {
        let (first, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(*first)
    }

    #[inline]
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let (&first, rest) = self.bytes.split_first()?;
        if first < 0x80 {
            self.bytes = rest;
            return Some(u64::from(first));
        }
        self.varint_continued(first, rest)
    }

    #[inline(never)]
    fn varint_continued(&mut self, first: u8, mut rest: &'x [u8]) -> Option<u64> {
        let mut value = u64::from(first & 0x7F);
        let mut shift = 7u32;
        loop {
            let (&byte, next) = rest.split_first()?;
            rest = next;
            let chunk = u64::from(byte & 0x7F);
            if shift == 63 && (chunk > 1 || byte & 0x80 != 0) {
                return None;
            }
            value |= chunk << shift;
            if byte & 0x80 == 0 {
                self.bytes = rest;
                return Some(value);
            }
            shift += 7;
        }
    }

    #[inline]
    pub(crate) fn len(&mut self) -> Option<usize> {
        self.varint().and_then(|len| usize::try_from(len).ok())
    }

    #[inline]
    pub(crate) fn take(&mut self, len: usize) -> Option<&'x [u8]> {
        let (taken, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(taken)
    }

    #[inline]
    pub(crate) fn take_reader(&mut self, len: usize) -> Option<Self> {
        self.take(len).map(|bytes| Reader { bytes })
    }

    #[inline]
    pub(crate) fn bytes(&mut self) -> Option<&'x [u8]> {
        let len = self.len()?;
        self.take(len)
    }

    #[inline]
    pub(crate) fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    #[inline]
    pub(crate) fn consumed_since(&self, start: &Self) -> Option<Self> {
        let len = start.bytes.len().checked_sub(self.bytes.len())?;
        start.bytes.get(..len).map(|bytes| Reader { bytes })
    }

    #[inline]
    pub(crate) fn text(&mut self, len: usize) -> Option<&'x str> {
        let bytes = self.take(len)?;
        if TRUSTED {
            Some(unsafe { std::str::from_utf8_unchecked(bytes) })
        } else {
            std::str::from_utf8(bytes).ok()
        }
    }

    #[inline]
    pub(crate) fn str(&mut self) -> Option<&'x str> {
        let len = self.len()?;
        self.text(len)
    }
}
