/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{guid::Guid, utf16::Utf16Le};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    pub offset: usize,
    pub needed: usize,
}

#[derive(Debug, Clone)]
pub struct LeReader<'a> {
    remaining: &'a [u8],
    start_len: usize,
}

impl<'a> LeReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            remaining: buf,
            start_len: buf.len(),
        }
    }

    pub fn offset(&self) -> usize {
        self.start_len.saturating_sub(self.remaining.len())
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    pub fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    #[cold]
    #[inline(never)]
    fn truncated(&self, needed: usize) -> Truncated {
        Truncated {
            offset: self.offset(),
            needed,
        }
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        match self.remaining.split_first_chunk::<N>() {
            Some((head, rest)) => {
                self.remaining = rest;
                Ok(*head)
            }
            None => Err(self.truncated(N)),
        }
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> {
        match self.remaining.split_first() {
            Some((byte, rest)) => {
                self.remaining = rest;
                Ok(*byte)
            }
            None => Err(self.truncated(1)),
        }
    }

    pub fn u16(&mut self) -> Result<u16, Truncated> {
        self.array().map(u16::from_le_bytes)
    }

    pub fn u32(&mut self) -> Result<u32, Truncated> {
        self.array().map(u32::from_le_bytes)
    }

    pub fn u64(&mut self) -> Result<u64, Truncated> {
        self.array().map(u64::from_le_bytes)
    }

    pub fn i32(&mut self) -> Result<i32, Truncated> {
        self.array().map(i32::from_le_bytes)
    }

    pub fn f64(&mut self) -> Result<f64, Truncated> {
        self.array().map(f64::from_le_bytes)
    }

    pub fn guid(&mut self) -> Result<Guid, Truncated> {
        self.array().map(Guid::from_wire)
    }

    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], Truncated> {
        match self.remaining.split_at_checked(len) {
            Some((head, rest)) => {
                self.remaining = rest;
                Ok(head)
            }
            None => Err(self.truncated(len)),
        }
    }

    pub fn skip(&mut self, len: usize) -> Result<(), Truncated> {
        self.bytes(len).map(|_| ())
    }

    pub fn ascii_z(&mut self) -> Result<&'a [u8], Truncated> {
        let Some(pos) = memchr::memchr(0, self.remaining) else {
            return Err(self.truncated(self.remaining.len().saturating_add(1)));
        };
        let value = self.bytes(pos)?;
        self.skip(1)?;
        Ok(value)
    }

    pub fn utf16_z(&mut self) -> Result<Utf16Le<'a>, Truncated> {
        let (units, _) = self.remaining.as_chunks::<2>();
        let Some(pos) = units.iter().position(|unit| *unit == [0, 0]) else {
            return Err(self.truncated(units.len().saturating_add(1).saturating_mul(2)));
        };
        let value = self.bytes(pos.saturating_mul(2))?;
        self.skip(2)?;
        Ok(Utf16Le::new(value).unwrap_or_default())
    }

    pub fn rest(self) -> &'a [u8] {
        self.remaining
    }
}
