/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(test)]
mod tests;

pub(crate) mod value;
pub(crate) use key::*;
pub(crate) use value::*;
pub(crate) mod key;

use crate::{U32_LEN, U64_LEN};
use utils::{
    cheeky_hash::CheekyHash,
    codec::leb128::{Leb128_, Leb128Iterator, Leb128Vec},
};

pub(crate) const CHUNK_TARGET_BYTES: usize = 24 * 1024;
pub(crate) const WAL_VALUE_LIMIT: usize = 80_000;
pub(crate) const FOLD_BATCH_BYTES: usize = 512 * 1024;
pub(crate) const SLICE_BUDGET_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_TERM_POSITIONS: usize = 8192;
pub(crate) const MAX_FIELD_TOKENS: usize = 65_536;

pub(crate) const WAL_ADDS: u8 = 0;
pub(crate) const WAL_TOMBSTONES: u8 = 1;

pub(crate) const GLOBAL_META_GENERATION: u8 = 0;
pub(crate) const GLOBAL_META_WATERMARK: u8 = 1;
pub(crate) const GLOBAL_META_SWEPT: u8 = 2;

pub(crate) const TYPE_MASK: u8 = 0b1110_0000;

pub(crate) type Probe = (u8, CheekyHash);

pub(crate) trait SearchDocId: Copy + Ord + std::fmt::Debug {
    const ZERO: Self;
    const TERM_KEY_BASE: usize;
    const TERM_KEY_SUFFIX: usize;
    const WAL_DOCUMENT_OVERHEAD: usize;
    fn write_wal_id(buf: &mut Vec<u8>, id: Self);
    fn read_wal_id(reader: &mut Reader<'_>) -> Option<Self>;
    fn write_delta(buf: &mut Vec<u8>, delta: Self);
    fn read_delta(reader: &mut Reader<'_>) -> Option<Self>;
    fn write_payload(buf: &mut Vec<u8>, payload: &[u8]);
    fn read_payload<'x>(reader: &mut Reader<'x>) -> Option<&'x [u8]>;
    fn from_be_slice(bytes: &[u8]) -> Option<Self>;
    fn delta_since(self, prev: Self) -> Self;
    fn add_delta(self, delta: Self) -> Option<Self>;
}

impl SearchDocId for u32 {
    const ZERO: Self = 0;
    const TERM_KEY_BASE: usize = 6;
    const TERM_KEY_SUFFIX: usize = U32_LEN + 1;
    const WAL_DOCUMENT_OVERHEAD: usize = 10;

    #[inline(always)]
    fn write_wal_id(buf: &mut Vec<u8>, id: Self) {
        buf.push_leb128(id);
    }

    #[inline(always)]
    fn read_wal_id(reader: &mut Reader<'_>) -> Option<Self> {
        reader.leb128()
    }

    #[inline(always)]
    fn write_delta(buf: &mut Vec<u8>, delta: Self) {
        buf.push_leb128(delta);
    }

    #[inline(always)]
    fn read_delta(reader: &mut Reader<'_>) -> Option<Self> {
        reader.leb128()
    }

    #[inline(always)]
    fn write_payload(buf: &mut Vec<u8>, payload: &[u8]) {
        buf.push_leb128(payload.len());
        buf.extend_from_slice(payload);
    }

    #[inline(always)]
    fn read_payload<'x>(reader: &mut Reader<'x>) -> Option<&'x [u8]> {
        reader.payload()
    }

    #[inline(always)]
    fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(u32::from_be_bytes)
    }

    #[inline(always)]
    fn delta_since(self, prev: Self) -> Self {
        self - prev
    }

    #[inline(always)]
    fn add_delta(self, delta: Self) -> Option<Self> {
        self.checked_add(delta)
    }
}

impl SearchDocId for u64 {
    const ZERO: Self = 0;
    const TERM_KEY_BASE: usize = 2;
    const TERM_KEY_SUFFIX: usize = U64_LEN + 1;
    const WAL_DOCUMENT_OVERHEAD: usize = U64_LEN + 5;

    #[inline(always)]
    fn write_wal_id(buf: &mut Vec<u8>, id: Self) {
        buf.extend_from_slice(&id.to_be_bytes());
    }

    #[inline(always)]
    fn read_wal_id(reader: &mut Reader<'_>) -> Option<Self> {
        reader.slice(U64_LEN).and_then(Self::from_be_slice)
    }

    #[inline(always)]
    fn write_delta(buf: &mut Vec<u8>, delta: Self) {
        buf.push_leb128(delta);
    }

    #[inline(always)]
    fn read_delta(reader: &mut Reader<'_>) -> Option<Self> {
        reader.leb128()
    }

    #[inline(always)]
    fn write_payload(_buf: &mut Vec<u8>, _payload: &[u8]) {}

    #[inline(always)]
    fn read_payload<'x>(_reader: &mut Reader<'x>) -> Option<&'x [u8]> {
        Some(&[])
    }

    #[inline(always)]
    fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(u64::from_be_bytes)
    }

    #[inline(always)]
    fn delta_since(self, prev: Self) -> Self {
        self - prev
    }

    #[inline(always)]
    fn add_delta(self, delta: Self) -> Option<Self> {
        self.checked_add(delta)
    }
}

pub(crate) struct Reader<'x> {
    iter: std::slice::Iter<'x, u8>,
}

impl<'x> Reader<'x> {
    pub fn new(bytes: &'x [u8]) -> Self {
        Reader { iter: bytes.iter() }
    }

    pub fn is_empty(&self) -> bool {
        self.iter.as_slice().is_empty()
    }

    pub fn leb128<T: Leb128_>(&mut self) -> Option<T> {
        self.iter.next_leb128()
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.iter.next().copied()
    }

    pub fn slice(&mut self, len: usize) -> Option<&'x [u8]> {
        let (slice, rest) = self.iter.as_slice().split_at_checked(len)?;
        self.iter = rest.iter();
        Some(slice)
    }

    pub fn term(&mut self) -> Option<CheekyHash> {
        let len = self.u8()?;
        let key = self.slice((len as usize).min(CheekyHash::HASH_SIZE))?;
        CheekyHash::from_key_bytes(key, len)
    }

    pub fn payload(&mut self) -> Option<&'x [u8]> {
        let positions_len = self.leb128::<usize>()?;
        let bytes = self.iter.as_slice();
        let (payload, rest) = bytes.split_at_checked(positions_len)?;
        self.iter = rest.iter();
        Some(payload)
    }
}

pub(crate) fn push_term(buf: &mut Vec<u8>, term: &CheekyHash) {
    buf.push(term.len() as u8);
    buf.extend_from_slice(term.as_key());
}

#[inline(always)]
fn leb128_size(value: u32) -> usize {
    ((32 - value.leading_zeros()).max(1) as usize).div_ceil(7)
}

pub(crate) fn encode_positions(positions: &[u32], buf: &mut Vec<u8>) {
    let mut prev = 0u32;
    for position in positions {
        buf.push_leb128(*position - prev);
        prev = *position;
    }
}

pub(crate) fn push_positions(positions: &[u32], buf: &mut Vec<u8>) {
    let mut len = 0;
    let mut prev = 0u32;
    for position in positions {
        len += leb128_size(*position - prev);
        prev = *position;
    }
    buf.push_leb128(len);
    buf.reserve(len);
    encode_positions(positions, buf);
}

pub(crate) fn decode_positions(payload: &[u8], positions: &mut Vec<u32>) -> Option<()> {
    positions.clear();
    let mut reader = Reader::new(payload);
    let mut current = 0u32;
    while !reader.is_empty() {
        current += reader.leb128::<u32>()?;
        positions.push(current);
    }
    Some(())
}
