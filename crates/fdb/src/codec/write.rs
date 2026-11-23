/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Uid;

pub type Pos = usize;

const HEADER_LEN: usize = 8;
const ROOT_ALIGN: usize = 8;
const LEN_PREFIX: usize = 4;
const MIN_ALIGN: usize = 4;
const OFFSET_LEN: usize = 4;
const INLINE_SLOTS: usize = 8;

pub trait Encode {
    fn vtables(&self) -> &'static [u8];
    fn file_identifier(&self) -> u32;
    fn layout<S: Sink>(&self, sink: &mut S) -> Pos;
}

pub trait Sink {
    type Table<'s, const LEN: usize>: TableSink
    where
        Self: 's;

    fn blob(&mut self, len: usize, fill: impl FnOnce(&mut [u8])) -> Pos;
    fn scalar<const N: usize>(&mut self, bytes: [u8; N]) -> Pos;
    fn scalar_vector<const N: usize, const ALIGN: usize>(
        &mut self,
        count: usize,
        items: impl Iterator<Item = [u8; N]>,
    ) -> Pos;
    fn vector_begin(&mut self, count: usize) -> VectorToken;
    fn vector_item(&mut self, vector: &mut VectorToken, item: Pos);
    fn vector_end(&mut self, vector: VectorToken) -> Pos;
    fn table<const LEN: usize, const ALIGN: usize>(
        &mut self,
        vtable: usize,
    ) -> Self::Table<'_, LEN>;

    fn bytes(&mut self, data: &[u8]) -> Pos {
        self.blob(data.len(), |dst| dst.copy_from_slice(data))
    }
}

pub trait TableSink: Sized {
    fn start(&self) -> Pos;
    fn put<const OFF: usize, const N: usize>(&mut self, bytes: [u8; N]);
    fn end(self) -> Pos;

    fn u8<const OFF: usize>(&mut self, value: u8) {
        self.put::<OFF, 1>([value]);
    }

    fn bool<const OFF: usize>(&mut self, value: bool) {
        self.put::<OFF, 1>([u8::from(value)]);
    }

    fn i8<const OFF: usize>(&mut self, value: i8) {
        self.put::<OFF, 1>(value.to_le_bytes());
    }

    fn u16<const OFF: usize>(&mut self, value: u16) {
        self.put::<OFF, 2>(value.to_le_bytes());
    }

    fn i16<const OFF: usize>(&mut self, value: i16) {
        self.put::<OFF, 2>(value.to_le_bytes());
    }

    fn u32<const OFF: usize>(&mut self, value: u32) {
        self.put::<OFF, 4>(value.to_le_bytes());
    }

    fn i32<const OFF: usize>(&mut self, value: i32) {
        self.put::<OFF, 4>(value.to_le_bytes());
    }

    fn u64<const OFF: usize>(&mut self, value: u64) {
        self.put::<OFF, 8>(value.to_le_bytes());
    }

    fn i64<const OFF: usize>(&mut self, value: i64) {
        self.put::<OFF, 8>(value.to_le_bytes());
    }

    fn f64<const OFF: usize>(&mut self, value: f64) {
        self.put::<OFF, 8>(value.to_le_bytes());
    }

    fn uid<const OFF: usize>(&mut self, value: Uid) {
        self.put::<OFF, 16>(value.to_le_bytes());
    }

    fn offset<const OFF: usize>(&mut self, target: Pos) {
        let relative = (self.start() - OFF - target) as u32;
        self.put::<OFF, 4>(relative.to_le_bytes());
    }

    fn optional<const TAG: usize, const OFF: usize>(&mut self, target: Option<Pos>) {
        if let Some(target) = target {
            self.u8::<TAG>(1);
            self.offset::<OFF>(target);
        }
    }

    fn union<const TAG: usize, const OFF: usize>(&mut self, alternative: Option<(u8, Pos)>) {
        if let Some((tag, target)) = alternative {
            self.u8::<TAG>(tag);
            self.offset::<OFF>(target);
        }
    }
}

#[derive(Debug)]
pub struct VectorToken {
    count: usize,
    slot: usize,
    body: Pos,
    next: usize,
}

#[derive(Debug, Default)]
pub struct Measure {
    pos: Pos,
    empty: Option<Pos>,
    slots: Slots,
}

#[derive(Debug, Clone, Copy)]
pub struct MeasureTable {
    start: Pos,
}

pub struct Writer<'b> {
    buf: &'b mut [u8],
    pos: Pos,
    empty: Option<Pos>,
    vtable_start: Pos,
    slots: &'b Slots,
    next_slot: usize,
}

pub struct WriteTable<'s, const LEN: usize> {
    table: &'s mut [u8],
    start: Pos,
}

#[derive(Debug, Default)]
struct Slots {
    inline: [Pos; INLINE_SLOTS],
    len: usize,
    spill: Vec<Pos>,
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

const fn assert_align<const ALIGN: usize>() {
    assert!(ALIGN.is_power_of_two() && ALIGN >= MIN_ALIGN);
}

pub fn encode(message: &impl Encode, out: &mut Vec<u8>) -> usize {
    let mut measure = Measure::default();
    message.layout(&mut measure);
    let vtables = message.vtables();
    let content = measure.pos;
    let vtable_start = content + vtables.len();
    let total = align_up(vtable_start + HEADER_LEN, ROOT_ALIGN);
    let start = out.len();
    out.resize(start + total, 0);
    let (_, buf) = out.split_at_mut(start);
    let (prefix, body) = buf.split_at_mut(total - content);
    let mut writer = Writer {
        buf: body,
        pos: 0,
        empty: None,
        vtable_start,
        slots: &measure.slots,
        next_slot: 0,
    };
    let root = message.layout(&mut writer);
    let (header, rest) = prefix.split_at_mut(HEADER_LEN);
    let (_, block) = rest.split_at_mut(rest.len() - vtables.len());
    block.copy_from_slice(vtables);
    let (root_offset, file_identifier) = header.split_at_mut(LEN_PREFIX);
    root_offset.copy_from_slice(&((total - root) as u32).to_le_bytes());
    file_identifier.copy_from_slice(&message.file_identifier().to_le_bytes());
    total
}

impl Measure {
    fn empty_vector(&mut self) -> Pos {
        if let Some(empty) = self.empty {
            return empty;
        }
        self.pos = align_up(self.pos, MIN_ALIGN) + LEN_PREFIX;
        self.empty = Some(self.pos);
        self.pos
    }
}

impl Sink for Measure {
    type Table<'s, const LEN: usize> = MeasureTable;

    fn blob(&mut self, len: usize, _fill: impl FnOnce(&mut [u8])) -> Pos {
        if len == 0 {
            return self.empty_vector();
        }
        self.pos = align_up(self.pos + len + LEN_PREFIX, MIN_ALIGN);
        self.pos
    }

    fn scalar<const N: usize>(&mut self, _bytes: [u8; N]) -> Pos {
        self.pos += N;
        self.pos
    }

    fn scalar_vector<const N: usize, const ALIGN: usize>(
        &mut self,
        count: usize,
        _items: impl Iterator<Item = [u8; N]>,
    ) -> Pos {
        const { assert_align::<ALIGN>() };
        if count == 0 {
            return self.empty_vector();
        }
        self.pos = align_up(self.pos + count * N, ALIGN) + LEN_PREFIX;
        self.pos
    }

    fn vector_begin(&mut self, count: usize) -> VectorToken {
        let slot = if count == 0 { 0 } else { self.slots.push() };
        VectorToken {
            count,
            slot,
            body: 0,
            next: 0,
        }
    }

    fn vector_item(&mut self, _vector: &mut VectorToken, _item: Pos) {}

    fn vector_end(&mut self, vector: VectorToken) -> Pos {
        if vector.count == 0 {
            return self.empty_vector();
        }
        self.pos = align_up(self.pos + vector.count * OFFSET_LEN, MIN_ALIGN) + LEN_PREFIX;
        self.slots.set(vector.slot, self.pos);
        self.pos
    }

    fn table<const LEN: usize, const ALIGN: usize>(&mut self, _vtable: usize) -> MeasureTable {
        const { assert_align::<ALIGN>() };
        self.pos = align_up(self.pos + LEN - OFFSET_LEN, ALIGN) + OFFSET_LEN;
        MeasureTable { start: self.pos }
    }
}

impl TableSink for MeasureTable {
    fn start(&self) -> Pos {
        self.start
    }

    fn put<const OFF: usize, const N: usize>(&mut self, _bytes: [u8; N]) {}

    fn end(self) -> Pos {
        self.start
    }
}

impl<'b> Writer<'b> {
    fn reserve(&mut self, start: Pos) -> &mut [u8] {
        let total = self.buf.len();
        let end = total - self.pos;
        self.pos = start;
        &mut self.buf[total - start..end]
    }

    fn empty_vector(&mut self) -> Pos {
        if let Some(empty) = self.empty {
            return empty;
        }
        let start = align_up(self.pos, MIN_ALIGN) + LEN_PREFIX;
        self.reserve(start);
        self.empty = Some(start);
        start
    }
}

impl<'b> Sink for Writer<'b> {
    type Table<'s, const LEN: usize>
        = WriteTable<'s, LEN>
    where
        Self: 's;

    fn blob(&mut self, len: usize, fill: impl FnOnce(&mut [u8])) -> Pos {
        if len == 0 {
            return self.empty_vector();
        }
        let start = align_up(self.pos + len + LEN_PREFIX, MIN_ALIGN);
        let chunk = self.reserve(start);
        let (prefix, rest) = chunk.split_at_mut(LEN_PREFIX);
        prefix.copy_from_slice(&(len as u32).to_le_bytes());
        fill(&mut rest[..len]);
        start
    }

    fn scalar<const N: usize>(&mut self, bytes: [u8; N]) -> Pos {
        let start = self.pos + N;
        self.reserve(start).copy_from_slice(&bytes);
        start
    }

    fn scalar_vector<const N: usize, const ALIGN: usize>(
        &mut self,
        count: usize,
        items: impl Iterator<Item = [u8; N]>,
    ) -> Pos {
        const { assert_align::<ALIGN>() };
        if count == 0 {
            return self.empty_vector();
        }
        let start = align_up(self.pos + count * N, ALIGN) + LEN_PREFIX;
        let chunk = self.reserve(start);
        let (prefix, rest) = chunk.split_at_mut(LEN_PREFIX);
        prefix.copy_from_slice(&(count as u32).to_le_bytes());
        for (dst, item) in rest[..count * N]
            .as_chunks_mut::<N>()
            .0
            .iter_mut()
            .zip(items)
        {
            *dst = item;
        }
        start
    }

    fn vector_begin(&mut self, count: usize) -> VectorToken {
        let body = if count == 0 {
            0
        } else {
            let body = self.slots.get(self.next_slot);
            self.next_slot += 1;
            body
        };
        VectorToken {
            count,
            slot: 0,
            body,
            next: 0,
        }
    }

    fn vector_item(&mut self, vector: &mut VectorToken, item: Pos) {
        debug_assert!(vector.next < vector.count);
        if vector.next >= vector.count {
            return;
        }
        let field = vector.body - LEN_PREFIX - vector.next * OFFSET_LEN;
        let total = self.buf.len();
        let relative = (field - item) as u32;
        self.buf[total - field..total - field + OFFSET_LEN]
            .copy_from_slice(&relative.to_le_bytes());
        vector.next += 1;
    }

    fn vector_end(&mut self, vector: VectorToken) -> Pos {
        debug_assert_eq!(vector.next, vector.count);
        if vector.count == 0 {
            return self.empty_vector();
        }
        let chunk = self.reserve(vector.body);
        chunk[..LEN_PREFIX].copy_from_slice(&(vector.count as u32).to_le_bytes());
        vector.body
    }

    fn table<const LEN: usize, const ALIGN: usize>(
        &mut self,
        vtable: usize,
    ) -> WriteTable<'_, LEN> {
        const { assert_align::<ALIGN>() };
        let start = align_up(self.pos + LEN - OFFSET_LEN, ALIGN) + OFFSET_LEN;
        let soffset = (self.vtable_start - vtable - start) as i32;
        let table = &mut self.reserve(start)[..LEN];
        table[..OFFSET_LEN].copy_from_slice(&soffset.to_le_bytes());
        WriteTable { table, start }
    }
}

impl<const LEN: usize> TableSink for WriteTable<'_, LEN> {
    fn start(&self) -> Pos {
        self.start
    }

    fn put<const OFF: usize, const N: usize>(&mut self, bytes: [u8; N]) {
        const { assert!(OFF >= OFFSET_LEN && OFF + N <= LEN) };
        self.table[OFF..OFF + N].copy_from_slice(&bytes);
    }

    fn end(self) -> Pos {
        self.start
    }
}

impl Slots {
    fn push(&mut self) -> usize {
        let index = self.len;
        if index >= INLINE_SLOTS {
            self.spill.push(0);
        }
        self.len += 1;
        index
    }

    fn set(&mut self, index: usize, value: Pos) {
        if let Some(slot) = self.inline.get_mut(index) {
            *slot = value;
        } else if let Some(slot) = self.spill.get_mut(index - INLINE_SLOTS) {
            *slot = value;
        }
    }

    fn get(&self, index: usize) -> Pos {
        match self.inline.get(index) {
            Some(slot) => *slot,
            None => self
                .spill
                .get(index - INLINE_SLOTS)
                .copied()
                .unwrap_or_default(),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/codec/write/tests.rs"]
mod tests;
