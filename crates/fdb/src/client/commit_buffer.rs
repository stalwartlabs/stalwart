/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::{
    KEYSPACE_END, MAX_KEY_SIZE, MAX_TRANSACTION_SIZE, MAX_VALUE_SIZE,
    error::{Error, ErrorCode, Result},
    transaction::AtomicOp,
};
use std::{iter::FusedIterator, slice};
use write_index::WriteIndex;

pub(crate) use merge::Merged;
pub(crate) use write_index::{Lookup, PendingOps};

mod merge;
mod write_index;

const SELF_CONFLICT_PREFIX: &[u8; 5] = b"\xff/SC/";
const SELF_CONFLICT_KEY_LEN: usize = SELF_CONFLICT_PREFIX.len() + 16;
const MUTATION_REF_SIZE: usize = 44;
const KEY_RANGE_REF_SIZE: usize = 24;
const WRITE_OVERHEAD: usize = MUTATION_REF_SIZE + KEY_RANGE_REF_SIZE;
const CLEAR_SPLIT_OVERHEAD: usize = MUTATION_REF_SIZE - KEY_RANGE_REF_SIZE;
const LARGE_VALUE: usize = 16 << 10;

const _: () = assert!(MAX_KEY_SIZE + 1 < LARGE_VALUE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MutationKind {
    SetValue = 0,
    ClearRange = 1,
    AddValue = 2,
    AppendIfFits = 9,
    CompareAndClear = 20,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mutation<'a> {
    pub(crate) kind: MutationKind,
    pub(crate) param1: &'a [u8],
    pub(crate) param2: &'a [u8],
}

#[derive(Debug, Default)]
pub(crate) struct CommitBuffer {
    writes: Vec<u8>,
    values: Vec<Box<[u8]>>,
    mutations: Vec<Record>,
    write_ranges: Vec<RangeSpan>,
    reads: Vec<u8>,
    read_ranges: Vec<RangeSpan>,
    read_segments: Vec<u32>,
    write_size: usize,
    read_size: usize,
    split_charged: u32,
    cleared_range: bool,
    failed: Option<Error>,
    self_conflict: [u8; SELF_CONFLICT_KEY_LEN + 1],
    index: Option<Box<WriteIndex>>,
}

pub(crate) struct CommitView<'a> {
    pub(crate) mutations: Mutations<'a>,
    pub(crate) reads: Ranges<'a>,
    pub(crate) writes: Ranges<'a>,
    pub(crate) conflict_key: &'a [u8],
}

#[derive(Debug, Clone)]
pub(crate) struct Mutations<'a> {
    buffer: &'a CommitBuffer,
    records: slice::Iter<'a, Record>,
}

#[derive(Debug, Clone)]
pub(crate) struct Ranges<'a> {
    arena: &'a [u8],
    spans: slice::Iter<'a, RangeSpan>,
    tail: Option<(&'a [u8], &'a [u8])>,
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: u32,
    len: u32,
}

#[derive(Debug, Clone, Copy)]
struct RangeSpan {
    begin: Span,
    end: Span,
}

#[derive(Debug, Clone, Copy)]
struct Record {
    kind: MutationKind,
    param1: Span,
    param2: Span,
}

impl From<AtomicOp> for MutationKind {
    fn from(op: AtomicOp) -> Self {
        match op {
            AtomicOp::Add => MutationKind::AddValue,
            AtomicOp::AppendIfFits => MutationKind::AppendIfFits,
            AtomicOp::CompareAndClear => MutationKind::CompareAndClear,
        }
    }
}

const _: () = assert!(2 * MAX_TRANSACTION_SIZE < u32::MAX as usize);

impl Span {
    fn push(arena: &mut Vec<u8>, bytes: &[u8]) -> Span {
        let span = Span {
            start: arena.len() as u32,
            len: bytes.len() as u32,
        };
        arena.extend_from_slice(bytes);
        span
    }

    fn push_value(arena: &mut Vec<u8>, values: &mut Vec<Box<[u8]>>, value: &[u8]) -> Span {
        if value.len() < LARGE_VALUE {
            return Span::push(arena, value);
        }
        let span = Span {
            start: values.len() as u32,
            len: value.len() as u32,
        };
        values.push(value.into());
        span
    }

    fn push_key(arena: &mut Vec<u8>, key: &[u8]) -> Span {
        let span = Span::push(arena, key);
        arena.push(0);
        span
    }

    fn with_nul(self) -> Span {
        Span {
            start: self.start,
            len: self.len + 1,
        }
    }

    fn len(self) -> usize {
        self.len as usize
    }

    fn get(self, arena: &[u8]) -> &[u8] {
        debug_assert!(self.len() < LARGE_VALUE);
        let start = self.start as usize;
        let bytes = arena.get(start..start + self.len());
        debug_assert!(bytes.is_some());
        bytes.unwrap_or_default()
    }

    fn value<'a>(self, arena: &'a [u8], values: &'a [Box<[u8]>]) -> &'a [u8] {
        if self.len() < LARGE_VALUE {
            return self.get(arena);
        }
        let value = values.get(self.start as usize);
        debug_assert!(value.is_some_and(|value| value.len() == self.len()));
        value.map_or(&[], |value| value)
    }
}

impl Record {
    fn read_split_cost(&self) -> usize {
        match self.kind {
            MutationKind::SetValue => KEY_RANGE_REF_SIZE + 2 * self.param1.len() + 1,
            MutationKind::ClearRange => KEY_RANGE_REF_SIZE + self.param1.len() + self.param2.len(),
            _ => 0,
        }
    }

    fn write_conflict(&self) -> RangeSpan {
        match self.kind {
            MutationKind::ClearRange => RangeSpan {
                begin: self.param1,
                end: self.param2,
            },
            _ => RangeSpan {
                begin: self.param1,
                end: self.param1.with_nul(),
            },
        }
    }
}

impl CommitBuffer {
    pub(crate) fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.mutate(|buffer| {
            check_write(key, value)?;
            buffer.reserve(3 * key.len() + 1 + value.len() + buffer.keyed_overhead())?;
            buffer.push_keyed(MutationKind::SetValue, key, value);
            Ok(())
        })
    }

    pub(crate) fn atomic_op(&mut self, key: &[u8], param: &[u8], op: AtomicOp) -> Result<()> {
        self.mutate(|buffer| {
            check_write(key, param)?;
            buffer.reserve(3 * key.len() + 1 + param.len() + buffer.keyed_overhead())?;
            buffer.push_keyed(op.into(), key, param);
            Ok(())
        })
    }

    pub(crate) fn clear(&mut self, key: &[u8]) -> Result<()> {
        self.mutate(|buffer| {
            if key >= KEYSPACE_END {
                return Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE));
            }
            if key.len() > MAX_KEY_SIZE {
                return Ok(());
            }
            buffer.reserve(4 * key.len() + 2 + WRITE_OVERHEAD)?;
            let param1 = Span::push_key(&mut buffer.writes, key);
            buffer.push(Record {
                kind: MutationKind::ClearRange,
                param1,
                param2: param1.with_nul(),
            });
            Ok(())
        })
    }

    pub(crate) fn clear_range(&mut self, begin: &[u8], end: &[u8]) -> Result<()> {
        self.mutate(|buffer| {
            if begin > end {
                return Err(Error::new(ErrorCode::INVERTED_RANGE));
            }
            if end > KEYSPACE_END {
                return Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE));
            }
            let (begin, end) = (truncate(begin), truncate(end));
            if begin == end {
                return Ok(());
            }
            buffer.reserve(2 * (begin.len() + end.len()) + WRITE_OVERHEAD)?;
            let param1 = Span::push(&mut buffer.writes, begin);
            let param2 = Span::push(&mut buffer.writes, end);
            buffer.push(Record {
                kind: MutationKind::ClearRange,
                param1,
                param2,
            });
            buffer.cleared_range = true;
            buffer.split_read_segment();
            Ok(())
        })
    }

    pub(crate) fn read_key(&mut self, key: &[u8]) {
        if key < KEYSPACE_END && key.len() <= MAX_KEY_SIZE && !self.overflowed() {
            let begin = Span::push_key(&mut self.reads, key);
            self.add_read(RangeSpan {
                begin,
                end: begin.with_nul(),
            });
        }
    }

    pub(crate) fn read_range(&mut self, begin: &[u8], end: &[u8]) {
        let (begin, end) = (truncate(begin), truncate(end.min(KEYSPACE_END)));
        if begin < end && !self.overflowed() {
            self.charge_read_splits();
            let begin = Span::push(&mut self.reads, begin);
            let end = Span::push(&mut self.reads, end);
            self.add_read(RangeSpan { begin, end });
        }
    }

    pub(crate) fn check(&self) -> Result<()> {
        self.failed.map_or(Ok(()), Err)
    }

    pub(crate) fn size(&self) -> usize {
        self.write_size + self.read_size
    }

    pub(crate) fn has_mutations(&self) -> bool {
        !self.mutations.is_empty()
    }

    pub(crate) fn clear_all(&mut self) {
        self.writes.clear();
        self.values.clear();
        self.mutations.clear();
        self.write_ranges.clear();
        self.reads.clear();
        self.read_ranges.clear();
        self.read_segments.clear();
        self.write_size = 0;
        self.read_size = 0;
        self.split_charged = 0;
        self.cleared_range = false;
        self.failed = None;
        if let Some(index) = &mut self.index {
            index.clear();
        }
    }

    pub(crate) fn lookup(&mut self, key: &[u8]) -> Lookup {
        if self.mutations.is_empty() {
            return Lookup::Unmodified;
        }
        self.index
            .get_or_insert_with(|| Box::new(WriteIndex::build(&self.writes, &self.mutations)))
            .lookup(&self.writes, &self.values, &self.mutations, key)
    }

    pub(crate) fn prepare(&mut self, self_conflict: [u8; 16]) -> Result<Option<CommitView<'_>>> {
        self.check()?;
        if self.mutations.is_empty() {
            return Ok(None);
        }
        if self.overflowed() {
            return Err(Error::new(ErrorCode::TRANSACTION_TOO_LARGE));
        }
        self.write_ranges.clear();
        self.write_ranges
            .extend(self.mutations.iter().map(Record::write_conflict));
        coalesce(&self.writes, &mut self.write_ranges, &mut []);
        coalesce(&self.reads, &mut self.read_ranges, &mut []);
        self.read_segments.clear();
        let (conflict_key, tail) = match first_intersection(
            &self.writes,
            &self.write_ranges,
            &self.reads,
            &self.read_ranges,
        ) {
            Some(Conflict::Write(span)) => (span.get(&self.writes), None),
            Some(Conflict::Read(span)) => (span.get(&self.reads), None),
            None => {
                let bytes = SELF_CONFLICT_PREFIX.iter().chain(&self_conflict);
                for (byte, value) in self.self_conflict.iter_mut().zip(bytes) {
                    *byte = *value;
                }
                let range = self.self_conflict.as_slice();
                let key = range.split_last().map_or(range, |(_, key)| key);
                (key, Some((key, range)))
            }
        };
        Ok(Some(CommitView {
            mutations: Mutations {
                buffer: self,
                records: self.mutations.iter(),
            },
            reads: Ranges {
                arena: &self.reads,
                spans: self.read_ranges.iter(),
                tail,
            },
            writes: Ranges {
                arena: &self.writes,
                spans: self.write_ranges.iter(),
                tail,
            },
            conflict_key,
        }))
    }

    fn mutate(&mut self, op: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        self.check()?;
        op(self).inspect_err(|error| self.failed = Some(*error))
    }

    fn push_keyed(&mut self, kind: MutationKind, key: &[u8], param: &[u8]) {
        let param1 = Span::push_key(&mut self.writes, key);
        let param2 = Span::push_value(&mut self.writes, &mut self.values, param);
        self.push(Record {
            kind,
            param1,
            param2,
        });
    }

    fn push(&mut self, record: Record) {
        if let Some(index) = &mut self.index {
            index.insert(&self.writes, &record);
        }
        self.mutations.push(record);
    }

    fn keyed_overhead(&self) -> usize {
        if self.cleared_range {
            WRITE_OVERHEAD + CLEAR_SPLIT_OVERHEAD
        } else {
            WRITE_OVERHEAD
        }
    }

    fn split_read_segment(&mut self) {
        let start = self.read_segments.last().map_or(0, |&start| start as usize);
        if self.read_ranges.len() > start {
            self.read_segments.push(self.read_ranges.len() as u32);
        }
    }

    fn charge_read_splits(&mut self) {
        if let Some(records) = self.mutations.get(self.split_charged as usize..) {
            self.write_size += records.iter().map(Record::read_split_cost).sum::<usize>();
        }
        self.split_charged = self.mutations.len() as u32;
    }

    fn overflowed(&self) -> bool {
        self.size() > MAX_TRANSACTION_SIZE
    }

    fn reserve(&mut self, cost: usize) -> Result<()> {
        if !self.overflowed() && self.size() + cost > MAX_TRANSACTION_SIZE {
            self.recount_reads();
        }
        if self.size() + cost > MAX_TRANSACTION_SIZE {
            return Err(Error::new(ErrorCode::TRANSACTION_TOO_LARGE));
        }
        self.write_size += cost;
        Ok(())
    }

    fn add_read(&mut self, range: RangeSpan) {
        self.read_size += range.begin.len() + range.end.len() + KEY_RANGE_REF_SIZE;
        self.read_ranges.push(range);
        if self.overflowed() {
            self.recount_reads();
        }
    }

    fn recount_reads(&mut self) {
        coalesce(&self.reads, &mut self.read_ranges, &mut self.read_segments);
        let bytes: usize = self
            .read_ranges
            .iter()
            .map(|range| range.begin.len() + range.end.len())
            .sum();
        self.read_size = bytes + self.read_ranges.len() * KEY_RANGE_REF_SIZE;
        let mut reads = Vec::with_capacity(bytes);
        for range in &mut self.read_ranges {
            let (begin, end) = (range.begin.get(&self.reads), range.end.get(&self.reads));
            *range = if end.strip_prefix(begin) == Some(&[0]) {
                let begin = Span::push_key(&mut reads, begin);
                RangeSpan {
                    begin,
                    end: begin.with_nul(),
                }
            } else {
                RangeSpan {
                    begin: Span::push(&mut reads, begin),
                    end: Span::push(&mut reads, end),
                }
            };
        }
        self.reads = reads;
    }
}

enum Conflict {
    Write(Span),
    Read(Span),
}

fn check_write(key: &[u8], param: &[u8]) -> Result<()> {
    if key >= KEYSPACE_END {
        Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE))
    } else if key.len() > MAX_KEY_SIZE {
        Err(Error::new(ErrorCode::KEY_TOO_LARGE))
    } else if param.len() > MAX_VALUE_SIZE {
        Err(Error::new(ErrorCode::VALUE_TOO_LARGE))
    } else {
        Ok(())
    }
}

fn truncate(key: &[u8]) -> &[u8] {
    key.get(..=MAX_KEY_SIZE).unwrap_or(key)
}

fn coalesce(arena: &[u8], ranges: &mut Vec<RangeSpan>, segments: &mut [u32]) {
    let mut start = 0;
    for end in segments
        .iter()
        .map(|&end| end as usize)
        .chain([ranges.len()])
    {
        if let Some(segment) = ranges.get_mut(start..end) {
            segment.sort_unstable_by(|a, b| a.begin.get(arena).cmp(b.begin.get(arena)));
        }
        start = end;
    }
    let mut starts = segments.iter_mut().peekable();
    let (mut position, mut kept) = (0, 0);
    ranges.dedup_by(|next, current| {
        position += 1;
        if let Some(start) = starts.next_if(|start| **start as usize == position) {
            kept += 1;
            *start = kept;
            return false;
        }
        if next.begin.get(arena) > current.end.get(arena) {
            kept += 1;
            return false;
        }
        if next.end.get(arena) > current.end.get(arena) {
            current.end = next.end;
        }
        true
    });
    let len = ranges.len() as u32;
    starts.for_each(|start| *start = len);
}

fn first_intersection(
    writes: &[u8],
    write_ranges: &[RangeSpan],
    reads: &[u8],
    read_ranges: &[RangeSpan],
) -> Option<Conflict> {
    let mut write_ranges = write_ranges.iter().peekable();
    let mut read_ranges = read_ranges.iter().peekable();
    while let (Some(write), Some(read)) = (write_ranges.peek(), read_ranges.peek()) {
        let (write_begin, read_begin) = (write.begin.get(writes), read.begin.get(reads));
        if write.end.get(writes) <= read_begin {
            write_ranges.next();
        } else if read.end.get(reads) <= write_begin {
            read_ranges.next();
        } else if write_begin >= read_begin {
            return Some(Conflict::Write(write.begin));
        } else {
            return Some(Conflict::Read(read.begin));
        }
    }
    None
}

impl CommitView<'_> {
    pub(crate) fn size(&self) -> usize {
        self.mutations.buffer.size()
    }
}

impl<'a> Iterator for Mutations<'a> {
    type Item = Mutation<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let CommitBuffer { writes, values, .. } = self.buffer;
        self.records.next().map(|record| Mutation {
            kind: record.kind,
            param1: record.param1.get(writes),
            param2: record.param2.value(writes, values),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.records.size_hint()
    }
}

impl ExactSizeIterator for Mutations<'_> {}

impl FusedIterator for Mutations<'_> {}

impl<'a> Iterator for Ranges<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        match self.spans.next() {
            Some(span) => Some((span.begin.get(self.arena), span.end.get(self.arena))),
            None => self.tail.take(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.spans.len() + usize::from(self.tail.is_some());
        (len, Some(len))
    }
}

impl ExactSizeIterator for Ranges<'_> {}

impl FusedIterator for Ranges<'_> {}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/commit_buffer/tests.rs"]
mod tests;
