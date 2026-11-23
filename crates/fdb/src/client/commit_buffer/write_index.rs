/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MutationKind, Record, Span};
use crate::api::{MAX_VALUE_SIZE, range::Direction};
use bytes::Bytes;
use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    mem,
    ops::Range,
};
use xxhash_rust::xxh3::xxh3_64_with_seed;

const NO_RECORD: u32 = u32::MAX;
const OP_HEADER: usize = 5;

#[derive(Debug)]
pub(super) struct WriteIndex {
    seed: u64,
    heads: HashMap<u64, u32, BuildHasherDefault<KeyHash>>,
    prev: Vec<u32>,
    clears: Vec<u32>,
    scratch: Vec<u32>,
    sorted: Vec<u32>,
    sorted_for: usize,
    by_begin: Vec<u32>,
    covered: Vec<(Span, Span)>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    Unmodified,
    Known(Option<Bytes>),
    Dependent(PendingOps),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PendingOps(Box<[u8]>);

#[derive(Default)]
struct KeyHash(u64);

impl Hasher for KeyHash {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = xxh3_64_with_seed(bytes, self.0);
    }

    fn write_u64(&mut self, hash: u64) {
        self.0 = hash;
    }
}

impl WriteIndex {
    pub(super) fn build(arena: &[u8], records: &[Record]) -> Self {
        let mut index = WriteIndex {
            seed: fastrand::u64(..),
            heads: HashMap::default(),
            prev: Vec::with_capacity(records.len()),
            clears: Vec::new(),
            scratch: Vec::new(),
            sorted: Vec::new(),
            sorted_for: 0,
            by_begin: Vec::new(),
            covered: Vec::new(),
        };
        for record in records {
            index.insert(arena, record);
        }
        index
    }

    pub(super) fn insert(&mut self, arena: &[u8], record: &Record) {
        let position = self.prev.len() as u32;
        let link = match record.key(arena) {
            Some(key) => self
                .heads
                .insert(xxh3_64_with_seed(key, self.seed), position)
                .unwrap_or(NO_RECORD),
            None => {
                self.clears.push(position);
                NO_RECORD
            }
        };
        self.prev.push(link);
    }

    pub(super) fn clear(&mut self) {
        self.heads.clear();
        self.prev.clear();
        self.clears.clear();
        self.sorted.clear();
        self.sorted_for = 0;
        self.by_begin.clear();
        self.covered.clear();
    }

    pub(super) fn written_in(
        &mut self,
        arena: &[u8],
        records: &[Record],
        low: &[u8],
        high: &[u8],
        out: &mut Vec<u32>,
    ) {
        let key = |position: u32| {
            records
                .get(position as usize)
                .and_then(|record| record.key(arena))
                .unwrap_or_default()
        };
        if self.sorted_for != self.prev.len() {
            let pending = records
                .get(self.sorted_for..)
                .unwrap_or_default()
                .iter()
                .zip(self.sorted_for as u32..)
                .filter(|(record, _)| record.key(arena).is_some())
                .map(|(_, position)| position);
            absorb(&mut self.sorted, &mut self.scratch, pending, key);
            self.sorted_for = self.prev.len();
        }
        let start = self.sorted.partition_point(|&position| key(position) < low);
        let end = self
            .sorted
            .partition_point(|&position| key(position) < high);
        out.extend(self.sorted.get(start..end).unwrap_or_default());
    }

    pub(super) fn cleared_in(
        &mut self,
        arena: &[u8],
        records: &[Record],
        low: &[u8],
        high: &[u8],
    ) -> Range<usize> {
        self.sync_clears(arena, records);
        let start = self
            .covered
            .partition_point(|(_, end)| end.get(arena) <= low);
        let end = self
            .covered
            .partition_point(|(begin, _)| begin.get(arena) < high);
        start..end
    }

    pub(super) fn is_cleared(
        &self,
        arena: &[u8],
        span: &mut Range<usize>,
        key: &[u8],
        direction: Direction,
    ) -> bool {
        let mut covered = self.covered.get(span.clone()).unwrap_or_default();
        match direction {
            Direction::Forward => {
                let cleared = loop {
                    match covered.split_first() {
                        Some(((_, end), rest)) if end.get(arena) <= key => covered = rest,
                        Some(((begin, _), _)) => break begin.get(arena) <= key,
                        None => break false,
                    }
                };
                span.start = span.end - covered.len();
                cleared
            }
            Direction::Reverse => {
                let cleared = loop {
                    match covered.split_last() {
                        Some(((begin, _), rest)) if begin.get(arena) > key => covered = rest,
                        Some(((_, end), _)) => break key < end.get(arena),
                        None => break false,
                    }
                };
                span.end = span.start + covered.len();
                cleared
            }
        }
    }

    pub(super) fn skip_cleared<'a>(
        &mut self,
        arena: &'a [u8],
        records: &[Record],
        edge: &'a [u8],
        direction: Direction,
    ) -> &'a [u8] {
        self.sync_clears(arena, records);
        match direction {
            Direction::Forward => self
                .component(arena, edge)
                .map_or(edge, |(_, end)| end.get(arena)),
            Direction::Reverse => self
                .covered
                .partition_point(|(begin, _)| begin.get(arena) < edge)
                .checked_sub(1)
                .and_then(|last| self.covered.get(last))
                .filter(|(_, end)| edge <= end.get(arena))
                .map_or(edge, |(begin, _)| begin.get(arena)),
        }
    }

    fn component(&self, arena: &[u8], key: &[u8]) -> Option<(Span, Span)> {
        self.covered
            .partition_point(|(begin, _)| begin.get(arena) <= key)
            .checked_sub(1)
            .and_then(|last| self.covered.get(last))
            .filter(|(_, end)| key < end.get(arena))
            .copied()
    }

    fn sync_clears(&mut self, arena: &[u8], records: &[Record]) {
        if self.by_begin.len() == self.clears.len() {
            return;
        }
        let pending = self.clears.get(self.by_begin.len()..).unwrap_or_default();
        absorb(
            &mut self.by_begin,
            &mut self.scratch,
            pending.iter().copied(),
            |position| (begin(arena, records, position), position),
        );
        self.covered.clear();
        for record in self
            .by_begin
            .iter()
            .filter_map(|&position| records.get(position as usize))
        {
            match self.covered.last_mut() {
                Some((_, end)) if record.param1.get(arena) <= end.get(arena) => {
                    if record.param2.get(arena) > end.get(arena) {
                        *end = record.param2;
                    }
                }
                _ => self.covered.push((record.param1, record.param2)),
            }
        }
    }

    pub(super) fn lookup(
        &mut self,
        arena: &[u8],
        values: &[Box<[u8]>],
        records: &[Record],
        key: &[u8],
    ) -> Lookup {
        self.sync_clears(arena, records);
        self.scratch.clear();
        let mut base = None;
        let mut link = self
            .heads
            .get(&xxh3_64_with_seed(key, self.seed))
            .copied()
            .unwrap_or(NO_RECORD);
        while let Some(record) = records.get(link as usize) {
            if record.key(arena) == Some(key) {
                match record.kind {
                    MutationKind::SetValue => {
                        base = Some((link, Some(record.param2.value(arena, values))));
                        break;
                    }
                    MutationKind::ClearRange => {
                        base = Some((link, None));
                        break;
                    }
                    _ => self.scratch.push(link),
                }
            }
            link = self.prev.get(link as usize).copied().unwrap_or(NO_RECORD);
        }
        let floor = base.map(|(position, _)| position);
        let candidates = self.component(arena, key).map_or(&[][..], |(low, _)| {
            let low = low.get(arena);
            let first = self
                .by_begin
                .partition_point(|&position| begin(arena, records, position) < low);
            let upto = self
                .by_begin
                .partition_point(|&position| begin(arena, records, position) <= key);
            self.by_begin.get(first..upto).unwrap_or_default()
        });
        let cleared = candidates
            .iter()
            .copied()
            .filter(|&position| floor.is_none_or(|floor| position > floor))
            .filter(|&position| {
                records
                    .get(position as usize)
                    .is_some_and(|record| record.covers(arena, key))
            })
            .max();
        if let Some(cleared) = cleared {
            base = Some((cleared, None));
            self.scratch.retain(|&position| position > cleared);
        }
        let ops = self
            .scratch
            .iter()
            .rev()
            .filter_map(|&position| records.get(position as usize));
        match base {
            None if self.scratch.is_empty() => Lookup::Unmodified,
            None => Lookup::Dependent(PendingOps::capture(arena, values, ops)),
            Some((_, value)) if self.scratch.is_empty() => {
                Lookup::Known(value.map(Bytes::copy_from_slice))
            }
            Some((_, value)) => {
                let mut value = value.map(<[u8]>::to_vec);
                for record in ops {
                    apply(&mut value, record.kind, record.param2.value(arena, values));
                }
                Lookup::Known(value.map(Bytes::from))
            }
        }
    }
}

impl Record {
    pub(super) fn key<'a>(&self, arena: &'a [u8]) -> Option<&'a [u8]> {
        let key = self.param1.get(arena);
        match self.kind {
            MutationKind::ClearRange => {
                let (nul, end) = self.param2.get(arena).split_last()?;
                (*nul == 0 && end == key).then_some(key)
            }
            _ => Some(key),
        }
    }

    fn covers(&self, arena: &[u8], key: &[u8]) -> bool {
        self.param1.get(arena) <= key && key < self.param2.get(arena)
    }
}

impl PendingOps {
    fn capture<'a>(
        arena: &[u8],
        values: &[Box<[u8]>],
        ops: impl Iterator<Item = &'a Record> + Clone,
    ) -> Self {
        let size = ops
            .clone()
            .map(|record| OP_HEADER + record.param2.len())
            .sum();
        let mut buffer = Vec::with_capacity(size);
        for record in ops {
            let param = record.param2.value(arena, values);
            buffer.push(record.kind as u8);
            buffer.extend_from_slice(&record.param2.len.to_le_bytes());
            buffer.extend_from_slice(param);
        }
        PendingOps(buffer.into_boxed_slice())
    }

    pub(crate) fn apply(&self, existing: Option<Bytes>) -> Option<Bytes> {
        let mut value = existing.map(Vec::from);
        let mut rest = &*self.0;
        while let Some((&kind, tail)) = rest.split_first()
            && let Some((len, tail)) = tail.split_first_chunk::<4>()
            && let Some((param, tail)) = tail.split_at_checked(u32::from_le_bytes(*len) as usize)
        {
            if let Some(kind) = MutationKind::from_op(kind) {
                apply(&mut value, kind, param);
            }
            rest = tail;
        }
        value.map(Bytes::from)
    }
}

impl MutationKind {
    fn from_op(kind: u8) -> Option<Self> {
        match kind {
            2 => Some(MutationKind::AddValue),
            9 => Some(MutationKind::AppendIfFits),
            20 => Some(MutationKind::CompareAndClear),
            _ => None,
        }
    }
}

fn apply(value: &mut Option<Vec<u8>>, kind: MutationKind, param: &[u8]) {
    match kind {
        MutationKind::AddValue => add(value.get_or_insert_default(), param),
        MutationKind::AppendIfFits => match value {
            Some(existing) if !existing.is_empty() => {
                if existing.len() + param.len() <= MAX_VALUE_SIZE {
                    existing.extend_from_slice(param);
                }
            }
            _ => *value = Some(param.to_vec()),
        },
        MutationKind::CompareAndClear => {
            if value.as_deref().is_none_or(|existing| existing == param) {
                *value = None;
            }
        }
        MutationKind::SetValue => *value = Some(param.to_vec()),
        MutationKind::ClearRange => *value = None,
    }
}

fn begin<'a>(arena: &'a [u8], records: &[Record], position: u32) -> &'a [u8] {
    records
        .get(position as usize)
        .map(|record| record.param1.get(arena))
        .unwrap_or_default()
}

fn absorb<K: Ord>(
    sorted: &mut Vec<u32>,
    scratch: &mut Vec<u32>,
    pending: impl IntoIterator<Item = u32>,
    key: impl Fn(u32) -> K,
) {
    let settled = sorted.len();
    sorted.extend(pending);
    let Some((old, tail)) = sorted.split_at_mut_checked(settled) else {
        return;
    };
    if tail.is_empty() {
        return;
    }
    tail.sort_unstable_by_key(|&position| key(position));
    scratch.clear();
    scratch.reserve(old.len() + tail.len());
    let mut old: &[u32] = old;
    for &position in tail.iter() {
        let new = key(position);
        let at = old.partition_point(|&settled| key(settled) < new);
        let Some((before, rest)) = old.split_at_checked(at) else {
            break;
        };
        scratch.extend_from_slice(before);
        old = rest;
        let duplicate = scratch.last().is_some_and(|&last| key(last) == new)
            || old.first().is_some_and(|&first| key(first) == new);
        if !duplicate {
            scratch.push(position);
        }
    }
    scratch.extend_from_slice(old);
    mem::swap(sorted, scratch);
}

fn add(value: &mut Vec<u8>, param: &[u8]) {
    value.resize(param.len(), 0);
    let mut carry = 0u16;
    for (byte, operand) in value.iter_mut().zip(param) {
        let sum = u16::from(*byte) + u16::from(*operand) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/fdb/src/client/commit_buffer/write_index/tests.rs"]
mod tests;
