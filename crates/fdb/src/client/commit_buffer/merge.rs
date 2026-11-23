/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CommitBuffer, Lookup, WriteIndex};
use crate::{
    api::{
        error::{Error, ErrorCode, Result},
        range::{Direction, PageSize},
    },
    client::cursor::row_limit,
    codec::kv::{KeyValues, KeyValuesBuf},
};
use bytes::Bytes;
use std::cmp::Ordering;

const COUNT_PREFIX: usize = 4;

pub(crate) enum Merged {
    Unchanged(Option<KeyValuesBuf>),
    Rows {
        rows: KeyValuesBuf,
        cut: Option<Vec<u8>>,
    },
}

enum Next {
    Stored,
    Written,
    Both,
}

impl CommitBuffer {
    pub(crate) fn skip_cleared<'a>(&'a mut self, edge: &'a [u8], direction: Direction) -> &'a [u8] {
        if self.mutations.is_empty() {
            return edge;
        }
        self.index
            .get_or_insert_with(|| Box::new(WriteIndex::build(&self.writes, &self.mutations)))
            .skip_cleared(&self.writes, &self.mutations, edge, direction)
    }

    pub(crate) fn merge(
        &mut self,
        rows: Option<KeyValuesBuf>,
        low: &[u8],
        high: &[u8],
        direction: Direction,
        page: PageSize,
    ) -> Result<Merged> {
        if self.mutations.is_empty() || low >= high {
            return Ok(Merged::Unchanged(rows));
        }
        let CommitBuffer {
            writes: arena,
            values,
            mutations: records,
            index,
            ..
        } = self;
        let index = index.get_or_insert_with(|| Box::new(WriteIndex::build(arena, records)));
        let mut written = Vec::new();
        index.written_in(arena, records, low, high, &mut written);
        let mut cleared = index.cleared_in(arena, records, low, high);
        if written.is_empty() && cleared.is_empty() {
            return Ok(Merged::Unchanged(rows));
        }
        let row_limit = row_limit(page);
        let byte_limit = COUNT_PREFIX + page.bytes().get() as usize;
        if direction == Direction::Reverse {
            written.reverse();
        }
        let order = match direction {
            Direction::Forward => Ordering::Less,
            Direction::Reverse => Ordering::Greater,
        };
        let stored = rows.as_ref().map(KeyValuesBuf::view).unwrap_or_default();
        let mut stored = stored.iter().peekable();
        let mut written = written
            .iter()
            .filter_map(|&position| records.get(position as usize))
            .filter_map(|record| record.key(arena))
            .peekable();
        let mut blob = vec![0; COUNT_PREFIX];
        let mut count = 0usize;
        let mut cut = None;
        loop {
            let next = match (stored.peek(), written.peek()) {
                (None, None) => break,
                (Some(_), None) => Next::Stored,
                (None, Some(_)) => Next::Written,
                (Some((stored, _)), Some(written)) => match stored.cmp(written) {
                    Ordering::Equal => Next::Both,
                    ordering if ordering == order => Next::Stored,
                    _ => Next::Written,
                },
            };
            let (key, value) = match next {
                Next::Stored => match stored.next() {
                    Some((key, value)) => (key, Some(value)),
                    None => break,
                },
                Next::Written => match written.next() {
                    Some(key) => (key, None),
                    None => break,
                },
                Next::Both => {
                    written.next();
                    match stored.next() {
                        Some((key, value)) => (key, Some(value)),
                        None => break,
                    }
                }
            };
            let emitted = match next {
                Next::Stored => value
                    .filter(|_| !index.is_cleared(arena, &mut cleared, key, direction))
                    .map(|value| push(&mut blob, key, value)),
                Next::Written | Next::Both => match index.lookup(arena, values, records, key) {
                    Lookup::Unmodified => value.map(|value| push(&mut blob, key, value)),
                    Lookup::Known(value) => value.map(|value| push(&mut blob, key, &value)),
                    Lookup::Dependent(ops) => ops
                        .apply(value.map(Bytes::copy_from_slice))
                        .map(|value| push(&mut blob, key, &value)),
                },
            };
            if emitted.is_some() {
                count += 1;
                if count == row_limit || blob.len() >= byte_limit {
                    if stored.peek().is_some() || written.peek().is_some() {
                        cut = Some(key.to_vec());
                    }
                    break;
                }
            }
        }
        if let Some(prefix) = blob.first_chunk_mut::<COUNT_PREFIX>() {
            *prefix = u32::try_from(count)
                .map_err(|_| Error::new(ErrorCode::INTERNAL_ERROR))?
                .to_le_bytes();
        }
        let blob = Bytes::from(blob);
        let rows = KeyValues::parse(&blob)
            .and_then(|view| KeyValuesBuf::new(&blob, view))
            .map_err(|_| Error::new(ErrorCode::INTERNAL_ERROR))?;
        Ok(Merged::Rows { rows, cut })
    }
}

fn push(blob: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    blob.reserve(2 * COUNT_PREFIX + key.len() + value.len());
    blob.extend_from_slice(&(key.len() as u32).to_le_bytes());
    blob.extend_from_slice(key);
    blob.extend_from_slice(&(value.len() as u32).to_le_bytes());
    blob.extend_from_slice(value);
}
