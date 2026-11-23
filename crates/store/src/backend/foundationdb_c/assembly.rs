/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MAX_VALUE_SIZE;
use crate::{Fetch, write::key::KeySerializer};
use foundationdb::future::{FdbKeyValue, FdbValues};
use std::iter::once;

pub(super) struct ChunkedValueCollector {
    pub(super) key: Vec<u8>,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct RowSink<F> {
    cb: F,
    pub(super) left: u64,
}

impl<F> RowSink<F>
where
    F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
{
    pub(super) fn new(cb: F, fetch: Fetch) -> Self {
        RowSink {
            cb,
            left: match fetch {
                Fetch::Limit(rows) => u64::from(rows),
                Fetch::All | Fetch::Expect(_) => u64::MAX,
            },
        }
    }

    fn deliver(&mut self, key: &[u8], value: &[u8]) -> trc::Result<bool> {
        self.left -= 1;
        Ok((self.cb)(key.get(1..).unwrap_or_default(), value)? && self.left != 0)
    }
}

impl ChunkedValueCollector {
    pub(super) fn tail_end(&self) -> Vec<u8> {
        KeySerializer::new(self.key.len() + 1)
            .write(self.key.as_slice())
            .write(u8::MAX)
            .finalize()
    }
}

#[derive(Default)]
pub(super) struct ReverseRun {
    held: Option<FdbValues>,
    key: Vec<u8>,
    suffixes: Vec<u8>,
    first: Vec<u8>,
    chunks: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone, Copy)]
enum ChunkLink {
    Sibling,
    Base,
}

impl ChunkLink {
    fn of(held: &[u8], row: &FdbKeyValue) -> Option<Self> {
        let key = row.key();
        let (_, prefix) = held.split_last()?;
        if row.value().len() < MAX_VALUE_SIZE {
            None
        } else if key == prefix {
            Some(ChunkLink::Base)
        } else if key.len() == held.len() && key.starts_with(prefix) {
            Some(ChunkLink::Sibling)
        } else {
            None
        }
    }
}

impl ReverseRun {
    pub(super) fn members(&self) -> u64 {
        self.suffixes.len() as u64 + u64::from(self.held.is_some())
    }

    fn hold(&mut self, row: &FdbKeyValue, values: bool) {
        let key = row.key();
        self.key.clear();
        self.key.extend_from_slice(key);
        self.suffixes.clear();
        self.suffixes.extend(key.last());
        self.first.clear();
        self.chunks.clear();
        if values {
            self.first.extend_from_slice(row.value());
        }
    }

    fn push(&mut self, row: &FdbKeyValue, values: bool) {
        self.suffixes.extend(row.key().last());
        if values {
            self.chunks.extend_from_slice(row.value());
        }
    }

    fn complete<F>(
        &mut self,
        base: &FdbKeyValue,
        sink: &mut RowSink<F>,
        values: bool,
    ) -> trc::Result<bool>
    where
        F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
    {
        self.suffixes.clear();
        self.value.clear();
        if values {
            self.value
                .reserve(base.value().len() + self.chunks.len() + self.first.len());
            self.value.extend_from_slice(base.value());
            for chunk in self.chunks.as_chunks::<MAX_VALUE_SIZE>().0.iter().rev() {
                self.value.extend_from_slice(chunk);
            }
            self.value.extend_from_slice(&self.first);
        }
        sink.deliver(base.key(), &self.value)
    }

    fn flush<F>(&mut self, sink: &mut RowSink<F>) -> trc::Result<bool>
    where
        F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
    {
        let ReverseRun {
            key,
            suffixes,
            first,
            chunks,
            ..
        } = self;
        let mut values = once(first.as_slice()).chain(
            chunks
                .as_chunks::<MAX_VALUE_SIZE>()
                .0
                .iter()
                .map(|chunk| chunk.as_slice()),
        );
        for suffix in suffixes.drain(..) {
            if let Some(last) = key.last_mut() {
                *last = suffix;
            }
            if !sink.deliver(key, values.next().unwrap_or_default())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn batch<F>(
        &mut self,
        rows: FdbValues,
        sink: &mut RowSink<F>,
        values: bool,
    ) -> trc::Result<bool>
    where
        F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
    {
        let previous = self.held.take();
        let mut local = previous.as_ref().and_then(|batch| batch.last());
        for row in rows.iter() {
            let held = match local {
                Some(prev) => prev.key(),
                None if !self.suffixes.is_empty() => self.key.as_slice(),
                None => {
                    local = Some(row);
                    continue;
                }
            };
            match ChunkLink::of(held, row) {
                Some(link) => {
                    if let Some(prev) = local.take() {
                        self.hold(prev, values);
                    }
                    match link {
                        ChunkLink::Sibling => self.push(row, values),
                        ChunkLink::Base => {
                            if !self.complete(row, sink, values)? {
                                return Ok(false);
                            }
                        }
                    }
                }
                None => {
                    let continues = match local.replace(row) {
                        Some(prev) => sink.deliver(prev.key(), prev.value())?,
                        None => self.flush(sink)?,
                    };
                    if !continues {
                        return Ok(false);
                    }
                }
            }
        }
        if local.is_some() {
            self.held = if rows.is_empty() {
                previous
            } else {
                Some(rows)
            };
        }
        Ok(true)
    }

    fn finish<F>(&mut self, sink: &mut RowSink<F>) -> trc::Result<()>
    where
        F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
    {
        match self.held.take() {
            Some(batch) => {
                if let Some(row) = batch.last() {
                    sink.deliver(row.key(), row.value())?;
                }
            }
            None => {
                self.flush(sink)?;
            }
        }
        Ok(())
    }
}

pub(super) enum Assembly {
    Forward(Option<ChunkedValueCollector>),
    Reverse(ReverseRun),
}

impl Assembly {
    pub(super) fn batch<F>(
        &mut self,
        rows: FdbValues,
        sink: &mut RowSink<F>,
        values: bool,
    ) -> trc::Result<bool>
    where
        F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
    {
        match self {
            Assembly::Forward(pending) => {
                for row in rows.iter() {
                    let (key, value) = (row.key(), row.value());
                    if let Some(chunk) = pending {
                        if key.len() == chunk.key.len() + 1 && key.starts_with(&chunk.key) {
                            if values {
                                chunk.bytes.extend_from_slice(value);
                            }
                            continue;
                        }
                        if values && !sink.deliver(&chunk.key, &chunk.bytes)? {
                            return Ok(false);
                        }
                        *pending = None;
                    }
                    if value.len() < MAX_VALUE_SIZE {
                        if !sink.deliver(key, value)? {
                            return Ok(false);
                        }
                    } else if values {
                        *pending = Some(ChunkedValueCollector {
                            key: key.to_vec(),
                            bytes: value.to_vec(),
                        });
                    } else {
                        *pending = Some(ChunkedValueCollector {
                            key: key.to_vec(),
                            bytes: Vec::new(),
                        });
                        if !sink.deliver(key, &[])? {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            Assembly::Reverse(run) => run.batch(rows, sink, values),
        }
    }

    pub(super) fn finish<F>(&mut self, sink: &mut RowSink<F>, values: bool) -> trc::Result<()>
    where
        F: for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool>,
    {
        match self {
            Assembly::Forward(pending) => {
                if values && let Some(chunk) = pending.take() {
                    sink.deliver(&chunk.key, &chunk.bytes)?;
                }
            }
            Assembly::Reverse(run) => run.finish(sink)?,
        }
        Ok(())
    }
}
