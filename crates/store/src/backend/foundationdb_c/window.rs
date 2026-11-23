/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_VALUE_SIZE, assembly::ChunkedValueCollector};
use foundationdb::{
    FdbError, FdbResult, KeySelector, RangeOption, Transaction,
    future::{FdbSlice, FdbValues},
    options::StreamingMode,
};
use futures::{FutureExt, StreamExt, future::Either, stream::FuturesOrdered};
use std::{
    cmp::Ordering,
    mem,
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

const WINDOW_BUDGET: usize = 64;
const MIN_WINDOW: usize = 16;
const MAX_WINDOW: usize = 64;
const BATCH_BYTES: usize = 1 << 20;

#[derive(Default)]
pub(crate) struct WindowLoad(AtomicUsize);

struct WindowSlot<'x>(&'x AtomicUsize);

#[derive(Clone, Copy)]
pub(super) enum WindowRead<'k> {
    Key(&'k [u8]),
    Range { begin: &'k [u8], end: &'k [u8] },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowRows {
    Values,
    Keys,
    Raw,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Isolation {
    Snapshot,
    Serializable,
}

pub(super) enum WindowError {
    Fdb {
        error: FdbError,
        resume: Resume,
        progressed: bool,
    },
    Store(trc::Error),
}

#[derive(Default)]
pub(super) struct Resume {
    index: usize,
    begin: Option<Vec<u8>>,
}

enum Issued<'k> {
    Exists(&'k [u8], FdbResult<FdbSlice>),
    Value(&'k [u8], FdbResult<Option<FdbSlice>>),
    Rows(&'k [u8], &'k [u8], FdbResult<FdbValues>),
}

struct Head {
    rows: WindowRows,
    snapshot: bool,
    largest: usize,
    progressed: bool,
    last_key: Vec<u8>,
    pending: Option<ChunkedValueCollector>,
}

pub(super) async fn read_window<'k>(
    trx: &Transaction,
    load: &WindowLoad,
    rows: WindowRows,
    isolation: Isolation,
    reads: impl IntoIterator<Item = (usize, WindowRead<'k>)>,
    mut cb: impl FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
) -> Result<(), WindowError> {
    let _slot = load.enter();
    let mut reads = reads.into_iter();
    let mut window = FuturesOrdered::new();
    let mut width = MIN_WINDOW;
    let snapshot = isolation == Isolation::Snapshot;
    let mut head = Head {
        rows,
        snapshot,
        largest: 0,
        progressed: false,
        last_key: Vec::new(),
        pending: None,
    };

    loop {
        while window.len() < width
            && let Some((index, read)) = reads.next()
        {
            window.push_back(issue(trx, rows, snapshot, index, read));
        }
        let Some((index, issued)) = window.next().await else {
            return Ok(());
        };
        if !head.complete(trx, index, issued, &mut cb).await? {
            return Ok(());
        }
        width = (BATCH_BYTES / head.largest.max(1)).clamp(1, load.width());
    }
}

impl WindowLoad {
    fn enter(&self) -> WindowSlot<'_> {
        self.0.fetch_add(1, AtomicOrdering::Relaxed);
        WindowSlot(&self.0)
    }

    fn width(&self) -> usize {
        (WINDOW_BUDGET / self.0.load(AtomicOrdering::Relaxed).max(1)).clamp(MIN_WINDOW, MAX_WINDOW)
    }
}

impl Drop for WindowSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, AtomicOrdering::Relaxed);
    }
}

impl Resume {
    pub(super) fn reads<'k>(
        &'k self,
        bounds: &'k [(Vec<u8>, Vec<u8>)],
    ) -> impl Iterator<Item = (usize, WindowRead<'k>)> + Send {
        bounds
            .iter()
            .enumerate()
            .skip(self.index)
            .filter_map(move |(index, (begin, end))| {
                let begin = match &self.begin {
                    Some(resumed) if index == self.index => resumed,
                    _ => begin,
                };
                match begin.cmp(end) {
                    Ordering::Less => Some((index, WindowRead::Range { begin, end })),
                    Ordering::Equal => Some((index, WindowRead::Key(begin))),
                    Ordering::Greater => None,
                }
            })
    }
}

fn issue<'k>(
    trx: &Transaction,
    rows: WindowRows,
    snapshot: bool,
    index: usize,
    read: WindowRead<'k>,
) -> impl Future<Output = (usize, Issued<'k>)> + Send + use<'k> {
    match read {
        WindowRead::Key(key) if rows == WindowRows::Keys => Either::Left(Either::Left(
            trx.get_key(&KeySelector::first_greater_or_equal(key), snapshot)
                .map(move |found| (index, Issued::Exists(key, found))),
        )),
        WindowRead::Key(key) => Either::Left(Either::Right(
            trx.get(key, snapshot)
                .map(move |value| (index, Issued::Value(key, value))),
        )),
        WindowRead::Range { begin, end } => Either::Right(
            trx.get_range(
                &range_option(
                    KeySelector::first_greater_or_equal(begin),
                    KeySelector::first_greater_than(end),
                ),
                1,
                snapshot,
            )
            .map(move |values| (index, Issued::Rows(begin, end, values))),
        ),
    }
}

impl Head {
    async fn complete<F>(
        &mut self,
        trx: &Transaction,
        index: usize,
        issued: Issued<'_>,
        cb: &mut F,
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        match issued {
            Issued::Exists(key, found) => {
                let found = found.map_err(|error| self.fail(error, index, None))?;
                if *found == *key {
                    self.deliver(cb, index, key, &[])
                } else {
                    self.progressed = true;
                    Ok(true)
                }
            }
            Issued::Value(key, value) => {
                match value.map_err(|error| self.fail(error, index, None))? {
                    Some(value) if value.len() < MAX_VALUE_SIZE || self.rows == WindowRows::Raw => {
                        self.deliver(cb, index, key, &value)
                    }
                    Some(value) => {
                        let mut chunk = ChunkedValueCollector {
                            key: key.to_vec(),
                            bytes: value.to_vec(),
                        };
                        drop(value);
                        let tail = chunk.tail_end();
                        if let Err(error) = read_chunks(
                            trx,
                            &chunk.key,
                            &chunk.key,
                            &tail,
                            &mut chunk.bytes,
                            self.snapshot,
                        )
                        .await
                        {
                            return Err(self.fail(error, index, None));
                        }
                        self.deliver(cb, index, key, &chunk.bytes)
                    }
                    None => {
                        self.progressed = true;
                        Ok(true)
                    }
                }
            }
            Issued::Rows(begin, end, values) => {
                self.last_key.clear();
                let values = values.map_err(|error| self.fail(error, index, Some(begin)))?;
                self.range(trx, index, begin, end, values, cb).await
            }
        }
    }

    async fn range<F>(
        &mut self,
        trx: &Transaction,
        index: usize,
        begin: &[u8],
        end: &[u8],
        mut values: FdbValues,
        cb: &mut F,
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        loop {
            if !self.rows_of(index, &values, cb)? {
                return Ok(false);
            }
            if !values.more() || values.is_empty() {
                break;
            }
            drop(values);
            let next = trx.get_range(
                &range_option(
                    KeySelector::first_greater_than(self.last_key.as_slice()),
                    KeySelector::first_greater_than(end),
                ),
                1,
                self.snapshot,
            );
            values = next
                .await
                .map_err(|error| self.fail(error, index, Some(begin)))?;
        }

        if self.rows == WindowRows::Values
            && let Some(chunk) = &mut self.pending
        {
            let tail = chunk.tail_end();
            if end < tail.as_slice()
                && let Err(error) =
                    read_chunks(trx, &chunk.key, end, &tail, &mut chunk.bytes, self.snapshot).await
            {
                return Err(self.fail(error, index, Some(begin)));
            }
        }
        match self.pending.take() {
            Some(chunk) => self.deliver(cb, index, &chunk.key, &chunk.bytes),
            None => {
                self.progressed = true;
                Ok(true)
            }
        }
    }

    fn rows_of<F>(
        &mut self,
        index: usize,
        values: &FdbValues,
        cb: &mut F,
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        #[cfg(stalwart_tests)]
        super::probe::range_batch(values);
        let mut bytes = 0;
        for row in values.iter() {
            let (key, value) = (row.key(), row.value());
            bytes += value.len();
            if let Some(chunk) = &mut self.pending
                && is_chunk_of(key, &chunk.key)
            {
                if self.rows == WindowRows::Values {
                    chunk.bytes.extend_from_slice(value);
                }
                continue;
            }
            if let Some(chunk) = self.pending.take()
                && !self.deliver(cb, index, &chunk.key, &chunk.bytes)?
            {
                return Ok(false);
            }
            let delivered = match self.rows {
                WindowRows::Raw => self.deliver(cb, index, key, value)?,
                _ if value.len() >= MAX_VALUE_SIZE => {
                    self.pending = Some(ChunkedValueCollector {
                        key: key.to_vec(),
                        bytes: if self.rows == WindowRows::Values {
                            value.to_vec()
                        } else {
                            Vec::new()
                        },
                    });
                    true
                }
                WindowRows::Values => self.deliver(cb, index, key, value)?,
                WindowRows::Keys => self.deliver(cb, index, key, &[])?,
            };
            if !delivered {
                return Ok(false);
            }
        }
        if let Some(last) = values.last() {
            self.last_key.clear();
            self.last_key.extend_from_slice(last.key());
        }
        self.largest = self.largest.max(bytes);
        Ok(true)
    }

    fn deliver<F>(
        &mut self,
        cb: &mut F,
        index: usize,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        self.progressed = true;
        self.largest = self.largest.max(value.len());
        cb(index, key, value).map_err(WindowError::Store)
    }

    fn fail(&mut self, error: FdbError, index: usize, begin: Option<&[u8]>) -> WindowError {
        let begin = begin.map(|begin| match self.pending.take() {
            Some(chunk) => chunk.key,
            None if self.last_key.is_empty() => begin.to_vec(),
            None => {
                let mut after = mem::take(&mut self.last_key);
                after.push(0);
                after
            }
        });
        WindowError::Fdb {
            error,
            resume: Resume { index, begin },
            progressed: self.progressed,
        }
    }
}

async fn read_chunks(
    trx: &Transaction,
    base: &[u8],
    after: &[u8],
    tail: &[u8],
    bytes: &mut Vec<u8>,
    snapshot: bool,
) -> FdbResult<()> {
    let mut chunks = range_option(
        KeySelector::first_greater_than(after),
        KeySelector::first_greater_or_equal(tail),
    );
    loop {
        let values = trx.get_range(&chunks, 1, snapshot).await?;
        #[cfg(stalwart_tests)]
        super::probe::range_batch(&values);
        for row in values.iter() {
            if is_chunk_of(row.key(), base) {
                bytes.extend_from_slice(row.value());
            }
        }
        match chunks.next_range(&values) {
            Some(next) => chunks = next,
            None => return Ok(()),
        }
    }
}

fn range_option<'a>(begin: KeySelector<'a>, end: KeySelector<'a>) -> RangeOption<'a> {
    RangeOption {
        begin,
        end,
        mode: StreamingMode::WantAll,
        reverse: false,
        ..Default::default()
    }
}

fn is_chunk_of(key: &[u8], base: &[u8]) -> bool {
    key.len() == base.len() + 1 && key.starts_with(base)
}
