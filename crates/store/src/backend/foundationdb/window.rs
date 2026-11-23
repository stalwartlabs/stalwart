/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MAX_VALUE_SIZE, assembly::ChunkedValueCollector};
use fdb::{Bytes, KeyValue, RangeCursor, RangeOptions, RangePage, Snapshot, Transaction};
use futures::{StreamExt, future::Either, stream::FuturesOrdered};
use std::{
    cmp::Ordering,
    mem,
    ops::Bound,
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
}

pub(super) enum WindowError {
    Fdb {
        error: fdb::Error,
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

#[allow(clippy::large_enum_variant)]
enum Issued<'k> {
    Exists(&'k [u8], fdb::Result<bool>),
    Value(&'k [u8], fdb::Result<Option<Bytes>>),
    Rows {
        begin: &'k [u8],
        end: &'k [u8],
        read: fdb::Result<(RangeCursor<'k>, Option<RangePage>)>,
    },
}

const _: () = assert!(size_of::<Issued<'static>>() <= 328);

struct Head<'db> {
    snapshot: Snapshot<'db>,
    rows: WindowRows,
    largest: usize,
    progressed: bool,
    last_key: Vec<u8>,
    pending: Option<ChunkedValueCollector>,
}

pub(super) async fn read_window<'k>(
    snapshot: Snapshot<'_>,
    load: &WindowLoad,
    rows: WindowRows,
    reads: impl IntoIterator<Item = (usize, WindowRead<'k>)>,
    mut cb: impl FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
) -> Result<(), WindowError> {
    let _slot = load.enter();
    let mut reads = reads.into_iter();
    let mut window = FuturesOrdered::new();
    let mut width = MIN_WINDOW;
    let mut head = Head {
        snapshot,
        rows,
        largest: 0,
        progressed: false,
        last_key: Vec::new(),
        pending: None,
    };

    loop {
        while window.len() < width
            && let Some((index, read)) = reads.next()
        {
            window.push_back(issue(snapshot, rows, index, read));
        }
        let Some((index, issued)) = window.next().await else {
            return Ok(());
        };
        if !head.complete(index, issued, &mut cb).await? {
            return Ok(());
        }
        width = (BATCH_BYTES / head.largest.max(1)).clamp(1, load.width());
    }
}

pub(super) async fn read_keys<'k>(
    trx: &mut Transaction<'_>,
    load: &WindowLoad,
    keys: impl IntoIterator<Item = (usize, &'k [u8])>,
    mut cb: impl FnMut(usize, &[u8]),
) -> fdb::Result<()> {
    let _slot = load.enter();
    let mut keys = keys.into_iter();
    let mut window = FuturesOrdered::new();
    let mut width = MIN_WINDOW;
    let mut largest = 0;

    loop {
        while window.len() < width
            && let Some((index, key)) = keys.next()
        {
            #[cfg(stalwart_tests)]
            super::probe::point_read(key);
            let read = trx.get(key);
            window.push_back(async move { (index, read.await) });
        }
        let Some((index, value)) = window.next().await else {
            return Ok(());
        };
        if let Some(value) = value? {
            largest = largest.max(value.len());
            cb(index, &value);
        }
        width = (BATCH_BYTES / largest.max(1)).clamp(1, load.width());
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

fn issue<'db, 'k>(
    snapshot: Snapshot<'db>,
    rows: WindowRows,
    index: usize,
    read: WindowRead<'k>,
) -> impl Future<Output = (usize, Issued<'k>)> + Send + use<'db, 'k> {
    match read {
        WindowRead::Key(key) if rows == WindowRows::Keys => {
            Either::Left(Either::Left(async move {
                (index, Issued::Exists(key, snapshot.exists(key).await))
            }))
        }
        WindowRead::Key(key) => Either::Left(Either::Right(async move {
            (index, Issued::Value(key, snapshot.get(key).await))
        })),
        WindowRead::Range { begin, end } => Either::Right(async move {
            let read = match RangeCursor::new(
                Bound::Included(begin),
                Bound::Included(end),
                RangeOptions::default(),
            ) {
                Ok(mut cursor) => cursor.next(snapshot).await.map(|page| (cursor, page)),
                Err(error) => Err(error),
            };
            (index, Issued::Rows { begin, end, read })
        }),
    }
}

impl Head<'_> {
    async fn complete<F>(
        &mut self,
        index: usize,
        issued: Issued<'_>,
        cb: &mut F,
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        match issued {
            Issued::Exists(key, found) => {
                if found.map_err(|error| self.fail(error, index, None))? {
                    self.deliver(cb, index, key, &[])
                } else {
                    self.progressed = true;
                    Ok(true)
                }
            }
            Issued::Value(key, value) => {
                match value.map_err(|error| self.fail(error, index, None))? {
                    Some(value) if value.len() < MAX_VALUE_SIZE => {
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
                            self.snapshot,
                            &chunk.key,
                            &chunk.key,
                            &tail,
                            &mut chunk.bytes,
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
            Issued::Rows { begin, end, read } => {
                self.last_key.clear();
                let (cursor, page) = read.map_err(|error| self.fail(error, index, Some(begin)))?;
                self.range(index, begin, end, cursor, page, cb).await
            }
        }
    }

    async fn range<F>(
        &mut self,
        index: usize,
        begin: &[u8],
        end: &[u8],
        mut cursor: RangeCursor<'_>,
        mut page: Option<RangePage>,
        cb: &mut F,
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        while let Some(rows) = page.take() {
            if !self.rows_of(index, &rows, cb)? {
                return Ok(false);
            }
            if cursor.is_done() || rows.is_empty() {
                break;
            }
            drop(rows);
            page = cursor
                .next(self.snapshot)
                .await
                .map_err(|error| self.fail(error, index, Some(begin)))?;
        }

        if self.rows == WindowRows::Values
            && let Some(chunk) = &mut self.pending
        {
            let tail = chunk.tail_end();
            if end < tail.as_slice()
                && let Err(error) =
                    read_chunks(self.snapshot, &chunk.key, end, &tail, &mut chunk.bytes).await
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
        page: &RangePage,
        cb: &mut F,
    ) -> Result<bool, WindowError>
    where
        F: FnMut(usize, &[u8], &[u8]) -> trc::Result<bool> + Send,
    {
        #[cfg(stalwart_tests)]
        super::probe::range_batch(page);
        let mut bytes = 0;
        for KeyValue { key, value } in page {
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
            let delivered = if value.len() >= MAX_VALUE_SIZE {
                self.pending = Some(ChunkedValueCollector {
                    key: key.to_vec(),
                    bytes: if self.rows == WindowRows::Values {
                        value.to_vec()
                    } else {
                        Vec::new()
                    },
                });
                true
            } else {
                match self.rows {
                    WindowRows::Values => self.deliver(cb, index, key, value)?,
                    WindowRows::Keys => self.deliver(cb, index, key, &[])?,
                }
            };
            if !delivered {
                return Ok(false);
            }
        }
        if let Some(last) = page.last() {
            self.last_key.clear();
            self.last_key.extend_from_slice(last.key);
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

    fn fail(&mut self, error: fdb::Error, index: usize, begin: Option<&[u8]>) -> WindowError {
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
    snapshot: Snapshot<'_>,
    base: &[u8],
    after: &[u8],
    tail: &[u8],
    bytes: &mut Vec<u8>,
) -> fdb::Result<()> {
    let mut chunks = RangeCursor::new(
        Bound::Excluded(after),
        Bound::Excluded(tail),
        RangeOptions::default(),
    )?;
    while let Some(page) = chunks.next(snapshot).await? {
        #[cfg(stalwart_tests)]
        super::probe::range_batch(&page);
        for KeyValue { key, value } in &page {
            if is_chunk_of(key, base) {
                bytes.extend_from_slice(value);
            }
        }
    }
    Ok(())
}

fn is_chunk_of(key: &[u8], base: &[u8]) -> bool {
    key.len() == base.len() + 1 && key.starts_with(base)
}
