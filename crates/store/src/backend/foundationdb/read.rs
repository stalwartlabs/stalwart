/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FdbStore, MAX_VALUE_SIZE,
    assembly::{Assembly, ReverseRun, RowSink},
    into_error,
    window::{Resume, WindowError, WindowRows, read_window},
};
use crate::{
    Deserialize, Fetch, ITERATE_BATCH_GROWTH, IterateParams, Key, ValueKey, WITH_SUBSPACE,
    backend::deserialize_i64_le,
    write::{MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, ValueClass, key::KeySerializer},
};
use fdb::{
    Bytes, Direction, ErrorCode, PageSize, RangeCursor, RangeOptions, ReadOptions, ReadTransaction,
    ReadVersionPolicy, Readahead, Snapshot, Transaction, Version,
};
use std::{
    mem::{swap, take},
    num::NonZeroU32,
    ops::Bound,
    time::Instant,
};

pub(crate) enum ChunkedValue {
    Single(Bytes),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

pub(super) enum Source<'a, 'db> {
    Snapshot(Snapshot<'db>),
    Transaction(&'a mut Transaction<'db>),
}

impl ChunkedValue {
    pub(super) fn written(value: Vec<u8>) -> Option<Self> {
        let n_chunks = u8::try_from(value.len().div_ceil(MAX_VALUE_SIZE).saturating_sub(1)).ok()?;
        Some(if n_chunks == 0 {
            ChunkedValue::Single(Bytes::from(value))
        } else {
            ChunkedValue::Chunked {
                n_chunks,
                bytes: value,
            }
        })
    }

    pub(super) fn bytes(&self) -> Option<&[u8]> {
        match self {
            ChunkedValue::Single(bytes) => Some(bytes),
            ChunkedValue::Chunked { bytes, .. } => Some(bytes),
            ChunkedValue::None => None,
        }
    }
}

impl FdbStore {
    pub(crate) fn get_value<U>(&self, key: impl Key) -> impl Future<Output = trc::Result<Option<U>>>
    where
        U: Deserialize,
    {
        self.get_value_at(key, ReadVersionPolicy::Cached)
    }

    pub(crate) fn get_value_fresh<U>(
        &self,
        key: impl Key,
    ) -> impl Future<Output = trc::Result<Option<U>>>
    where
        U: Deserialize,
    {
        self.get_value_at(key, ReadVersionPolicy::Fresh)
    }

    async fn get_value_at<U>(
        &self,
        key: impl Key,
        policy: ReadVersionPolicy,
    ) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();
        let mut trx = self.read_trx_with(policy).await?;

        loop {
            match read_chunked_value(&key, &mut Source::Snapshot(trx.snapshot())).await {
                Ok(ChunkedValue::Single(bytes)) => {
                    return U::deserialize_with_key(key.get(1..).unwrap_or_default(), &bytes)
                        .map(Some);
                }
                Ok(ChunkedValue::Chunked { bytes, .. }) => {
                    return U::deserialize_owned_with_key(key.get(1..).unwrap_or_default(), bytes)
                        .map(Some);
                }
                Ok(ChunkedValue::None) => return Ok(None),
                Err(err) => {
                    self.on_read_error(&mut trx, err, &mut retry_count, start)
                        .await?;
                }
            }
        }
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let key = key.serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();
        let mut trx = self.read_trx().await?;

        loop {
            match trx.exists(&key).await {
                Ok(exists) => return Ok(exists),
                Err(err) => {
                    self.on_read_error(&mut trx, err, &mut retry_count, start)
                        .await?;
                }
            }
        }
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let begin = params.begin.serialize(WITH_SUBSPACE);
        let end = params.end.serialize(WITH_SUBSPACE);
        if begin > end {
            return Ok(());
        }
        let mut sink = RowSink::new(cb, params.fetch);
        let (mut assembly, direction) = if params.ascending {
            (Assembly::Forward(None), Direction::Forward)
        } else {
            (Assembly::Reverse(ReverseRun::default()), Direction::Reverse)
        };
        let mut expect_window = match params.fetch {
            Fetch::Expect(rows) => Some((u64::from(rows) + 1).max(MIN_EXPECT_WINDOW)),
            Fetch::All | Fetch::Limit(_) => None,
        };
        let mut retry_count = 0;
        let start = Instant::now();
        let mut last_key = vec![];
        let mut read_key = vec![];
        let mut next_trx: Option<ReadTransaction<'_>> = None;
        let mut carried = false;

        'outer: loop {
            let tail_end: Vec<u8>;
            let (begin_bound, mut end_bound) = if last_key.is_empty() {
                (
                    Bound::Included(begin.as_slice()),
                    Bound::Included(end.as_slice()),
                )
            } else if params.ascending {
                (
                    Bound::Excluded(last_key.as_slice()),
                    Bound::Included(end.as_slice()),
                )
            } else {
                (
                    Bound::Included(begin.as_slice()),
                    Bound::Excluded(last_key.as_slice()),
                )
            };
            let mut budget = match params.fetch {
                Fetch::All => None,
                Fetch::Expect(_) => expect_window,
                Fetch::Limit(_) => match &assembly {
                    Assembly::Forward(Some(chunk)) if params.values && sink.left == 1 => {
                        tail_end = chunk.tail_end();
                        if tail_end <= end {
                            end_bound = Bound::Excluded(tail_end.as_slice());
                        }
                        None
                    }
                    Assembly::Forward(pending) => {
                        Some(sink.left - u64::from(params.values && pending.is_some()))
                    }
                    Assembly::Reverse(run) => Some(sink.left.saturating_sub(run.members()) + 1),
                },
            };
            let mut cursor = RangeCursor::new(
                begin_bound,
                end_bound,
                RangeOptions {
                    direction,
                    page: page_size(budget),
                    readahead: Readahead::Off,
                },
            )
            .map_err(into_error)?;

            let mut trx = match next_trx.take() {
                Some(trx) => trx,
                None => self.read_trx().await?,
            };
            let progressed = take(&mut carried);
            read_key.clear();

            loop {
                match cursor.next(trx.snapshot()).await {
                    Ok(Some(page)) => {
                        #[cfg(stalwart_tests)]
                        super::probe::range_batch(&page);
                        let more = !cursor.is_done();
                        read_key.clear();
                        if more && let Some(last) = page.last() {
                            read_key.extend_from_slice(last.key);
                        }
                        let rows = page.len() as u64;
                        if !assembly.batch(page, &mut sink, params.values)? {
                            return Ok(());
                        }
                        if let Some(left) = &mut budget {
                            *left = left.saturating_sub(rows);
                            if *left == 0 && more {
                                drop(cursor);
                                expect_window = expect_window.map(|rows| {
                                    rows.saturating_mul(u64::from(ITERATE_BATCH_GROWTH))
                                });
                                swap(&mut last_key, &mut read_key);
                                next_trx = Some(trx);
                                carried = true;
                                continue 'outer;
                            }
                            cursor.set_page(page_size(budget));
                        }
                    }
                    Ok(None) => return assembly.finish(&mut sink, params.values),
                    Err(err) => {
                        drop(cursor);
                        if err.error_code() == ErrorCode::TRANSACTION_TOO_OLD
                            && (progressed || !read_key.is_empty())
                        {
                            if !read_key.is_empty() {
                                swap(&mut last_key, &mut read_key);
                            }
                            self.db.invalidate_read_version();
                            continue 'outer;
                        } else if err.is_retryable()
                            && retry_count < MAX_COMMIT_ATTEMPTS
                            && start.elapsed() < MAX_COMMIT_TIME
                        {
                            if !read_key.is_empty() {
                                swap(&mut last_key, &mut read_key);
                            }
                            trx.on_error(err).await.map_err(into_error)?;
                            next_trx = Some(trx);
                            retry_count += 1;
                            continue 'outer;
                        } else {
                            return Err(into_error(err));
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let rows = if ranges.first().is_none_or(|params| params.values) {
            WindowRows::Values
        } else {
            WindowRows::Keys
        };
        let bounds = ranges
            .iter()
            .map(|params| {
                (
                    params.begin.serialize(WITH_SUBSPACE),
                    params.end.serialize(WITH_SUBSPACE),
                )
            })
            .collect::<Vec<_>>();
        let mut resume = Resume::default();
        let mut retry_count = 0;
        let start = Instant::now();
        let mut trx = self.read_trx().await?;

        loop {
            let result = read_window(
                trx.snapshot(),
                &self.windows,
                rows,
                resume.reads(&bounds),
                |_, key, value| cb(key.get(1..).unwrap_or_default(), value),
            )
            .await;

            match result {
                Ok(()) => return Ok(()),
                Err(WindowError::Store(err)) => return Err(err),
                Err(WindowError::Fdb {
                    error,
                    resume: next,
                    progressed,
                }) => {
                    resume = next;
                    if error.error_code() == ErrorCode::TRANSACTION_TOO_OLD && progressed {
                        self.db.invalidate_read_version();
                        trx = self.read_trx().await?;
                    } else {
                        self.on_read_error(&mut trx, error, &mut retry_count, start)
                            .await?;
                    }
                }
            }
        }
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into().serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();
        let mut trx = self.read_trx().await?;

        loop {
            match trx.get(&key).await {
                Ok(Some(bytes)) => return deserialize_i64_le(&key, &bytes),
                Ok(None) => return Ok(0),
                Err(err) => {
                    self.on_read_error(&mut trx, err, &mut retry_count, start)
                        .await?;
                }
            }
        }
    }

    pub(super) async fn on_read_error(
        &self,
        trx: &mut ReadTransaction<'_>,
        err: fdb::Error,
        retry_count: &mut u32,
        start: Instant,
    ) -> trc::Result<()> {
        if err.is_retryable()
            && *retry_count < MAX_COMMIT_ATTEMPTS
            && start.elapsed() < MAX_COMMIT_TIME
        {
            trx.on_error(err).await.map_err(into_error)?;
            *retry_count += 1;
            Ok(())
        } else {
            Err(into_error(err))
        }
    }

    pub(super) fn read_trx(&self) -> impl Future<Output = trc::Result<ReadTransaction<'_>>> {
        self.read_trx_with(ReadVersionPolicy::Cached)
    }

    pub(super) async fn read_trx_with(
        &self,
        policy: ReadVersionPolicy,
    ) -> trc::Result<ReadTransaction<'_>> {
        self.read(ReadOptions {
            version: policy,
            ..Default::default()
        })
        .await
    }

    pub(super) async fn read(&self, options: ReadOptions) -> trc::Result<ReadTransaction<'_>> {
        #[cfg(stalwart_tests)]
        let options = super::probe::pin_read_version(options);
        let trx = self.db.read(options).await.map_err(into_error)?;
        #[cfg(stalwart_tests)]
        super::probe::read_version_applied(&trx);
        Ok(trx)
    }

    pub(crate) fn invalidate_read_snapshot(&self) {
        self.db.invalidate_read_version();
    }

    pub(crate) fn read_snapshot_version(&self) -> Option<u64> {
        self.db
            .last_committed_version()
            .and_then(|version| u64::try_from(version.get()).ok())
    }

    pub(crate) fn advance_read_snapshot(&self, version: u64) {
        if let Some(version) = i64::try_from(version).ok().and_then(Version::new) {
            self.db.advance_read_version(version);
        }
    }
}

const MIN_EXPECT_WINDOW: u64 = 64;

fn page_size(rows: Option<u64>) -> PageSize {
    PageSize::new(
        rows.and_then(|rows| NonZeroU32::new(u32::try_from(rows).unwrap_or(u32::MAX))),
        PageSize::DEFAULT_BYTES,
    )
}

impl Source<'_, '_> {
    async fn get(&mut self, key: &[u8]) -> fdb::Result<Option<Bytes>> {
        #[cfg(stalwart_tests)]
        super::probe::point_read(key);
        match self {
            Source::Snapshot(snapshot) => snapshot.get(key).await,
            Source::Transaction(trx) => trx.get(key).await,
        }
    }
}

pub(super) async fn read_chunked_value(
    key: &[u8],
    source: &mut Source<'_, '_>,
) -> fdb::Result<ChunkedValue> {
    if let Some(bytes) = source.get(key).await? {
        if bytes.len() < MAX_VALUE_SIZE {
            return Ok(ChunkedValue::Single(bytes));
        }
        Ok(match read_chunk_tail(key, source, &bytes).await? {
            Some(chunked) => chunked,
            None => ChunkedValue::Single(bytes),
        })
    } else {
        Ok(ChunkedValue::None)
    }
}

pub(super) async fn read_chunk_tail(
    key: &[u8],
    source: &mut Source<'_, '_>,
    head: &[u8],
) -> fdb::Result<Option<ChunkedValue>> {
    let mut chunk_key = KeySerializer::new(key.len() + 1)
        .write(key)
        .write(0u8)
        .finalize();
    let Some(chunk) = source.get(&chunk_key).await? else {
        return Ok(None);
    };

    let mut value = Vec::with_capacity(head.len() + chunk.len());
    value.extend_from_slice(head);
    value.extend_from_slice(&chunk);
    let mut n_chunks = 1u8;
    loop {
        if let Some(last) = chunk_key.last_mut() {
            *last = n_chunks;
        }
        match source.get(&chunk_key).await? {
            Some(chunk) => {
                value.extend_from_slice(&chunk);
                n_chunks += 1;
            }
            None => break,
        }
    }

    Ok(Some(ChunkedValue::Chunked {
        bytes: value,
        n_chunks,
    }))
}
