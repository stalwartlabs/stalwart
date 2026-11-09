/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FdbStore, MAX_EXACT_MODE_ROWS, MAX_READ_VERSION_AGE, MAX_VALUE_SIZE,
    REFRESH_READ_VERSION_AFTER,
    assembly::{Assembly, ReverseRun, RowSink},
    into_error,
    window::{Isolation, Resume, WindowError, WindowRows, read_window},
};
use crate::{
    Deserialize, Fetch, ITERATE_BATCH_GROWTH, IterateParams, Key, ValueKey, WITH_SUBSPACE,
    backend::deserialize_i64_le,
    write::{MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, ValueClass, key::KeySerializer},
};
use foundationdb::{
    FdbError, KeySelector, RangeOption, Transaction,
    future::FdbSlice,
    options::{self, TransactionOption},
};
use futures::TryStreamExt;
use std::{
    mem::{swap, take},
    time::Instant,
};

enum ReadAt {
    Cached,
    Fresh,
}

#[allow(dead_code)]
pub(crate) enum ChunkedValue {
    Single(FdbSlice),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

impl FdbStore {
    pub(crate) fn get_value<U>(&self, key: impl Key) -> impl Future<Output = trc::Result<Option<U>>>
    where
        U: Deserialize,
    {
        self.get_value_at(key, ReadAt::Cached)
    }

    pub(crate) fn get_value_fresh<U>(
        &self,
        key: impl Key,
    ) -> impl Future<Output = trc::Result<Option<U>>>
    where
        U: Deserialize,
    {
        self.get_value_at(key, ReadAt::Fresh)
    }

    async fn get_value_at<U>(&self, key: impl Key, read_at: ReadAt) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(WITH_SUBSPACE);
        let mut retry_count = 0;
        let start = Instant::now();
        let mut trx = match read_at {
            ReadAt::Cached => self.read_trx().await?,
            ReadAt::Fresh => self.fresh_trx().await?,
        };

        loop {
            match read_chunked_value(&key, &trx, true).await {
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
                    trx = self
                        .on_read_error(trx, err, &mut retry_count, start)
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
            match trx.get(&key, true).await {
                Ok(value) => return Ok(value.is_some()),
                Err(err) => {
                    trx = self
                        .on_read_error(trx, err, &mut retry_count, start)
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
        let mut sink = RowSink::new(cb, params.fetch);
        let mut assembly = if params.ascending {
            Assembly::Forward(None)
        } else {
            Assembly::Reverse(ReverseRun::default())
        };
        let mut expect_window = match params.fetch {
            Fetch::Expect(rows) => Some((u64::from(rows) + 1).max(MIN_EXPECT_WINDOW)),
            Fetch::All | Fetch::Limit(_) => None,
        };
        let mut retry_count = 0;
        let start = Instant::now();
        let mut last_key = vec![];
        let mut read_key = vec![];
        let mut next_trx: Option<Transaction> = None;
        let mut carried = false;

        'outer: loop {
            let (begin_selector, end_selector) = if last_key.is_empty() {
                (
                    KeySelector::first_greater_or_equal(&begin),
                    KeySelector::first_greater_than(&end),
                )
            } else if params.ascending {
                (
                    KeySelector::first_greater_than(&last_key),
                    KeySelector::first_greater_than(&end),
                )
            } else {
                (
                    KeySelector::first_greater_or_equal(&begin),
                    KeySelector::first_greater_or_equal(&last_key),
                )
            };
            let tail_end: Vec<u8>;
            let mut range = RangeOption {
                begin: begin_selector,
                end: end_selector,
                mode: options::StreamingMode::WantAll,
                reverse: !params.ascending,
                ..Default::default()
            };
            let rows = match params.fetch {
                Fetch::All => None,
                Fetch::Expect(_) => expect_window,
                Fetch::Limit(_) => match &assembly {
                    Assembly::Forward(Some(chunk)) if params.values && sink.left == 1 => {
                        tail_end = chunk.tail_end();
                        if tail_end <= end {
                            range.end = KeySelector::first_greater_or_equal(&tail_end);
                        }
                        None
                    }
                    Assembly::Forward(pending) => {
                        Some(sink.left - u64::from(params.values && pending.is_some()))
                    }
                    Assembly::Reverse(run) => Some(sink.left.saturating_sub(run.members()) + 1),
                },
            };
            if let Some(rows) = rows {
                range.limit = Some(fetch_limit(rows));
                range.mode = match params.fetch {
                    Fetch::Expect(_) => options::StreamingMode::WantAll,
                    Fetch::All | Fetch::Limit(_) => bounded_mode(rows),
                };
            }

            let trx = match next_trx.take() {
                Some(trx) => trx,
                None => self.read_trx().await?,
            };
            let progressed = take(&mut carried);
            let mut stream = trx.get_ranges(range, true);
            read_key.clear();

            loop {
                match stream.try_next().await {
                    Ok(Some(values)) => {
                        #[cfg(stalwart_tests)]
                        super::probe::range_batch(&values);
                        read_key.clear();
                        if values.more()
                            && let Some(last) = values.last()
                        {
                            read_key.extend_from_slice(last.key());
                        }
                        if !assembly.batch(values, &mut sink, params.values)? {
                            return Ok(());
                        }
                    }
                    Ok(None) => {
                        drop(stream);
                        if read_key.is_empty() {
                            return assembly.finish(&mut sink, params.values);
                        }
                        expect_window = expect_window
                            .map(|rows| rows.saturating_mul(u64::from(ITERATE_BATCH_GROWTH)));
                        swap(&mut last_key, &mut read_key);
                        next_trx = Some(trx);
                        carried = true;
                        continue 'outer;
                    }
                    Err(e) => {
                        drop(stream);
                        if e.code() == 1007 && (progressed || !read_key.is_empty()) {
                            // Transaction is too old to perform reads or be committed
                            if !read_key.is_empty() {
                                swap(&mut last_key, &mut read_key);
                            }
                            self.version.expire();
                            continue 'outer;
                        } else if e.is_retryable()
                            && retry_count < MAX_COMMIT_ATTEMPTS
                            && start.elapsed() < MAX_COMMIT_TIME
                        {
                            // Transient error such as a cached read version ahead of lagging
                            // storage servers (code 1009); resume from the last key read,
                            // refresh the read version and back off before retrying.
                            if !read_key.is_empty() {
                                swap(&mut last_key, &mut read_key);
                            }
                            self.version.expire();
                            let trx = trx.on_error(e).await.map_err(into_error)?;
                            next_trx = Some(self.apply_read_version(trx).await?);
                            retry_count += 1;
                            continue 'outer;
                        } else {
                            return Err(into_error(e));
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
                &trx,
                &self.windows,
                rows,
                Isolation::Snapshot,
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
                    trx = self
                        .on_window_error(trx, error, progressed, &mut retry_count, start)
                        .await?;
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
            match trx.get(&key, true).await {
                Ok(Some(bytes)) => return deserialize_i64_le(&key, &bytes),
                Ok(None) => return Ok(0),
                Err(e) => {
                    trx = self.on_read_error(trx, e, &mut retry_count, start).await?;
                }
            }
        }
    }

    pub(super) async fn on_read_error(
        &self,
        trx: Transaction,
        err: FdbError,
        retry_count: &mut u32,
        start: Instant,
    ) -> trc::Result<Transaction> {
        if err.is_retryable()
            && *retry_count < MAX_COMMIT_ATTEMPTS
            && start.elapsed() < MAX_COMMIT_TIME
        {
            // The cached read version may be ahead of lagging storage servers under heavy write
            // load (code 1009); expire it so the retry obtains a fresh read version, then let
            // FoundationDB back off before retrying.
            self.version.expire();
            let trx = trx.on_error(err).await.map_err(into_error)?;
            *retry_count += 1;
            self.apply_read_version(trx).await
        } else {
            Err(into_error(err))
        }
    }

    pub(super) async fn on_window_error(
        &self,
        trx: Transaction,
        err: FdbError,
        progressed: bool,
        retry_count: &mut u32,
        start: Instant,
    ) -> trc::Result<Transaction> {
        if err.code() == 1007 && progressed {
            self.version.expire();
            self.read_trx().await
        } else {
            self.on_read_error(trx, err, retry_count, start).await
        }
    }

    pub(crate) async fn read_trx(&self) -> trc::Result<Transaction> {
        let trx = self.db.create_trx().map_err(into_error)?;
        self.apply_read_version(trx).await
    }

    async fn fresh_trx(&self) -> trc::Result<Transaction> {
        let trx = self.db.create_trx().map_err(into_error)?;
        trx.set_option(TransactionOption::ReadYourWritesDisable)
            .map_err(into_error)?;
        let read_version = trx.get_read_version().await.map_err(into_error)?;
        self.version.refreshed(read_version);
        Ok(trx)
    }

    pub(super) async fn apply_read_version(&self, trx: Transaction) -> trc::Result<Transaction> {
        trx.set_option(TransactionOption::ReadYourWritesDisable)
            .map_err(into_error)?;
        #[cfg(stalwart_tests)]
        if let Some(version) = super::probe::pinned_read_version() {
            trx.set_read_version(version);
            return Ok(trx);
        }
        let version = self.version.current();
        let age = self.version.age();

        if version != 0 && age < MAX_READ_VERSION_AGE.as_nanos() as u64 {
            if age >= REFRESH_READ_VERSION_AFTER.as_nanos() as u64
                && let Some(_guard) = self.version.try_begin_refresh()
            {
                let read_version = trx.get_read_version().await.map_err(into_error)?;
                self.version.refreshed(read_version);
            } else {
                trx.set_read_version(version);
            }
        } else {
            let read_version = trx.get_read_version().await.map_err(into_error)?;
            self.version.refreshed(read_version);
        }

        #[cfg(stalwart_tests)]
        super::probe::read_version_applied(&trx).await;

        Ok(trx)
    }

    pub(crate) fn invalidate_read_snapshot(&self) {
        self.version.expire();
    }

    pub(crate) fn read_snapshot_version(&self) -> Option<u64> {
        self.version
            .last_committed()
            .and_then(|version| u64::try_from(version).ok())
    }

    pub(crate) fn advance_read_snapshot(&self, version: u64) {
        if let Ok(version) = i64::try_from(version) {
            self.version.advance(version);
        }
    }
}

const MIN_EXPECT_WINDOW: u64 = 64;

fn bounded_mode(rows: u64) -> options::StreamingMode {
    if rows <= MAX_EXACT_MODE_ROWS {
        options::StreamingMode::Exact
    } else {
        options::StreamingMode::WantAll
    }
}

fn fetch_limit(rows: u64) -> usize {
    usize::try_from(rows).unwrap_or(usize::MAX)
}

pub(crate) async fn read_chunked_value(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
) -> Result<ChunkedValue, FdbError> {
    if let Some(bytes) = trx.get(key, snapshot).await? {
        if bytes.len() < MAX_VALUE_SIZE {
            return Ok(ChunkedValue::Single(bytes));
        }
        Ok(match read_chunk_tail(key, trx, snapshot, &bytes).await? {
            Some(chunked) => chunked,
            None => ChunkedValue::Single(bytes),
        })
    } else {
        Ok(ChunkedValue::None)
    }
}

pub(crate) async fn read_chunk_tail(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
    head: &[u8],
) -> Result<Option<ChunkedValue>, FdbError> {
    let mut chunk_key = KeySerializer::new(key.len() + 1)
        .write(key)
        .write(0u8)
        .finalize();
    let Some(chunk) = trx.get(&chunk_key, snapshot).await? else {
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
        match trx.get(&chunk_key, snapshot).await? {
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
