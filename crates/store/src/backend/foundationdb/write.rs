/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FDB_VALUE_TOO_LARGE, FdbStore, MAX_THROTTLED_TIME, MAX_VALUE_SIZE, into_error,
    known::KnownValues,
    preread::{MergePreRead, Prefetched},
    read::{ChunkedValue, Source, read_chunk_tail, read_chunked_value},
};
use crate::{
    backend::deserialize_i64_le,
    write::{
        Advance, Allocation, AnyKey, AssignedIds, Batch, BatchCursor, CommitPriority, CounterBound,
        LogSet, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, MAX_CONCURRENT_ALLOCATIONS, MergeResult,
        ValueClass, ValueOp, commit_backoff, exhausted, key::KeySerializer,
    },
    *,
};
use fdb::{
    AtomicOp, Bytes, CommitError, ErrorCode, KeyValue, Priority, RangeCursor, RangeOptions,
    ReadOptions, Transaction, TransactionOptions,
};
use futures::future::{Either, ready, try_join_all};
use std::{
    borrow::Cow,
    cmp::Ordering,
    mem::swap,
    ops::{Bound, Range},
    time::Instant,
};

const PURGE_BATCH_SIZE: usize = 1024;

enum Previous<'x> {
    Prefetched(Option<&'x [u8]>),
    Read(ChunkedValue),
    Known(&'x ChunkedValue),
}

struct Throttle {
    priority: CommitPriority,
    since: Option<Instant>,
}

struct CounterKeys {
    buf: Vec<u8>,
    ranges: Vec<Range<usize>>,
    reservation_key: Vec<usize>,
    reservation_total: Vec<i64>,
}

#[derive(Clone, Copy)]
enum Written {
    Set(i64),
    Add(i64),
}

#[derive(Clone, Copy, Default)]
struct OwnWrites {
    set: Option<i64>,
    add: i64,
}

impl FdbStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        result: &mut AssignedIds,
    ) -> trc::Result<()> {
        let mut start = Instant::now();
        let mut retry_count = 0;
        let mut throttle = Throttle::new(batch.priority);
        let mark = result.mark();
        let counter_keys = counter_keys(&batch);
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        let mut next_trx: Option<Transaction<'_>> = None;

        'retry: loop {
            let mut cursor = BatchCursor::new(&batch);
            result.rollback(mark);

            let mut trx = match next_trx.take() {
                Some(trx) => trx,
                None => self.transaction(batch.priority),
            };

            let mut preread = if counter_keys.is_empty() {
                MergePreRead::plan(&mut batch, result)
            } else {
                if let Err(err) = allocate_counters(&mut trx, &batch, &counter_keys, result).await {
                    match err {
                        ApplyError::Retryable(err) => {
                            self.on_write_error(
                                &mut trx,
                                err,
                                &mut retry_count,
                                &mut start,
                                &mut throttle,
                            )
                            .await?;
                            next_trx = Some(trx);
                            continue 'retry;
                        }
                        ApplyError::Fatal(err) => return Err(err),
                    }
                }
                MergePreRead::plan(&mut batch, result)
            };
            let mut known = KnownValues::plan(&mut batch, result);
            if let Some(preread) = &mut preread {
                if let Err(err) = preread.read(&mut trx, &self.windows).await {
                    self.on_write_error(&mut trx, err, &mut retry_count, &mut start, &mut throttle)
                        .await?;
                    next_trx = Some(trx);
                    continue 'retry;
                }
                known.seed(preread.prefetched());
            }

            let mut key_buf = Vec::with_capacity(64);
            for op in batch.ops.iter_mut() {
                match cursor.advance(op, result) {
                    Advance::Cursor => {}
                    Advance::Value { class, op } => {
                        cursor.value_key(class, &mut key_buf, WITH_SUBSPACE);
                        let slot = known.slot(&key_buf);

                        match op {
                            ValueOp::Set(set_value) => {
                                let value = set_value.resolve(result)?;
                                if !chunk_value(&mut trx, &mut key_buf, &value, class, None).await?
                                {
                                    return Err(value_too_large());
                                }
                                known.forget(slot);
                            }
                            ValueOp::MergeFnc(merge_op) => {
                                let prefetched = preread.as_mut().map(MergePreRead::next_merge);
                                let previous = match (known.get(slot), prefetched) {
                                    (Some(value), _) => Ok(Previous::Known(value)),
                                    (None, Some(Prefetched::Value(value))) => {
                                        Ok(Previous::Prefetched(value))
                                    }
                                    (None, Some(Prefetched::Head(head))) => read_chunk_tail(
                                        &key_buf,
                                        &mut Source::Transaction(&mut trx),
                                        head,
                                    )
                                    .await
                                    .map(|tail| match tail {
                                        Some(chunked) => Previous::Read(chunked),
                                        None => Previous::Prefetched(Some(head)),
                                    }),
                                    (None, Some(Prefetched::Sequential) | None) => {
                                        read_chunked_value(
                                            &key_buf,
                                            &mut Source::Transaction(&mut trx),
                                        )
                                        .await
                                        .map(Previous::Read)
                                    }
                                };
                                let previous = match previous {
                                    Ok(previous) => previous,
                                    Err(err) => {
                                        self.on_write_error(
                                            &mut trx,
                                            err,
                                            &mut retry_count,
                                            &mut start,
                                            &mut throttle,
                                        )
                                        .await?;
                                        next_trx = Some(trx);
                                        continue 'retry;
                                    }
                                };
                                let (current_value, merge_input, prev_num_chunks) = match &previous
                                {
                                    Previous::Prefetched(Some(bytes)) => {
                                        (Some(*bytes), Some(*bytes), 1)
                                    }
                                    Previous::Prefetched(None)
                                    | Previous::Read(ChunkedValue::None)
                                    | Previous::Known(ChunkedValue::None) => (None, None, 0),
                                    Previous::Read(ChunkedValue::Single(bytes))
                                    | Previous::Known(ChunkedValue::Single(bytes)) => {
                                        (Some(bytes.as_ref()), Some(bytes.as_ref()), 1)
                                    }
                                    Previous::Read(ChunkedValue::Chunked { bytes, n_chunks })
                                    | Previous::Known(ChunkedValue::Chunked { bytes, n_chunks }) => {
                                        (None, Some(bytes.as_slice()), *n_chunks as usize + 1)
                                    }
                                };
                                let merge_result = (merge_op.0)(result, merge_input)?;

                                match merge_result {
                                    MergeResult::Update(value) => {
                                        if let Some(append_bytes) =
                                            current_value.and_then(|current| {
                                                value
                                                    .strip_prefix(current)
                                                    .filter(|_| value.len() < MAX_VALUE_SIZE)
                                            })
                                        {
                                            trx.atomic_op(
                                                &key_buf,
                                                append_bytes,
                                                AtomicOp::AppendIfFits,
                                            )
                                            .map_err(into_error)?;
                                            known.update(slot, move || {
                                                Some(ChunkedValue::Single(Bytes::from(value)))
                                            });
                                        } else if chunk_value(
                                            &mut trx,
                                            &mut key_buf,
                                            &value,
                                            class,
                                            Some(prev_num_chunks),
                                        )
                                        .await?
                                        {
                                            known
                                                .update(slot, move || ChunkedValue::written(value));
                                        } else {
                                            return Err(value_too_large());
                                        }
                                    }
                                    MergeResult::Delete => {
                                        let cleared = if prev_num_chunks > 1 {
                                            clear_chunks(&mut trx, &key_buf, None).await
                                        } else {
                                            trx.clear(&key_buf)
                                        };
                                        cleared.map_err(into_error)?;
                                        known.update(slot, || Some(ChunkedValue::None));
                                    }
                                    MergeResult::Skip => match previous {
                                        Previous::Read(value) => {
                                            known.update(slot, move || Some(value))
                                        }
                                        Previous::Prefetched(value) if slot.is_some() => {
                                            let value = value.map_or(ChunkedValue::None, |value| {
                                                ChunkedValue::Single(Bytes::copy_from_slice(value))
                                            });
                                            known.update(slot, move || Some(value));
                                        }
                                        Previous::Prefetched(_) | Previous::Known(_) => (),
                                    },
                                }
                            }
                            ValueOp::AtomicAdd(by) => {
                                trx.atomic_op(&key_buf, &by.to_le_bytes()[..], AtomicOp::Add)
                                    .map_err(into_error)?;
                                known.forget(slot);
                            }
                            ValueOp::AddAndGet(by) => {
                                let read;
                                let current = match known.get(slot) {
                                    Some(value) => value.bytes(),
                                    None => {
                                        #[cfg(stalwart_tests)]
                                        super::probe::point_read(&key_buf);
                                        match trx.get(&key_buf).await {
                                            Ok(current) => {
                                                read = current;
                                                read.as_deref()
                                            }
                                            Err(err) => {
                                                self.on_write_error(
                                                    &mut trx,
                                                    err,
                                                    &mut retry_count,
                                                    &mut start,
                                                    &mut throttle,
                                                )
                                                .await?;
                                                next_trx = Some(trx);
                                                continue 'retry;
                                            }
                                        }
                                    }
                                };
                                let num = if let Some(bytes) = current {
                                    deserialize_i64_le(&key_buf, bytes)? + *by
                                } else {
                                    *by
                                };
                                trx.set(&key_buf, &num.to_le_bytes()[..])
                                    .map_err(into_error)?;
                                known.forget(slot);
                                result.push_counter_id(num);
                            }
                            ValueOp::Clear => {
                                let cleared = if class.may_be_chunked() {
                                    clear_chunks(&mut trx, &key_buf, None).await
                                } else {
                                    trx.clear(&key_buf)
                                };
                                cleared.map_err(into_error)?;
                                known.forget(slot);
                            }
                        }
                    }
                    Advance::Index { field, key, set } => {
                        cursor.index_key(field, key, &mut key_buf, WITH_SUBSPACE);

                        let written = if set {
                            trx.set(&key_buf, &[])
                        } else {
                            trx.clear(&key_buf)
                        };
                        written.map_err(into_error)?;
                    }
                    Advance::Log { collection, set } => {
                        cursor.log_key(collection, result, &mut key_buf, WITH_SUBSPACE);

                        let written = match set {
                            LogSet::Bytes(bytes) => trx.set(&key_buf, bytes),
                            LogSet::Pending(changes) => {
                                changes.serialize_into(
                                    collection.is_prefixed(),
                                    result,
                                    &mut log_scratch,
                                    &mut log_buf,
                                );
                                trx.set(&key_buf, &log_buf)
                            }
                        };
                        written.map_err(into_error)?;
                    }
                    Advance::ClearRange { subspace, from, to } => {
                        key_buf.clear();
                        AnyKey {
                            subspace,
                            key: from,
                        }
                        .serialize_into(&mut key_buf, WITH_SUBSPACE);
                        let mut end = Vec::with_capacity(to.len() + 1);
                        AnyKey { subspace, key: to }.serialize_into(&mut end, WITH_SUBSPACE);
                        trx.clear_range(&key_buf, &end).map_err(into_error)?;
                        known.forget_all();
                    }
                    Advance::Assert {
                        class,
                        assert_value,
                    } => {
                        cursor.value_key(class, &mut key_buf, WITH_SUBSPACE);
                        let slot = known.slot(&key_buf);

                        let mut read = None;
                        let value = match known.get(slot) {
                            Some(value) => value,
                            None => match read_chunked_value(
                                &key_buf,
                                &mut Source::Transaction(&mut trx),
                            )
                            .await
                            {
                                Ok(value) => read.insert(value),
                                Err(err) => {
                                    self.on_write_error(
                                        &mut trx,
                                        err,
                                        &mut retry_count,
                                        &mut start,
                                        &mut throttle,
                                    )
                                    .await?;
                                    next_trx = Some(trx);
                                    continue 'retry;
                                }
                            },
                        };
                        let matches = match value.bytes() {
                            Some(bytes) => assert_value.matches(bytes),
                            None => assert_value.is_none(),
                        };

                        if !matches {
                            if let Ok(read_version) = trx.read_version().await {
                                self.db.advance_read_version(read_version);
                            }
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                        if let Some(value) = read {
                            known.update(slot, move || Some(value));
                        }
                    }
                }
            }

            let will_retry = retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME;
            #[cfg(stalwart_tests)]
            let injected = super::probe::injected_throttle(batch.priority);
            #[cfg(not(stalwart_tests))]
            let injected = None;
            let (err, failed) = match injected {
                Some(err) => (err, None),
                None => match self.try_commit(trx).await {
                    Ok(()) => return Ok(()),
                    Err(failed) => (failed.error(), Some(failed)),
                },
            };
            if throttle.waits(err) {
                start = Instant::now();
                tokio::time::sleep(commit_backoff(MAX_COMMIT_ATTEMPTS)).await;
            } else {
                retry_not_committed(err, will_retry, retry_count)?;
                #[cfg(stalwart_tests)]
                crate::write::record_retry(retry_count);
                tokio::time::sleep(commit_backoff(retry_count)).await;
                retry_count += 1;
            }
            next_trx = failed.map(CommitError::into_transaction);
        }
    }

    fn transaction(&self, priority: CommitPriority) -> Transaction<'_> {
        self.db.transaction(TransactionOptions {
            priority: match priority {
                CommitPriority::Default => Priority::Default,
                CommitPriority::Background => Priority::Batch,
            },
            #[cfg(stalwart_tests)]
            conflict_report: super::probe::conflict_report(),
            ..Default::default()
        })
    }

    async fn on_write_error<'db>(
        &'db self,
        trx: &mut Transaction<'db>,
        err: fdb::Error,
        retry_count: &mut u32,
        start: &mut Instant,
        throttle: &mut Throttle,
    ) -> trc::Result<()> {
        if throttle.waits(err) {
            *start = Instant::now();
            tokio::time::sleep(commit_backoff(MAX_COMMIT_ATTEMPTS)).await;
            *trx = self.transaction(throttle.priority);
            Ok(())
        } else if !err.is_retryable() {
            Err(into_error(err))
        } else if *retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME {
            #[cfg(stalwart_tests)]
            crate::write::record_retry(*retry_count);
            trx.on_error(err).await.map_err(into_error)?;
            *retry_count += 1;
            Ok(())
        } else {
            Err(exhausted(into_error(err), *retry_count))
        }
    }

    pub(super) async fn commit_attempt(
        &self,
        trx: Transaction<'_>,
        retry_count: u32,
        start: Instant,
    ) -> trc::Result<bool> {
        let will_retry = retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME;

        match self.try_commit(trx).await {
            Ok(()) => Ok(true),
            Err(err) => retry_not_committed(err.error(), will_retry, retry_count).map(|()| false),
        }
    }

    async fn try_commit<'db>(&self, trx: Transaction<'db>) -> Result<(), CommitError<'db>> {
        match trx.commit().await {
            Ok(_) => {
                #[cfg(stalwart_tests)]
                super::probe::commit_ok();
                Ok(())
            }
            Err(err) => {
                #[cfg(stalwart_tests)]
                super::probe::commit_failed(&err);
                Err(err)
            }
        }
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
        {
            let from_key = [subspace.byte()];
            let to_key = [subspace.byte() + 1];
            let mut delete_keys: Vec<Vec<u8>> = Vec::new();
            let mut last_key: Vec<u8> = Vec::new();
            let mut read_key: Vec<u8> = Vec::new();
            let mut retry_count = 0;
            let mut start = Instant::now();
            let mut next_trx = None;

            'scan: loop {
                let mut trx = match next_trx.take() {
                    Some(trx) => trx,
                    None => {
                        self.read(ReadOptions {
                            priority: Priority::Batch,
                            ..Default::default()
                        })
                        .await?
                    }
                };
                let mut made_progress = false;
                let begin = if last_key.is_empty() {
                    Bound::Included(&from_key[..])
                } else {
                    Bound::Excluded(last_key.as_slice())
                };
                let mut values =
                    RangeCursor::new(begin, Bound::Excluded(&to_key[..]), RangeOptions::default())
                        .map_err(into_error)?;
                read_key.clear();

                loop {
                    match values.next(trx.snapshot()).await {
                        Ok(Some(page)) => {
                            for KeyValue { key, value } in &page {
                                made_progress = true;
                                read_key.clear();
                                read_key.extend_from_slice(key);

                                if value.iter().all(|byte| *byte == 0) {
                                    delete_keys.push(key.to_vec());

                                    if delete_keys.len() >= PURGE_BATCH_SIZE {
                                        drop(values);
                                        swap(&mut last_key, &mut read_key);
                                        self.purge_counters(&mut delete_keys).await?;
                                        retry_count = 0;
                                        start = Instant::now();
                                        continue 'scan;
                                    }
                                }
                            }
                        }
                        Ok(None) => break 'scan,
                        Err(err) => {
                            drop(values);
                            if made_progress {
                                swap(&mut last_key, &mut read_key);
                                retry_count = 0;
                                start = Instant::now();
                            }
                            if err.is_retryable()
                                && retry_count < MAX_COMMIT_ATTEMPTS
                                && start.elapsed() < MAX_COMMIT_TIME
                            {
                                trx.on_error(err).await.map_err(into_error)?;
                                next_trx = Some(trx);
                                retry_count += 1;
                                continue 'scan;
                            }
                            return Err(into_error(err));
                        }
                    }
                }
            }

            self.purge_counters(&mut delete_keys).await?;
        }

        Ok(())
    }

    async fn purge_counters(&self, delete_keys: &mut Vec<Vec<u8>>) -> trc::Result<()> {
        if delete_keys.is_empty() {
            return Ok(());
        }

        let integer = 0i64.to_le_bytes();
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            let mut trx = self.db.transaction(TransactionOptions {
                priority: Priority::Batch,
                ..Default::default()
            });
            for key in delete_keys.iter() {
                trx.atomic_op(key, &integer, AtomicOp::CompareAndClear)
                    .map_err(into_error)?;
            }

            if self.commit_attempt(trx, retry_count, start).await? {
                delete_keys.clear();
                return Ok(());
            }

            #[cfg(stalwart_tests)]
            crate::write::record_retry(retry_count);
            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let from = from.serialize(WITH_SUBSPACE);
        let to = to.serialize(WITH_SUBSPACE);
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            let mut trx = self.db.transaction(TransactionOptions::default());
            trx.clear_range(&from, &to).map_err(into_error)?;

            if self.commit_attempt(trx, retry_count, start).await? {
                return Ok(());
            }

            #[cfg(stalwart_tests)]
            crate::write::record_retry(retry_count);
            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }
}

impl Throttle {
    fn new(priority: CommitPriority) -> Self {
        Throttle {
            priority,
            since: None,
        }
    }

    fn waits(&mut self, err: fdb::Error) -> bool {
        self.priority == CommitPriority::Background
            && err.error_code() == ErrorCode::BATCH_TRANSACTION_THROTTLED
            && self.since.get_or_insert_with(Instant::now).elapsed() < MAX_THROTTLED_TIME
    }
}

fn retry_not_committed(err: fdb::Error, will_retry: bool, retry_count: u32) -> trc::Result<()> {
    if !err.is_retryable_not_committed() {
        Err(into_error(err))
    } else if will_retry {
        Ok(())
    } else {
        Err(exhausted(into_error(err), retry_count))
    }
}

#[cold]
fn value_too_large() -> trc::Error {
    trc::StoreEvent::FoundationdbError
        .ctx(trc::Key::Reason, "Value is too large")
        .ctx(trc::Key::Code, FDB_VALUE_TOO_LARGE)
}

async fn clear_chunks(
    trx: &mut Transaction<'_>,
    key: &[u8],
    from_chunk: Option<u8>,
) -> fdb::Result<()> {
    let to = KeySerializer::new(key.len() + 1)
        .write(key)
        .write(u8::MAX)
        .finalize();
    let from = match from_chunk {
        Some(from_chunk) => Cow::Owned(
            KeySerializer::new(key.len() + 1)
                .write(key)
                .write(from_chunk)
                .finalize(),
        ),
        None => Cow::Borrowed(key),
    };

    #[cfg(debug_assertions)]
    if let Ok(snapshot) = trx.snapshot().await
        && let Ok(mut chunks) = RangeCursor::new(
            Bound::Included(from.as_ref()),
            Bound::Excluded(to.as_slice()),
            RangeOptions::default(),
        )
    {
        while let Ok(Some(page)) = chunks.next(snapshot).await {
            for found in page.iter().map(|row| row.key) {
                debug_assert!(
                    found.len() == key.len() + 1 || found == key,
                    "chunk range of {key:?} holds foreign key {found:?}, clearing it would destroy data"
                );
            }
        }
    }

    trx.clear_range(from.as_ref(), &to)
}

async fn chunk_value(
    trx: &mut Transaction<'_>,
    key: &mut Vec<u8>,
    value: &[u8],
    class: &ValueClass,
    prev_num_chunks: Option<usize>,
) -> trc::Result<bool> {
    let num_chunks = if value.len() >= MAX_VALUE_SIZE {
        value.len().div_ceil(MAX_VALUE_SIZE)
    } else {
        1
    };

    if num_chunks > u8::MAX as usize {
        return Ok(false);
    }

    debug_assert!(
        num_chunks == 1 || class.may_be_chunked() || matches!(class, ValueClass::Any(_)),
        "{class:?} was split into {num_chunks} chunks but is not declared chunkable, \
         stale chunks will be spliced onto a later shorter value"
    );

    if class.may_be_chunked()
        && prev_num_chunks.is_none_or(|prev_num_chunks| prev_num_chunks > num_chunks)
    {
        clear_chunks(trx, key, Some((num_chunks - 1) as u8))
            .await
            .map_err(into_error)?;
    }

    if value.len() >= MAX_VALUE_SIZE {
        for (pos, chunk) in value.chunks(MAX_VALUE_SIZE).enumerate() {
            match pos.cmp(&1) {
                Ordering::Less => {}
                Ordering::Equal => key.push(0),
                Ordering::Greater => {
                    if let Some(last) = key.last_mut() {
                        *last += 1;
                    }
                }
            }
            trx.set(key, chunk).map_err(into_error)?;
        }
    } else {
        trx.set(key, value).map_err(into_error)?;
    }

    Ok(true)
}

enum ApplyError {
    Retryable(fdb::Error),
    Fatal(trc::Error),
}

impl From<trc::Error> for ApplyError {
    fn from(err: trc::Error) -> Self {
        ApplyError::Fatal(err)
    }
}

impl CounterKeys {
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[inline(always)]
    fn key(&self, index: usize) -> &[u8] {
        &self.buf[self.ranges[index].clone()]
    }
}

fn counter_keys(batch: &Batch<'_>) -> CounterKeys {
    let num_accounts = batch.change_accounts.len();
    let total = num_accounts + batch.reservations.len() + batch.bounds.len();
    let mut keys = CounterKeys {
        buf: Vec::with_capacity(total * 16),
        ranges: Vec::with_capacity(total),
        reservation_key: Vec::with_capacity(batch.reservations.len()),
        reservation_total: Vec::with_capacity(batch.reservations.len()),
    };
    let mut key = Vec::with_capacity(16);

    for counter in batch.change_accounts {
        debug_assert!(counter.account_id != u32::MAX);
        let start = keys.buf.len();
        Allocation::ChangeId(*counter).serialize_key_into(&mut keys.buf, WITH_SUBSPACE);
        keys.ranges.push(start..keys.buf.len());
    }

    for reservation in batch.reservations {
        key.clear();
        Allocation::Reserved(*reservation).serialize_key_into(&mut key, WITH_SUBSPACE);

        let key_index = match keys.ranges[num_accounts..]
            .iter()
            .position(|range| keys.buf[range.clone()] == key[..])
        {
            Some(offset) => {
                keys.reservation_total[offset] += reservation.count as i64;
                num_accounts + offset
            }
            None => {
                let start = keys.buf.len();
                keys.buf.extend_from_slice(&key);
                keys.ranges.push(start..keys.buf.len());
                keys.reservation_total.push(reservation.count as i64);
                keys.ranges.len() - 1
            }
        };
        keys.reservation_key.push(key_index);
    }

    for bound in batch.bounds {
        let start = keys.buf.len();
        bound.serialize_key_into(&mut keys.buf, WITH_SUBSPACE);
        keys.ranges.push(start..keys.buf.len());
    }

    keys
}

async fn allocate_counters(
    trx: &mut Transaction<'_>,
    batch: &Batch<'_>,
    keys: &CounterKeys,
    result: &mut AssignedIds,
) -> Result<(), ApplyError> {
    let num_accounts = batch.change_accounts.len();
    let num_reserved = num_accounts + keys.reservation_total.len();
    let mut cursors = vec![0i64; keys.reservation_total.len()];
    let tracks_writes = keys.ranges.len() > MAX_CONCURRENT_ALLOCATIONS;
    let mut written = Vec::new();
    let mut snapshot = None;
    let overshoots = |index: usize| {
        index >= num_reserved
            && batch
                .bounds
                .get(index - num_reserved)
                .is_some_and(CounterBound::allows_overshoot)
    };

    for chunk_start in (0..keys.ranges.len()).step_by(MAX_CONCURRENT_ALLOCATIONS) {
        let chunk_end = (chunk_start + MAX_CONCURRENT_ALLOCATIONS).min(keys.ranges.len());
        if snapshot.is_none() && (chunk_start..chunk_end).any(overshoots) {
            snapshot = Some(trx.snapshot().await.map_err(ApplyError::Retryable)?);
        }
        let mut own = [None; MAX_CONCURRENT_ALLOCATIONS];
        if chunk_start > 0 {
            let earlier = written.get(..chunk_start).unwrap_or_default();
            for (slot, index) in own.iter_mut().zip(chunk_start..chunk_end) {
                if overshoots(index) {
                    *slot = Some(OwnWrites::fold(keys, earlier, keys.key(index)));
                }
            }
        }
        let values = try_join_all((chunk_start..chunk_end).zip(own).map(|(index, own)| {
            let key = keys.key(index);
            match (own, snapshot.filter(|_| overshoots(index))) {
                (Some(OwnWrites { set: Some(_), .. }), _) => {
                    Either::Left(Either::Left(ready(Ok(None))))
                }
                (_, Some(snapshot)) => {
                    Either::Left(Either::Right(async move { snapshot.get(key).await }))
                }
                (_, None) => Either::Right(trx.get(key)),
            }
        }))
        .await
        .map_err(ApplyError::Retryable)?;

        for ((offset, value), own) in values.into_iter().enumerate().zip(own) {
            let index = chunk_start + offset;
            let key = keys.key(index);
            let mut current = match value {
                Some(bytes) => deserialize_i64_le(key, &bytes)?,
                None => 0,
            };
            if let Some(own) = own {
                current = own.apply(current);
            }

            let write = if index < num_accounts {
                let account = &batch.change_accounts[index];
                let change_id = current + 1;
                trx.set(key, &change_id.to_le_bytes()[..])
                    .map_err(into_error)?;
                result.push_change_id(*account, change_id as u64);
                Written::Set(change_id)
            } else if index < num_reserved {
                let key_offset = index - num_accounts;
                let last_id = current + keys.reservation_total[key_offset];
                trx.set(key, &last_id.to_le_bytes()[..])
                    .map_err(into_error)?;
                cursors[key_offset] = current;
                Written::Set(last_id)
            } else {
                let bound = &batch.bounds[index - num_reserved];
                let value = current.saturating_add(bound.by);
                bound.verify(value)?;
                if bound.allows_overshoot() {
                    trx.atomic_op(key, &bound.by.to_le_bytes()[..], AtomicOp::Add)
                        .map_err(into_error)?;
                    Written::Add(bound.by)
                } else {
                    trx.set(key, &value.to_le_bytes()[..]).map_err(into_error)?;
                    Written::Set(value)
                }
            };
            if tracks_writes {
                written.push(write);
            }
        }
    }

    for (reservation, key_index) in batch.reservations.iter().zip(keys.reservation_key.iter()) {
        let cursor = &mut cursors[key_index - num_accounts];
        *cursor += reservation.count as i64;
        result.fill_slots(reservation.first_slot, reservation.count, *cursor as u32);
    }

    Ok(())
}

impl OwnWrites {
    fn fold(keys: &CounterKeys, written: &[Written], key: &[u8]) -> Self {
        written
            .iter()
            .enumerate()
            .filter(|(index, _)| keys.key(*index) == key)
            .fold(OwnWrites::default(), |own, (_, write)| match write {
                Written::Set(set) => OwnWrites {
                    set: Some(*set),
                    add: 0,
                },
                Written::Add(by) => OwnWrites {
                    add: own.add.wrapping_add(*by),
                    ..own
                },
            })
    }

    fn apply(self, snapshot_value: i64) -> i64 {
        self.set.unwrap_or(snapshot_value).wrapping_add(self.add)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/foundationdb/write/tests.rs"]
mod tests;
