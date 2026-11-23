/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FDB_BATCH_THROTTLED, FDB_VALUE_TOO_LARGE, FdbStore, MAX_THROTTLED_TIME, MAX_VALUE_SIZE,
    into_error,
    preread::{MergePreRead, Prefetched},
    read::{ChunkedValue, read_chunk_tail, read_chunked_value},
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
use foundationdb::{
    FdbError, KeySelector, RangeOption, Transaction,
    options::{self, MutationType},
};
use futures::TryStreamExt;
use std::{borrow::Cow, cmp::Ordering, ops::Range, time::Instant};

const PURGE_BATCH_SIZE: usize = 1024;

enum Previous<'x> {
    Prefetched(Option<&'x [u8]>),
    Read(ChunkedValue),
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

        let mut next_trx: Option<Transaction> = None;

        'retry: loop {
            let mut cursor = BatchCursor::new(&batch);
            result.rollback(mark);

            let trx = match next_trx.take() {
                Some(trx) => trx,
                None => self.db.create_trx().map_err(into_error)?,
            };
            if batch.priority == CommitPriority::Background {
                trx.set_option(options::TransactionOption::PriorityBatch)
                    .map_err(into_error)?;
            }
            #[cfg(stalwart_tests)]
            super::probe::report_conflicts(&trx);

            let mut preread = if counter_keys.is_empty() {
                let preread = MergePreRead::plan(&mut batch, result);
                if preread
                    .as_ref()
                    .is_some_and(|preread| !preread.reads_own_writes())
                {
                    trx.set_option(options::TransactionOption::ReadYourWritesDisable)
                        .map_err(into_error)?;
                }
                preread
            } else {
                if let Err(err) = allocate_counters(&trx, &batch, &counter_keys, result).await {
                    match err {
                        ApplyError::Retryable(err) => {
                            next_trx = Some(
                                self.on_write_error(
                                    trx,
                                    err,
                                    &mut retry_count,
                                    &mut start,
                                    &mut throttle,
                                )
                                .await?,
                            );
                            continue 'retry;
                        }
                        ApplyError::Fatal(err) => {
                            trx.cancel();
                            return Err(err);
                        }
                    }
                }
                MergePreRead::plan(&mut batch, result)
            };
            if let Some(preread) = &mut preread
                && let Err(err) = preread.read(&trx, &self.windows).await
            {
                next_trx = Some(
                    self.on_write_error(trx, err, &mut retry_count, &mut start, &mut throttle)
                        .await?,
                );
                continue 'retry;
            }

            let mut key_buf = Vec::with_capacity(64);
            for op in batch.ops.iter_mut() {
                match cursor.advance(op, result) {
                    Advance::Cursor => {}
                    Advance::Value { class, op } => {
                        cursor.value_key(class, &mut key_buf, WITH_SUBSPACE);

                        match op {
                            ValueOp::Set(set_value) => {
                                let value = set_value.resolve(result)?;
                                if !chunk_value(&trx, &mut key_buf, &value, class, None).await {
                                    trx.cancel();
                                    return Err(trc::StoreEvent::FoundationdbError
                                        .ctx(trc::Key::Reason, "Value is too large")
                                        .ctx(trc::Key::Code, FDB_VALUE_TOO_LARGE));
                                }
                            }
                            ValueOp::MergeFnc(merge_op) => {
                                let previous = match preread.as_mut().map(MergePreRead::next_merge)
                                {
                                    Some(Prefetched::Value(value)) => {
                                        Ok(Previous::Prefetched(value))
                                    }
                                    Some(Prefetched::Head(head)) => {
                                        read_chunk_tail(&key_buf, &trx, false, head).await.map(
                                            |tail| match tail {
                                                Some(chunked) => Previous::Read(chunked),
                                                None => Previous::Prefetched(Some(head)),
                                            },
                                        )
                                    }
                                    Some(Prefetched::Sequential) | None => {
                                        read_chunked_value(&key_buf, &trx, false)
                                            .await
                                            .map(Previous::Read)
                                    }
                                };
                                let previous = match previous {
                                    Ok(previous) => previous,
                                    Err(err) => {
                                        next_trx = Some(
                                            self.on_write_error(
                                                trx,
                                                err,
                                                &mut retry_count,
                                                &mut start,
                                                &mut throttle,
                                            )
                                            .await?,
                                        );
                                        continue 'retry;
                                    }
                                };
                                let (current_value, merge_input, prev_num_chunks) = match &previous
                                {
                                    Previous::Prefetched(Some(bytes)) => {
                                        (Some(*bytes), Some(*bytes), 1)
                                    }
                                    Previous::Prefetched(None)
                                    | Previous::Read(ChunkedValue::None) => (None, None, 0),
                                    Previous::Read(ChunkedValue::Single(slice)) => {
                                        (Some(slice.as_ref()), Some(slice.as_ref()), 1)
                                    }
                                    Previous::Read(ChunkedValue::Chunked { bytes, n_chunks }) => {
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
                                                MutationType::AppendIfFits,
                                            );
                                        } else if !chunk_value(
                                            &trx,
                                            &mut key_buf,
                                            &value,
                                            class,
                                            Some(prev_num_chunks),
                                        )
                                        .await
                                        {
                                            trx.cancel();
                                            return Err(trc::StoreEvent::FoundationdbError
                                                .ctx(trc::Key::Reason, "Value is too large")
                                                .ctx(trc::Key::Code, FDB_VALUE_TOO_LARGE));
                                        }
                                    }
                                    MergeResult::Delete => {
                                        if prev_num_chunks > 1 {
                                            clear_chunks(&trx, &key_buf, None).await;
                                        } else {
                                            trx.clear(&key_buf);
                                        }
                                    }
                                    MergeResult::Skip => (),
                                }
                            }
                            ValueOp::AtomicAdd(by) => {
                                trx.atomic_op(&key_buf, &by.to_le_bytes()[..], MutationType::Add);
                            }
                            ValueOp::AddAndGet(by) => {
                                let current = match trx.get(&key_buf, false).await {
                                    Ok(current) => current,
                                    Err(err) => {
                                        next_trx = Some(
                                            self.on_write_error(
                                                trx,
                                                err,
                                                &mut retry_count,
                                                &mut start,
                                                &mut throttle,
                                            )
                                            .await?,
                                        );
                                        continue 'retry;
                                    }
                                };
                                let num = if let Some(bytes) = current {
                                    deserialize_i64_le(&key_buf, &bytes)? + *by
                                } else {
                                    *by
                                };
                                trx.set(&key_buf, &num.to_le_bytes()[..]);
                                result.push_counter_id(num);
                            }
                            ValueOp::Clear => {
                                if class.may_be_chunked() {
                                    clear_chunks(&trx, &key_buf, None).await;
                                } else {
                                    trx.clear(&key_buf);
                                }
                            }
                        }
                    }
                    Advance::Index { field, key, set } => {
                        cursor.index_key(field, key, &mut key_buf, WITH_SUBSPACE);

                        if set {
                            trx.set(&key_buf, &[]);
                        } else {
                            trx.clear(&key_buf);
                        }
                    }
                    Advance::Log { collection, set } => {
                        cursor.log_key(collection, result, &mut key_buf, WITH_SUBSPACE);

                        match set {
                            LogSet::Bytes(bytes) => {
                                trx.set(&key_buf, bytes);
                            }
                            LogSet::Pending(changes) => {
                                changes.serialize_into(
                                    collection.is_prefixed(),
                                    result,
                                    &mut log_scratch,
                                    &mut log_buf,
                                );
                                trx.set(&key_buf, &log_buf);
                            }
                        }
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
                        trx.clear_range(&key_buf, &end);
                    }
                    Advance::Assert {
                        class,
                        assert_value,
                    } => {
                        cursor.value_key(class, &mut key_buf, WITH_SUBSPACE);

                        let matches = match read_chunked_value(&key_buf, &trx, false).await {
                            Ok(ChunkedValue::Single(bytes)) => assert_value.matches(bytes.as_ref()),
                            Ok(ChunkedValue::Chunked { bytes, .. }) => {
                                assert_value.matches(bytes.as_ref())
                            }
                            Ok(ChunkedValue::None) => assert_value.is_none(),
                            Err(err) => {
                                next_trx = Some(
                                    self.on_write_error(
                                        trx,
                                        err,
                                        &mut retry_count,
                                        &mut start,
                                        &mut throttle,
                                    )
                                    .await?,
                                );
                                continue 'retry;
                            }
                        };

                        if !matches {
                            if let Ok(read_version) = trx.get_read_version().await {
                                self.version.advance(read_version);
                            }
                            trx.cancel();
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                    }
                }
            }

            let will_retry = retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME;
            #[cfg(stalwart_tests)]
            let commit = match super::probe::injected_throttle(batch.priority) {
                Some(err) => {
                    trx.cancel();
                    Ok(Err(err))
                }
                None => self.try_commit(trx).await,
            };
            #[cfg(not(stalwart_tests))]
            let commit = self.try_commit(trx).await;
            match commit? {
                Ok(()) => return Ok(()),
                Err(err) if throttle.waits(err) => {
                    start = Instant::now();
                    tokio::time::sleep(commit_backoff(MAX_COMMIT_ATTEMPTS)).await;
                }
                Err(err) => {
                    retry_not_committed(err, will_retry, retry_count)?;
                    #[cfg(stalwart_tests)]
                    crate::write::record_retry(retry_count);
                    tokio::time::sleep(commit_backoff(retry_count)).await;
                    retry_count += 1;
                }
            }
        }
    }

    async fn on_write_error(
        &self,
        trx: Transaction,
        err: FdbError,
        retry_count: &mut u32,
        start: &mut Instant,
        throttle: &mut Throttle,
    ) -> trc::Result<Transaction> {
        if throttle.waits(err) {
            trx.cancel();
            *start = Instant::now();
            tokio::time::sleep(commit_backoff(MAX_COMMIT_ATTEMPTS)).await;
            self.db.create_trx().map_err(into_error)
        } else if !err.is_retryable() {
            Err(into_error(err))
        } else if *retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME {
            #[cfg(stalwart_tests)]
            crate::write::record_retry(*retry_count);
            let trx = trx.on_error(err).await.map_err(into_error)?;
            *retry_count += 1;
            Ok(trx)
        } else {
            Err(exhausted(into_error(err), *retry_count))
        }
    }

    pub(super) async fn commit_attempt(
        &self,
        trx: Transaction,
        retry_count: u32,
        start: Instant,
    ) -> trc::Result<bool> {
        let will_retry = retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME;

        match self.try_commit(trx).await? {
            Ok(()) => Ok(true),
            Err(err) => retry_not_committed(err, will_retry, retry_count).map(|()| false),
        }
    }

    async fn try_commit(&self, trx: Transaction) -> trc::Result<Result<(), FdbError>> {
        match trx.commit().await {
            Ok(result) => {
                #[cfg(stalwart_tests)]
                super::probe::commit_ok();
                let commit_version = result.committed_version().map_err(into_error)?;
                self.version.raise_floor(commit_version);
                Ok(Ok(()))
            }
            Err(err) => {
                #[cfg(stalwart_tests)]
                super::probe::commit_failed(&err).await;
                Ok(Err(FdbError::from(err)))
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
            let mut retry_count = 0;
            let mut start = Instant::now();
            let mut next_trx: Option<Transaction> = None;

            'scan: loop {
                let trx = match next_trx.take() {
                    Some(trx) => trx,
                    None => self.read_trx().await?,
                };
                trx.set_option(options::TransactionOption::PriorityBatch)
                    .map_err(into_error)?;
                let mut made_progress = false;

                let begin = if last_key.is_empty() {
                    KeySelector::first_greater_or_equal(&from_key[..])
                } else {
                    KeySelector::first_greater_than(last_key.clone())
                };
                let mut values = trx.get_ranges_keyvalues(
                    RangeOption {
                        begin,
                        end: KeySelector::first_greater_or_equal(&to_key[..]),
                        mode: options::StreamingMode::WantAll,
                        reverse: false,
                        ..Default::default()
                    },
                    true,
                );

                loop {
                    match values.try_next().await {
                        Ok(Some(value)) => {
                            made_progress = true;
                            last_key.clear();
                            last_key.extend_from_slice(value.key());

                            if value.value().iter().all(|byte| *byte == 0) {
                                delete_keys.push(value.key().to_vec());

                                if delete_keys.len() >= PURGE_BATCH_SIZE {
                                    drop(values);
                                    self.purge_counters(&mut delete_keys).await?;
                                    retry_count = 0;
                                    start = Instant::now();
                                    continue 'scan;
                                }
                            }
                        }
                        Ok(None) => break 'scan,
                        Err(err) => {
                            drop(values);
                            if made_progress {
                                retry_count = 0;
                                start = Instant::now();
                            }
                            if err.is_retryable()
                                && retry_count < MAX_COMMIT_ATTEMPTS
                                && start.elapsed() < MAX_COMMIT_TIME
                            {
                                self.version.expire();
                                let trx = trx.on_error(err).await.map_err(into_error)?;
                                next_trx = Some(self.apply_read_version(trx).await?);
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
            let trx = self.db.create_trx().map_err(into_error)?;
            trx.set_option(options::TransactionOption::PriorityBatch)
                .map_err(into_error)?;
            for key in delete_keys.iter() {
                trx.atomic_op(key, &integer, MutationType::CompareAndClear);
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
            let trx = self.db.create_trx().map_err(into_error)?;
            trx.clear_range(&from, &to);

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

    fn waits(&mut self, err: FdbError) -> bool {
        self.priority == CommitPriority::Background
            && err.code() == FDB_BATCH_THROTTLED
            && self.since.get_or_insert_with(Instant::now).elapsed() < MAX_THROTTLED_TIME
    }
}

fn retry_not_committed(err: FdbError, will_retry: bool, retry_count: u32) -> trc::Result<()> {
    if !err.is_retryable_not_committed() {
        Err(into_error(err))
    } else if will_retry {
        Ok(())
    } else {
        Err(exhausted(into_error(err), retry_count))
    }
}

async fn clear_chunks(trx: &Transaction, key: &[u8], from_chunk: Option<u8>) {
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
    {
        let mut chunks = trx.get_ranges_keyvalues(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(from.as_ref()),
                end: KeySelector::first_greater_or_equal(to.as_slice()),
                mode: options::StreamingMode::WantAll,
                ..Default::default()
            },
            true,
        );

        while let Ok(Some(chunk)) = chunks.try_next().await {
            let found = chunk.key();
            debug_assert!(
                found.len() == key.len() + 1 || found == key,
                "chunk range of {key:?} holds foreign key {found:?}, clearing it would destroy data"
            );
        }
    }

    trx.clear_range(from.as_ref(), &to);
}

async fn chunk_value(
    trx: &Transaction,
    key: &mut Vec<u8>,
    value: &[u8],
    class: &ValueClass,
    prev_num_chunks: Option<usize>,
) -> bool {
    let num_chunks = if value.len() >= MAX_VALUE_SIZE {
        value.len().div_ceil(MAX_VALUE_SIZE)
    } else {
        1
    };

    if num_chunks > u8::MAX as usize {
        return false;
    }

    debug_assert!(
        num_chunks == 1 || class.may_be_chunked() || matches!(class, ValueClass::Any(_)),
        "{class:?} was split into {num_chunks} chunks but is not declared chunkable, \
         stale chunks will be spliced onto a later shorter value"
    );

    if class.may_be_chunked()
        && prev_num_chunks.is_none_or(|prev_num_chunks| prev_num_chunks > num_chunks)
    {
        clear_chunks(trx, key, Some((num_chunks - 1) as u8)).await;
    }

    if value.len() >= MAX_VALUE_SIZE {
        for (pos, chunk) in value.chunks(MAX_VALUE_SIZE).enumerate() {
            match pos.cmp(&1) {
                Ordering::Less => {}
                Ordering::Equal => {
                    key.push(0);
                }
                Ordering::Greater => {
                    *key.last_mut().unwrap() += 1;
                }
            }
            trx.set(key, chunk);
        }
    } else {
        trx.set(key, value);
    }

    true
}

enum ApplyError {
    Retryable(FdbError),
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
    trx: &Transaction,
    batch: &Batch<'_>,
    keys: &CounterKeys,
    result: &mut AssignedIds,
) -> Result<(), ApplyError> {
    let num_accounts = batch.change_accounts.len();
    let num_reserved = num_accounts + keys.reservation_total.len();
    let mut cursors = vec![0i64; keys.reservation_total.len()];

    for chunk_start in (0..keys.ranges.len()).step_by(MAX_CONCURRENT_ALLOCATIONS) {
        let chunk_end = (chunk_start + MAX_CONCURRENT_ALLOCATIONS).min(keys.ranges.len());
        let values = futures::future::try_join_all((chunk_start..chunk_end).map(|index| {
            let snapshot = index >= num_reserved
                && batch
                    .bounds
                    .get(index - num_reserved)
                    .is_some_and(CounterBound::allows_overshoot);
            trx.get(keys.key(index), snapshot)
        }))
        .await
        .map_err(ApplyError::Retryable)?;

        for (offset, value) in values.into_iter().enumerate() {
            let index = chunk_start + offset;
            let key = keys.key(index);
            let current = match value {
                Some(bytes) => deserialize_i64_le(key, &bytes)?,
                None => 0,
            };

            if index < num_accounts {
                let account = &batch.change_accounts[index];
                let change_id = current + 1;
                trx.set(key, &change_id.to_le_bytes()[..]);
                result.push_change_id(*account, change_id as u64);
            } else if index < num_reserved {
                let key_offset = index - num_accounts;
                let last_id = current + keys.reservation_total[key_offset];
                trx.set(key, &last_id.to_le_bytes()[..]);
                cursors[key_offset] = current;
            } else {
                let bound = &batch.bounds[index - num_reserved];
                let value = current.saturating_add(bound.by);
                bound.verify(value)?;
                if bound.allows_overshoot() {
                    trx.atomic_op(key, &bound.by.to_le_bytes()[..], MutationType::Add);
                } else {
                    trx.set(key, &value.to_le_bytes()[..]);
                }
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
