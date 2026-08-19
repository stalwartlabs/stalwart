/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FdbStore, MAX_VALUE_SIZE, into_error,
    read::{ChunkedValue, read_chunked_value},
};
use crate::{
    backend::deserialize_i64_le,
    write::{
        AssignedIds, Batch, IndexPropertyClass, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, MergeResult,
        Operation, QueueClass, RegistryClass, SearchIndexClass, TaskQueueClass, TelemetryClass,
        ValueClass, ValueOp, key::KeySerializer,
    },
    *,
};
use foundationdb::{
    FdbError, KeySelector, RangeOption, Transaction,
    options::{self, MutationType},
};
use futures::TryStreamExt;
use rand::RngExt;
use std::{
    borrow::Cow,
    cmp::Ordering,
    time::{Duration, Instant},
};
use trc::AddContext;

impl FdbStore {
    pub(crate) async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let start = Instant::now();
        let mut retry_count = 0;
        let has_changes = !batch.changes.is_empty();

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = 0u64;
            let mut result = AssignedIds::default();

            let trx = self.db.create_trx().map_err(into_error)?;

            if has_changes {
                for &account_id in batch.changes.keys() {
                    debug_assert!(account_id != u32::MAX);
                    let key = ValueClass::ChangeId.serialize(account_id, 0, 0, WITH_SUBSPACE);
                    let change_id =
                        if let Some(bytes) = trx.get(&key, false).await.map_err(into_error)? {
                            deserialize_i64_le(&key, &bytes)? + 1
                        } else {
                            1
                        };
                    trx.set(&key, &change_id.to_le_bytes()[..]);
                    result.push_change_id(account_id, change_id as u64);
                }
            }

            let mut key_buf = Vec::with_capacity(64);
            for op in batch.ops.iter_mut() {
                match op {
                    Operation::AccountId {
                        account_id: account_id_,
                    } => {
                        account_id = *account_id_;
                        if has_changes {
                            change_id = result.set_current_change_id(account_id)?;
                        }
                    }
                    Operation::Collection {
                        collection: collection_,
                    } => {
                        collection = u8::from(*collection_);
                    }
                    Operation::DocumentId {
                        document_id: document_id_,
                    } => {
                        document_id = *document_id_;
                    }
                    Operation::Value { class, op } => {
                        let subspace = class.subspace(collection);
                        key_buf.clear();
                        class.serialize_into(
                            &mut key_buf,
                            account_id,
                            collection,
                            document_id,
                            WITH_SUBSPACE,
                        );

                        match op {
                            ValueOp::Set(value) => {
                                if !chunk_value(&trx, &mut key_buf, value, subspace, class, None)
                                    .await
                                {
                                    trx.cancel();
                                    return Err(trc::StoreEvent::FoundationdbError
                                        .ctx(trc::Key::Reason, "Value is too large"));
                                }
                            }
                            ValueOp::SetFnc(set_op) => {
                                let value = (set_op.0)(&result)?;
                                if !chunk_value(&trx, &mut key_buf, &value, subspace, class, None)
                                    .await
                                {
                                    trx.cancel();
                                    return Err(trc::StoreEvent::FoundationdbError
                                        .ctx(trc::Key::Reason, "Value is too large"));
                                }
                            }
                            ValueOp::MergeFnc(merge_op) => {
                                let chunked_value = read_chunked_value(&key_buf, &trx, false)
                                    .await
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                                let mut current_value = None;
                                let (merge_result, prev_num_chunks) = match &chunked_value {
                                    ChunkedValue::Single(slice) => {
                                        current_value = Some(slice.as_ref());
                                        ((merge_op.0)(&result, Some(slice.as_ref()))?, 1)
                                    }
                                    ChunkedValue::Chunked { bytes, n_chunks } => (
                                        (merge_op.0)(&result, Some(bytes.as_ref()))?,
                                        *n_chunks as usize + 1,
                                    ),
                                    ChunkedValue::None => ((merge_op.0)(&result, None)?, 0),
                                };

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
                                            subspace,
                                            class,
                                            Some(prev_num_chunks),
                                        )
                                        .await
                                        {
                                            trx.cancel();
                                            return Err(trc::StoreEvent::FoundationdbError
                                                .ctx(trc::Key::Reason, "Value is too large"));
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
                                let num = if let Some(bytes) =
                                    trx.get(&key_buf, false).await.map_err(into_error)?
                                {
                                    deserialize_i64_le(&key_buf, &bytes)? + *by
                                } else {
                                    *by
                                };
                                trx.set(&key_buf, &num.to_le_bytes()[..]);
                                result.push_counter_id(num);
                            }
                            ValueOp::Clear => {
                                if is_chunked_value(subspace, class) {
                                    clear_chunks(&trx, &key_buf, None).await;
                                } else {
                                    trx.clear(&key_buf);
                                }
                            }
                        }
                    }
                    Operation::Index { field, key, set } => {
                        key_buf.clear();
                        IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key: &*key,
                        }
                        .serialize_into(&mut key_buf, WITH_SUBSPACE);

                        if *set {
                            trx.set(&key_buf, &[]);
                        } else {
                            trx.clear(&key_buf);
                        }
                    }
                    Operation::Log { collection, set } => {
                        key_buf.clear();
                        LogKey {
                            account_id,
                            collection: u8::from(*collection),
                            change_id,
                        }
                        .serialize_into(&mut key_buf, WITH_SUBSPACE);

                        trx.set(&key_buf, set);
                    }
                    Operation::AssertValue {
                        class,
                        assert_value,
                    } => {
                        key_buf.clear();
                        class.serialize_into(
                            &mut key_buf,
                            account_id,
                            collection,
                            document_id,
                            WITH_SUBSPACE,
                        );

                        let matches = match read_chunked_value(&key_buf, &trx, false).await {
                            Ok(ChunkedValue::Single(bytes)) => assert_value.matches(bytes.as_ref()),
                            Ok(ChunkedValue::Chunked { bytes, .. }) => {
                                assert_value.matches(bytes.as_ref())
                            }
                            Ok(ChunkedValue::None) => assert_value.is_none(),
                            Err(_) => false,
                        };

                        if !matches {
                            trx.cancel();
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                    }
                }
            }

            if self
                .commit(
                    trx,
                    retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME,
                )
                .await?
            {
                return Ok(result);
            } else {
                let backoff = rand::rng().random_range(50..=100);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                retry_count += 1;
            }
        }
    }

    pub(crate) async fn commit(&self, trx: Transaction, will_retry: bool) -> trc::Result<bool> {
        match trx.commit().await {
            Ok(result) => {
                let commit_version = result.committed_version().map_err(into_error)?;
                self.version.raise_floor(commit_version);
                Ok(true)
            }
            Err(err) => {
                if will_retry {
                    err.on_error().await.map_err(into_error)?;
                    Ok(false)
                } else {
                    Err(into_error(FdbError::from(err)))
                }
            }
        }
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        // Obtain all zero counters
        let mut delete_keys = Vec::new();
        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
        {
            let trx = self.db.create_trx().map_err(into_error)?;
            let from_key = [subspace.byte(), 0u8];
            let to_key = [subspace.byte(), u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX];

            let mut values = trx.get_ranges_keyvalues(
                RangeOption {
                    begin: KeySelector::first_greater_or_equal(&from_key[..]),
                    end: KeySelector::first_greater_or_equal(&to_key[..]),
                    mode: options::StreamingMode::WantAll,
                    reverse: false,
                    ..Default::default()
                },
                true,
            );

            while let Some(value) = values.try_next().await.map_err(into_error)? {
                if value.value().iter().all(|byte| *byte == 0) {
                    delete_keys.push(value.key().to_vec());
                }
            }
        }

        if delete_keys.is_empty() {
            return Ok(());
        }

        // Delete keys
        let integer = 0i64.to_le_bytes();
        for chunk in delete_keys.chunks(1024) {
            let mut retry_count = 0;
            loop {
                let trx = self.db.create_trx().map_err(into_error)?;
                for key in chunk {
                    trx.atomic_op(key, &integer, MutationType::CompareAndClear);
                }

                if self.commit(trx, retry_count < MAX_COMMIT_ATTEMPTS).await? {
                    break;
                } else {
                    retry_count += 1;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let from = from.serialize(WITH_SUBSPACE);
        let to = to.serialize(WITH_SUBSPACE);

        let trx = self.db.create_trx().map_err(into_error)?;
        trx.clear_range(&from, &to);
        self.commit(trx, false).await.map(|_| ())
    }
}

fn is_chunked_subspace(subspace: Subspace) -> bool {
    matches!(
        subspace,
        Subspace::Property
            | Subspace::Immutable
            | Subspace::IndexProperty
            | Subspace::SearchDocument
            | Subspace::QueueMessage
            | Subspace::TaskQueue
            | Subspace::Directory
            | Subspace::Registry
            | Subspace::DeletedItems
            | Subspace::SpamSamples
            | Subspace::ReportIn
            | Subspace::ReportOut
            | Subspace::TelemetrySpan
    )
}

fn is_chunked_value(subspace: Subspace, class: &ValueClass) -> bool {
    is_chunked_subspace(subspace)
        && matches!(
            class,
            ValueClass::Property(_)
                | ValueClass::Immutable(_)
                | ValueClass::IndexProperty(IndexPropertyClass::Hash { .. })
                | ValueClass::Registry(RegistryClass::Item { .. })
                | ValueClass::Queue(QueueClass::Message(_))
                | ValueClass::TaskQueue(TaskQueueClass::Task { .. })
                | ValueClass::Telemetry(TelemetryClass::Span(_))
                | ValueClass::SearchIndex(SearchIndexClass::Document { .. })
        )
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
    subspace: Subspace,
    class: &ValueClass,
    prev_num_chunks: Option<usize>,
) -> bool {
    let num_chunks = if value.len() > MAX_VALUE_SIZE {
        value.len().div_ceil(MAX_VALUE_SIZE)
    } else {
        1
    };

    if num_chunks > u8::MAX as usize {
        return false;
    }

    if is_chunked_value(subspace, class)
        && prev_num_chunks.is_none_or(|prev_num_chunks| prev_num_chunks > num_chunks)
    {
        clear_chunks(trx, key, Some((num_chunks - 1) as u8)).await;
    }

    if value.len() > MAX_VALUE_SIZE {
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
