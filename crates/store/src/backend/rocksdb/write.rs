/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CF_INDEXES, CF_LOGS, CfHandle, RocksDbStore, into_error};
use crate::{
    Deserialize, IndexKey, Key, LogKey, Shape, Subspace,
    backend::deserialize_i64_le,
    write::{
        AssignedIds, Batch, LogSet, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, MergeResult, Operation,
        ValueClass, ValueOp, commit_backoff,
    },
};
use rocksdb::{
    BoundColumnFamily, ErrorKind, IteratorMode, OptimisticTransactionDB,
    OptimisticTransactionOptions, WriteOptions,
};
use std::{sync::Arc, time::Instant};
use types::collection::SyncCollection;

impl RocksDbStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let db = self.db.clone();
        let mut retry_count = 0;
        let start = Instant::now();
        let mark = assigned_ids.mark();

        loop {
            let attempt = self
                .spawn_worker(|| {
                    assigned_ids.rollback(mark);
                    let mut txn = RocksDBTransaction {
                        db: &db,
                        cf_indexes: db.cf_handle(CF_INDEXES).unwrap(),
                        cf_logs: db.cf_handle(CF_LOGS).unwrap(),
                        txn_opts: OptimisticTransactionOptions::default(),
                        batch: &mut batch,
                        result: assigned_ids,
                    };
                    txn.txn_opts.set_snapshot(true);

                    match txn.commit() {
                        Ok(()) => Ok(Ok(())),
                        Err(CommitError::Internal(err)) => Err(err),
                        Err(CommitError::RocksDB(err)) => Ok(Err(err)),
                    }
                })
                .await?;

            match attempt {
                Ok(()) => return Ok(()),
                Err(err) => match err.kind() {
                    ErrorKind::Busy | ErrorKind::MergeInProgress | ErrorKind::TryAgain
                        if retry_count < MAX_COMMIT_ATTEMPTS
                            && start.elapsed() < MAX_COMMIT_TIME =>
                    {
                        tokio::time::sleep(commit_backoff(retry_count)).await;
                        retry_count += 1;
                    }
                    _ => return Err(into_error(err)),
                },
            }
        }
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.delete_range_cf(
                &db.subspace_handle(from.subspace()),
                from.serialize(0),
                to.serialize(0),
            )
            .map_err(into_error)
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            for subspace in Subspace::ALL
                .iter()
                .copied()
                .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
            {
                let cf = db.subspace_handle(subspace);

                let mut delete_keys = Vec::new();

                for row in db.iterator_cf(&cf, IteratorMode::Start) {
                    let (key, value) = row.map_err(into_error)?;

                    if i64::deserialize(&value)? == 0 {
                        delete_keys.push(key);
                    }
                }

                let txn_opts = OptimisticTransactionOptions::default();
                for key in delete_keys {
                    let txn = db.transaction_opt(&WriteOptions::default(), &txn_opts);
                    if txn
                        .get_pinned_for_update_cf(&cf, &key, true)
                        .map_err(into_error)?
                        .map(|value| i64::deserialize(&value).map(|v| v == 0).unwrap_or(false))
                        .unwrap_or(false)
                    {
                        txn.delete_cf(&cf, key).map_err(into_error)?;
                        txn.commit().map_err(into_error)?;
                    } else {
                        txn.rollback().map_err(into_error)?;
                    }
                }
            }

            Ok(())
        })
        .await
    }
}

struct RocksDBTransaction<'x, 'y> {
    db: &'x OptimisticTransactionDB,
    cf_indexes: Arc<BoundColumnFamily<'x>>,
    cf_logs: Arc<BoundColumnFamily<'x>>,
    txn_opts: OptimisticTransactionOptions,
    batch: &'x mut Batch<'y>,
    result: &'x mut AssignedIds,
}

enum CommitError {
    Internal(trc::Error),
    RocksDB(rocksdb::Error),
}

fn read_counter(
    txn: &rocksdb::Transaction<'_, OptimisticTransactionDB>,
    cf: &Arc<BoundColumnFamily<'_>>,
    key: &[u8],
) -> Result<i64, CommitError> {
    match txn.get_pinned_for_update_cf(cf, key, true)? {
        Some(bytes) => deserialize_i64_le(key, &bytes).map_err(CommitError::from),
        None => Ok(0),
    }
}

impl RocksDBTransaction<'_, '_> {
    fn commit(&mut self) -> Result<(), CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut change_group = SyncCollection::None.change_group();
        let mut document_id = u32::MAX;
        let result = &mut *self.result;
        let has_changes = !self.batch.change_accounts.is_empty();
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        let txn = self
            .db
            .transaction_opt(&WriteOptions::default(), &self.txn_opts);

        if self.batch.has_allocations() {
            let cf = self.db.subspace_handle(Subspace::Counter);
            let mut key_buf = Vec::with_capacity(16);

            for account in self.batch.change_accounts {
                key_buf.clear();
                ValueClass::ChangeId(account.group).serialize_into(
                    &mut key_buf,
                    account.account_id,
                    0,
                    0,
                    0,
                );
                let change_id = read_counter(&txn, &cf, &key_buf)? + 1;
                txn.put_cf(&cf, &key_buf, &change_id.to_le_bytes()[..])?;
                result.push_change_id(account.account_id, account.group, change_id as u64);
            }

            for reservation in self.batch.reservations {
                reservation.serialize_key_into(&mut key_buf, 0);
                let last_id = read_counter(&txn, &cf, &key_buf)? + reservation.count as i64;
                txn.put_cf(&cf, &key_buf, &last_id.to_le_bytes()[..])?;
                result.fill_slots(reservation.first_slot, reservation.count, last_id as u32);
            }
        }

        let mut key_buf = Vec::with_capacity(64);
        for op in self.batch.ops.iter_mut() {
            match op {
                Operation::AccountId {
                    account_id: account_id_,
                } => {
                    account_id = *account_id_;
                    if has_changes {
                        result.set_current_change_id(account_id, change_group);
                    }
                }
                Operation::Collection {
                    collection: collection_,
                } => {
                    collection = u8::from(*collection_);
                    change_group = collection_.change_group();
                    if has_changes {
                        result.set_current_change_id(account_id, change_group);
                    }
                }
                Operation::DocumentId {
                    document_id: document_id_,
                } => {
                    document_id = document_id_.resolve(result);
                }
                Operation::Value { class, op } => {
                    key_buf.clear();
                    class.serialize_into(&mut key_buf, account_id, collection, document_id, 0);
                    let key = &key_buf;
                    let cf = self.db.subspace_handle(class.subspace(collection));

                    match op {
                        ValueOp::Set(value) => {
                            let value = value.resolve(result)?;
                            txn.put_cf(&cf, key, &*value)?;
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let merge_result = (merge_op.0)(
                                result,
                                txn.get_pinned_for_update_cf(&cf, key, true)?.as_deref(),
                            )?;

                            match merge_result {
                                MergeResult::Update(value) => {
                                    txn.put_cf(&cf, key, value)?;
                                }
                                MergeResult::Delete => {
                                    txn.delete_cf(&cf, key)?;
                                }
                                MergeResult::Skip => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            txn.merge_cf(&cf, key, &by.to_le_bytes()[..])?;
                        }
                        ValueOp::AddAndGet(by) => {
                            let num = txn
                                .get_pinned_for_update_cf(&cf, key, true)
                                .map_err(CommitError::from)
                                .and_then(|bytes| {
                                    if let Some(bytes) = bytes {
                                        deserialize_i64_le(key, &bytes)
                                            .map(|v| v + *by)
                                            .map_err(CommitError::from)
                                    } else {
                                        Ok(*by)
                                    }
                                })?;
                            txn.put_cf(&cf, key, &num.to_le_bytes()[..])?;
                            result.push_counter_id(num);
                        }
                        ValueOp::Clear => {
                            txn.delete_cf(&cf, key)?;
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
                    .serialize_into(&mut key_buf, 0);
                    let key = &key_buf;

                    if *set {
                        txn.put_cf(&self.cf_indexes, key, [])?;
                    } else {
                        txn.delete_cf(&self.cf_indexes, key)?;
                    }
                }
                Operation::Log { collection, set } => {
                    let log_change_id = result
                        .change_id(account_id, collection.change_group())
                        .unwrap_or_default();
                    debug_assert!(
                        log_change_id != 0,
                        "no change id was allocated for this account"
                    );
                    key_buf.clear();
                    LogKey {
                        account_id,
                        collection: u8::from(*collection),
                        change_id: log_change_id,
                    }
                    .serialize_into(&mut key_buf, 0);

                    match set {
                        LogSet::Bytes(bytes) => {
                            txn.put_cf(&self.cf_logs, &key_buf, &*bytes)?;
                        }
                        LogSet::Pending(changes) => {
                            changes.serialize_into(
                                collection.is_prefixed(),
                                Some(result),
                                &mut log_scratch,
                                &mut log_buf,
                            );
                            txn.put_cf(&self.cf_logs, &key_buf, &log_buf)?;
                        }
                    }
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    key_buf.clear();
                    class.serialize_into(&mut key_buf, account_id, collection, document_id, 0);
                    let cf = self.db.subspace_handle(class.subspace(collection));

                    let matches = txn
                        .get_pinned_for_update_cf(&cf, &key_buf, true)?
                        .map(|value| assert_value.matches(&value))
                        .unwrap_or_else(|| assert_value.is_none());

                    if !matches {
                        txn.rollback()?;
                        return Err(CommitError::Internal(
                            trc::StoreEvent::AssertValueFailed.into(),
                        ));
                    }
                }
            }
        }

        txn.commit().map_err(Into::into)
    }
}

impl From<rocksdb::Error> for CommitError {
    fn from(err: rocksdb::Error) -> Self {
        CommitError::RocksDB(err)
    }
}

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}
