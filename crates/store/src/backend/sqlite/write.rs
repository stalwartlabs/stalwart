/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error, sql::SqlStatements};
use crate::{
    Key, Shape, Subspace,
    write::{
        Advance, AssignedIds, Batch, BatchCursor, LogSet, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
        MergeResult, ValueOp, commit_backoff,
    },
};
use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};
use std::time::Instant;
use trc::AddContext;

impl SqliteStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let mut retry_count = 0;
        let start = Instant::now();
        let mark = assigned_ids.mark();

        loop {
            if self.write_once(&mut batch, assigned_ids, mark).await? {
                return Ok(());
            } else if retry_count >= MAX_COMMIT_ATTEMPTS || start.elapsed() >= MAX_COMMIT_TIME {
                return Err(trc::StoreEvent::SqliteError
                    .into_err()
                    .details("Database is locked")
                    .caused_by(trc::location!()));
            }

            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }

    async fn write_once(
        &self,
        batch: &mut Batch<'_>,
        assigned_ids: &mut AssignedIds,
        mark: crate::write::AssignedIdsMark,
    ) -> trc::Result<bool> {
        let manager = self.conn_pool.clone();
        let sql = &*self.sql;

        self.block_worker(move || {
            let mut conn = manager.get().map_err(into_error)?;

            let mut cursor = BatchCursor::new(batch);
            let trx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(trx) => trx,
                Err(err) if is_busy(&err) => return Ok(false),
                Err(err) => return Err(into_error(err)).caused_by(trc::location!()),
            };
            let result = &mut *assigned_ids;
            result.rollback(mark);
            let mut log_buf = Vec::new();
            let mut log_scratch = Vec::new();

            if batch.has_allocations() {
                let mut key_buf = Vec::with_capacity(16);

                for allocation in batch.allocations() {
                    key_buf.clear();
                    allocation.serialize_key_into(&mut key_buf, 0);
                    let last_id =
                        incr_counter(&trx, sql, &key_buf, allocation.increment_by())?;
                    result.apply(allocation, last_id);
                }
            }

            let mut key_buf = Vec::with_capacity(64);
            for op in batch.ops.iter_mut() {
                match cursor.advance(op, result) {
                    Advance::Cursor => {}
                    Advance::Value { class, op } => {
                        cursor.value_key(class, &mut key_buf, 0);
                        let key = &key_buf;
                        let subspace = cursor.subspace(class);
                        let stmts = sql.get(subspace);

                        match op {
                            ValueOp::Set(set_value) => {
                                let value = set_value.resolve(result)?;
                                let value = &*value;
                                if !matches!(subspace.shape(), Shape::Presence) {
                                    trx.prepare_cached(&stmts.upsert_value)
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?
                                        .execute([key.as_slice(), value])
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?;
                                } else {
                                    trx.prepare_cached(&stmts.insert_presence)
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?
                                        .execute([&key])
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?;
                                }
                            }
                            ValueOp::MergeFnc(merge_op) => {
                                let merge_result = trx
                                    .prepare_cached(&stmts.get_value)
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .query_row([&key], |row| {
                                        Ok((merge_op.0)(
                                            &*result,
                                            Some(row.get_ref(0)?.as_bytes()?),
                                        ))
                                    })
                                    .optional()
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .unwrap_or_else(|| (merge_op.0)(&*result, None))?;

                                match merge_result {
                                    MergeResult::Update(value) => {
                                        trx.prepare_cached(&stmts.upsert_value)
                                            .map_err(into_error)
                                            .caused_by(trc::location!())?
                                            .execute([key, &value])
                                            .map_err(into_error)
                                            .caused_by(trc::location!())?;
                                    }
                                    MergeResult::Delete => {
                                        trx.prepare_cached(&stmts.delete_key)
                                            .map_err(into_error)
                                            .caused_by(trc::location!())?
                                            .execute([&key])
                                            .map_err(into_error)
                                            .caused_by(trc::location!())?;
                                    }
                                    MergeResult::Skip => (),
                                }
                            }
                            ValueOp::AtomicAdd(by) => {
                                if *by >= 0 {
                                    trx.prepare_cached(&stmts.increment)
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?
                                        .execute(params![&key, *by])
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?;
                                } else {
                                    trx.prepare_cached(&stmts.decrement)
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?
                                        .execute(params![*by, &key])
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?;
                                }
                            }
                            ValueOp::AddAndGet(by) => {
                                result.push_counter_id(
                                    trx.prepare_cached(&stmts.increment_returning)
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?
                                        .query_row(params![&key, &*by], |row| row.get::<_, i64>(0))
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?,
                                );
                            }
                            ValueOp::Clear => {
                                trx.prepare_cached(&stmts.delete_key)
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute([&key])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                            }
                        }
                    }
                    Advance::Index { field, key, set } => {
                        cursor.index_key(field, key, &mut key_buf, 0);
                        let key = &key_buf;

                        let stmts = sql.get(Subspace::Indexes);

                        if set {
                            trx.prepare_cached(&stmts.insert_presence)
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                        } else {
                            trx.prepare_cached(&stmts.delete_key)
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                        }
                    }
                    Advance::Log { collection, set } => {
                        cursor.log_key(collection, result, &mut key_buf, 0);
                        let key = &key_buf;
                        let value = match set {
                            LogSet::Bytes(bytes) => &*bytes,
                            LogSet::Pending(changes) => {
                                changes.serialize_into(
                                    collection.is_prefixed(),
                                    Some(result),
                                    &mut log_scratch,
                                    &mut log_buf,
                                );
                                &log_buf
                            }
                        };

                        trx.prepare_cached(&sql.get(Subspace::Logs).upsert_value)
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .execute([key.as_slice(), value.as_slice()])
                            .map_err(into_error)
                            .caused_by(trc::location!())?;
                    }
                    Advance::Assert {
                        class,
                        assert_value,
                    } => {
                        cursor.value_key(class, &mut key_buf, 0);
                        let key = &key_buf;

                        let matches = trx
                            .prepare_cached(&sql.get(cursor.subspace(class)).get_value)
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .query_row([&key], |row| {
                                Ok(assert_value.matches(row.get_ref(0)?.as_bytes()?))
                            })
                            .optional()
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .unwrap_or_else(|| assert_value.is_none());
                        if !matches {
                            trx.rollback()
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                            return Err(trc::StoreEvent::AssertValueFailed
                                .into_err()
                                .caused_by(trc::location!()));
                        }
                    }
                }
            }

            match trx.commit() {
                Ok(()) => Ok(true),
                Err(err) if is_busy(&err) => Ok(false),
                Err(err) => Err(into_error(err)).caused_by(trc::location!()),
            }
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            for subspace in Subspace::ALL
                .iter()
                .copied()
                .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
            {
                conn.prepare_cached(&sql.get(subspace).purge_zero)
                    .map_err(into_error)
                    .caused_by(trc::location!())?
                    .execute([])
                    .map_err(into_error)
                    .caused_by(trc::location!())?;
            }

            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(into_error)
                .caused_by(trc::location!())?;

            Ok(())
        })
        .await
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let subspace = from.subspace();
        let from = from.serialize(0);
        let to = to.serialize(0);

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;

            conn.prepare_cached(&sql.get(subspace).delete_range)
                .map_err(into_error)
                .caused_by(trc::location!())?
                .execute([from, to])
                .map_err(into_error)
                .caused_by(trc::location!())?;

            Ok(())
        })
        .await
    }
}

fn incr_counter(
    trx: &Transaction<'_>,
    sql: &SqlStatements,
    key: &[u8],
    by: i64,
) -> trc::Result<i64> {
    trx.prepare_cached(&sql.get(Subspace::Counter).increment_returning)
        .map_err(into_error)
        .caused_by(trc::location!())?
        .query_row(params![&key, &by], |row| row.get::<_, i64>(0))
        .map_err(into_error)
        .caused_by(trc::location!())
}

fn is_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(err, _)
            if matches!(err.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}
