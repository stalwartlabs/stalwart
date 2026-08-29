/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error};
use crate::{
    Key, Shape, Subspace,
    write::{Advance, AssignedIds, Batch, BatchCursor, LogSet, MergeResult, ValueOp},
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use trc::AddContext;

impl SqliteStore {
    pub(crate) async fn write(
        &self,
        batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        let mark = assigned_ids.mark();
        self.spawn_worker(move || {
            let mut conn = manager.get().map_err(into_error)?;

            let mut cursor = BatchCursor::new(&batch);
            let trx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(into_error)
                .caused_by(trc::location!())?;
            let result = &mut *assigned_ids;
            result.rollback(mark);
            let mut log_buf = Vec::new();
            let mut log_scratch = Vec::new();

            if batch.has_allocations() {
                let mut key_buf = Vec::with_capacity(16);

                for allocation in batch.allocations() {
                    key_buf.clear();
                    allocation.serialize_key_into(&mut key_buf, 0);
                    let last_id = incr_counter(&trx, &key_buf, allocation.increment_by())?;
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
                        let table = subspace.name();

                        match op {
                            ValueOp::Set(set_value) => {
                                let value = set_value.resolve(result)?;
                                let value = &*value;
                                if !matches!(subspace.shape(), Shape::Presence) {
                                    trx.prepare_cached(&format!(
                                        "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                        table
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute([key.as_slice(), value])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                                } else {
                                    trx.prepare_cached(&format!(
                                        "INSERT OR IGNORE INTO {} (k) VALUES (?)",
                                        table
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute([&key])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                                }
                            }
                            ValueOp::MergeFnc(merge_op) => {
                                let merge_result = trx
                                    .prepare_cached(&format!("SELECT v FROM {} WHERE k = ?", table))
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
                                        trx.prepare_cached(&format!(
                                            "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                            table
                                        ))
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?
                                        .execute([key, &value])
                                        .map_err(into_error)
                                        .caused_by(trc::location!())?;
                                    }
                                    MergeResult::Delete => {
                                        trx.prepare_cached(&format!(
                                            "DELETE FROM {} WHERE k = ?",
                                            table
                                        ))
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
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
                                        ),
                                        table
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute(params![&key, *by])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                                } else {
                                    trx.prepare_cached(&format!(
                                        "UPDATE {table} SET v = v + ? WHERE k = ?"
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute(params![*by, &key])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                                }
                            }
                            ValueOp::AddAndGet(by) => {
                                result.push_counter_id(
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = v + ",
                                            "excluded.v RETURNING v"
                                        ),
                                        table
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .query_row(params![&key, &*by], |row| row.get::<_, i64>(0))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?,
                                );
                            }
                            ValueOp::Clear => {
                                trx.prepare_cached(&format!("DELETE FROM {} WHERE k = ?", table))
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

                        if set {
                            trx.prepare_cached("INSERT OR IGNORE INTO i (k) VALUES (?)")
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                        } else {
                            trx.prepare_cached("DELETE FROM i WHERE k = ?")
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

                        trx.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")
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
                        let table = cursor.subspace(class).name();

                        let matches = trx
                            .prepare_cached(&format!("SELECT v FROM {} WHERE k = ?", table))
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

            trx.commit().map_err(into_error)
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            for subspace in Subspace::ALL
                .iter()
                .copied()
                .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
            {
                conn.prepare_cached(&format!("DELETE FROM {} WHERE v = 0", subspace.name()))
                    .map_err(into_error)
                    .caused_by(trc::location!())?
                    .execute([])
                    .map_err(into_error)
                    .caused_by(trc::location!())?;
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;

            conn.prepare_cached(&format!(
                "DELETE FROM {} WHERE k >= ? AND k < ?",
                from.subspace().name(),
            ))
            .map_err(into_error)
            .caused_by(trc::location!())?
            .execute([from.serialize(0), to.serialize(0)])
            .map_err(into_error)
            .caused_by(trc::location!())?;

            Ok(())
        })
        .await
    }
}

fn incr_counter(trx: &Transaction<'_>, key: &[u8], by: i64) -> trc::Result<i64> {
    trx.prepare_cached(concat!(
        "INSERT INTO n (k, v) VALUES (?, ?) ",
        "ON CONFLICT(k) DO UPDATE SET v = v + ",
        "excluded.v RETURNING v"
    ))
    .map_err(into_error)
    .caused_by(trc::location!())?
    .query_row(params![&key, &by], |row| row.get::<_, i64>(0))
    .map_err(into_error)
    .caused_by(trc::location!())
}
