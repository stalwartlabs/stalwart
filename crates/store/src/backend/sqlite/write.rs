/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error};
use crate::{
    IndexKey, Key, LogKey, Shape, Subspace,
    write::{AssignedIds, Batch, MergeResult, Operation, ValueClass, ValueOp},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use trc::AddContext;

impl SqliteStore {
    pub(crate) async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let manager = self.conn_pool.clone();
        self.spawn_worker(move || {
            let mut conn = manager.get().map_err(into_error)?;

            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = 0u64;
            let trx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(into_error)
                .caused_by(trc::location!())?;
            let mut result = AssignedIds::default();
            let has_changes = !batch.change_accounts.is_empty();

            if has_changes {
                for &account_id in batch.change_accounts {
                    let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                    let change_id = trx
                        .prepare_cached(concat!(
                            "INSERT INTO n (k, v) VALUES (?, ?) ",
                            "ON CONFLICT(k) DO UPDATE SET v = v + ",
                            "excluded.v RETURNING v"
                        ))
                        .map_err(into_error)
                        .caused_by(trc::location!())?
                        .query_row(params![&key, &1i64], |row| row.get::<_, i64>(0))
                        .map_err(into_error)
                        .caused_by(trc::location!())?;
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
                            change_id = result.set_current_change_id(account_id);
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
                        key_buf.clear();
                        class.serialize_into(&mut key_buf, account_id, collection, document_id, 0);
                        let key = &key_buf;
                        let subspace = class.subspace(collection);
                        let table = subspace.name();

                        match op {
                            ValueOp::Set(value) => {
                                if !matches!(subspace.shape(), Shape::Presence) {
                                    trx.prepare_cached(&format!(
                                        "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                        table
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute([key.as_slice(), value.as_slice()])
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
                            ValueOp::SetFnc { payload, fnc } => {
                                (fnc.0)(&result, payload)?;
                                trx.prepare_cached(&format!(
                                    "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                    table
                                ))
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([key, &*payload])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                            }
                            ValueOp::MergeFnc(merge_op) => {
                                let merge_result = trx
                                    .prepare_cached(&format!("SELECT v FROM {} WHERE k = ?", table))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .query_row([&key], |row| {
                                        Ok((merge_op.0)(&result, Some(row.get_ref(0)?.as_bytes()?)))
                                    })
                                    .optional()
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .unwrap_or_else(|| (merge_op.0)(&result, None))?;

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
                    Operation::Log { collection, set } => {
                        debug_assert!(
                            change_id != 0,
                            "no change id was allocated for this account"
                        );
                        key_buf.clear();
                        LogKey {
                            account_id,
                            collection: u8::from(*collection),
                            change_id,
                        }
                        .serialize_into(&mut key_buf, 0);
                        let key = &key_buf;

                        trx.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .execute([key.as_slice(), set.as_slice()])
                            .map_err(into_error)
                            .caused_by(trc::location!())?;
                    }
                    Operation::AssertValue {
                        class,
                        assert_value,
                    } => {
                        key_buf.clear();
                        class.serialize_into(&mut key_buf, account_id, collection, document_id, 0);
                        let key = &key_buf;
                        let table = class.subspace(collection).name();

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

            trx.commit().map(|_| result).map_err(into_error)
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
