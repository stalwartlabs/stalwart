/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, MysqlStore, into_error, is_timeout_error};
use crate::{
    IndexKey, Key, LogKey, Shape, Subspace,
    write::{
        AssignedIds, Batch, LogSet, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, MergeResult, Operation,
        ValueClass, ValueOp, commit_backoff,
    },
};
use ahash::AHashMap;
use mysql_async::{Conn, Error, IsolationLevel, TxOpts, params, prelude::Queryable};
use std::time::Instant;
use types::collection::SyncCollection;

#[derive(Debug)]
enum CommitError {
    Mysql(mysql_async::Error),
    Internal(trc::Error),
}

impl MysqlStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let mark = assigned_ids.mark();

        loop {
            assigned_ids.rollback(mark);
            let err = match self.write_trx(&mut conn, &mut batch, assigned_ids).await {
                Ok(()) => {
                    return Ok(());
                }
                Err(err) => err,
            };

            let _ = conn.query_drop("ROLLBACK;").await;

            match err {
                CommitError::Mysql(Error::Server(err))
                    if [1062, 1213].contains(&err.code)
                        && retry_count < MAX_COMMIT_ATTEMPTS
                        && start.elapsed() < MAX_COMMIT_TIME => {}
                CommitError::Mysql(err) => {
                    return Err(into_error(err));
                }
                CommitError::Internal(err) => {
                    return Err(err);
                }
            }

            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }

    async fn write_trx(
        &self,
        conn: &mut Conn,
        batch: &mut Batch<'_>,
        result: &mut AssignedIds,
    ) -> Result<(), CommitError> {
        let has_changes = !batch.change_accounts.is_empty();
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut change_group = SyncCollection::None.change_group();
        let mut document_id = u32::MAX;
        let mut asserted_values = AHashMap::new();
        let mut tx_opts = TxOpts::default();
        tx_opts
            .with_consistent_snapshot(false)
            .with_isolation_level(IsolationLevel::ReadCommitted);
        let mut trx = conn.start_transaction(tx_opts).await?;
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        if batch.has_allocations() {
            let incr = trx
                .prep(concat!(
                    "INSERT INTO n (k, v) VALUES (:k, LAST_INSERT_ID(:v)) ",
                    "ON DUPLICATE KEY UPDATE v = LAST_INSERT_ID(v + :v)"
                ))
                .await?;
            let last_id = trx.prep("SELECT LAST_INSERT_ID()").await?;
            let mut key_buf = Vec::with_capacity(16);

            for account in batch.change_accounts {
                key_buf.clear();
                ValueClass::ChangeId(account.group).serialize_into(
                    &mut key_buf,
                    account.account_id,
                    0,
                    0,
                    0,
                );
                trx.exec_drop(&incr, params! {"k" => &key_buf, "v" => 1i64})
                    .await?;
                let change_id = trx
                    .exec_first::<i64, _, _>(&last_id, ())
                    .await?
                    .ok_or_else(missing_last_insert_id)?;
                result.push_change_id(account.account_id, account.group, change_id as u64);
            }

            for reservation in batch.reservations {
                reservation.serialize_key_into(&mut key_buf, 0);
                trx.exec_drop(
                    &incr,
                    params! {"k" => &key_buf, "v" => reservation.count as i64},
                )
                .await?;
                let counter = trx
                    .exec_first::<i64, _, _>(&last_id, ())
                    .await?
                    .ok_or_else(missing_last_insert_id)?;
                result.fill_slots(reservation.first_slot, reservation.count, counter as u32);
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
                    let subspace = class.subspace(collection);
                    let table = subspace.name();

                    match op {
                        ValueOp::Set(set_value) => {
                            let value = set_value.resolve(result)?;
                            let value = &*value;
                            if !matches!(subspace.shape(), Shape::Presence) {
                                let exists = asserted_values.get(key);
                                let s = if let Some(exists) = exists {
                                    if *exists {
                                        trx.prep(format!(
                                            "UPDATE {} SET v = :v WHERE k = :k",
                                            table
                                        ))
                                        .await?
                                    } else {
                                        trx.prep(format!(
                                            "INSERT INTO {} (k, v) VALUES (:k, :v)",
                                            table
                                        ))
                                        .await?
                                    }
                                } else {
                                    trx
                            .prep(
                                format!("INSERT INTO {} (k, v) VALUES (:k, :v) ON DUPLICATE KEY UPDATE v = VALUES(v)", table),
                            )
                            .await?
                                };

                                match trx.exec_drop(&s, params! {"k" => key, "v" => value}).await {
                                    Ok(_) => {
                                        if trx.affected_rows() == 0 {
                                            trx.rollback().await?;
                                            return Err(trc::StoreEvent::AssertValueFailed
                                                .into_err()
                                                .caused_by(trc::location!())
                                                .into());
                                        }
                                    }
                                    Err(err) => {
                                        trx.rollback().await?;
                                        return Err(err.into());
                                    }
                                }
                            } else {
                                let s = trx
                                    .prep(format!("INSERT IGNORE INTO {table} (k) VALUES (?)"))
                                    .await?;
                                trx.exec_drop(&s, (key,)).await?;
                            }
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let s = trx
                                .prep(format!("SELECT v FROM {} WHERE k = ? FOR UPDATE", table))
                                .await?;
                            let (exists, merge_result) = trx
                                .exec_first::<Vec<u8>, _, _>(&s, (&key,))
                                .await?
                                .map(|bytes| {
                                    (merge_op.0)(result, Some(bytes.as_ref()))
                                        .map(|v| (true, v))
                                        .map_err(CommitError::from)
                                })
                                .unwrap_or_else(|| {
                                    (merge_op.0)(result, None)
                                        .map(|v| (false, v))
                                        .map_err(CommitError::from)
                                })?;

                            let s = if exists {
                                trx.prep(format!("UPDATE {} SET v = :v WHERE k = :k", table))
                                    .await?
                            } else {
                                trx.prep(format!("INSERT INTO {} (k, v) VALUES (:k, :v)", table))
                                    .await?
                            };

                            match merge_result {
                                MergeResult::Update(value) => {
                                    if let Err(err) =
                                        trx.exec_drop(&s, params! {"k" => key, "v" => &value}).await
                                    {
                                        trx.rollback().await?;
                                        return Err(err.into());
                                    }
                                }
                                MergeResult::Delete if exists => {
                                    // Update asserted value
                                    if let Some(exists) = asserted_values.get_mut(key) {
                                        *exists = false;
                                    }

                                    let s = trx
                                        .prep(format!("DELETE FROM {} WHERE k = ?", table))
                                        .await?;
                                    trx.exec_drop(&s, (key,)).await?;
                                }
                                _ => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            if *by >= 0 {
                                let s = trx
                                    .prep(format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON DUPLICATE KEY UPDATE v = v + VALUES(v)"
                                        ),
                                        table
                                    ))
                                    .await?;
                                trx.exec_drop(&s, (key, &*by)).await?;
                            } else {
                                let s = trx
                                    .prep(format!("UPDATE {table} SET v = v + ? WHERE k = ?"))
                                    .await?;
                                trx.exec_drop(&s, (&*by, key)).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            let s = trx
                                .prep(format!(
                                    concat!(
                                        "INSERT INTO {} (k, v) VALUES (:k, LAST_INSERT_ID(:v)) ",
                                        "ON DUPLICATE KEY UPDATE v = LAST_INSERT_ID(v + :v)"
                                    ),
                                    table
                                ))
                                .await?;
                            trx.exec_drop(&s, params! {"k" => key, "v" => &*by}).await?;
                            let s = trx.prep("SELECT LAST_INSERT_ID()").await?;
                            result.push_counter_id(
                                trx.exec_first::<i64, _, _>(&s, ()).await?.ok_or_else(|| {
                                    mysql_async::Error::Io(mysql_async::IoError::Io(
                                        std::io::Error::other(
                                            "LAST_INSERT_ID() did not return a value",
                                        ),
                                    ))
                                })?,
                            );
                        }
                        ValueOp::Clear => {
                            // Update asserted value
                            if let Some(exists) = asserted_values.get_mut(key) {
                                *exists = false;
                            }

                            let s = trx
                                .prep(format!("DELETE FROM {} WHERE k = ?", table))
                                .await?;
                            trx.exec_drop(&s, (key,)).await?;
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

                    let s = if *set {
                        trx.prep("INSERT IGNORE INTO i (k) VALUES (?)").await?
                    } else {
                        trx.prep("DELETE FROM i WHERE k = ?").await?
                    };
                    trx.exec_drop(&s, (key,)).await?;
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

                    let s = trx
                        .prep("INSERT INTO l (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)")
                        .await?;

                    trx.exec_drop(&s, (key, value)).await?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let table = class.subspace(collection).name();

                    let s = trx
                        .prep(format!("SELECT v FROM {} WHERE k = ? FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .exec_first::<Vec<u8>, _, _>(&s, (&key,))
                        .await?
                        .map(|bytes| (true, assert_value.matches(&bytes)))
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
                        trx.rollback().await?;
                        return Err(trc::StoreEvent::AssertValueFailed
                            .into_err()
                            .caused_by(trc::location!())
                            .into());
                    }
                    asserted_values.insert(key, exists);
                }
            }
        }

        trx.commit().await.map_err(Into::into)
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
        {
            purge_table(&mut conn, subspace.name()).await?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let table = from.subspace().name();
        let mut from = from.serialize(0);
        let to = to.serialize(0);

        let delete = conn
            .prep(format!("DELETE FROM {table} WHERE k >= ? AND k < ?"))
            .await
            .map_err(into_error)?;

        match conn.exec_drop(&delete, (&from, &to)).await {
            Ok(_) => return Ok(()),
            Err(err) if is_timeout_error(&err) => (),
            Err(err) => return Err(into_error(err)),
        }

        let mut chunk_size = DELETE_CHUNK_SIZE;

        loop {
            let boundary = conn
                .prep(format!(
                    "SELECT k FROM {table} WHERE k >= ? AND k < ? ORDER BY k ASC LIMIT 1 OFFSET {chunk_size}"
                ))
                .await
                .map_err(into_error)?;

            loop {
                let next = match conn
                    .exec_first::<Vec<u8>, _, _>(&boundary, (&from, &to))
                    .await
                {
                    Ok(next) => next,
                    Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                        chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                };

                match conn
                    .exec_drop(&delete, (&from, next.as_ref().unwrap_or(&to)))
                    .await
                {
                    Ok(_) => (),
                    Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                        chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                }

                match next {
                    Some(next) => from = next,
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn purge_table(conn: &mut Conn, table: &str) -> trc::Result<()> {
    let s = conn
        .prep(format!("DELETE FROM {table} WHERE v = 0"))
        .await
        .map_err(into_error)?;

    match conn.exec_drop(&s, ()).await {
        Ok(_) => return Ok(()),
        Err(err) if is_timeout_error(&err) => (),
        Err(err) => return Err(into_error(err)),
    }

    let purge = conn
        .prep(format!(
            "DELETE FROM {table} WHERE v = 0 AND k >= ? AND k < ?"
        ))
        .await
        .map_err(into_error)?;
    let purge_last = conn
        .prep(format!("DELETE FROM {table} WHERE v = 0 AND k >= ?"))
        .await
        .map_err(into_error)?;
    let mut chunk_size = DELETE_CHUNK_SIZE;
    let mut from = Vec::new();

    loop {
        let boundary = conn
            .prep(format!(
                "SELECT k FROM {table} WHERE k >= ? ORDER BY k ASC LIMIT 1 OFFSET {chunk_size}"
            ))
            .await
            .map_err(into_error)?;

        loop {
            let next = match conn.exec_first::<Vec<u8>, _, _>(&boundary, (&from,)).await {
                Ok(next) => next,
                Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                    chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                    break;
                }
                Err(err) => return Err(into_error(err)),
            };

            let result = match &next {
                Some(next) => conn.exec_drop(&purge, (&from, next)).await,
                None => conn.exec_drop(&purge_last, (&from,)).await,
            };

            match result {
                Ok(_) => (),
                Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                    chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                    break;
                }
                Err(err) => return Err(into_error(err)),
            }

            match next {
                Some(next) => from = next,
                None => return Ok(()),
            }
        }
    }
}

fn missing_last_insert_id() -> mysql_async::Error {
    mysql_async::Error::Io(mysql_async::IoError::Io(std::io::Error::other(
        "LAST_INSERT_ID() did not return a value",
    )))
}

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}

impl From<mysql_async::Error> for CommitError {
    fn from(err: mysql_async::Error) -> Self {
        CommitError::Mysql(err)
    }
}
