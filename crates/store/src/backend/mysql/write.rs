/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DELETE_CHUNK_SIZE, ER_DUP_ENTRY, ER_LOCK_DEADLOCK, ER_LOCK_WAIT_TIMEOUT, MIN_DELETE_CHUNK_SIZE,
    MysqlStore, into_error, is_timeout_error, sql::SubspaceSql,
};
use crate::{
    Key, Shape, Subspace,
    write::{
        Advance, AssignedIds, Batch, BatchCursor, ChunkedRetry, LogSet, MAX_COMMIT_ATTEMPTS,
        MAX_COMMIT_TIME, MergeResult, ValueOp, commit_backoff,
    },
};
use ahash::AHashMap;
use mysql_async::{Conn, Error, IsolationLevel, TxOpts, prelude::Queryable};
use std::time::Instant;

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

            match err {
                CommitError::Mysql(Error::Server(err))
                    if [ER_LOCK_DEADLOCK, ER_LOCK_WAIT_TIMEOUT].contains(&err.code)
                        && retry_count < MAX_COMMIT_ATTEMPTS
                        && start.elapsed() < MAX_COMMIT_TIME => {}
                CommitError::Mysql(Error::Server(err)) if err.code == ER_DUP_ENTRY => {
                    return Err(trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .reason("Unique violation")
                        .caused_by(trc::location!()));
                }
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
        let mut cursor = BatchCursor::new(batch);
        let mut asserted_values = AHashMap::new();
        let sql = &*self.sql;
        let mut tx_opts = TxOpts::default();
        tx_opts
            .with_consistent_snapshot(false)
            .with_isolation_level(IsolationLevel::ReadCommitted);
        let mut trx = conn.start_transaction(tx_opts).await?;
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        if batch.has_allocations() {
            let incr = trx
                .prep(&*sql.get(Subspace::Counter).increment_returning)
                .await?;
            let mut key_buf = Vec::with_capacity(16);

            for allocation in batch.allocations() {
                key_buf.clear();
                allocation.serialize_key_into(&mut key_buf, 0);
                let increment_by = allocation.increment_by();
                trx.exec_drop(&incr, (&key_buf, increment_by, increment_by))
                    .await?;
                let counter = trx.last_insert_id().ok_or_else(missing_last_insert_id)? as i64;
                result.apply(allocation, counter);
            }
        }

        let index_stmts = sql.get(Subspace::Indexes);
        let log_stmts = sql.get(Subspace::Logs);
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
                                let updated = match asserted_values.get(key) {
                                    Some(true) => {
                                        let s = trx.prep(&*stmts.update_value).await?;
                                        trx.exec_drop(&s, (value, key)).await
                                    }
                                    Some(false) => {
                                        let s = trx.prep(&*stmts.insert_value).await?;
                                        trx.exec_drop(&s, (key, value)).await
                                    }
                                    None => {
                                        let s = trx.prep(&*stmts.upsert_value).await?;
                                        trx.exec_drop(&s, (key, value)).await
                                    }
                                };

                                match updated {
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
                                let s = trx.prep(&*stmts.insert_presence).await?;
                                trx.exec_drop(&s, (key,)).await?;
                            }
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let s = trx.prep(&*stmts.get_value_for_update).await?;
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

                            match merge_result {
                                MergeResult::Update(value) => {
                                    let updated = if exists {
                                        let s = trx.prep(&*stmts.update_value).await?;
                                        trx.exec_drop(&s, (&value, key)).await
                                    } else {
                                        let s = trx.prep(&*stmts.insert_value).await?;
                                        trx.exec_drop(&s, (key, &value)).await
                                    };

                                    if let Err(err) = updated {
                                        trx.rollback().await?;
                                        return Err(err.into());
                                    }
                                }
                                MergeResult::Delete if exists => {
                                    // Update asserted value
                                    if let Some(exists) = asserted_values.get_mut(key) {
                                        *exists = false;
                                    }

                                    let s = trx.prep(&*stmts.delete_key).await?;
                                    trx.exec_drop(&s, (key,)).await?;
                                }
                                _ => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            if *by >= 0 {
                                let s = trx.prep(&*stmts.increment).await?;
                                trx.exec_drop(&s, (key, &*by)).await?;
                            } else {
                                let s = trx.prep(&*stmts.decrement).await?;
                                trx.exec_drop(&s, (&*by, key)).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            let s = trx.prep(&*stmts.increment_returning).await?;
                            trx.exec_drop(&s, (key, *by, *by)).await?;
                            result.push_counter_id(
                                trx.last_insert_id().ok_or_else(missing_last_insert_id)? as i64,
                            );
                        }
                        ValueOp::Clear => {
                            // Update asserted value
                            if let Some(exists) = asserted_values.get_mut(key) {
                                *exists = false;
                            }

                            let s = trx.prep(&*stmts.delete_key).await?;
                            trx.exec_drop(&s, (key,)).await?;
                        }
                    }
                }
                Advance::Index { field, key, set } => {
                    cursor.index_key(field, key, &mut key_buf, 0);
                    let key = &key_buf;

                    let s = if set {
                        trx.prep(&*index_stmts.insert_presence).await?
                    } else {
                        trx.prep(&*index_stmts.delete_key).await?
                    };
                    trx.exec_drop(&s, (key,)).await?;
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

                    let s = trx.prep(&*log_stmts.upsert_value).await?;

                    trx.exec_drop(&s, (key, value)).await?;
                }
                Advance::Assert {
                    class,
                    assert_value,
                } => {
                    let key = cursor.value_key_owned(class, 0);

                    let s = trx
                        .prep(&*sql.get(cursor.subspace(class)).get_value_for_update)
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
            purge_table(&mut conn, self.sql.get(subspace)).await?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let stmts = self.sql.get(from.subspace());
        let mut from = from.serialize(0);
        let to = to.serialize(0);

        let delete = conn.prep(&*stmts.delete_range).await.map_err(into_error)?;

        match conn.exec_drop(&delete, (&from, &to)).await {
            Ok(_) => return Ok(()),
            Err(err) if is_timeout_error(&err) => (),
            Err(err) => return Err(into_error(err)),
        }

        let mut retry = ChunkedRetry::bounded(DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE);

        let boundary = conn
            .prep(&*stmts.range_boundary)
            .await
            .map_err(into_error)?;

        loop {
            let chunk_size = retry.chunk_size().unwrap_or(DELETE_CHUNK_SIZE) as u64;

            loop {
                let next = match conn
                    .exec_first::<Vec<u8>, _, _>(&boundary, (&from, &to, chunk_size))
                    .await
                {
                    Ok(next) => next,
                    Err(err) if is_timeout_error(&err) => {
                        if !retry.degrade().await {
                            return Err(into_error(err));
                        }
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                };

                match conn
                    .exec_drop(&delete, (&from, next.as_ref().unwrap_or(&to)))
                    .await
                {
                    Ok(_) => retry.progressed(),
                    Err(err) if is_timeout_error(&err) => {
                        if !retry.degrade().await {
                            return Err(into_error(err));
                        }
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

async fn purge_table(conn: &mut Conn, stmts: &SubspaceSql) -> trc::Result<()> {
    let s = conn.prep(&*stmts.purge_zero).await.map_err(into_error)?;

    match conn.exec_drop(&s, ()).await {
        Ok(_) => return Ok(()),
        Err(err) if is_timeout_error(&err) => (),
        Err(err) => return Err(into_error(err)),
    }

    let purge = conn
        .prep(&*stmts.purge_zero_range)
        .await
        .map_err(into_error)?;
    let purge_last = conn
        .prep(&*stmts.purge_zero_from)
        .await
        .map_err(into_error)?;
    let boundary = conn
        .prep(&*stmts.purge_boundary)
        .await
        .map_err(into_error)?;
    let mut retry = ChunkedRetry::bounded(DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE);
    let mut from = Vec::new();

    loop {
        let chunk_size = retry.chunk_size().unwrap_or(DELETE_CHUNK_SIZE) as u64;

        loop {
            let next = match conn
                .exec_first::<Vec<u8>, _, _>(&boundary, (&from, chunk_size))
                .await
            {
                Ok(next) => next,
                Err(err) if is_timeout_error(&err) => {
                    if !retry.degrade().await {
                        return Err(into_error(err));
                    }
                    break;
                }
                Err(err) => return Err(into_error(err)),
            };

            let result = match &next {
                Some(next) => conn.exec_drop(&purge, (&from, next)).await,
                None => conn.exec_drop(&purge_last, (&from,)).await,
            };

            match result {
                Ok(_) => retry.progressed(),
                Err(err) if is_timeout_error(&err) => {
                    if !retry.degrade().await {
                        return Err(into_error(err));
                    }
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
