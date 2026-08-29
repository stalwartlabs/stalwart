/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PostgresStore, into_error, is_timeout_error};
use crate::{
    Key, Shape, Subspace,
    backend::postgres::{DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, into_pool_error},
    write::{
        Advance, AssignedIds, Batch, BatchCursor, LogSet, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
        MergeResult, ValueOp, commit_backoff,
    },
};
use ahash::AHashMap;
use deadpool_postgres::Object;
use std::time::Instant;
use tokio_postgres::{IsolationLevel, error::SqlState};

#[derive(Debug)]
enum CommitError {
    Postgres(tokio_postgres::Error),
    Internal(trc::Error),
}

impl PostgresStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let start = Instant::now();
        let mut retry_count = 0;
        let mark = assigned_ids.mark();

        loop {
            assigned_ids.rollback(mark);
            match self.write_trx(&mut conn, &mut batch, assigned_ids).await {
                Ok(()) => {
                    return Ok(());
                }
                Err(err) => {
                    match err {
                        CommitError::Postgres(err) => match err.code() {
                            Some(
                                &SqlState::T_R_SERIALIZATION_FAILURE
                                | &SqlState::T_R_DEADLOCK_DETECTED,
                            ) if retry_count < MAX_COMMIT_ATTEMPTS
                                && start.elapsed() < MAX_COMMIT_TIME => {}
                            Some(&SqlState::UNIQUE_VIOLATION) => {
                                return Err(trc::StoreEvent::AssertValueFailed
                                    .into_err()
                                    .reason("Unique violation")
                                    .caused_by(trc::location!()));
                            }
                            _ => return Err(into_error(err)),
                        },
                        CommitError::Internal(err) => return Err(err),
                    }

                    tokio::time::sleep(commit_backoff(retry_count)).await;
                    retry_count += 1;
                }
            }
        }
    }

    async fn write_trx(
        &self,
        conn: &mut Object,
        batch: &mut Batch<'_>,
        result: &mut AssignedIds,
    ) -> Result<(), CommitError> {
        let mut cursor = BatchCursor::new(batch);
        let mut asserted_values = AHashMap::new();
        let trx = conn
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        if batch.has_allocations() {
            let s = trx
                .prepare_cached(concat!(
                    "INSERT INTO n (k, v) VALUES ($1, $2) ",
                    "ON CONFLICT(k) DO UPDATE SET v = n.v + excluded.v RETURNING v"
                ))
                .await?;
            let mut key_buf = Vec::with_capacity(16);

            for allocation in batch.allocations() {
                key_buf.clear();
                allocation.serialize_key_into(&mut key_buf, 0);
                let last_id = trx
                    .query_one(&s, &[&key_buf, &allocation.increment_by()])
                    .await
                    .and_then(|row| row.try_get::<_, i64>(0))?;
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
                                let s = if let Some(exists) = asserted_values.get(key) {
                                    if *exists {
                                        trx.prepare_cached(&format!(
                                            "UPDATE {} SET v = $2 WHERE k = $1",
                                            table
                                        ))
                                        .await?
                                    } else {
                                        trx.prepare_cached(&format!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2)",
                                            table
                                        ))
                                        .await?
                                    }
                                } else {
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                                        ),
                                        table
                                    ))
                                    .await?
                                };

                                if trx.execute(&s, &[&key, &value]).await? == 0 {
                                    return Err(trc::StoreEvent::AssertValueFailed
                                        .into_err()
                                        .caused_by(trc::location!())
                                        .into());
                                }
                            } else {
                                let s = trx
                                    .prepare_cached(&format!(
                                        "INSERT INTO {table} (k) VALUES ($1) ON CONFLICT (k) DO NOTHING"
                                    ))
                                    .await?;
                                trx.execute(&s, &[&key]).await?;
                            }
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let s = trx
                                .prepare_cached(&format!(
                                    "SELECT v FROM {} WHERE k = $1 FOR UPDATE",
                                    table
                                ))
                                .await?;
                            let (exists, merge_result) = trx
                                .query_opt(&s, &[&key])
                                .await?
                                .map(|row| {
                                    row.try_get::<_, &[u8]>(0)
                                        .map_err(CommitError::from)
                                        .and_then(|v| {
                                            (merge_op.0)(result, Some(v))
                                                .map(|v| (true, v))
                                                .map_err(CommitError::from)
                                        })
                                })
                                .unwrap_or_else(|| {
                                    (merge_op.0)(result, None)
                                        .map(|v| (false, v))
                                        .map_err(CommitError::from)
                                })?;

                            match merge_result {
                                MergeResult::Update(value) => {
                                    let s = if exists {
                                        trx.prepare_cached(&format!(
                                            "UPDATE {} SET v = $2 WHERE k = $1",
                                            table
                                        ))
                                        .await?
                                    } else {
                                        trx.prepare_cached(&format!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2)",
                                            table
                                        ))
                                        .await?
                                    };

                                    trx.execute(&s, &[&key, &value]).await?;
                                }
                                MergeResult::Delete if exists => {
                                    let s = trx
                                        .prepare_cached(&format!(
                                            "DELETE FROM {} WHERE k = $1",
                                            table
                                        ))
                                        .await?;
                                    trx.execute(&s, &[&key]).await?;

                                    // Update asserted value
                                    if let Some(exists) = asserted_values.get_mut(key) {
                                        *exists = false;
                                    }
                                }
                                _ => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            if *by >= 0 {
                                let s = trx
                                    .prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = {}.v + EXCLUDED.v"
                                        ),
                                        table, table
                                    ))
                                    .await?;
                                trx.execute(&s, &[&key, &*by]).await?;
                            } else {
                                let s = trx
                                    .prepare_cached(&format!(
                                        "UPDATE {table} SET v = v + $1 WHERE k = $2"
                                    ))
                                    .await?;
                                trx.execute(&s, &[&*by, &key]).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            let s = trx
                                .prepare_cached(&format!(
                                    concat!(
                                    "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                    "ON CONFLICT(k) DO UPDATE SET v = {}.v + EXCLUDED.v RETURNING v"
                                ),
                                    table, table
                                ))
                                .await?;
                            result.push_counter_id(
                                trx.query_one(&s, &[&key, &*by])
                                    .await
                                    .and_then(|row| row.try_get::<_, i64>(0))?,
                            );
                        }
                        ValueOp::Clear => {
                            let s = trx
                                .prepare_cached(&format!("DELETE FROM {} WHERE k = $1", table))
                                .await?;
                            trx.execute(&s, &[&key]).await?;

                            // Update asserted value
                            if let Some(exists) = asserted_values.get_mut(key) {
                                *exists = false;
                            }
                        }
                    }
                }
                Advance::Index { field, key, set } => {
                    cursor.index_key(field, key, &mut key_buf, 0);
                    let key = &key_buf;

                    let s = if set {
                        trx.prepare_cached(
                            "INSERT INTO i (k) VALUES ($1) ON CONFLICT (k) DO NOTHING",
                        )
                        .await?
                    } else {
                        trx.prepare_cached("DELETE FROM i WHERE k = $1").await?
                    };
                    trx.execute(&s, &[&key]).await?;
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

                    let s = trx
                        .prepare_cached(concat!(
                            "INSERT INTO l (k, v) VALUES ($1, $2) ",
                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                        ))
                        .await?;

                    trx.execute(&s, &[&key, &value]).await?;
                }
                Advance::Assert {
                    class,
                    assert_value,
                } => {
                    let key = cursor.value_key_owned(class, 0);
                    let table = cursor.subspace(class).name();

                    let s = trx
                        .prepare_cached(&format!("SELECT v FROM {} WHERE k = $1 FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .query_opt(&s, &[&key])
                        .await?
                        .map(|row| {
                            row.try_get::<_, &[u8]>(0)
                                .map_or((true, false), |v| (true, assert_value.matches(v)))
                        })
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
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
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
        {
            purge_table(&conn, subspace.name()).await?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let table = from.subspace().name();
        let mut from = from.serialize(0);
        let to = to.serialize(0);

        let delete = conn
            .prepare_cached(&format!("DELETE FROM {table} WHERE k >= $1 AND k < $2"))
            .await
            .map_err(into_error)?;

        match conn.execute(&delete, &[&from, &to]).await {
            Ok(_) => return Ok(()),
            Err(err) if is_timeout_error(&err) => (),
            Err(err) => return Err(into_error(err)),
        }

        let mut chunk_size = DELETE_CHUNK_SIZE;

        loop {
            let boundary = conn
                .prepare_cached(&format!(
                    "SELECT k FROM {table} WHERE k >= $1 AND k < $2 ORDER BY k ASC LIMIT 1 OFFSET {chunk_size}"
                ))
                .await
                .map_err(into_error)?;

            loop {
                let next = match conn.query_opt(&boundary, &[&from, &to]).await {
                    Ok(next) => match next {
                        Some(row) => Some(row.try_get::<_, Vec<u8>>(0).map_err(into_error)?),
                        None => None,
                    },
                    Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                        chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                };

                match conn
                    .execute(&delete, &[&from, next.as_ref().unwrap_or(&to)])
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

async fn purge_table(conn: &Object, table: &str) -> trc::Result<()> {
    let s = conn
        .prepare_cached(&format!("DELETE FROM {table} WHERE v = 0"))
        .await
        .map_err(into_error)?;

    match conn.execute(&s, &[]).await {
        Ok(_) => return Ok(()),
        Err(err) if is_timeout_error(&err) => (),
        Err(err) => return Err(into_error(err)),
    }

    let purge = conn
        .prepare_cached(&format!(
            "DELETE FROM {table} WHERE v = 0 AND k >= $1 AND k < $2"
        ))
        .await
        .map_err(into_error)?;
    let purge_last = conn
        .prepare_cached(&format!("DELETE FROM {table} WHERE v = 0 AND k >= $1"))
        .await
        .map_err(into_error)?;
    let mut chunk_size = DELETE_CHUNK_SIZE;
    let mut from = Vec::new();

    loop {
        let boundary = conn
            .prepare_cached(&format!(
                "SELECT k FROM {table} WHERE k >= $1 ORDER BY k ASC LIMIT 1 OFFSET {chunk_size}"
            ))
            .await
            .map_err(into_error)?;

        loop {
            let next = match conn.query_opt(&boundary, &[&from]).await {
                Ok(next) => match next {
                    Some(row) => Some(row.try_get::<_, Vec<u8>>(0).map_err(into_error)?),
                    None => None,
                },
                Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                    chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                    break;
                }
                Err(err) => return Err(into_error(err)),
            };

            let result = match &next {
                Some(next) => conn.execute(&purge, &[&from, next]).await,
                None => conn.execute(&purge_last, &[&from]).await,
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

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}

impl From<tokio_postgres::Error> for CommitError {
    fn from(err: tokio_postgres::Error) -> Self {
        CommitError::Postgres(err)
    }
}
