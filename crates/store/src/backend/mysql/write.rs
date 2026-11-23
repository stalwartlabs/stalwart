/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod reads;

use self::reads::{ReadSet, missing_read, unprefixed};
use super::{
    DELETE_CHUNK_SIZE, ER_DUP_ENTRY, ER_LOCK_DEADLOCK, ER_LOCK_WAIT_TIMEOUT, MIN_DELETE_CHUNK_SIZE,
    MysqlStore, into_error, is_chunk_too_large_error, sql::SubspaceSql,
};
use crate::{
    Key, Shape, Subspace, WITH_SUBSPACE,
    write::{
        Advance, AssignedIds, Batch, BatchCursor, ChunkedRetry, LogSet, MAX_COMMIT_ATTEMPTS,
        MAX_COMMIT_TIME, MergeResult, NewKeyAsserts, Operation, SetValue, ValueOp, commit_backoff,
        exhausted,
    },
};
use mysql_async::{Conn, Error, ServerError, TxOpts, prelude::Queryable};
use std::{borrow::Cow, time::Instant};

#[derive(Debug)]
enum CommitError {
    Mysql(mysql_async::Error),
    Internal(trc::Error),
}

struct AutocommitWrite<'x> {
    subspace: Subspace,
    key: Vec<u8>,
    op: AutocommitOp<'x>,
}

enum AutocommitOp<'x> {
    Set(&'x mut SetValue),
    SetPresence,
    Add(i64),
    AddAndGet(i64),
    Clear,
}

enum WriteShape<'x, 'y> {
    Autocommit(AutocommitWrite<'x>),
    Transaction(&'x mut Batch<'y>),
}

impl MysqlStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut new_key_asserts = NewKeyAsserts::CheckedByInsert;
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let mark = assigned_ids.mark();
        let mut shape = match AutocommitWrite::parse(&mut batch, assigned_ids) {
            Some(write) => WriteShape::Autocommit(write),
            None => WriteShape::Transaction(&mut batch),
        };

        loop {
            assigned_ids.rollback(mark);
            let result = match &mut shape {
                WriteShape::Autocommit(write) => {
                    self.write_autocommit(&mut conn, write, assigned_ids).await
                }
                WriteShape::Transaction(batch) => {
                    self.write_trx(&mut conn, batch, assigned_ids, new_key_asserts)
                        .await
                }
            };
            let err = match result {
                Ok(()) => {
                    return Ok(());
                }
                Err(err) => err,
            };

            match err {
                CommitError::Mysql(Error::Server(err))
                    if [ER_LOCK_DEADLOCK, ER_LOCK_WAIT_TIMEOUT, ER_DUP_ENTRY]
                        .contains(&err.code)
                        && retry_count < MAX_COMMIT_ATTEMPTS
                        && start.elapsed() < MAX_COMMIT_TIME =>
                {
                    if err.code == ER_DUP_ENTRY {
                        new_key_asserts = NewKeyAsserts::Read;
                    }
                }
                CommitError::Mysql(Error::Server(err)) if err.code == ER_DUP_ENTRY => {
                    return Err(trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .reason("Unique violation")
                        .caused_by(trc::location!()));
                }
                CommitError::Mysql(
                    err @ Error::Server(ServerError {
                        code: ER_LOCK_DEADLOCK | ER_LOCK_WAIT_TIMEOUT,
                        ..
                    }),
                ) => {
                    return Err(exhausted(into_error(err), retry_count));
                }
                CommitError::Mysql(err) => {
                    return Err(into_error(err));
                }
                CommitError::Internal(err) => {
                    return Err(err);
                }
            }

            #[cfg(stalwart_tests)]
            crate::write::record_retry(retry_count);
            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }

    async fn write_autocommit(
        &self,
        conn: &mut Conn,
        write: &mut AutocommitWrite<'_>,
        result: &mut AssignedIds,
    ) -> Result<(), CommitError> {
        let stmts = self.sql.get(write.subspace);
        let key = &write.key;

        match &mut write.op {
            AutocommitOp::Set(value) => {
                let value = value.resolve(result)?;
                let s = conn.prep(&*stmts.upsert_value).await?;
                conn.exec_drop(&s, (key, &*value)).await?;
                if conn.affected_rows() == 0 {
                    return Err(trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .caused_by(trc::location!())
                        .into());
                }
            }
            AutocommitOp::SetPresence => {
                let s = conn.prep(&*stmts.insert_presence).await?;
                conn.exec_drop(&s, (key,)).await?;
            }
            AutocommitOp::Add(by) if *by >= 0 => {
                let s = conn.prep(&*stmts.increment).await?;
                conn.exec_drop(&s, (key, *by)).await?;
            }
            AutocommitOp::Add(by) => {
                let s = conn.prep(&*stmts.decrement).await?;
                conn.exec_drop(&s, (*by, key)).await?;
            }
            AutocommitOp::AddAndGet(by) => {
                let s = conn.prep(&*stmts.increment_returning).await?;
                conn.exec_drop(&s, (key, *by, *by)).await?;
                result.push_counter_id(conn.last_insert_id().unwrap_or_default() as i64);
            }
            AutocommitOp::Clear => {
                let s = conn.prep(&*stmts.delete_key).await?;
                conn.exec_drop(&s, (key,)).await?;
            }
        }

        Ok(())
    }

    async fn write_trx(
        &self,
        conn: &mut Conn,
        batch: &mut Batch<'_>,
        result: &mut AssignedIds,
        new_key_asserts: NewKeyAsserts,
    ) -> Result<(), CommitError> {
        let sql = &*self.sql;
        let mut trx = conn.start_transaction(TxOpts::default()).await?;
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();

        if batch.has_id_allocations() {
            let incr = trx
                .prep(&*sql.get(Subspace::Counter).increment_returning)
                .await?;
            let mut key_buf = Vec::with_capacity(16);

            for allocation in batch.id_allocations() {
                key_buf.clear();
                allocation.serialize_key_into(&mut key_buf, 0);
                let increment_by = allocation.increment_by();
                trx.exec_drop(&incr, (&key_buf, increment_by, increment_by))
                    .await?;
                let counter = trx.last_insert_id().ok_or_else(missing_last_insert_id)? as i64;
                if let Err(err) = result.apply(allocation, counter) {
                    trx.rollback().await?;
                    return Err(err.into());
                }
            }
        }

        let mut key_buf = Vec::with_capacity(64);
        let mut reads = ReadSet::collect(batch, result, &mut key_buf, new_key_asserts);
        if reads.needs_fetch() {
            reads.fetch(&mut trx, sql).await?;
        }

        let mut cursor = BatchCursor::new(batch);
        let index_stmts = sql.get(Subspace::Indexes);
        let log_stmts = sql.get(Subspace::Logs);
        for (op_index, op) in batch.ops.iter_mut().enumerate() {
            match cursor.advance(op, result) {
                Advance::Cursor => {}
                Advance::Value { class, op } => {
                    cursor.value_key(class, &mut key_buf, WITH_SUBSPACE);
                    let slot = reads.find(&key_buf);
                    let key = unprefixed(&key_buf);
                    let subspace = cursor.subspace(class);
                    let stmts = sql.get(subspace);

                    match op {
                        ValueOp::Set(set_value) => {
                            let value = set_value.resolve(result)?;
                            let value = &*value;
                            if !matches!(subspace.shape(), Shape::Presence) {
                                let updated = match slot.filter(|slot| reads.is_asserted(*slot)) {
                                    Some(slot) if reads.exists(slot) => {
                                        let s = trx.prep(&*stmts.update_value).await?;
                                        trx.exec_drop(&s, (value, key)).await
                                    }
                                    Some(_) => {
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

                                if let Some(slot) = slot {
                                    reads.written(slot, op_index, Cow::Borrowed(value));
                                }
                            } else {
                                let s = trx.prep(&*stmts.insert_presence).await?;
                                trx.exec_drop(&s, (key,)).await?;
                            }
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let slot = slot.ok_or_else(missing_read)?;
                            let exists = reads.exists(slot);

                            match (merge_op.0)(result, reads.value(slot)?)? {
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

                                    reads.written(slot, op_index, Cow::Owned(value));
                                }
                                MergeResult::Delete if exists => {
                                    let s = trx.prep(&*stmts.delete_key).await?;
                                    trx.exec_drop(&s, (key,)).await?;
                                    reads.cleared(slot);
                                }
                                MergeResult::Delete | MergeResult::Skip => (),
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
                            result.push_counter_id(trx.last_insert_id().unwrap_or_default() as i64);
                        }
                        ValueOp::Clear => {
                            let s = trx.prep(&*stmts.delete_key).await?;
                            trx.exec_drop(&s, (key,)).await?;
                            if let Some(slot) = slot {
                                reads.cleared(slot);
                            }
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
                    cursor.log_key(collection, result, &mut key_buf, WITH_SUBSPACE);
                    let value = match set {
                        LogSet::Bytes(bytes) => &*bytes,
                        LogSet::Pending(changes) => {
                            changes.serialize_into(
                                collection.is_prefixed(),
                                result,
                                &mut log_scratch,
                                &mut log_buf,
                            );
                            &log_buf
                        }
                    };

                    let s = trx.prep(&*log_stmts.upsert_value).await?;
                    trx.exec_drop(&s, (unprefixed(&key_buf), value)).await?;
                    if let Some(slot) = reads.find(&key_buf) {
                        reads.written(slot, op_index, Cow::Borrowed(value));
                    }
                }
                Advance::ClearRange { subspace, from, to } => {
                    reads.clear_range(subspace, from, to);
                    let s = trx.prep(&*sql.get(subspace).delete_range).await?;
                    trx.exec_drop(&s, (from, to)).await?;
                }
                Advance::Assert {
                    class,
                    assert_value,
                } => {
                    cursor.value_key(class, &mut key_buf, WITH_SUBSPACE);
                    let slot = reads.find(&key_buf).ok_or_else(missing_read)?;
                    let matches = match reads.value(slot)? {
                        Some(value) => assert_value.matches(value),
                        None => assert_value.is_none(),
                    };
                    if !matches {
                        trx.rollback().await?;
                        return Err(trc::StoreEvent::AssertValueFailed
                            .into_err()
                            .caused_by(trc::location!())
                            .into());
                    }
                    reads.asserted(slot);
                }
            }
        }

        if !batch.bounds.is_empty() {
            let incr = trx
                .prep(&*sql.get(Subspace::Counter).increment_returning)
                .await?;
            for bound in batch.bounds {
                key_buf.clear();
                bound.serialize_key_into(&mut key_buf, 0);
                trx.exec_drop(&incr, (&key_buf, bound.by, bound.by)).await?;
                let value = trx.last_insert_id().unwrap_or_default() as i64;
                if let Err(err) = bound.verify(value) {
                    trx.rollback().await?;
                    return Err(err.into());
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

        let mut retry = ChunkedRetry::bounded(DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE);

        let delete_limit = conn
            .prep(&*stmts.delete_range_limit)
            .await
            .map_err(into_error)?;
        match conn
            .exec_drop(&delete_limit, (&from, &to, DELETE_CHUNK_SIZE as u64))
            .await
        {
            Ok(_) if conn.affected_rows() < DELETE_CHUNK_SIZE as u64 => return Ok(()),
            Ok(_) => (),
            Err(err) if is_chunk_too_large_error(&err) => {
                if !retry.degrade().await {
                    return Err(into_error(err));
                }
            }
            Err(err) => return Err(into_error(err)),
        }

        let delete = conn.prep(&*stmts.delete_range).await.map_err(into_error)?;
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
                    Err(err) if is_chunk_too_large_error(&err) => {
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
                    Err(err) if is_chunk_too_large_error(&err) => {
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
        Err(err) if is_chunk_too_large_error(&err) => (),
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
                Err(err) if is_chunk_too_large_error(&err) => {
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
                Err(err) if is_chunk_too_large_error(&err) => {
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

impl<'x> AutocommitWrite<'x> {
    fn parse(batch: &'x mut Batch<'_>, ids: &mut AssignedIds) -> Option<Self> {
        if batch.has_allocations() {
            return None;
        }

        let mut writes = batch.ops.iter().filter(|op| {
            !matches!(
                op,
                Operation::AccountId { .. }
                    | Operation::Collection { .. }
                    | Operation::DocumentId { .. }
            )
        });
        if writes.next().is_none() || writes.next().is_some() {
            return None;
        }

        let mut cursor = BatchCursor::new(batch);
        for op in batch.ops.iter_mut() {
            match cursor.advance(op, ids) {
                Advance::Cursor => {}
                Advance::Value { class, op } => {
                    let subspace = cursor.subspace(class);
                    let op = match op {
                        ValueOp::Set(_) if matches!(subspace.shape(), Shape::Presence) => {
                            AutocommitOp::SetPresence
                        }
                        ValueOp::Set(value) => AutocommitOp::Set(value),
                        ValueOp::AtomicAdd(by) => AutocommitOp::Add(*by),
                        ValueOp::AddAndGet(by) => AutocommitOp::AddAndGet(*by),
                        ValueOp::Clear => AutocommitOp::Clear,
                        ValueOp::MergeFnc(_) => return None,
                    };
                    return Some(AutocommitWrite {
                        subspace,
                        key: cursor.value_key_owned(class, 0),
                        op,
                    });
                }
                Advance::Index { field, key, set } => {
                    return Some(AutocommitWrite {
                        subspace: Subspace::Indexes,
                        key: cursor.index_key_owned(field, key, 0),
                        op: if set {
                            AutocommitOp::SetPresence
                        } else {
                            AutocommitOp::Clear
                        },
                    });
                }
                Advance::Log { .. } | Advance::Assert { .. } | Advance::ClearRange { .. } => {
                    return None;
                }
            }
        }

        None
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/mysql/write/tests.rs"]
mod tests;
