/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PostgresStore, into_error, is_timeout_error};
use crate::{
    Deserialize, IterateParams, Key, ValueKey, backend::postgres::into_pool_error,
    write::ValueClass,
};
use futures::{TryStreamExt, pin_mut};
use std::fmt::Write;

impl PostgresStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&format!(
                "SELECT v FROM {} WHERE k = $1",
                key.subspace().name()
            ))
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        conn.query_opt(&s, &[&key])
            .await
            .map_err(into_error)
            .and_then(|r| {
                if let Some(r) = r {
                    Ok(Some(U::deserialize_with_key(&key, r.get(0))?))
                } else {
                    Ok(None)
                }
            })
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&format!(
                "SELECT 1 FROM {} WHERE k = $1",
                key.subspace().name()
            ))
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        conn.query_opt(&s, &[&key])
            .await
            .map_err(into_error)
            .map(|r| r.is_some())
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let table = params.begin.subspace().name();
        let begin = params.begin.serialize(0);
        let end = params.end.serialize(0);
        let keys = if params.values { "k, v" } else { "k" };

        let s = conn
            .prepare_cached(&match (params.first, params.ascending) {
                (true, true) => {
                    format!(
                        "SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC LIMIT 1"
                    )
                }
                (true, false) => {
                    format!(
                    "SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k DESC LIMIT 1"
                )
                }
                (false, true) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC")
                }
                (false, false) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k DESC")
                }
            })
            .await.map_err(into_error)?;
        let mut from = begin;
        let mut to = end;
        let mut resume_key: Option<Vec<u8>> = None;

        loop {
            let mut last_key = None;
            let mut timed_out = false;

            {
                let rows = conn
                    .query_raw(&s, &[&from, &to])
                    .await
                    .map_err(into_error)?;

                pin_mut!(rows);

                loop {
                    match rows.try_next().await {
                        Ok(Some(row)) => {
                            let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                            let value = if params.values {
                                row.try_get::<_, &[u8]>(1).map_err(into_error)?
                            } else {
                                b"".as_slice()
                            };

                            if resume_key.take().is_some_and(|resumed| resumed == key) {
                                continue;
                            }

                            if !cb(key, value)? {
                                return Ok(());
                            }

                            last_key = Some(key.to_vec());
                        }
                        Ok(None) => break,
                        Err(err) => {
                            if params.first || last_key.is_none() || !is_timeout_error(&err) {
                                return Err(into_error(err));
                            }
                            timed_out = true;
                            break;
                        }
                    }
                }
            }

            match last_key {
                Some(last_key) if timed_out => {
                    if params.ascending {
                        from.clone_from(&last_key);
                    } else {
                        to.clone_from(&last_key);
                    }
                    resume_key = Some(last_key);
                }
                _ => return Ok(()),
            }
        }
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        const MAX_RANGES_PER_STMT: usize = 64;

        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let table = ranges[0].begin.subspace().name();
        let bounds = ranges
            .iter()
            .map(|params| (params.begin.serialize(0), params.end.serialize(0)))
            .collect::<Vec<_>>();

        type RangeCallback<'y> =
            &'y mut (dyn for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Send + Sync);

        async fn emit(
            rows: tokio_postgres::RowStream,
            resume_key: &mut Option<Vec<u8>>,
            cb: RangeCallback<'_>,
        ) -> trc::Result<Emitted> {
            pin_mut!(rows);
            let mut last_key = None;

            loop {
                match rows.try_next().await {
                    Ok(Some(row)) => {
                        let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                        let value = row.try_get::<_, &[u8]>(1).map_err(into_error)?;

                        if resume_key.take().is_some_and(|resumed| resumed == key) {
                            continue;
                        }

                        if !cb(key, value)? {
                            return Ok(Emitted::Stopped);
                        }

                        last_key = Some(key.to_vec());
                    }
                    Ok(None) => return Ok(Emitted::Done),
                    Err(err) => {
                        return match last_key {
                            Some(last_key) if is_timeout_error(&err) => {
                                Ok(Emitted::TimedOut(last_key))
                            }
                            _ => Err(into_error(err)),
                        };
                    }
                }
            }
        }

        let build_query = |count: usize| {
            let mut query = String::with_capacity(count * 28 + 40);
            let _ = write!(query, "SELECT k, v FROM {table} WHERE ");
            for i in 0..count {
                if i > 0 {
                    query.push_str(" OR ");
                }
                let _ = write!(query, "(k >= ${} AND k <= ${})", i * 2 + 1, i * 2 + 2);
            }
            query.push_str(" ORDER BY k ASC");
            query
        };

        if bounds.len() <= MAX_RANGES_PER_STMT {
            let mut pending = bounds;
            let mut resume_key = None;

            loop {
                let s = conn
                    .prepare_cached(&build_query(pending.len()))
                    .await
                    .map_err(into_error)?;
                let rows = conn
                    .query_raw(
                        &s,
                        pending
                            .iter()
                            .flat_map(|(begin, end)| [begin, end])
                            .collect::<Vec<_>>(),
                    )
                    .await
                    .map_err(into_error)?;

                match emit(rows, &mut resume_key, &mut cb).await? {
                    Emitted::Done | Emitted::Stopped => return Ok(()),
                    Emitted::TimedOut(last_key) => {
                        pending = resume_from(&pending, &last_key);
                        resume_key = Some(last_key);
                    }
                }
            }
        } else {
            let mut chunk_start = 0;
            let mut pending = None;
            let mut resume_key = None;

            loop {
                let trx = conn.transaction().await.map_err(into_error)?;
                trx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", &[])
                    .await
                    .map_err(into_error)?;
                let mut timed_out = false;

                while chunk_start < bounds.len() {
                    let chunk = pending.take().unwrap_or_else(|| {
                        bounds[chunk_start..bounds.len().min(chunk_start + MAX_RANGES_PER_STMT)]
                            .to_vec()
                    });
                    let s = trx
                        .prepare_cached(&build_query(chunk.len()))
                        .await
                        .map_err(into_error)?;
                    let rows = trx
                        .query_raw(
                            &s,
                            chunk
                                .iter()
                                .flat_map(|(begin, end)| [begin, end])
                                .collect::<Vec<_>>(),
                        )
                        .await
                        .map_err(into_error)?;

                    match emit(rows, &mut resume_key, &mut cb).await? {
                        Emitted::Done => {
                            resume_key = None;
                            chunk_start += MAX_RANGES_PER_STMT;
                        }
                        Emitted::Stopped => return Ok(()),
                        Emitted::TimedOut(last_key) => {
                            pending = Some(resume_from(&chunk, &last_key));
                            resume_key = Some(last_key);
                            timed_out = true;
                            break;
                        }
                    }
                }

                if !timed_out {
                    return trx.commit().await.map(|_| ()).map_err(into_error);
                }

                trx.rollback().await.map_err(into_error)?;
            }
        }
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let table = key.subspace().name();
        let key = key.serialize(0);

        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&format!("SELECT v FROM {table} WHERE k = $1"))
            .await
            .map_err(into_error)?;
        match conn.query_opt(&s, &[&key]).await {
            Ok(Some(row)) => row.try_get(0).map_err(into_error),
            Ok(None) => Ok(0),
            Err(e) => Err(into_error(e)),
        }
    }
}

enum Emitted {
    Done,
    Stopped,
    TimedOut(Vec<u8>),
}

fn resume_from(bounds: &[(Vec<u8>, Vec<u8>)], last_key: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    bounds
        .iter()
        .filter(|(_, end)| end.as_slice() >= last_key)
        .map(|(begin, end)| {
            (
                if begin.as_slice() < last_key {
                    last_key.to_vec()
                } else {
                    begin.clone()
                },
                end.clone(),
            )
        })
        .collect()
}
