/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MysqlStore, into_error, is_timeout_error};
use crate::{
    Deserialize, IterateParams, Key, ValueKey,
    backend::mysql::{ITERATE_CHUNK_SIZE, MIN_ITERATE_CHUNK_SIZE},
    write::{ChunkedRetry, ValueClass},
};
use futures::TryStreamExt;
use mysql_async::{IsolationLevel, Row, TxOpts, prelude::Queryable};

impl MysqlStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn
            .prep(&*self.sql.get(key.subspace()).get_value)
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        conn.exec_first::<Vec<u8>, _, _>(&s, (&key,))
            .await
            .map_err(into_error)
            .and_then(|r| {
                if let Some(r) = r {
                    Ok(Some(U::deserialize_owned_with_key(&key, r)?))
                } else {
                    Ok(None)
                }
            })
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn
            .prep(&*self.sql.get(key.subspace()).key_exists)
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        conn.exec_first::<u8, _, _>(&s, (&key,))
            .await
            .map_err(into_error)
            .map(|r| r.is_some())
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let stmts = self.sql.get(params.begin.subspace());
        let mut from = params.begin.serialize(0);
        let mut to = params.end.serialize(0);
        let mut resume_key: Option<Vec<u8>> = None;
        let mut retry = ChunkedRetry::unbounded(ITERATE_CHUNK_SIZE, MIN_ITERATE_CHUNK_SIZE);

        loop {
            let chunk_size = if params.first {
                None
            } else {
                retry.chunk_size()
            };
            let s = match chunk_size {
                Some(chunk_size) => conn
                    .prep(format!(
                        "{} LIMIT {chunk_size}",
                        stmts.iterate(false, params.ascending, params.values)
                    ))
                    .await
                    .map_err(into_error)?,
                None => conn
                    .prep(stmts.iterate(params.first, params.ascending, params.values))
                    .await
                    .map_err(into_error)?,
            };
            let mut last_key = None;
            let mut fetched = 0;
            let mut timed_out = None;

            match conn
                .exec_stream::<Row, _, _>(&s, (from.clone(), to.clone()))
                .await
            {
                Ok(mut rows) => loop {
                    match rows.try_next().await {
                        Ok(Some(mut row)) => {
                            let value = if params.values {
                                row.take_opt::<Vec<u8>, _>(1)
                                    .unwrap_or_else(|| Ok(vec![]))
                                    .map_err(into_error)?
                            } else {
                                vec![]
                            };
                            let key = row
                                .take_opt::<Vec<u8>, _>(0)
                                .unwrap_or_else(|| Ok(vec![]))
                                .map_err(into_error)?;

                            fetched += 1;
                            if resume_key.take().is_some_and(|resumed| resumed == key) {
                                continue;
                            }

                            if !cb(&key, &value)? {
                                return Ok(());
                            }

                            last_key = Some(key);
                        }
                        Ok(None) => break,
                        Err(err) => {
                            if params.first || !is_timeout_error(&err) {
                                return Err(into_error(err));
                            }
                            timed_out = Some(err);
                            break;
                        }
                    }
                },
                Err(err) => {
                    if params.first || !is_timeout_error(&err) {
                        return Err(into_error(err));
                    }
                    timed_out = Some(err);
                }
            }

            match last_key {
                Some(last_key) => {
                    retry.progressed();
                    if timed_out.is_none() && !(!params.first && retry.is_chunk_full(fetched)) {
                        return Ok(());
                    }
                    if params.ascending {
                        from.clone_from(&last_key);
                    } else {
                        to.clone_from(&last_key);
                    }
                    resume_key = Some(last_key);
                }
                None => match timed_out {
                    Some(err) if !retry.degrade().await => return Err(into_error(err)),
                    Some(_) => (),
                    None => return Ok(()),
                },
            }
        }
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        const MAX_RANGES_PER_STMT: usize = 64;

        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let table = ranges[0].begin.subspace().name();
        let bounds = ranges
            .iter()
            .map(|params| (params.begin.serialize(0), params.end.serialize(0)))
            .collect::<Vec<_>>();

        type RangeCallback<'y> =
            &'y mut (dyn for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Send + Sync);

        let build_query = |count: usize| {
            let mut query = String::with_capacity(count * 24 + 40);
            query.push_str("SELECT k, v FROM ");
            query.push_str(table);
            query.push_str(" WHERE ");
            for i in 0..count {
                if i > 0 {
                    query.push_str(" OR ");
                }
                query.push_str("(k >= ? AND k <= ?)");
            }
            query.push_str(" ORDER BY k ASC");
            query
        };

        async fn emit<Q: Queryable>(
            q: &mut Q,
            query: &str,
            bounds: &[(Vec<u8>, Vec<u8>)],
            resume_key: &mut Option<Vec<u8>>,
            cb: RangeCallback<'_>,
        ) -> trc::Result<Emitted> {
            let s = q.prep(query).await.map_err(into_error)?;
            let params = bounds
                .iter()
                .flat_map(|(begin, end)| {
                    [
                        mysql_async::Value::Bytes(begin.clone()),
                        mysql_async::Value::Bytes(end.clone()),
                    ]
                })
                .collect::<Vec<_>>();
            let mut rows = q
                .exec_stream::<Row, _, _>(&s, params)
                .await
                .map_err(into_error)?;
            let mut last_key = None;

            loop {
                match rows.try_next().await {
                    Ok(Some(mut row)) => {
                        let value = row
                            .take_opt::<Vec<u8>, _>(1)
                            .unwrap_or_else(|| Ok(vec![]))
                            .map_err(into_error)?;
                        let key = row
                            .take_opt::<Vec<u8>, _>(0)
                            .unwrap_or_else(|| Ok(vec![]))
                            .map_err(into_error)?;

                        if resume_key.take().is_some_and(|resumed| resumed == key) {
                            continue;
                        }

                        if !cb(&key, &value)? {
                            return Ok(Emitted::Stopped);
                        }

                        last_key = Some(key);
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

        if bounds.len() <= MAX_RANGES_PER_STMT {
            let mut pending = bounds;
            let mut resume_key = None;

            loop {
                match emit(
                    &mut conn,
                    &build_query(pending.len()),
                    &pending,
                    &mut resume_key,
                    &mut cb,
                )
                .await?
                {
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
                let mut tx_opts = TxOpts::default();
                tx_opts
                    .with_consistent_snapshot(true)
                    .with_isolation_level(IsolationLevel::RepeatableRead);
                let mut trx = conn.start_transaction(tx_opts).await.map_err(into_error)?;
                let mut timed_out = false;

                while chunk_start < bounds.len() {
                    let chunk: Vec<(Vec<u8>, Vec<u8>)> = pending.take().unwrap_or_else(|| {
                        bounds[chunk_start..bounds.len().min(chunk_start + MAX_RANGES_PER_STMT)]
                            .to_vec()
                    });

                    match emit(
                        &mut trx,
                        &build_query(chunk.len()),
                        &chunk,
                        &mut resume_key,
                        &mut cb,
                    )
                    .await?
                    {
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
        let subspace = key.subspace();
        let key = key.serialize(0);
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn
            .prep(&*self.sql.get(subspace).get_value)
            .await
            .map_err(into_error)?;
        match conn.exec_first::<i64, _, _>(&s, (key,)).await {
            Ok(Some(num)) => Ok(num),
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
