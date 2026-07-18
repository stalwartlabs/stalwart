/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PostgresStore, into_error};
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
                char::from(key.subspace())
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
                char::from(key.subspace())
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
        let table = char::from(params.begin.subspace());
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
        let rows = conn
            .query_raw(&s, &[&begin, &end])
            .await
            .map_err(into_error)?;

        pin_mut!(rows);

        if params.values {
            while let Some(row) = rows.try_next().await.map_err(into_error)? {
                let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                let value = row.try_get::<_, &[u8]>(1).map_err(into_error)?;

                if !cb(key, value)? {
                    break;
                }
            }
        } else {
            while let Some(row) = rows.try_next().await.map_err(into_error)? {
                if !cb(row.try_get::<_, &[u8]>(0).map_err(into_error)?, b"")? {
                    break;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        const MAX_RANGES_PER_STMT: usize = 64;

        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let table = char::from(ranges[0].begin.subspace());
        let bounds = ranges
            .iter()
            .map(|params| (params.begin.serialize(0), params.end.serialize(0)))
            .collect::<Vec<_>>();

        type RangeCallback<'y> =
            &'y mut (dyn for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Send + Sync);

        async fn emit(rows: tokio_postgres::RowStream, cb: RangeCallback<'_>) -> trc::Result<bool> {
            pin_mut!(rows);
            while let Some(row) = rows.try_next().await.map_err(into_error)? {
                let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                let value = row.try_get::<_, &[u8]>(1).map_err(into_error)?;
                if !cb(key, value)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        let build_query = |chunk: &[(Vec<u8>, Vec<u8>)]| {
            let mut query = String::with_capacity(chunk.len() * 28 + 40);
            let _ = write!(query, "SELECT k, v FROM {table} WHERE ");
            for i in 0..chunk.len() {
                if i > 0 {
                    query.push_str(" OR ");
                }
                let _ = write!(query, "(k >= ${} AND k <= ${})", i * 2 + 1, i * 2 + 2);
            }
            query.push_str(" ORDER BY k ASC");
            query
        };

        if bounds.len() <= MAX_RANGES_PER_STMT {
            let s = conn
                .prepare_cached(&build_query(&bounds))
                .await
                .map_err(into_error)?;
            let params = bounds
                .iter()
                .flat_map(|(begin, end)| [begin, end])
                .collect::<Vec<_>>();
            let rows = conn.query_raw(&s, params).await.map_err(into_error)?;
            emit(rows, &mut cb).await?;
        } else {
            let trx = conn.transaction().await.map_err(into_error)?;
            trx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", &[])
                .await
                .map_err(into_error)?;
            for chunk in bounds.chunks(MAX_RANGES_PER_STMT) {
                let s = trx
                    .prepare_cached(&build_query(chunk))
                    .await
                    .map_err(into_error)?;
                let params = chunk
                    .iter()
                    .flat_map(|(begin, end)| [begin, end])
                    .collect::<Vec<_>>();
                let rows = trx.query_raw(&s, params).await.map_err(into_error)?;
                if !emit(rows, &mut cb).await? {
                    break;
                }
            }
            trx.commit().await.map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let table = char::from(key.subspace());
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
