/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MysqlStore, into_error};
use crate::{Deserialize, IterateParams, Key, ValueKey, write::ValueClass};
use futures::TryStreamExt;
use mysql_async::{Row, prelude::Queryable};

impl MysqlStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn
            .prep(format!(
                "SELECT v FROM {} WHERE k = ?",
                char::from(key.subspace())
            ))
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        conn.exec_first::<Vec<u8>, _, _>(&s, (key,))
            .await
            .map_err(into_error)
            .and_then(|r| {
                if let Some(r) = r {
                    Ok(Some(U::deserialize_owned(r)?))
                } else {
                    Ok(None)
                }
            })
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let table = char::from(params.begin.subspace());
        let begin = params.begin.serialize(0);
        let end = params.end.serialize(0);
        let keys = if params.values { "k, v" } else { "k" };

        let s = conn
            .prep(&match (params.first, params.ascending) {
                (true, true) => {
                    format!(
                        "SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC LIMIT 1"
                    )
                }
                (true, false) => {
                    format!(
                        "SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC LIMIT 1"
                    )
                }
                (false, true) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC")
                }
                (false, false) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC")
                }
            })
            .await
            .map_err(into_error)?;
        let mut rows = conn
            .exec_stream::<Row, _, _>(&s, (begin, end))
            .await
            .map_err(into_error)?;

        if params.values {
            while let Some(mut row) = rows.try_next().await.map_err(into_error)? {
                let value = row
                    .take_opt::<Vec<u8>, _>(1)
                    .unwrap_or_else(|| Ok(vec![]))
                    .map_err(into_error)?;
                let key = row
                    .take_opt::<Vec<u8>, _>(0)
                    .unwrap_or_else(|| Ok(vec![]))
                    .map_err(into_error)?;

                if !cb(&key, &value)? {
                    break;
                }
            }
        } else {
            while let Some(mut row) = rows.try_next().await.map_err(into_error)? {
                if !cb(
                    &row.take_opt::<Vec<u8>, _>(0)
                        .unwrap_or_else(|| Ok(vec![]))
                        .map_err(into_error)?,
                    b"",
                )? {
                    break;
                }
            }
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
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn
            .prep(format!("SELECT v FROM {table} WHERE k = ?"))
            .await
            .map_err(into_error)?;
        match conn.exec_first::<i64, _, _>(&s, (key,)).await {
            Ok(Some(num)) => Ok(num),
            Ok(None) => Ok(0),
            Err(e) => Err(into_error(e)),
        }
    }
}
