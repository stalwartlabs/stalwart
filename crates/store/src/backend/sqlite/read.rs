/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error};
use crate::{Deserialize, IterateParams, Key, ValueKey, write::ValueClass};
use rusqlite::OptionalExtension;

impl SqliteStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            let bytes = conn
                .prepare_cached(&sql.get(subspace).get_value)
                .map_err(into_error)?
                .query_row([&key], |row| Ok(row.get_ref(0)?.as_bytes()?.to_vec()))
                .optional()
                .map_err(into_error)?;

            match bytes {
                Some(bytes) => U::deserialize_with_key(&key, &bytes).map(Some),
                None => Ok(None),
            }
        })
        .await
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            conn.prepare_cached(&sql.get(subspace).key_exists)
                .map_err(into_error)?
                .query_row([&key], |_| Ok(()))
                .optional()
                .map(|opt| opt.is_some())
                .map_err(into_error)
        })
        .await
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.get(params.begin.subspace()).iterate(
            params.first,
            params.ascending,
            params.values,
        );

        self.block_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);

            let mut query = conn.prepare_cached(sql).map_err(into_error)?;
            let mut rows = query.query([&begin, &end]).map_err(into_error)?;

            if params.values {
                while let Some(row) = rows.next().map_err(into_error)? {
                    let key = row
                        .get_ref(0)
                        .map_err(into_error)?
                        .as_bytes()
                        .map_err(into_error)?;
                    let value = row
                        .get_ref(1)
                        .map_err(into_error)?
                        .as_bytes()
                        .map_err(into_error)?;

                    if !cb(key, value)? {
                        break;
                    }
                }
            } else {
                while let Some(row) = rows.next().map_err(into_error)? {
                    if !cb(
                        row.get_ref(0)
                            .map_err(into_error)?
                            .as_bytes()
                            .map_err(into_error)?,
                        b"",
                    )? {
                        break;
                    }
                }
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        let values = ranges[0].values;
        let sql = self
            .sql
            .get(ranges[0].begin.subspace())
            .iterate(false, true, values);

        self.block_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            let mut stmt = conn.prepare_cached(sql).map_err(into_error)?;

            'outer: for params in &ranges {
                let begin = params.begin.serialize(0);
                let end = params.end.serialize(0);
                let mut rows = stmt.query([&begin, &end]).map_err(into_error)?;

                while let Some(row) = rows.next().map_err(into_error)? {
                    let key = row
                        .get_ref(0)
                        .map_err(into_error)?
                        .as_bytes()
                        .map_err(into_error)?;
                    let value = if values {
                        row.get_ref(1)
                            .map_err(into_error)?
                            .as_bytes()
                            .map_err(into_error)?
                    } else {
                        b""
                    };

                    if !cb(key, value)? {
                        break 'outer;
                    }
                }
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            match conn
                .prepare_cached(&sql.get(subspace).get_value)
                .map_err(into_error)?
                .query_row([&key], |row| row.get::<_, i64>(0))
            {
                Ok(value) => Ok(value),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
                Err(e) => Err(into_error(e)),
            }
        })
        .await
    }
}
