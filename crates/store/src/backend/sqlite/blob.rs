/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use rusqlite::OptionalExtension;

use super::{SqliteStore, into_error};
use crate::Subspace;

impl SqliteStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let key = key.to_vec();

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            conn.prepare_cached(&sql.get(Subspace::Blobs).get_value)
                .map_err(into_error)?
                .query_row([&key], |row| {
                    Ok({
                        let bytes = row.get_ref(0)?.as_bytes()?;
                        if range.start == 0 && range.end == usize::MAX {
                            bytes.to_vec()
                        } else {
                            bytes
                                .get(range.start..std::cmp::min(bytes.len(), range.end))
                                .unwrap_or_default()
                                .to_vec()
                        }
                    })
                })
                .optional()
                .map_err(into_error)
        })
        .await
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: Vec<u8>) -> trc::Result<()> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let key = key.to_vec();

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            conn.prepare_cached(&sql.get(Subspace::Blobs).upsert_value)
                .map_err(into_error)?
                .execute([key.as_slice(), data.as_slice()])
                .map_err(into_error)
                .map(|_| ())
        })
        .await
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        let manager = self.conn_pool.clone();
        let sql = self.sql.clone();
        let key = key.to_vec();

        self.spawn_worker(move || {
            let conn = manager.get().map_err(into_error)?;
            conn.prepare_cached(&sql.get(Subspace::Blobs).delete_key)
                .map_err(into_error)?
                .execute([key])
                .map_err(into_error)
                .map(|rows| rows > 0)
        })
        .await
    }
}
