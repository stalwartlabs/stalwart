/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error, pool::SqliteConnectionManager};
use crate::*;
use ::registry::schema::structs;
use r2d2::Pool;
use tokio::sync::oneshot;

impl SqliteStore {
    pub fn open(config: structs::SqliteStore) -> Result<Store, String> {
        Ok(Store::SQLite(Arc::new(SqliteStore {
            conn_pool: Pool::builder()
                .max_size(config.pool_max_connections as u32)
                .build(SqliteConnectionManager::file(&config.path).with_init(|c| {
                    c.execute_batch(concat!(
                        "PRAGMA journal_mode = WAL; ",
                        "PRAGMA synchronous = NORMAL; ",
                        "PRAGMA temp_store = memory;",
                        "PRAGMA busy_timeout = 30000;"
                    ))
                }))
                .map_err(|err| format!("Failed to build connection pool: {err}"))?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .pool_workers
                        .filter(|v| *v > 0)
                        .map(|v| v as usize)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| format!("Failed to build worker pool: {err}"))?,
        })))
    }

    #[cfg(feature = "test_mode")]
    pub fn open_memory() -> trc::Result<Self> {
        use super::into_error;

        let db = Self {
            conn_pool: Pool::builder()
                .max_size(1)
                .build(SqliteConnectionManager::memory())
                .map_err(into_error)?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .map_err(|err| {
                    into_error(err).ctx(trc::Key::Reason, "Failed to build worker pool")
                })?,
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(crate) fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_BLOB_EXTRA,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_REGISTRY,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_SEARCH_INDEX,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY,
                        v BLOB NOT NULL
                    )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        let table = char::from(SUBSPACE_INDEXES);
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY
                )"
            ),
            [],
        )
        .map_err(into_error)?;

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA, SUBSPACE_IN_MEMORY_COUNTER] {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                    k BLOB PRIMARY KEY,
                    v INTEGER NOT NULL DEFAULT 0
                )",
                    char::from(table)
                ),
                [],
            )
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.scope(|s| {
            s.spawn(|_| {
                tx.send(f()).ok();
            });
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)),
        }
    }
}
