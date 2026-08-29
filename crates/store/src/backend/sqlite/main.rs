/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error, pool::SqliteConnectionManager, sql::SqlStatements};
use crate::{backend::worker, *};
use ::registry::schema::structs;
use r2d2::Pool;
use rusqlite::Connection;

const PAGE_SIZE: u32 = 8192;
const CACHE_SIZE_KIB: i64 = -32768;
const MMAP_SIZE: u64 = 256 * 1024 * 1024;
const WAL_AUTOCHECKPOINT: u32 = 8192;
const BUSY_TIMEOUT_MS: u32 = 30000;
const STATEMENT_CACHE_CAPACITY: usize = 256;

impl SqliteStore {
    pub fn open(config: structs::SqliteStore) -> Result<Store, String> {
        Ok(Store::SQLite(Arc::new(SqliteStore {
            conn_pool: Pool::builder()
                .max_size(std::cmp::max(config.pool_max_connections as u32, 1))
                .max_lifetime(None)
                .idle_timeout(None)
                .build(SqliteConnectionManager::file(&config.path).with_init(init_connection))
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
            sql: Arc::new(SqlStatements::new()),
        })))
    }

    #[cfg(feature = "test_mode")]
    pub fn open_memory() -> trc::Result<Self> {
        use super::into_error;

        let db = Self {
            conn_pool: Pool::builder()
                .max_size(1)
                .max_lifetime(None)
                .idle_timeout(None)
                .build(SqliteConnectionManager::memory().with_init(init_connection))
                .map_err(into_error)?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .map_err(|err| {
                    into_error(err).ctx(trc::Key::Reason, "Failed to build worker pool")
                })?,
            sql: Arc::new(SqlStatements::new()),
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(crate) fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        for subspace in Subspace::ALL.iter().copied() {
            let table = subspace.name();
            let columns = match subspace.shape() {
                Shape::Value => "k BLOB PRIMARY KEY, v BLOB NOT NULL",
                Shape::Presence => "k BLOB PRIMARY KEY",
                Shape::Counter => "k BLOB PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0",
            };

            conn.execute(
                &format!("CREATE TABLE IF NOT EXISTS {table} ({columns})"),
                [],
            )
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn spawn_worker<U, V>(&self, f: U) -> trc::Result<V>
    where
        U: FnOnce() -> trc::Result<V> + Send + 'static,
        V: Send + 'static,
    {
        worker::spawn(&self.worker_pool, f).await
    }

    pub(crate) async fn block_worker<U, V>(&self, f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        worker::block(f)
    }
}

fn init_connection(conn: &mut Connection) -> Result<(), rusqlite::Error> {
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    conn.execute_batch(&format!(
        concat!(
            "PRAGMA page_size = {}; ",
            "PRAGMA journal_mode = WAL; ",
            "PRAGMA synchronous = NORMAL; ",
            "PRAGMA cache_size = {}; ",
            "PRAGMA mmap_size = {}; ",
            "PRAGMA temp_store = memory; ",
            "PRAGMA busy_timeout = {}; ",
            "PRAGMA wal_autocheckpoint = {};"
        ),
        PAGE_SIZE, CACHE_SIZE_KIB, MMAP_SIZE, BUSY_TIMEOUT_MS, WAL_AUTOCHECKPOINT
    ))?;

    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        conn.execute_batch("PRAGMA synchronous = FULL;")?;
    }

    Ok(())
}
