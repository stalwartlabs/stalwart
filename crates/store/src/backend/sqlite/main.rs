/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error, pool::SqliteConnectionManager, sql::SqlStatements};
use crate::{
    backend::worker::{self, Access, BlockingPermits},
    *,
};
use ::registry::schema::structs;
use r2d2::Pool;
use rusqlite::Connection;
use std::path::Path;

const PAGE_SIZE: u32 = 8192;
const CACHE_SIZE_KIB: i64 = -32768;
const MMAP_SIZE: u64 = 256 * 1024 * 1024;
const WAL_AUTOCHECKPOINT: u32 = 8192;
const BUSY_TIMEOUT_MS: u32 = 30000;
const STATEMENT_CACHE_CAPACITY: usize = 256;
const MIN_POOL_CONNECTIONS: u32 = 4;
const MAX_POOL_CONNECTIONS: u32 = 16;
const DEFAULT_DATABASE_FILE: &str = "stalwart.db";

impl SqliteStore {
    pub fn open(config: structs::SqliteStore) -> Result<Store, String> {
        let pool_workers = worker::pool_workers(config.pool_workers);
        let pool_max_connections = config.pool_max_connections.map_or_else(
            || {
                u32::try_from(pool_workers)
                    .unwrap_or(u32::MAX)
                    .clamp(MIN_POOL_CONNECTIONS, MAX_POOL_CONNECTIONS)
            },
            |max| u32::try_from(max).unwrap_or(u32::MAX).max(1),
        );

        let path = Path::new(&config.path);
        let manager = if path.is_dir() {
            SqliteConnectionManager::file(path.join(DEFAULT_DATABASE_FILE))
        } else {
            SqliteConnectionManager::file(path)
        };

        Ok(Store::SQLite(Arc::new(SqliteStore {
            conn_pool: Pool::builder()
                .max_size(pool_max_connections)
                .max_lifetime(None)
                .idle_timeout(None)
                .build(manager.with_init(init_connection))
                .map_err(|err| format!("Failed to build connection pool: {err}"))?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(pool_workers)
                .build()
                .map_err(|err| format!("Failed to build worker pool: {err}"))?,
            blocking: BlockingPermits::new(pool_workers),
            sql: Arc::new(SqlStatements::new()),
        })))
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

    pub(crate) fn spawn_worker<U, V>(&self, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnOnce() -> trc::Result<V> + Send + 'static,
        V: Send + 'static,
    {
        worker::spawn(&self.worker_pool, f)
    }

    pub(crate) fn block<U, V>(&self, access: Access, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        self.blocking.block(access, f)
    }

    pub(crate) fn block_reader<U, V>(&self, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        self.blocking.block(Access::Read, f)
    }

    pub(crate) fn block_writer<U, V>(&self, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        self.blocking.block(Access::Write, f)
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

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/sqlite/main/test_support.rs"]
mod test_support;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/sqlite/main/tests.rs"]
mod tests;
