/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Store;
use registry::schema::structs::DataStore;

impl Store {
    pub async fn build(config: DataStore) -> Result<Self, String> {
        #[allow(unreachable_patterns)]
        match config {
            #[cfg(feature = "rocks")]
            DataStore::RocksDb(store) => crate::backend::rocksdb::RocksDbStore::open(store).await,
            #[cfg(feature = "foundation")]
            DataStore::FoundationDb(store) => {
                crate::backend::foundationdb::FdbStore::open(store).await
            }
            #[cfg(feature = "postgres")]
            DataStore::PostgreSql(store) => {
                crate::backend::postgres::PostgresStore::open(store).await
            }
            #[cfg(feature = "mysql")]
            DataStore::MySql(store) => crate::backend::mysql::MysqlStore::open(store).await,
            #[cfg(feature = "sqlite")]
            DataStore::Sqlite(store) => crate::backend::sqlite::SqliteStore::open(store),
            _ => Err("Binary was not compiled with the selected data store backend".to_string()),
        }
    }
}
