/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Store, registry::bootstrap::Bootstrap};
use registry::schema::{
    prelude::ObjectType,
    structs::{DataStore, MetricsStore, TracingStore},
};

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

    pub async fn build_tracing(bp: &mut Bootstrap) -> Option<Self> {
        let result = match bp.setting_infallible::<TracingStore>().await {
            TracingStore::Disabled => Ok(None),
            TracingStore::Default => Ok(Some(bp.data_store.clone())),
            #[cfg(feature = "foundation")]
            TracingStore::FoundationDb(store) => {
                crate::backend::foundationdb::FdbStore::open(store)
                    .await
                    .map(Some)
            }
            #[cfg(feature = "postgres")]
            TracingStore::PostgreSql(store) => crate::backend::postgres::PostgresStore::open(store)
                .await
                .map(Some),
            #[cfg(feature = "mysql")]
            TracingStore::MySql(store) => crate::backend::mysql::MysqlStore::open(store)
                .await
                .map(Some),
            _ => Err("Binary was not compiled with the selected tracing store backend".to_string()),
        };

        match result {
            Ok(store) => store,
            Err(err) => {
                bp.build_warning(ObjectType::TracingStore.singleton(), err);
                None
            }
        }
    }

    pub async fn build_metrics(bp: &mut Bootstrap) -> Option<Self> {
        let result = match bp.setting_infallible::<MetricsStore>().await {
            MetricsStore::Disabled => Ok(None),
            MetricsStore::Default => Ok(Some(bp.data_store.clone())),
            #[cfg(feature = "foundation")]
            MetricsStore::FoundationDb(store) => {
                crate::backend::foundationdb::FdbStore::open(store)
                    .await
                    .map(Some)
            }
            #[cfg(feature = "postgres")]
            MetricsStore::PostgreSql(store) => crate::backend::postgres::PostgresStore::open(store)
                .await
                .map(Some),
            #[cfg(feature = "mysql")]
            MetricsStore::MySql(store) => crate::backend::mysql::MysqlStore::open(store)
                .await
                .map(Some),
            _ => Err("Binary was not compiled with the selected metrics store backend".to_string()),
        };

        match result {
            Ok(store) => store,
            Err(err) => {
                bp.build_warning(ObjectType::MetricsStore.singleton(), err);
                None
            }
        }
    }
}
