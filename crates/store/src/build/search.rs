/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SearchStore,
    backend::{elastic::ElasticSearchStore, meili::MeiliSearchStore},
    registry::bootstrap::Bootstrap,
};
use registry::schema::{prelude::Object, structs};

#[allow(unreachable_patterns)]
impl SearchStore {
    pub async fn build(bp: &mut Bootstrap) -> Option<Self> {
        let result = match bp.setting_infallible::<structs::SearchStore>().await {
            structs::SearchStore::Default => {
                return Some(SearchStore::Store(bp.data_store.clone()));
            }
            structs::SearchStore::ElasticSearch(elastic_search_store) => {
                ElasticSearchStore::open(elastic_search_store).await
            }
            structs::SearchStore::Meilisearch(meilisearch_store) => {
                MeiliSearchStore::open(meilisearch_store).await
            }
            #[cfg(feature = "foundation")]
            structs::SearchStore::FoundationDb(foundation_db_store) => {
                crate::backend::foundationdb::FdbStore::open(foundation_db_store)
                    .await
                    .map(SearchStore::Store)
            }
            #[cfg(feature = "postgres")]
            structs::SearchStore::PostgreSql(postgre_sql_store) => {
                crate::backend::postgres::PostgresStore::open(postgre_sql_store)
                    .await
                    .map(SearchStore::Store)
            }
            #[cfg(feature = "mysql")]
            structs::SearchStore::MySql(my_sql_store) => {
                crate::backend::mysql::MysqlStore::open(my_sql_store)
                    .await
                    .map(SearchStore::Store)
            }
            _ => Err("Binary was not compiled with the selected search store backend".to_string()),
        };

        match result {
            Ok(store) => Some(store),
            Err(err) => {
                bp.build_error(Object::SearchStore.singleton(), err);
                None
            }
        }
    }
}
