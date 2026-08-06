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
use registry::schema::{prelude::ObjectType, structs};

#[allow(unreachable_patterns)]
impl SearchStore {
    pub async fn build(bp: &mut Bootstrap) -> Option<Self> {
        let result = match bp.setting_infallible::<structs::SearchStore>().await {
            structs::SearchStore::Default => {
                return Some(match bp.data_store.clone() {
                    #[cfg(feature = "postgres")]
                    crate::Store::PostgreSQL(store) => SearchStore::PostgreSQL(store),
                    #[cfg(feature = "mysql")]
                    crate::Store::MySQL(store) => SearchStore::MySQL(store),
                    #[cfg(all(
                        feature = "enterprise",
                        any(feature = "postgres", feature = "mysql")
                    ))]
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    crate::Store::SQLReadReplica(store) => SearchStore::SQLReadReplica(store),
                    // SPDX-SnippetEnd
                    store => SearchStore::Store(store),
                });
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
                    .map(|store| match store {
                        crate::Store::PostgreSQL(store) => SearchStore::PostgreSQL(store),
                        // SPDX-SnippetBegin
                        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                        // SPDX-License-Identifier: LicenseRef-SEL
                        #[cfg(feature = "enterprise")]
                        crate::Store::SQLReadReplica(store) => SearchStore::SQLReadReplica(store),
                        // SPDX-SnippetEnd
                        _ => unreachable!(),
                    })
            }
            #[cfg(feature = "mysql")]
            structs::SearchStore::MySql(my_sql_store) => {
                crate::backend::mysql::MysqlStore::open(my_sql_store)
                    .await
                    .map(|store| match store {
                        crate::Store::MySQL(store) => SearchStore::MySQL(store),
                        // SPDX-SnippetBegin
                        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                        // SPDX-License-Identifier: LicenseRef-SEL
                        #[cfg(feature = "enterprise")]
                        crate::Store::SQLReadReplica(store) => SearchStore::SQLReadReplica(store),
                        // SPDX-SnippetEnd
                        _ => unreachable!(),
                    })
            }
            _ => Err("Binary was not compiled with the selected search store backend".to_string()),
        };

        match result {
            Ok(store) => Some(store),
            Err(err) => {
                bp.build_error(ObjectType::SearchStore.singleton(), err);
                None
            }
        }
    }
}
