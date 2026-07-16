/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SearchStore, Store,
    search::{
        IndexDocument, QueryResults, SearchFilter, SearchQuery,
        split::{SplitFilter, split_filters},
    },
    write::SearchIndex,
};
use roaring::{RoaringBitmap, RoaringTreemap};
use std::cmp::Ordering;
use trc::AddContext;

impl SearchStore {
    pub async fn query_account(&self, query: SearchQuery) -> trc::Result<Vec<u32>> {
        // Pre-filter by mask
        if query.mask.is_empty() {
            return Ok(vec![]);
        }

        // If the store does not support FTS, use the internal FTS store
        if let Some(store) = self.internal_fts() {
            return store.query_account(query).await;
        }

        // If all filters and comparators are external, delegate to the underlying store
        let mut account_id = u32::MAX;
        let mut has_local_filters = false;
        let mut has_external_filters = false;
        for filter in &query.filters {
            match filter {
                SearchFilter::Integer { value, .. } => {
                    account_id = *value as u32;
                }
                SearchFilter::DocumentSet(_) => {
                    has_local_filters = true;
                }
                SearchFilter::Text { .. } => {
                    has_external_filters = true;
                }
                _ => (),
            }
        }

        if account_id == u32::MAX {
            return Err(trc::StoreEvent::UnexpectedError
                .reason("Account ID filter is required for account queries")
                .caused_by(trc::location!()));
        }

        if !has_local_filters && !has_external_filters && query.comparators.is_empty() {
            return Ok(query.mask.iter().collect());
        }

        if !has_local_filters {
            return self
                .sub_query(query.index, &query.filters)
                .await
                .map(|results| {
                    QueryResults::new(results & query.mask, query.comparators).into_sorted()
                })
                .caused_by(trc::location!());
        }

        let filters = if has_external_filters {
            // Split filters
            let split_filters = split_filters(query.filters).ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .reason("Invalid filter query")
                    .caused_by(trc::location!())
            })?;

            let mut filters = Vec::with_capacity(split_filters.len());
            for split_filter in split_filters {
                match split_filter {
                    SplitFilter::External(external) => {
                        // Execute sub-query
                        filters.push(SearchFilter::DocumentSet(
                            self.sub_query(query.index, &external).await?,
                        ));
                    }
                    SplitFilter::Internal(filter) => {
                        filters.push(filter);
                    }
                }
            }

            filters
        } else {
            query.filters
        };

        // Merge results locally
        let results = SearchQuery::new(query.index)
            .with_filters(filters)
            .with_mask(query.mask)
            .filter();

        let total_results = results.results().len();
        match total_results.cmp(&1) {
            Ordering::Equal => Ok(vec![results.results().min().unwrap()]),
            Ordering::Less => Ok(vec![]),
            Ordering::Greater => {
                if !query.comparators.is_empty() {
                    Ok(results.with_comparators(query.comparators).into_sorted())
                } else {
                    Ok(results.results().iter().collect())
                }
            }
        }
    }

    async fn sub_query(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
    ) -> trc::Result<RoaringBitmap> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.query(index, filters).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.query(index, filters).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.query(index, filters).await,
                // SPDX-SnippetEnd
                _ => unreachable!(),
            },
            SearchStore::ElasticSearch(store) => store.query(index, filters).await,
            SearchStore::MeiliSearch(store) => store.query(index, filters).await,
        }
    }

    pub async fn query_global(&self, query: SearchQuery) -> trc::Result<RoaringTreemap> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.query(query.index, &query.filters).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.query(query.index, &query.filters).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.query(query.index, &query.filters).await,
                // SPDX-SnippetEnd
                store => store.query_global(query).await,
            },
            SearchStore::ElasticSearch(store) => store.query(query.index, &query.filters).await,
            SearchStore::MeiliSearch(store) => store.query(query.index, &query.filters).await,
        }
    }

    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.index(documents).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.index(documents).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.index(documents).await,
                // SPDX-SnippetEnd
                store => store.index(documents).await,
            },
            SearchStore::ElasticSearch(store) => store.index(documents).await,
            SearchStore::MeiliSearch(store) => store.index(documents).await,
        }
    }

    pub async fn unindex(&self, query: SearchQuery) -> trc::Result<u64> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.unindex(query).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.unindex(query).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.unindex(query).await,
                // SPDX-SnippetEnd
                store => store.unindex(query).await.map(|_| 0),
            },
            SearchStore::ElasticSearch(store) => store.unindex(query).await,
            SearchStore::MeiliSearch(store) => store.unindex(query).await,
        }
    }

    pub fn internal_fts(&self) -> Option<&Store> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(_) => None,
                #[cfg(feature = "mysql")]
                Store::MySQL(_) => None,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(_) => None,
                // SPDX-SnippetEnd
                store => Some(store),
            },
            _ => None,
        }
    }

    pub fn is_mysql(&self) -> bool {
        match self {
            #[cfg(feature = "mysql")]
            SearchStore::Store(Store::MySQL(_)) => true,
            _ => false,
        }
    }

    pub fn is_postgres(&self) -> bool {
        match self {
            #[cfg(feature = "postgres")]
            SearchStore::Store(Store::PostgreSQL(_)) => true,
            _ => false,
        }
    }

    pub fn is_elasticsearch(&self) -> bool {
        matches!(self, SearchStore::ElasticSearch(_))
    }

    pub fn is_meilisearch(&self) -> bool {
        matches!(self, SearchStore::MeiliSearch(_))
    }

    pub async fn create_indexes(&self) -> trc::Result<()> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.create_search_tables().await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.create_search_tables().await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => match store.primary_store() {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(primary) => primary.create_search_tables().await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(primary) => primary.create_search_tables().await,
                    _ => Ok(()),
                },
                // SPDX-SnippetEnd
                _ => Ok(()),
            },
            SearchStore::ElasticSearch(store) => store.create_indexes().await,
            SearchStore::MeiliSearch(store) => store.create_indexes().await,
        }
    }
}

impl SearchFilter {
    pub fn is_external(&self) -> bool {
        matches!(self, SearchFilter::Text { .. })
    }
}
