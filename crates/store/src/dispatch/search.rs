/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;

use crate::{
    SearchStore, Store,
    search::{
        IndexDocument, SearchComparator, SearchField, SearchFilter, SearchOperator, SearchQuery,
        SearchValue,
        split::{SplitFilter, split_filters},
    },
    write::SearchIndex,
};
use std::cmp::Ordering;

impl SearchStore {
    pub async fn query_account(&self, query: SearchQuery) -> trc::Result<Vec<u32>> {
        // Pre-filter by mask
        match query.mask.len().cmp(&1) {
            Ordering::Equal => {
                return Ok(vec![query.mask.min().unwrap()]);
            }
            Ordering::Less => {
                return Ok(vec![]);
            }
            Ordering::Greater => {}
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
                SearchFilter::Operator {
                    field: SearchField::AccountId,
                    op: SearchOperator::Equal,
                    value: SearchValue::Uint(id),
                } => {
                    account_id = *id as u32;
                }
                SearchFilter::DocumentSet(_) => {
                    has_local_filters = true;
                }
                SearchFilter::Operator { .. } => {
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

        if !has_local_filters && query.comparators.iter().all(|c| c.is_external()) {
            return self
                .sub_query(query.index, &query.filters, &query.comparators)
                .await
                .map(|results| {
                    if !results.is_empty() || has_external_filters {
                        results
                            .into_iter()
                            .filter(|id| query.mask.contains(*id))
                            .collect()
                    } else {
                        // Database sort is broken, return masked results
                        query.mask.iter().collect()
                    }
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
                            self.sub_query(query.index, &external, &[])
                                .await?
                                .into_iter()
                                .collect(),
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
                    let mut local = Vec::with_capacity(query.comparators.len());
                    let mut external = Vec::with_capacity(query.comparators.len());
                    let mut external_first = false;
                    for (pos, comparator) in query.comparators.into_iter().enumerate() {
                        if comparator.is_external() {
                            external.push(comparator);
                            if pos == 0 {
                                external_first = true;
                            }
                        } else {
                            local.push(comparator);
                        }
                    }

                    if !external.is_empty() {
                        let mut results = results.results().clone();
                        let filters = vec![
                            SearchFilter::Operator {
                                field: SearchField::AccountId,
                                op: SearchOperator::Equal,
                                value: SearchValue::Uint(account_id as u64),
                            },
                            SearchFilter::Operator {
                                field: SearchField::DocumentId,
                                op: SearchOperator::GreaterEqualThan,
                                value: SearchValue::Uint(results.min().unwrap() as u64),
                            },
                            SearchFilter::Operator {
                                field: SearchField::DocumentId,
                                op: SearchOperator::LowerEqualThan,
                                value: SearchValue::Uint(results.max().unwrap() as u64),
                            },
                        ];

                        let mut ordered_results = Vec::with_capacity(total_results as usize);
                        for ordered_result in
                            self.sub_query(query.index, &filters, &external).await?
                        {
                            if results.remove(ordered_result) {
                                ordered_results.push(ordered_result);
                            }
                        }
                        // Add any remaining results not yet in the index
                        ordered_results.extend(results.into_iter());

                        if local.is_empty() {
                            return Ok(ordered_results);
                        }

                        let comparator = SearchComparator::SortedSet {
                            set: ordered_results
                                .into_iter()
                                .enumerate()
                                .map(|(pos, id)| (id, pos as u32))
                                .collect(),
                            ascending: true,
                        };

                        if external_first {
                            local.insert(0, comparator);
                        } else {
                            local.push(comparator);
                        }
                    }

                    Ok(results.with_comparators(local).into_sorted())
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
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<u32>> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.query(index, filters, sort).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.query(index, filters, sort).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.query(index, filters, sort).await,
                // SPDX-SnippetEnd
                _ => unreachable!(),
            },
            SearchStore::ElasticSearch(store) => store.query(index, filters, sort).await,
            SearchStore::MeiliSearch(store) => store.query(index, filters, sort).await,
        }
    }

    pub async fn query_global(&self, query: SearchQuery) -> trc::Result<Vec<u64>> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => {
                    store
                        .query(query.index, &query.filters, &query.comparators)
                        .await
                }
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => {
                    store
                        .query(query.index, &query.filters, &query.comparators)
                        .await
                }
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => {
                    store
                        .query(query.index, &query.filters, &query.comparators)
                        .await
                }
                // SPDX-SnippetEnd
                store => store.query_global(query).await,
            },
            SearchStore::ElasticSearch(store) => {
                store
                    .query(query.index, &query.filters, &query.comparators)
                    .await
            }
            SearchStore::MeiliSearch(store) => {
                store
                    .query(query.index, &query.filters, &query.comparators)
                    .await
            }
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
}

impl SearchFilter {
    pub fn is_external(&self) -> bool {
        matches!(self, SearchFilter::Operator { .. })
    }
}

impl SearchComparator {
    pub fn is_external(&self) -> bool {
        matches!(self, SearchComparator::Field { .. })
    }
}
