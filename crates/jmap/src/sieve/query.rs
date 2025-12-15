/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::StateManager};
use common::Server;
use email::sieve::ingest::SieveScriptIngest;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::sieve::{Sieve, SieveComparator, SieveFilter},
};
use std::future::Future;
use store::{
    IndexKeyPrefix, IterateParams, U32_LEN,
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::{SearchIndex, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::SieveField,
};

pub trait SieveScriptQuery: Sync + Send {
    fn sieve_script_query(
        &self,
        request: QueryRequest<Sieve>,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl SieveScriptQuery for Server {
    async fn sieve_script_query(
        &self,
        mut request: QueryRequest<Sieve>,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let active_script_id = if request
            .filter
            .iter()
            .any(|f| matches!(f, Filter::Property(SieveFilter::IsActive(_))))
            || request.sort.as_ref().is_some_and(|s| {
                s.iter()
                    .any(|c| matches!(c.property, SieveComparator::IsActive))
            }) {
            self.sieve_script_get_active_id(account_id).await?
        } else {
            None
        };

        let mut document_ids = RoaringBitmap::new();
        let mut names = Vec::new();
        self.store()
            .iterate(
                IterateParams::new(
                    IndexKeyPrefix {
                        account_id,
                        collection: Collection::SieveScript.into(),
                        field: SieveField::Name.into(),
                    },
                    IndexKeyPrefix {
                        account_id,
                        collection: Collection::SieveScript.into(),
                        field: u8::from(SieveField::Name) + 1,
                    },
                )
                .no_values(),
                |key, _| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;

                    names.push((
                        document_id,
                        key.get(IndexKeyPrefix::len()..key.len() - U32_LEN)
                            .and_then(|v| std::str::from_utf8(v).ok())
                            .unwrap_or_default()
                            .to_string(),
                    ));

                    document_ids.insert(document_id);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    SieveFilter::Name(name) => {
                        let name = name.to_lowercase();

                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            names
                                .iter()
                                .filter_map(|(id, n)| (n.contains(&name)).then_some(*id))
                                .collect::<Vec<_>>(),
                        )));
                    }
                    SieveFilter::IsActive(is_active) => {
                        if is_active {
                            if let Some(active_script_id) = active_script_id {
                                filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter([
                                    active_script_id,
                                ])));
                            } else {
                                // No active script, so no results
                                filters.push(SearchFilter::is_in_set(RoaringBitmap::new()));
                            }
                        } else {
                            let mut inactive_set = document_ids.clone();
                            if let Some(active_script_id) = active_script_id {
                                inactive_set.remove(active_script_id);
                            }
                            filters.push(SearchFilter::is_in_set(inactive_set));
                        }
                    }
                    SieveFilter::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedFilter.into_err().details(other));
                    }
                },
                Filter::And => {
                    filters.push(SearchFilter::And);
                }
                Filter::Or => {
                    filters.push(SearchFilter::Or);
                }
                Filter::Not => {
                    filters.push(SearchFilter::Not);
                }
                Filter::Close => {
                    filters.push(SearchFilter::End);
                }
            }
        }

        // Parse sort criteria
        let mut sort_by_active = None;
        for comparator in request
            .sort
            .take()
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
        {
            match comparator.property {
                SieveComparator::Name => {
                    if !comparator.is_ascending {
                        names.reverse();
                    }
                }
                SieveComparator::IsActive => {
                    sort_by_active = Some(comparator.is_ascending);
                }
                SieveComparator::_T(other) => {
                    return Err(trc::JmapEvent::UnsupportedSort.into_err().details(other));
                }
            };
        }

        let mut results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(document_ids)
            .filter()
            .into_bitmap();

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            self.get_state(account_id, SyncCollection::SieveScript)
                .await?,
            &request,
        );

        if !results.is_empty() {
            if matches!(sort_by_active, Some(true))
                && results.remove(active_script_id.unwrap_or_default())
                && !response.add(0, active_script_id.unwrap())
            {
                return response.build();
            }

            let mut last_id = None;
            for (document_id, _) in names {
                if results.contains(document_id) {
                    if sort_by_active.is_some() && Some(document_id) == active_script_id {
                        last_id = Some(document_id);
                    } else if !response.add(0, document_id) {
                        return response.build();
                    }
                }
            }

            if let Some(active_id) = last_id {
                response.add(0, active_id);
            }
        }

        response.build()
    }
}
