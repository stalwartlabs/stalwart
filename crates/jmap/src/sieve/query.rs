/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::StateManager};
use common::Server;
use email::sieve::ingest::SieveScriptIngest;
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::sieve::{Sieve, SieveComparator, SieveFilter},
};
use std::future::Future;
use store::{
    query::{self},
    roaring::RoaringBitmap,
};
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

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    SieveFilter::Name(name) => {
                        filters.push(query::Filter::contains(SieveField::Name, &name))
                    }
                    SieveFilter::IsActive(is_active) => {
                        if !is_active {
                            filters.push(query::Filter::Not);
                        }
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
                            active_script_id,
                        )));
                        if !is_active {
                            filters.push(query::Filter::End);
                        }
                    }
                    SieveFilter::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedFilter.into_err().details(other));
                    }
                },

                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
            }
        }

        let result_set = self
            .filter(account_id, Collection::SieveScript, filters)
            .await?;

        let (response, paginate) = self
            .build_query_response(
                result_set.results.len() as usize,
                self.get_state(account_id, SyncCollection::SieveScript)
                    .await?,
                &request,
            )
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| vec![Comparator::descending(SieveComparator::Name)])
            {
                comparators.push(match comparator.property {
                    SieveComparator::Name => {
                        query::Comparator::field(SieveField::Name, comparator.is_ascending)
                    }
                    SieveComparator::IsActive => query::Comparator::set(
                        RoaringBitmap::from_iter(active_script_id),
                        comparator.is_ascending,
                    ),
                    SieveComparator::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedSort.into_err().details(other));
                    }
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }
    }
}
