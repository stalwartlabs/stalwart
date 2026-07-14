/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{DavResourceMetadata, Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::calendar_event_notification::{
        CalendarEventNotification, CalendarEventNotificationComparator,
        CalendarEventNotificationFilter,
    },
    request::IntoValid,
};
use store::{
    ahash::AHashSet,
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::SearchIndex,
};
use types::collection::SyncCollection;

pub trait CalendarEventNotificationQuery: Sync + Send {
    fn calendar_event_notification_query(
        &self,
        request: QueryRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl CalendarEventNotificationQuery for Server {
    async fn calendar_event_notification_query(
        &self,
        mut request: QueryRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    CalendarEventNotificationFilter::Before(before) => {
                        let before = before.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if let DavResourceMetadata::CalendarEventNotification {
                                    names,
                                    created_at,
                                    ..
                                } = &r.data
                                {
                                    (!names.is_empty() && *created_at < before)
                                        .then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )))
                    }
                    CalendarEventNotificationFilter::After(after) => {
                        let after = after.timestamp();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if let DavResourceMetadata::CalendarEventNotification {
                                    names,
                                    created_at,
                                    ..
                                } = &r.data
                                {
                                    (!names.is_empty() && *created_at > after)
                                        .then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )))
                    }
                    CalendarEventNotificationFilter::CalendarEventIds(ids) => {
                        let ids = ids
                            .into_valid()
                            .map(|id| id.document_id())
                            .collect::<AHashSet<_>>();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if let DavResourceMetadata::CalendarEventNotification {
                                    names,
                                    event_id,
                                    ..
                                } = &r.data
                                {
                                    (!names.is_empty() && ids.contains(event_id))
                                        .then_some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )))
                    }
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(unsupported.into_string()));
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
        let mut is_ascending = true;
        for comparator in request.sort.take().unwrap_or_default() {
            match comparator.property {
                CalendarEventNotificationComparator::Created => {
                    is_ascending = comparator.is_ascending;
                }
                CalendarEventNotificationComparator::_T(unsupported) => {
                    return Err(trc::JmapEvent::UnsupportedSort
                        .into_err()
                        .details(unsupported));
                }
            };
        }
        let results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(cache.document_ids(false).collect())
            .filter()
            .into_bitmap();

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            cache.get_state(false),
            &request,
        );

        if !results.is_empty() {
            let mut notifications = cache
                .resources
                .iter()
                .filter_map(|r| {
                    if let DavResourceMetadata::CalendarEventNotification {
                        names,
                        created_at,
                        ..
                    } = &r.data
                    {
                        (!names.is_empty() && results.contains(r.document_id))
                            .then_some((r.document_id, *created_at))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            notifications
                .sort_unstable_by_key(|(document_id, created_at)| (*created_at, *document_id));
            if !is_ascending {
                notifications.reverse();
            }

            for (document_id, _) in notifications {
                if !response.add(0, document_id) {
                    break;
                }
            }
        }

        response.build()
    }
}
