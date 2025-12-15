/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken};
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
    IterateParams, U32_LEN, U64_LEN, ValueKey,
    ahash::AHashSet,
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::{IndexPropertyClass, SearchIndex, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::CalendarNotificationField,
};

pub trait CalendarEventNotificationQuery: Sync + Send {
    fn calendar_event_notification_query(
        &self,
        request: QueryRequest<CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

struct Notification {
    document_id: u32,
    created: u64,
    event_id: u32,
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
                access_token,
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await?;
        let mut notifications = Vec::with_capacity(16);
        let mut document_ids = RoaringBitmap::new();

        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: CalendarNotificationField::CreatedToId.into(),
                            value: 0,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: CalendarNotificationField::CreatedToId.into(),
                            value: u64::MAX,
                        }),
                    },
                )
                .ascending(),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    notifications.push(Notification {
                        document_id,
                        created: key.deserialize_be_u64(key.len() - U32_LEN - U64_LEN)?,
                        event_id: value.deserialize_be_u32(0)?,
                    });
                    document_ids.insert(document_id);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    CalendarEventNotificationFilter::Before(before) => {
                        let before = before.timestamp() as u64;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            notifications
                                .iter()
                                .filter_map(|n| (n.created < before).then_some(n.document_id)),
                        )))
                    }
                    CalendarEventNotificationFilter::After(after) => {
                        let after = after.timestamp() as u64;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            notifications
                                .iter()
                                .filter_map(|n| (n.created > after).then_some(n.document_id)),
                        )))
                    }
                    CalendarEventNotificationFilter::CalendarEventIds(ids) => {
                        let ids = ids
                            .into_valid()
                            .map(|id| id.document_id())
                            .collect::<AHashSet<_>>();
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            notifications
                                .iter()
                                .filter_map(|n| ids.contains(&n.event_id).then_some(n.document_id)),
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
        if !is_ascending {
            notifications.reverse();
        }

        let results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(document_ids)
            .filter()
            .into_bitmap();

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            cache.get_state(false),
            &request,
        );

        if !results.is_empty() {
            let results = results.into_iter().collect::<AHashSet<_>>();
            for notification in notifications {
                if results.contains(&notification.document_id)
                    && !response.add(0, notification.document_id)
                {
                    break;
                }
            }
        }

        response.build()
    }
}
