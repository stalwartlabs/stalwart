/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::calendar_event_notification::{
        CalendarEventNotification, CalendarEventNotificationComparator,
        CalendarEventNotificationFilter,
    },
    request::IntoValid,
};
use store::{SerializeInfallible, query};
use types::{
    collection::{Collection, SyncCollection},
    field::CalendarField,
};

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
                access_token,
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    CalendarEventNotificationFilter::Before(before) => {
                        filters.push(query::Filter::lt(
                            CalendarField::Created,
                            (before.timestamp() as u64).serialize(),
                        ))
                    }
                    CalendarEventNotificationFilter::After(after) => {
                        filters.push(query::Filter::gt(
                            CalendarField::Created,
                            (after.timestamp() as u64).serialize(),
                        ))
                    }
                    CalendarEventNotificationFilter::CalendarEventIds(ids) => {
                        let has_many = ids.len() > 1;
                        if has_many {
                            filters.push(query::Filter::Or);
                        }
                        for id in ids.into_valid() {
                            filters.push(query::Filter::eq(
                                CalendarField::EventId,
                                id.document_id().serialize(),
                            ));
                        }
                        if has_many {
                            filters.push(query::Filter::End);
                        }
                    }
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(unsupported.into_string()));
                    }
                },

                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
            }
        }

        let result_set = self
            .filter(account_id, Collection::CalendarEventNotification, filters)
            .await?;

        let (response, paginate) = self
            .build_query_response(
                result_set.results.len() as usize,
                cache.get_state(false),
                &request,
            )
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request.sort.filter(|s| !s.is_empty()).unwrap_or_else(|| {
                vec![Comparator::descending(
                    CalendarEventNotificationComparator::Created,
                )]
            }) {
                comparators.push(match comparator.property {
                    CalendarEventNotificationComparator::Created => {
                        query::Comparator::field(CalendarField::Created, comparator.is_ascending)
                    }
                    CalendarEventNotificationComparator::_T(unsupported) => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(unsupported));
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
