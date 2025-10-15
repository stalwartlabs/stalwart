/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, UpdateResults, changes::state::JmapCacheState};
use calcard::{common::timezone::Tz, jscalendar::JSCalendarDateTime};
use chrono::offset::TimeZone;
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::calendar_event::{self, CalendarEventComparator, CalendarEventFilter},
    request::MaybeInvalid,
};
use nlp::tokenizers::word::WordTokenizer;
use std::{cmp::Ordering, sync::Arc};
use store::{backend::MAX_TOKEN_LENGTH, query, roaring::RoaringBitmap};
use trc::AddContext;
use types::{
    TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarField,
};

pub trait CalendarEventQuery: Sync + Send {
    fn calendar_event_query(
        &self,
        request: QueryRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl CalendarEventQuery for Server {
    async fn calendar_event_query(
        &self,
        mut request: QueryRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let filter_mask = (access_token.is_shared(account_id))
            .then(|| cache.shared_items(access_token, [Acl::ReadItems], true));
        let default_tz = request.arguments.time_zone.unwrap_or(Tz::UTC);
        let expand_recurrences = request.arguments.expand_recurrences.unwrap_or(false);
        let mut filter: Option<TimeRange> = None;
        let mut did_filter_by_time = false;

        // Extract from/to arguments
        for cond in &request.filter {
            if let Filter::Property(CalendarEventFilter::After(date)) = cond {
                if let Some(after) = local_timestamp(date, default_tz) {
                    filter.get_or_insert_default().start = after;
                }
            } else if let Filter::Property(CalendarEventFilter::Before(date)) = cond
                && let Some(before) = local_timestamp(date, default_tz)
            {
                filter.get_or_insert_default().end = before;
            }
        }

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    CalendarEventFilter::InCalendar(MaybeInvalid::Value(id)) => {
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )))
                    }
                    CalendarEventFilter::Uid(uid) => {
                        filters.push(query::Filter::eq(CalendarField::Uid, uid.into_bytes()))
                    }
                    CalendarEventFilter::Text(value) => {
                        for token in WordTokenizer::new(&value, MAX_TOKEN_LENGTH) {
                            filters.push(query::Filter::eq(
                                CalendarField::Text,
                                token.word.into_owned().into_bytes(),
                            ));
                        }
                    }
                    CalendarEventFilter::After(_) | CalendarEventFilter::Before(_) => {
                        if let Some(filter) = &filter
                            && !did_filter_by_time
                        {
                            filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
                                cache.resources.iter().filter_map(|r| {
                                    r.event_time_range().and_then(|(start, end)| {
                                        filter
                                            .is_in_range(false, start, end)
                                            .then_some(r.document_id)
                                    })
                                }),
                            )));
                            did_filter_by_time = true;
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

        let mut result_set = self
            .filter(account_id, Collection::CalendarEvent, filters)
            .await?;

        if let Some(filter_mask) = filter_mask {
            result_set.apply_mask(filter_mask);
        }

        let num_results = result_set.results.len() as usize;
        if num_results > 0 {
            // Extract comparators
            let comparators = request
                .sort
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or_default();
            if expand_recurrences {
                let Some(time_range) = filter.filter(|f| f.start != i64::MIN && f.end != i64::MAX)
                else {
                    return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                        "Both 'after' and 'before' filters are required when expanding recurrences",
                    ));
                };
                let max_instances = self.core.groupware.max_ical_instances;
                let mut results = Vec::with_capacity(result_set.results.len() as usize);
                let has_uid_comparator = comparators
                    .iter()
                    .any(|c| matches!(c.property, CalendarEventComparator::Uid));

                for document_id in result_set.results {
                    let Some(_calendar_event) = self
                        .get_archive(account_id, Collection::CalendarEvent, document_id)
                        .await?
                    else {
                        continue;
                    };
                    let calendar_event = _calendar_event
                        .unarchive::<CalendarEvent>()
                        .caused_by(trc::location!())?;

                    // Expand recurrences
                    let uid = if has_uid_comparator {
                        Arc::new(
                            calendar_event
                                .data
                                .event
                                .uids()
                                .next()
                                .unwrap_or_default()
                                .to_string(),
                        )
                    } else {
                        Arc::new(String::new())
                    };
                    for expansion in calendar_event
                        .data
                        .expand(default_tz, time_range)
                        .unwrap_or_default()
                    {
                        if results.len() < max_instances {
                            results.push(SearchResult {
                                created: calendar_event.created.to_native().to_be_bytes(),
                                updated: calendar_event.modified.to_native().to_be_bytes(),
                                start: expansion.start.to_be_bytes(),
                                uid: uid.clone(),
                                document_id,
                                expansion_id: expansion.expansion_id,
                            });
                        } else {
                            return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                                "The number of expanded recurrences exceeds the server limit",
                            ));
                        }
                    }
                }

                // Sort results
                if !results.is_empty() {
                    results.sort_by(|a, b| {
                        for comparator in comparators {
                            let ordering = a
                                .get_property(&comparator.property)
                                .cmp(b.get_property(&comparator.property));

                            let ordering = if comparator.is_ascending {
                                ordering.reverse()
                            } else {
                                ordering
                            };

                            if ordering != Ordering::Equal {
                                return ordering;
                            }
                        }
                        Ordering::Equal
                    });
                }

                // Add results
                let (mut response, paginate) = self
                    .build_query_response(results.len(), cache.get_state(false), &request)
                    .await?;
                if let Some(mut paginate) = paginate {
                    for result in results {
                        if !paginate.add(result.expansion_id + 1, result.document_id) {
                            break;
                        }
                    }
                    response.update_results(paginate.build())?;
                }

                Ok(response)
            } else {
                let mut comparators_ = Vec::with_capacity(comparators.len());

                for comparator in comparators {
                    comparators_.push(match &comparator.property {
                        CalendarEventComparator::Uid => {
                            query::Comparator::field(CalendarField::Uid, comparator.is_ascending)
                        }
                        CalendarEventComparator::Start => {
                            query::Comparator::field(CalendarField::Start, comparator.is_ascending)
                        }
                        CalendarEventComparator::Created => query::Comparator::field(
                            CalendarField::Created,
                            comparator.is_ascending,
                        ),
                        CalendarEventComparator::Updated => query::Comparator::field(
                            CalendarField::Updated,
                            comparator.is_ascending,
                        ),
                        unsupported => {
                            return Err(trc::JmapEvent::UnsupportedSort
                                .into_err()
                                .details(unsupported.clone().into_string()));
                        }
                    });
                }

                // Sort results
                let (response, paginate) = self
                    .build_query_response(num_results, cache.get_state(false), &request)
                    .await?;
                if let Some(paginate) = paginate {
                    self.sort(result_set, comparators_, paginate, response)
                        .await
                } else {
                    Ok(response)
                }
            }
        } else {
            let (response, _) = self
                .build_query_response(
                    result_set.results.len() as usize,
                    cache.get_state(false),
                    &request,
                )
                .await?;

            Ok(response)
        }
    }
}

fn local_timestamp(dt: &JSCalendarDateTime, tz: Tz) -> Option<i64> {
    tz.from_local_datetime(&dt.to_naive_date_time()?)
        .single()
        .map(|dt| dt.timestamp())
}

#[derive(Debug)]
struct SearchResult {
    expansion_id: u32,
    document_id: u32,
    start: [u8; std::mem::size_of::<i64>()],
    created: [u8; std::mem::size_of::<i64>()],
    updated: [u8; std::mem::size_of::<i64>()],
    uid: Arc<String>,
}

impl SearchResult {
    fn get_property(&self, comparator: &CalendarEventComparator) -> &[u8] {
        match comparator {
            CalendarEventComparator::Uid => self.uid.as_bytes(),
            CalendarEventComparator::Start | CalendarEventComparator::RecurrenceId => {
                self.start.as_ref()
            }
            CalendarEventComparator::Created => self.created.as_ref(),
            CalendarEventComparator::Updated => self.updated.as_ref(),
            CalendarEventComparator::_T(_) => &[],
        }
    }
}
