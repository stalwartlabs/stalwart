/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use calcard::{common::timezone::Tz, jscalendar::JSCalendarDateTime};
use chrono::offset::TimeZone;
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::calendar_event::{self, CalendarEventComparator, CalendarEventFilter},
    request::MaybeInvalid,
};
use nlp::language::Language;
use std::{cmp::Ordering, sync::Arc};
use store::{
    ValueKey, roaring::RoaringBitmap, search::{CalendarSearchField, SearchComparator, SearchFilter, SearchQuery}, write::{AlignedBytes, Archive, SearchIndex}
};
use trc::AddContext;
use types::{
    TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
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
        let default_tz = request.arguments.time_zone.unwrap_or(Tz::UTC);
        let mut filter: Option<TimeRange> = None;

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
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )))
                    }
                    CalendarEventFilter::Uid(uid) => {
                        filters.push(SearchFilter::eq(CalendarSearchField::Uid, uid));
                    }
                    CalendarEventFilter::Text(value) => {
                        let (text, language) =
                            Language::detect(value, self.core.jmap.default_language);
                        filters.push(SearchFilter::Or);
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Title,
                            text.clone(),
                            language,
                        ));
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Description,
                            text.clone(),
                            language,
                        ));
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Location,
                            text.clone(),
                            language,
                        ));
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Owner,
                            text.clone(),
                            language,
                        ));
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Attendee,
                            text,
                            language,
                        ));
                        filters.push(SearchFilter::End);
                    }
                    CalendarEventFilter::Title(title) => {
                        filters.push(SearchFilter::has_text_detect(
                            CalendarSearchField::Title,
                            title,
                            self.core.jmap.default_language,
                        ));
                    }
                    CalendarEventFilter::Description(description) => {
                        filters.push(SearchFilter::has_text_detect(
                            CalendarSearchField::Description,
                            description,
                            self.core.jmap.default_language,
                        ));
                    }
                    CalendarEventFilter::Location(location) => {
                        filters.push(SearchFilter::has_text_detect(
                            CalendarSearchField::Location,
                            location,
                            self.core.jmap.default_language,
                        ));
                    }
                    CalendarEventFilter::Owner(owner) => {
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Owner,
                            owner,
                            Language::None,
                        ));
                    }
                    CalendarEventFilter::Attendee(attendee) => {
                        filters.push(SearchFilter::has_text(
                            CalendarSearchField::Attendee,
                            attendee,
                            Language::None,
                        ));
                    }
                    CalendarEventFilter::After(after) => {
                        /*
                            The end of the event, or any recurrence of the event, in the time zone given
                            as the "timeZone" argument, must be after this date to match the condition.
                        */
                        if let Some(after) = local_timestamp(&after, default_tz) {
                            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                                cache.resources.iter().filter_map(|r| {
                                    r.event_time_range()
                                        .and_then(|(_, end)| (after < end).then_some(r.document_id))
                                }),
                            )));
                        }
                    }
                    CalendarEventFilter::Before(before) => {
                        /*
                            The start of the event, or any recurrence of the event, in the time zone given
                            as the "timeZone" argument, must be before this date to match the condition.
                        */

                        if let Some(before) = local_timestamp(&before, default_tz) {
                            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                                cache.resources.iter().filter_map(|r| {
                                    r.event_time_range().and_then(|(start, _)| {
                                        (before > start).then_some(r.document_id)
                                    })
                                }),
                            )));
                        }
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

        let expand_recurrences = request.arguments.expand_recurrences.unwrap_or(false);
        let comparators = if !expand_recurrences {
            request
                .sort
                .take()
                .unwrap_or_default()
                .into_iter()
                .map(|comparator| match comparator.property {
                    CalendarEventComparator::Start | CalendarEventComparator::RecurrenceId => {
                        Ok(SearchComparator::field(
                            CalendarSearchField::Start,
                            comparator.is_ascending,
                        ))
                    }
                    CalendarEventComparator::Uid => Ok(SearchComparator::field(
                        CalendarSearchField::Uid,
                        comparator.is_ascending,
                    )),
                    CalendarEventComparator::Created | CalendarEventComparator::Updated => {
                        Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(comparator.property.into_string().into_owned()))
                    }
                    CalendarEventComparator::_T(other) => Err(trc::JmapEvent::UnsupportedSort
                        .into_err()
                        .details(other.to_string())),
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };

        let results = self
            .search_store()
            .query_account(
                SearchQuery::new(SearchIndex::Calendar)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_account_id(account_id)
                    .with_mask(if access_token.is_shared(account_id) {
                        cache.shared_items(access_token, [Acl::ReadItems], true)
                    } else {
                        cache.document_ids(false).collect()
                    }),
            )
            .await?;

        // Extract comparators
        let comparators = request
            .sort
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or_default();

        if expand_recurrences && !results.is_empty() {
            let Some(time_range) = filter.filter(|f| f.start != i64::MIN && f.end != i64::MAX)
            else {
                return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                    "Both 'after' and 'before' filters are required when expanding recurrences",
                ));
            };
            let max_instances = self.core.groupware.max_ical_instances;
            let mut expanded_results = Vec::with_capacity(results.len() as usize);
            let has_uid_comparator = comparators
                .iter()
                .any(|c| matches!(c.property, CalendarEventComparator::Uid));

            for document_id in results {
                let Some(_calendar_event) = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                    ))
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
                    if expanded_results.len() < max_instances {
                        expanded_results.push(SearchResult {
                            created: calendar_event.created.to_native().to_be_bytes(),
                            updated: calendar_event.modified.to_native().to_be_bytes(),
                            start: expansion.start.to_be_bytes(),
                            uid: uid.clone(),
                            document_id,
                            expansion_id: expansion.expansion_id.into(),
                        });
                    } else {
                        return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                            "The number of expanded recurrences exceeds the server limit",
                        ));
                    }
                }
            }

            let mut response = QueryResponseBuilder::new(
                expanded_results.len(),
                self.core.jmap.query_max_results,
                cache.get_state(false),
                &request,
            );
            // Sort results
            if !expanded_results.is_empty() {
                expanded_results.sort_by(|a, b| {
                    for comparator in comparators {
                        let ordering = if comparator.is_ascending {
                            a.get_property(&comparator.property)
                                .cmp(b.get_property(&comparator.property))
                        } else {
                            b.get_property(&comparator.property)
                                .cmp(a.get_property(&comparator.property))
                        };

                        if ordering != Ordering::Equal {
                            return ordering;
                        }
                    }
                    Ordering::Equal
                });

                // Add results
                for result in expanded_results {
                    if !response.add(result.expansion_id.unwrap() + 1, result.document_id) {
                        break;
                    }
                }
            }
            response.build()
        } else {
            let mut response = QueryResponseBuilder::new(
                results.len(),
                self.core.jmap.query_max_results,
                cache.get_state(false),
                &request,
            );
            for document_id in results {
                if !response.add(0, document_id) {
                    break;
                }
            }
            response.build()
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
    expansion_id: Option<u32>,
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
