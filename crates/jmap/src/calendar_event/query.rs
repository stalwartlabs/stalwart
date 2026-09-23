/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use calcard::{common::timezone::Tz, jscalendar::JSCalendarDateTime};
use common::{GroupwareResources, Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent, EVENT_HIDE_ATTENDEES, EVENT_PRIVATE, EVENT_SECRET,
        expand::MAX_UTC_OFFSET,
        instance_filter::{AttendeeSearch, InstanceTextFilter},
    },
};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::{
        calendar,
        calendar_event::{self, CalendarEventComparator, CalendarEventFilter},
    },
    request::MaybeInvalid,
};
use nlp::language::Language;
use std::cmp::Ordering;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    search::{CalendarSearchField, SearchComparator, SearchField, SearchFilter, SearchQuery},
    write::{Archive, ArchiveBytes, SearchIndex},
};
use trc::AddContext;
use types::{
    TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};

pub trait CalendarEventQuery: Sync + Send {
    fn calendar_event_query(
        &self,
        request: QueryRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;

    fn calendar_query(
        &self,
        request: QueryRequest<calendar::Calendar>,
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
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let default_tz = request.arguments.resolved_time_zone()?;
        let default_language = self.core.email.default_language;
        let is_member = access_token.is_member(account_id);
        let expand_recurrences = request.arguments.expand_recurrences.unwrap_or(false);
        let mut filter: Option<TimeRange> = None;
        let mut instance_filter = InstanceTextFilter::default();

        if expand_recurrences
            && (request
                .filter
                .iter()
                .any(|cond| matches!(cond, Filter::Or | Filter::Not))
                || request
                    .filter
                    .iter()
                    .filter(|cond| matches!(cond, Filter::And))
                    .count()
                    > 1)
        {
            return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                "The filter must be a single FilterCondition when expanding recurrences",
            ));
        }

        if expand_recurrences
            && let Some(unsupported) =
                request
                    .sort
                    .iter()
                    .flatten()
                    .find_map(|comparator| match &comparator.property {
                        CalendarEventComparator::_T(property) => Some(property),
                        _ => None,
                    })
        {
            return Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details(unsupported.clone()));
        }

        let is_shared = access_token.is_shared(account_id);
        let hides_text = !is_member
            && request.filter.iter().any(|cond| {
                matches!(
                    cond,
                    Filter::Property(
                        CalendarEventFilter::Text(_)
                            | CalendarEventFilter::Title(_)
                            | CalendarEventFilter::Description(_)
                            | CalendarEventFilter::Location(_)
                            | CalendarEventFilter::Owner(_)
                            | CalendarEventFilter::Attendee(_)
                    )
                )
            });
        let [secret_ids, private_ids, hidden_attendee_ids] = if is_shared || hides_text {
            cache.event_ids_with_flag_masks([
                EVENT_SECRET,
                EVENT_PRIVATE | EVENT_SECRET,
                EVENT_HIDE_ATTENDEES,
            ])
        } else {
            std::array::from_fn(|_| RoaringBitmap::new())
        };
        let visibility = if hides_text {
            TextVisibility::new(&cache, private_ids, hidden_attendee_ids)
        } else {
            TextVisibility::default()
        };
        let candidates = if expand_recurrences {
            BoundCandidates::Widened
        } else {
            BoundCandidates::Exact
        };

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
                    CalendarEventFilter::Uid(value) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                (r.uid() == Some(value.as_str())).then_some(r.document_id())
                            }),
                        )));
                    }
                    CalendarEventFilter::Text(value) => {
                        let (text, language) = Language::detect(value, default_language);
                        let filter =
                            SearchFilter::has_text(CalendarSearchField::Title, text, language);
                        if expand_recurrences {
                            instance_filter.add(TEXT_FIELDS, &filter);
                        }
                        visibility.push_any_field(&mut filters, filter);
                    }
                    CalendarEventFilter::Title(title) => {
                        let filter = SearchFilter::has_text_detect(
                            CalendarSearchField::Title,
                            title,
                            default_language,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Title], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Description(description) => {
                        let filter = SearchFilter::has_text_detect(
                            CalendarSearchField::Description,
                            description,
                            default_language,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Description], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Location(location) => {
                        let filter = SearchFilter::has_text_detect(
                            CalendarSearchField::Location,
                            location,
                            default_language,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Location], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Owner(owner) => {
                        let filter = SearchFilter::has_text(
                            CalendarSearchField::Owner,
                            owner,
                            Language::None,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Owner], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Attendee(attendee) => {
                        let filter = SearchFilter::has_text(
                            CalendarSearchField::Attendee,
                            attendee,
                            Language::None,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Attendee], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::After(after) => {
                        if let Some(after) = local_timestamp(&after, default_tz) {
                            filters.push(SearchFilter::is_in_set(
                                TimeBound::After(after)
                                    .event_ids(self, &cache, account_id, default_tz, candidates)
                                    .await?,
                            ));
                        }
                    }
                    CalendarEventFilter::Before(before) => {
                        if let Some(before) = local_timestamp(&before, default_tz) {
                            filters.push(SearchFilter::is_in_set(
                                TimeBound::Before(before)
                                    .event_ids(self, &cache, account_id, default_tz, candidates)
                                    .await?,
                            ));
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

        let expand_range = if expand_recurrences {
            let Some(time_range) = filter.filter(|f| f.start != i64::MIN && f.end != i64::MAX)
            else {
                return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                    "Both 'after' and 'before' filters are required when expanding recurrences",
                ));
            };
            if time_range.end.saturating_sub(time_range.start)
                > self.core.groupware.max_expanded_query_duration as i64
            {
                return Err(trc::JmapEvent::ExpandDurationTooLarge.into_err().details(
                    "The time span between 'after' and 'before' exceeds maxExpandedQueryDuration",
                ));
            }
            Some(time_range)
        } else {
            None
        };
        let comparators = if !expand_recurrences {
            request
                .sort
                .take()
                .unwrap_or_default()
                .into_iter()
                .map(|comparator| match comparator.property {
                    CalendarEventComparator::Start | CalendarEventComparator::RecurrenceId => {
                        let mut items = cache
                            .resources
                            .iter()
                            .filter_map(|r| {
                                r.event_time_range()
                                    .map(|(start, _)| (r.document_id(), start))
                            })
                            .collect::<Vec<_>>();
                        items.sort_by_key(|(document_id, start)| (*start, *document_id));

                        Ok(SearchComparator::sorted_set(
                            items
                                .iter()
                                .enumerate()
                                .map(|(idx, (u, _))| (*u, idx as u32))
                                .collect(),
                            comparator.is_ascending,
                        ))
                    }
                    CalendarEventComparator::Uid => {
                        let mut items = cache
                            .resources
                            .iter()
                            .filter_map(|r| r.uid().map(|uid| (r.document_id(), uid)))
                            .collect::<Vec<_>>();
                        items.sort_by(|(doc_id_a, uid_a), (doc_id_b, uid_b)| {
                            let uid_order = uid_a.cmp(uid_b);
                            if uid_order == Ordering::Equal {
                                doc_id_a.cmp(doc_id_b)
                            } else {
                                uid_order
                            }
                        });

                        Ok(SearchComparator::sorted_set(
                            items
                                .iter()
                                .enumerate()
                                .map(|(idx, (u, _))| (*u, idx as u32))
                                .collect(),
                            comparator.is_ascending,
                        ))
                    }
                    CalendarEventComparator::Created => {
                        let mut items = cache
                            .resources
                            .iter()
                            .filter_map(|r| {
                                r.created_at()
                                    .map(|created_at| (r.document_id(), created_at))
                            })
                            .collect::<Vec<_>>();
                        items.sort_by_key(|(document_id, created_at)| (*created_at, *document_id));

                        Ok(SearchComparator::sorted_set(
                            items
                                .iter()
                                .enumerate()
                                .map(|(idx, (u, _))| (*u, idx as u32))
                                .collect(),
                            comparator.is_ascending,
                        ))
                    }
                    CalendarEventComparator::Updated => {
                        let mut items = cache
                            .resources
                            .iter()
                            .filter_map(|r| {
                                r.modified_at()
                                    .map(|modified_at| (r.document_id(), modified_at))
                            })
                            .collect::<Vec<_>>();
                        items
                            .sort_by_key(|(document_id, modified_at)| (*modified_at, *document_id));

                        Ok(SearchComparator::sorted_set(
                            items
                                .iter()
                                .enumerate()
                                .map(|(idx, (u, _))| (*u, idx as u32))
                                .collect(),
                            comparator.is_ascending,
                        ))
                    }
                    CalendarEventComparator::_T(other) => {
                        Err(trc::JmapEvent::UnsupportedSort.into_err().details(other))
                    }
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
                    .with_mask(if is_shared {
                        let mut shared_ids =
                            cache.shared_items(access_token, [Acl::ReadItems], true);
                        shared_ids -= secret_ids;
                        shared_ids
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

        if let Some(time_range) = expand_range {
            let max_instances = self.core.groupware.max_ical_instances;
            let mut expanded_results = Vec::with_capacity(results.len() as usize);

            for document_id in results {
                let Some(resource) = cache.item_by_id(document_id) else {
                    continue;
                };
                let Some(_content) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await?
                else {
                    continue;
                };
                let content = _content
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                let event = &content.data.event;
                let mut scheduling_components = event
                    .components
                    .iter()
                    .filter(|component| component.component_type.is_scheduling_object());
                let is_recurring =
                    match (scheduling_components.next(), scheduling_components.next()) {
                        (Some(component), None) => component.is_recurrent(),
                        _ => true,
                    };
                let attendees = if !is_member
                    && resource
                        .event_flags()
                        .is_some_and(|flags| flags & EVENT_HIDE_ATTENDEES != 0)
                {
                    AttendeeSearch::Hidden
                } else {
                    AttendeeSearch::Visible
                };
                let event_filter = (!instance_filter.is_empty())
                    .then(|| instance_filter.for_event(event, default_language, attendees));
                let mut component_matches: Vec<(u32, bool)> = Vec::new();
                let created = resource.created_at().unwrap_or_default();
                let updated = resource.modified_at().unwrap_or_default();
                let uid = resource.uid().unwrap_or_default();

                for expansion in content
                    .data
                    .expand(default_tz, time_range)
                    .unwrap_or_default()
                {
                    let prefix = match (is_recurring, expansion.recurrence_key()) {
                        (false, _) => 0,
                        (true, Some(recurrence_key)) => recurrence_key.prefix(),
                        (true, None) => continue,
                    };
                    if let Some(event_filter) = &event_filter {
                        let is_match = match component_matches
                            .iter()
                            .find(|(comp_id, _)| *comp_id == expansion.comp_id)
                        {
                            Some((_, is_match)) => *is_match,
                            None => {
                                let is_match = event
                                    .components
                                    .get(expansion.comp_id as usize)
                                    .is_some_and(|component| event_filter.matches(component));
                                component_matches.push((expansion.comp_id, is_match));
                                is_match
                            }
                        };
                        if !is_match {
                            continue;
                        }
                    }
                    if expanded_results.len() >= max_instances {
                        return Err(trc::JmapEvent::CannotCalculateOccurrences
                            .into_err()
                            .details(
                                "The number of expanded recurrences exceeds the server limit",
                            ));
                    }
                    expanded_results.push(ExpandedResult {
                        prefix,
                        document_id,
                        start: expansion.start,
                        recurrence_id: expansion.recurrence_id().utc,
                        created,
                        updated,
                        uid,
                    });
                }
            }

            let mut response = QueryResponseBuilder::new(
                expanded_results.len(),
                self.core.jmap.query_max_results,
                cache.get_state(false),
                &request,
            );
            response.response.can_calculate_changes = false;
            expanded_results.sort_by(|a, b| {
                comparators
                    .iter()
                    .map(|comparator| {
                        let ordering = a.cmp_by(b, &comparator.property);
                        if comparator.is_ascending {
                            ordering
                        } else {
                            ordering.reverse()
                        }
                    })
                    .find(|ordering| ordering.is_ne())
                    .unwrap_or(Ordering::Equal)
            });
            for result in expanded_results {
                if !response.add(result.prefix, result.document_id) {
                    break;
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

    async fn calendar_query(
        &self,
        request: QueryRequest<calendar::Calendar>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;

        let results = if access_token.is_member(account_id) {
            cache.document_ids(true).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            cache.get_state(true),
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

fn local_timestamp(dt: &JSCalendarDateTime, tz: Tz) -> Option<i64> {
    tz.from_local(dt.to_naive_date_time()?)
        .map(|dt| dt.timestamp())
}

#[derive(Debug)]
struct ExpandedResult<'x> {
    prefix: u32,
    document_id: u32,
    start: i64,
    recurrence_id: i64,
    created: i64,
    updated: i64,
    uid: &'x str,
}

impl ExpandedResult<'_> {
    fn cmp_by(&self, other: &Self, comparator: &CalendarEventComparator) -> Ordering {
        match comparator {
            CalendarEventComparator::Start => self.start.cmp(&other.start),
            CalendarEventComparator::RecurrenceId => self.recurrence_id.cmp(&other.recurrence_id),
            CalendarEventComparator::Uid => self.uid.cmp(other.uid),
            CalendarEventComparator::Created => self.created.cmp(&other.created),
            CalendarEventComparator::Updated => self.updated.cmp(&other.updated),
            CalendarEventComparator::_T(_) => Ordering::Equal,
        }
    }
}

#[derive(Debug, Default)]
struct TextVisibility {
    public_ids: Option<RoaringBitmap>,
    attendee_ids: Option<RoaringBitmap>,
}

impl TextVisibility {
    fn new(
        cache: &GroupwareResources,
        private_ids: RoaringBitmap,
        hidden_attendee_ids: RoaringBitmap,
    ) -> Self {
        if private_ids.is_empty() && hidden_attendee_ids.is_empty() {
            return TextVisibility::default();
        }
        let all_ids = cache.document_ids(false).collect::<RoaringBitmap>();
        let visible_ids =
            |hidden_ids: RoaringBitmap| (!hidden_ids.is_empty()).then(|| &all_ids - hidden_ids);

        TextVisibility {
            public_ids: visible_ids(private_ids),
            attendee_ids: visible_ids(hidden_attendee_ids),
        }
    }

    fn push(&self, filters: &mut Vec<SearchFilter>, filter: SearchFilter) {
        let attendee_ids = self.attendee_ids.as_ref().filter(|_| {
            matches!(
                filter,
                SearchFilter::Text {
                    field: SearchField::Calendar(CalendarSearchField::Attendee),
                    ..
                }
            )
        });
        if self.public_ids.is_none() && attendee_ids.is_none() {
            filters.push(filter);
            return;
        }
        filters.push(SearchFilter::And);
        filters.push(filter);
        filters.extend(
            self.public_ids
                .iter()
                .chain(attendee_ids)
                .cloned()
                .map(SearchFilter::is_in_set),
        );
        filters.push(SearchFilter::End);
    }

    fn push_any_field(&self, filters: &mut Vec<SearchFilter>, filter: SearchFilter) {
        let SearchFilter::Text {
            op,
            value,
            language,
            ..
        } = filter
        else {
            return;
        };
        if self.public_ids.is_some() {
            filters.push(SearchFilter::And);
        }
        filters.push(SearchFilter::Or);
        for field in TEXT_FIELDS
            .iter()
            .filter(|field| **field != CalendarSearchField::Attendee)
        {
            filters.push(SearchFilter::Text {
                field: (*field).into(),
                op,
                value: value.clone(),
                language,
            });
        }
        let attendee = SearchFilter::Text {
            field: CalendarSearchField::Attendee.into(),
            op,
            value,
            language,
        };
        match &self.attendee_ids {
            Some(attendee_ids) => {
                filters.push(SearchFilter::And);
                filters.push(attendee);
                filters.push(SearchFilter::is_in_set(attendee_ids.clone()));
                filters.push(SearchFilter::End);
            }
            None => filters.push(attendee),
        }
        filters.push(SearchFilter::End);
        if let Some(public_ids) = &self.public_ids {
            filters.push(SearchFilter::is_in_set(public_ids.clone()));
            filters.push(SearchFilter::End);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundCandidates {
    Widened,
    Exact,
}

#[derive(Debug, Clone, Copy)]
enum TimeBound {
    After(i64),
    Before(i64),
}

impl TimeBound {
    fn matches(self, (start, end): (i64, i64), margin: i64) -> bool {
        match self {
            TimeBound::After(after) => after.saturating_sub(margin) < end,
            TimeBound::Before(before) => before.saturating_add(margin) > start,
        }
    }

    fn time_range(self) -> TimeRange {
        match self {
            TimeBound::After(after) => TimeRange::new(after, i64::MAX),
            TimeBound::Before(before) => TimeRange::new(i64::MIN, before),
        }
    }

    async fn event_ids(
        self,
        server: &Server,
        cache: &GroupwareResources,
        account_id: u32,
        default_tz: Tz,
        candidates: BoundCandidates,
    ) -> trc::Result<RoaringBitmap> {
        let margin = if default_tz.is_utc() {
            0
        } else {
            MAX_UTC_OFFSET
        };
        let mut event_ids = RoaringBitmap::new();

        for resource in cache.resources.iter() {
            let Some(range) = resource.event_time_range() else {
                continue;
            };
            let document_id = resource.document_id();
            if self.matches(range, -margin)
                || (self.matches(range, margin)
                    && (candidates == BoundCandidates::Widened
                        || self
                            .contains_instance(server, account_id, document_id, default_tz)
                            .await?))
            {
                event_ids.insert(document_id);
            }
        }

        Ok(event_ids)
    }

    async fn contains_instance(
        self,
        server: &Server,
        account_id: u32,
        document_id: u32,
        default_tz: Tz,
    ) -> trc::Result<bool> {
        let Some(archive) = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content,
            ))
            .await?
        else {
            return Ok(false);
        };

        Ok(archive
            .unarchive::<CalendarEventContent>()
            .caused_by(trc::location!())?
            .data
            .expand(default_tz, self.time_range())
            .is_some_and(|instances| !instances.is_empty()))
    }
}

const TEXT_FIELDS: &[CalendarSearchField] = &[
    CalendarSearchField::Title,
    CalendarSearchField::Description,
    CalendarSearchField::Location,
    CalendarSearchField::Owner,
    CalendarSearchField::Attendee,
];
