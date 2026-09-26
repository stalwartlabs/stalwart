/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    filter::{CalendarFilterPlan, FilterTimeRanges},
    view::{CalendarView, ChildIdView, ComponentView, EntryView},
};
use crate::{
    DavError,
    common::{
        CalendarQueryFilter, DavQuery, EventContent,
        propfind::PropFindRequestHandler,
        search::{QueryScope, TextIndex},
        uri::DavUriResource,
    },
};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponentType, ICalendarEntry, ICalendarProperty, ICalendarValue,
    },
};
use common::{DavResourcePath, GroupwareResource, Server, auth::AccessToken};
use compact_str::ToCompactString;
use dav_proto::{
    RequestHeaders,
    schema::{
        property::{CalDavProperty, CalendarData, DavProperty},
        request::{CalendarQuery, PropFind, Timezone},
        response::MultiStatus,
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ArchivedCalendarEvent, ArchivedCalendarEventContent,
        ArchivedCalendarEventNotificationContent, CalendarEventContent, CalendarEventData,
        EVENT_HAS_UNBOUNDED_TODO, EVENT_SECRET,
        expand::{CalendarEventExpansion, MAX_UTC_OFFSET},
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::{fmt::Write, slice::Iter, str::FromStr};
use store::write::{SearchIndex, serialize::rkyv_deserialize};
use trc::AddContext;
use types::{
    OverlapCondition, OverlapRule, TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait CalendarQueryRequestHandler: Sync + Send {
    fn handle_calendar_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: CalendarQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

pub(crate) trait QueryTimezone {
    fn resolve(&self) -> Option<Tz>;
}

pub(crate) trait EventTimeRange {
    fn is_in_time_range(&self, range: &TimeRange) -> bool;
}

pub(crate) trait CalendarDataRange {
    fn calendar_data_range(&self) -> Option<TimeRange>;
}

impl CalendarQueryRequestHandler for Server {
    async fn handle_calendar_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: CalendarQuery,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let collection = if resource_.collection == Collection::CalendarEventNotification {
            Collection::CalendarEventNotification
        } else {
            Collection::Calendar
        };
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::from(collection),
            )
            .await
            .caused_by(trc::location!())?;
        let Some(resource) = resources.by_path(
            resource_
                .resource
                .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
        ) else {
            return Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(MultiStatus::not_found(headers.uri).to_string()));
        };

        let shared_ids = (!access_token.is_member(account_id)).then(|| {
            let mut shared_ids = resources.shared_items(access_token, [Acl::ReadItems], false);
            shared_ids -= resources.event_ids_with_flags(EVENT_SECRET);
            shared_ids
        });
        let is_visible = |item: &DavResourcePath<'_>| {
            shared_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(item.document_id()))
        };
        let scope = if resource.is_container() {
            QueryScope::new(
                resources
                    .children(resource.document_id())
                    .filter(is_visible),
            )
        } else {
            QueryScope::new(std::iter::once(resource).filter(is_visible))
        };

        let filter_ranges = request
            .filter
            .as_ref()
            .map(CalendarFilterPlan::time_ranges)
            .unwrap_or_default();
        let items = match &request.filter {
            Some(filter) if collection == Collection::Calendar && !scope.is_empty() => {
                let candidates =
                    filter.candidates(&scope, TextIndex::new(self, SearchIndex::Calendar));
                scope
                    .resolve(
                        self,
                        SearchIndex::Calendar,
                        account_id,
                        candidates,
                        &resources,
                    )
                    .await
            }
            _ => scope.into_items(&resources, account_id),
        };

        let filter = CalendarQueryFilter {
            expansion: filter_ranges.union(FilterTimeRanges {
                range: request.properties.calendar_data_range(),
                has_alarms: false,
            }),
            timezone: request.timezone.resolve(),
            filter: request.filter,
        };

        self.handle_dav_query(
            access_token,
            DavQuery::calendar_query(request.properties, filter, collection, items, headers),
        )
        .await
    }
}

impl QueryTimezone for Timezone {
    fn resolve(&self) -> Option<Tz> {
        match self {
            Timezone::Id(id) => Tz::from_str(id).ok(),
            Timezone::Name(value) => Tz::from_str(value).ok().or_else(|| {
                ICalendar::parse(value).ok().and_then(|ical| {
                    ical.timezones()
                        .find_map(|timezone| timezone.timezone().map(|(_, tz)| tz))
                })
            }),
            Timezone::None => None,
        }
    }
}

impl EventTimeRange for GroupwareResource {
    fn is_in_time_range(&self, range: &TimeRange) -> bool {
        self.event_time_range().is_some_and(|(start, end)| {
            range.touches(
                start.saturating_sub(MAX_UTC_OFFSET),
                end.saturating_add(MAX_UTC_OFFSET),
            )
        })
    }
}

impl CalendarDataRange for PropFind {
    fn calendar_data_range(&self) -> Option<TimeRange> {
        let props = match self {
            PropFind::AllProp(props) | PropFind::Prop(props) => props,
            PropFind::PropName => return None,
        };

        props
            .iter()
            .find_map(|prop| match prop {
                DavProperty::CalDav(CalDavProperty::CalendarData(data)) => Some(data),
                _ => None,
            })
            .and_then(CalendarDataRange::calendar_data_range)
    }
}

impl CalendarDataRange for CalendarData {
    fn calendar_data_range(&self) -> Option<TimeRange> {
        [self.expand, self.limit_recurrence, self.limit_freebusy]
            .into_iter()
            .flatten()
            .reduce(TimeRange::union)
    }
}

impl CalendarQueryFilter {
    pub fn matches_scheduling_message(
        &self,
        content: &ArchivedCalendarEventNotificationContent,
        default_tz: Tz,
        max_instances: usize,
    ) -> trc::Result<bool> {
        let Some(filter) = &self.filter else {
            return Ok(true);
        };
        let Some(ical) = content.calendar_data() else {
            return Ok(false);
        };
        let time_ranges = filter.time_ranges();
        if time_ranges.range.is_none() {
            return Ok(CalendarQueryHandler::for_scheduling(default_tz).matches(ical, filter));
        }

        let content = CalendarEventContent {
            data: CalendarEventData::new(rkyv_deserialize(ical)?, Tz::Floating, max_instances),
            ..Default::default()
        };
        let mut handler = CalendarQueryHandler::for_event_data(&content, time_ranges, default_tz);
        handler.dateless_events_match = true;

        Ok(handler.matches(&content, filter))
    }
}

pub(crate) struct CalendarQueryHandler {
    pub(super) default_tz: Tz,
    pub(super) expanded_times: Vec<CalendarEventExpansion>,
    pub(super) undated_todos: Vec<u32>,
    pub(super) dateless_events_match: bool,
}

impl CalendarQueryHandler {
    pub fn new(
        event: &ArchivedCalendarEventContent,
        expansion_range: Option<TimeRange>,
        default_tz: Tz,
    ) -> Self {
        Self {
            default_tz,
            expanded_times: expansion_range
                .map(|expansion_range| {
                    event
                        .data
                        .expand(default_tz, expansion_range, OverlapRule::CalDav)
                        .unwrap_or_else(|| {
                            trc::event!(
                                Calendar(trc::CalendarEvent::RuleExpansionError),
                                Reason = "Failed to expand stored time ranges",
                                Details = event.data.event.to_compact_string(),
                            );
                            vec![]
                        })
                })
                .unwrap_or_default(),
            undated_todos: Vec::new(),
            dateless_events_match: false,
        }
        .indexed()
    }

    pub fn for_event_data(
        content: &CalendarEventContent,
        expansion: FilterTimeRanges,
        default_tz: Tz,
    ) -> Self {
        CalendarQueryHandler {
            default_tz,
            expanded_times: expansion
                .expansion_range(content)
                .and_then(|range| content.data.expand(default_tz, range, OverlapRule::CalDav))
                .unwrap_or_default(),
            undated_todos: content.data.undated_todos().collect(),
            dateless_events_match: false,
        }
        .indexed()
    }

    pub fn for_scheduling(default_tz: Tz) -> Self {
        CalendarQueryHandler {
            default_tz,
            expanded_times: Vec::new(),
            undated_todos: Vec::new(),
            dateless_events_match: true,
        }
    }

    pub fn for_content(
        event: &ArchivedCalendarEvent,
        content: &EventContent<'_>,
        expansion: FilterTimeRanges,
        default_tz: Tz,
    ) -> Self {
        let stored = content.stored();
        let expansion_range = match content.view() {
            Some(view) => expansion.expansion_range(view),
            None => expansion.expansion_range(stored),
        };
        let mut handler = Self::new(stored, expansion_range, default_tz);
        if event.flags.to_native() & EVENT_HAS_UNBOUNDED_TODO != 0 {
            handler.undated_todos.extend(stored.data.undated_todos());
        }
        if let Some(merged_overrides) = content
            .merged_overrides()
            .filter(|merged_overrides| !merged_overrides.is_empty())
        {
            for expansion in &mut handler.expanded_times {
                if let Some(base_id) = merged_overrides.base_of(expansion.comp_id) {
                    expansion.comp_id = base_id;
                }
            }
            handler = handler.indexed();
        }
        handler
    }

    fn indexed(mut self) -> Self {
        self.expanded_times
            .sort_unstable_by_key(|expansion| (expansion.comp_id, expansion.start));
        self
    }

    pub(super) fn expansions_of(&self, comp_id: u32) -> &[CalendarEventExpansion] {
        let from = self
            .expanded_times
            .partition_point(|expansion| expansion.comp_id < comp_id);
        let to = self
            .expanded_times
            .partition_point(|expansion| expansion.comp_id <= comp_id);
        self.expanded_times.get(from..to).unwrap_or_default()
    }

    pub fn serialize_content(
        &self,
        content: &EventContent<'_>,
        size: u32,
        data: &CalendarData,
        instances_limit: &mut usize,
    ) -> Option<String> {
        match content.view() {
            Some(view) => self.serialize_ical(view, size, data, instances_limit),
            None => self.serialize_ical(content.stored(), size, data, instances_limit),
        }
    }

    pub fn serialize_ical<V: CalendarView>(
        &self,
        event: &V,
        size: u32,
        data: &CalendarData,
        instances_limit: &mut usize,
    ) -> Option<String> {
        let mut out = String::with_capacity(size as usize);
        let root = [ChildIdOf::<V>::from(0u32)];
        let mut component_iter: Iter<'_, ChildIdOf<V>> = root.iter();
        let mut component_stack: Vec<(&V::Component, Iter<'_, ChildIdOf<V>>)> =
            Vec::with_capacity(4);

        loop {
            if let Some(component_id) = component_iter.next() {
                let component_id = component_id.child_id();
                let Some(component) =
                    event
                        .components()
                        .get(component_id as usize)
                        .filter(|component| {
                            data.expand.is_none()
                                || !component.is_type(ICalendarComponentType::VTimezone)
                        })
                else {
                    continue;
                };
                let is_todo = component.is_type(ICalendarComponentType::VTodo);

                // Limit recurrence override
                if let Some(limit_recurrence) = &data.limit_recurrence
                    && component.is_recurrence_override()
                    && !self.expansions_of(component_id).iter().any(|expansion| {
                        limit_recurrence.is_in_range(
                            expansion.flags.condition(),
                            expansion.start,
                            expansion.end,
                        )
                    })
                {
                    continue;
                }

                // Limit freebusy
                let is_freebusy = component.is_type(ICalendarComponentType::VFreebusy);
                if let Some(limit_freebusy) = &data.limit_freebusy
                    && is_freebusy
                    && !self.expansions_of(component_id).iter().any(|expansion| {
                        limit_freebusy.is_in_range(
                            OverlapCondition::Event,
                            expansion.start,
                            expansion.end,
                        )
                    })
                {
                    continue;
                }

                // Filter entries
                let is_calendar = component.is_type(ICalendarComponentType::VCalendar);
                let mut entries = component
                    .entries()
                    .iter()
                    .filter_map(|entry| {
                        if data.properties.is_empty() || is_calendar {
                            Some((entry, true))
                        } else {
                            data.properties
                                .iter()
                                .find(|prop| {
                                    prop.component.as_ref().is_none_or(|comp| {
                                        component.component_type() == comp
                                            || component_stack
                                                .iter()
                                                .any(|(parent, _)| parent.component_type() == comp)
                                    }) && prop.name.as_ref().is_none_or(|name| entry.is_named(name))
                                })
                                .map(|prop| (entry, !prop.no_value))
                        }
                    })
                    .peekable();

                // Expand recurrences
                let component_name = component.type_name();
                if let Some(expand) = &data.expand.filter(|_| {
                    component.has_time_ranges() && !self.undated_todos.contains(&component_id)
                }) {
                    let is_recurrent = component.is_recurrent();
                    let is_recurrent_or_override =
                        is_recurrent || component.is_recurrence_override();
                    let mut has_duration = false;
                    let entries = entries
                        .filter(|(entry, _)| {
                            let name = entry.name();
                            if name == &ICalendarProperty::Duration {
                                has_duration = true;
                                true
                            } else if is_todo && name == &ICalendarProperty::Due {
                                false
                            } else if name == &ICalendarProperty::Due
                                || name == &ICalendarProperty::Completed
                                || name == &ICalendarProperty::Created
                            {
                                is_recurrent
                            } else {
                                !(name == &ICalendarProperty::Dtstart
                                    || name == &ICalendarProperty::Dtend
                                    || name == &ICalendarProperty::Exdate
                                    || name == &ICalendarProperty::Exrule
                                    || name == &ICalendarProperty::Rdate
                                    || name == &ICalendarProperty::Rrule
                                    || name == &ICalendarProperty::RecurrenceId)
                            }
                        })
                        .collect::<Vec<_>>();
                    let end_property =
                        if has_duration || component.is_type(ICalendarComponentType::VJournal) {
                            None
                        } else if is_todo {
                            Some(ICalendarProperty::Due)
                        } else {
                            Some(ICalendarProperty::Dtend)
                        };
                    let mut date_entry = ICalendarEntry {
                        name: ICalendarProperty::Dtstart,
                        params: vec![],
                        values: [ICalendarValue::PartialDateTime(Default::default())].into(),
                    };
                    let mut write_date =
                        |out: &mut String, name: ICalendarProperty, timestamp: i64| {
                            date_entry.name = name;
                            if let Some(ICalendarValue::PartialDateTime(value)) =
                                date_entry.values.first_mut()
                            {
                                *value = PartialDateTime::from_utc_timestamp(timestamp);
                            }
                            let _ = date_entry.write_to(out);
                        };
                    for expansion in self.expansions_of(component_id) {
                        if !is_recurrent_or_override
                            || expand.is_in_range(
                                expansion.flags.condition(),
                                expansion.start,
                                expansion.end,
                            )
                        {
                            if *instances_limit > 0 {
                                *instances_limit -= 1;
                            } else {
                                return None;
                            }
                            let _ = write!(&mut out, "BEGIN:{component_name}\r\n");

                            // Write DTSTART, DTEND and RECURRENCE-ID
                            write_date(&mut out, ICalendarProperty::Dtstart, expansion.start);
                            if is_recurrent_or_override {
                                write_date(
                                    &mut out,
                                    ICalendarProperty::RecurrenceId,
                                    expansion.recurrence_id().utc,
                                );
                            }
                            if let Some(end_property) = &end_property
                                && if is_todo {
                                    matches!(
                                        expansion.flags.condition(),
                                        OverlapCondition::TodoStartDue
                                            | OverlapCondition::TodoStartDuration
                                    )
                                } else {
                                    expansion.end > expansion.start
                                }
                            {
                                write_date(&mut out, end_property.clone(), expansion.end);
                            }

                            // Write other component entries
                            for (entry, with_value) in &entries {
                                entry.write_value(&mut out, *with_value);
                            }
                            let _ = write!(&mut out, "END:{component_name}\r\n");
                        }
                    }
                } else if entries.peek().is_some()
                    || (is_calendar && !component.child_ids().is_empty())
                {
                    let _ = write!(&mut out, "BEGIN:{component_name}\r\n");

                    match data.limit_freebusy {
                        Some(range) if is_freebusy => {
                            // Filter freebusy
                            for (entry, with_value) in entries {
                                if entry.is_named(&ICalendarProperty::Freebusy) {
                                    if let Some(entry) =
                                        entry.freebusy_in_range(&range, self.default_tz)
                                    {
                                        let _ = entry.write_to(&mut out);
                                    }
                                } else {
                                    entry.write_value(&mut out, with_value);
                                }
                            }
                        }
                        _ => {
                            for (entry, with_value) in entries {
                                entry.write_value(&mut out, with_value);
                            }
                        }
                    }

                    if !component.child_ids().is_empty() {
                        component_stack.push((component, component_iter));
                        component_iter = component.child_ids().iter();
                    } else {
                        let _ = write!(&mut out, "END:{component_name}\r\n");
                    }
                }
            } else if let Some((component, iter)) = component_stack.pop() {
                let _ = write!(&mut out, "END:{}\r\n", component.type_name());
                component_iter = iter;
            } else {
                break;
            }
        }

        Some(out)
    }

    pub fn into_expanded_times(self) -> Vec<CalendarEventExpansion> {
        self.expanded_times
    }
}

type ChildIdOf<V> = <<V as CalendarView>::Component as ComponentView>::ChildId;
