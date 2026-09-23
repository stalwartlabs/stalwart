/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::view::{AlarmView, CalendarView, ChildIdView, ComponentView, EntryView, ParameterView};
use crate::{
    DavError,
    common::{
        CalendarFilter, DavQuery, EventContent,
        propfind::{PropFindItem, PropFindRequestHandler},
        uri::DavUriResource,
    },
};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{ICalendarComponentType, ICalendarEntry, ICalendarProperty, ICalendarValue},
};
use common::{GroupwareResource, Server, auth::AccessToken};
use compact_str::ToCompactString;
use dav_proto::{
    RequestHeaders,
    schema::{
        property::{CalDavProperty, CalendarData, DavProperty},
        request::{CalendarQuery, Filter, FilterOp, PropFind, Timezone},
        response::MultiStatus,
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ArchivedCalendarEventContent, EVENT_HAS_ALARMS, EVENT_SECRET,
        expand::CalendarEventExpansion,
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::{fmt::Write, slice::Iter, str::FromStr};
use store::ahash::AHashMap;
use trc::AddContext;
use types::{TimeRange, acl::Acl, collection::SyncCollection};

pub(crate) trait CalendarQueryRequestHandler: Sync + Send {
    fn handle_calendar_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: CalendarQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
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
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
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
        if !resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Obtain shared ids
        let shared_ids = if !access_token.is_member(account_id) {
            let mut shared_ids = resources.shared_items(access_token, [Acl::ReadItems], false);
            shared_ids -= resources.event_ids_with_flags(EVENT_SECRET);
            Some(shared_ids)
        } else {
            None
        };

        // Pre-filter by date range
        let filter_range = extract_filter_range(&request);
        let admits_alarms = filter_range.is_some() && has_alarm_time_range(&request);

        // Obtain document ids in folder
        let mut items = Vec::with_capacity(16);
        for resource in resources.children(resource.document_id()) {
            if shared_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(resource.document_id()))
                && filter_range.as_ref().is_none_or(|range| {
                    is_resource_in_time_range(resource.resource.resource, range)
                        || (admits_alarms && has_alarms(resource.resource.resource))
                })
            {
                items.push(PropFindItem::new(
                    resources.format_resource(resource),
                    account_id,
                    resource,
                ));
            }
        }

        // Extract the time range from the request
        let max_time_range = extract_data_range(&request.properties, filter_range);

        self.handle_dav_query(
            access_token,
            DavQuery::calendar_query(request, max_time_range, items, headers),
        )
        .await
    }
}

pub(crate) fn is_resource_in_time_range(resource: &GroupwareResource, filter: &TimeRange) -> bool {
    // Check whether the resource has a time range and if it overlaps with the filter
    if let Some((start, end)) = resource.event_time_range() {
        ((filter.start < end) || (filter.start <= start))
            && (filter.end > start || filter.end >= end)
    } else {
        // If the resource does not have a time range, it is not in the range
        false
    }
}

fn has_alarms(resource: &GroupwareResource) -> bool {
    resource
        .event_flags()
        .is_some_and(|flags| flags & EVENT_HAS_ALARMS != 0)
}

fn has_alarm_time_range(query: &CalendarQuery) -> bool {
    query.filters.iter().any(|filter| {
        matches!(
            filter,
            Filter::Component {
                comp,
                op: FilterOp::TimeRange(_)
            } if comp.last() == Some(&ICalendarComponentType::VAlarm)
        )
    })
}

fn extract_filter_range(query: &CalendarQuery) -> Option<TimeRange> {
    let mut range = TimeRange {
        start: i64::MAX,
        end: i64::MIN,
    };

    for filter in &query.filters {
        let op = match filter {
            Filter::Component { op, .. } => op,
            Filter::Property { op, .. } => op,
            Filter::Parameter { op, .. } => op,
            _ => continue,
        };
        if let FilterOp::TimeRange(date_range) = op {
            if date_range.start < range.start {
                range.start = date_range.start;
            }
            if date_range.end > range.end {
                range.end = date_range.end;
            }
        }
    }

    if range.start != i64::MAX {
        Some(range)
    } else {
        None
    }
}

fn extract_data_range(propfind: &PropFind, filter_range: Option<TimeRange>) -> Option<TimeRange> {
    let props = match propfind {
        PropFind::AllProp(props) | PropFind::Prop(props) => props,
        PropFind::PropName => &[][..],
    };

    for prop in props {
        if let DavProperty::CalDav(CalDavProperty::CalendarData(data)) = prop {
            let mut range = filter_range.unwrap_or(TimeRange {
                start: i64::MAX,
                end: i64::MIN,
            });

            for data_range in [&data.expand, &data.limit_recurrence, &data.limit_freebusy]
                .into_iter()
                .flatten()
            {
                if data_range.start < range.start {
                    range.start = data_range.start;
                }
                if data_range.end > range.end {
                    range.end = data_range.end;
                }
            }

            return if range.start != i64::MAX {
                Some(range)
            } else {
                None
            };
        }
    }

    filter_range
}

pub fn try_parse_tz(tz: &Timezone) -> Option<Tz> {
    match tz {
        Timezone::Name(value) | Timezone::Id(value) => Tz::from_str(value).ok(),
        Timezone::None => None,
    }
}

pub(crate) struct CalendarQueryHandler {
    default_tz: Tz,
    expanded_times: Vec<CalendarEventExpansion>,
}

impl CalendarQueryHandler {
    pub fn new(
        event: &ArchivedCalendarEventContent,
        max_time_range: Option<TimeRange>,
        default_tz: Tz,
    ) -> Self {
        Self {
            default_tz,
            expanded_times: max_time_range
                .map(|max_time_range| {
                    event
                        .data
                        .expand(default_tz, max_time_range)
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
        }
    }

    pub fn for_content(
        content: &EventContent<'_>,
        max_time_range: Option<TimeRange>,
        default_tz: Tz,
    ) -> Self {
        let mut handler = Self::new(content.stored(), max_time_range, default_tz);
        if let Some(merged_overrides) = content
            .merged_overrides()
            .filter(|merged_overrides| !merged_overrides.is_empty())
        {
            for expansion in &mut handler.expanded_times {
                if let Some(base_id) = merged_overrides.base_of(expansion.comp_id) {
                    expansion.comp_id = base_id;
                }
            }
        }
        handler
    }

    pub fn filter_content(&mut self, content: &EventContent<'_>, filters: &CalendarFilter) -> bool {
        match content.view() {
            Some(view) => self.filter(view, filters),
            None => self.filter(content.stored(), filters),
        }
    }

    pub fn serialize_content(
        &mut self,
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

    pub fn filter<V: CalendarView>(&mut self, event: &V, filters: &CalendarFilter) -> bool {
        let mut is_all = true;
        let mut matches_one = false;

        for filter in filters {
            match filter {
                Filter::AnyOf => {
                    is_all = false;
                }
                Filter::AllOf => {
                    is_all = true;
                }
                Filter::Property { prop, op, comp } => {
                    let mut properties = find_components(event, comp)
                        .flat_map(|(_, component)| find_properties(component, prop))
                        .peekable();

                    let result = if properties.peek().is_some() {
                        properties.any(|entry| match op {
                            FilterOp::Exists => true,
                            FilterOp::Undefined => false,
                            FilterOp::TextMatch(text_match) => {
                                entry.text_values().any(|text| text_match.matches(text))
                            }
                            FilterOp::TimeRange(range) => {
                                entry.date_time_timestamp(self.default_tz).is_some_and(
                                    |timestamp| range.start <= timestamp && range.end > timestamp,
                                )
                            }
                        })
                    } else {
                        matches!(op, FilterOp::Undefined)
                    };

                    if result {
                        matches_one = true;
                    } else if is_all {
                        return false;
                    }
                }
                Filter::Parameter {
                    prop,
                    param,
                    op,
                    comp,
                } => {
                    let mut parameters = find_components(event, comp)
                        .flat_map(|(_, component)| {
                            find_properties(component, prop)
                                .filter_map(|entry| entry.parameter(param))
                        })
                        .peekable();

                    let result = if parameters.peek().is_some() {
                        parameters.any(|parameter| match op {
                            FilterOp::Exists => true,
                            FilterOp::Undefined => false,
                            FilterOp::TextMatch(text_match) => parameter
                                .text()
                                .is_some_and(|text| text_match.matches(text)),
                            FilterOp::TimeRange(_) => false,
                        })
                    } else {
                        matches!(op, FilterOp::Undefined)
                    };

                    if result {
                        matches_one = true;
                    } else if is_all {
                        return false;
                    }
                }
                Filter::Component { comp, op } => {
                    let result = match op {
                        FilterOp::Exists => find_components(event, comp).next().is_some(),
                        FilterOp::Undefined => find_components(event, comp).next().is_none(),
                        FilterOp::TimeRange(range) => {
                            if !matches!(comp.last(), Some(ICalendarComponentType::VAlarm)) {
                                let matching_comp_ids = find_components(event, comp)
                                    .map(|(id, component)| {
                                        (
                                            id as u32,
                                            component.is_type(ICalendarComponentType::VTodo),
                                        )
                                    })
                                    .collect::<AHashMap<_, _>>();

                                !matching_comp_ids.is_empty()
                                    && self.expanded_times.iter().any(|expansion| {
                                        matching_comp_ids.get(&expansion.comp_id).is_some_and(
                                            |is_todo| {
                                                range.is_in_range(
                                                    *is_todo,
                                                    expansion.start,
                                                    expansion.end,
                                                )
                                            },
                                        )
                                    })
                            } else {
                                let alarms = event.alarms();

                                !alarms.is_empty()
                                    && self.expanded_times.iter().any(|expansion| {
                                        alarms.iter().any(|alarm| {
                                            alarm.parent_id() == expansion.comp_id
                                                && alarm
                                                    .timestamp(expansion, self.default_tz)
                                                    .is_some_and(|timestamp| {
                                                        range.is_in_range(
                                                            false, timestamp, timestamp,
                                                        )
                                                    })
                                        })
                                    })
                            }
                        }
                        FilterOp::TextMatch(_) => false,
                    };

                    if result {
                        matches_one = true;
                    } else if is_all {
                        return false;
                    }
                }
            }
        }

        is_all || matches_one
    }

    pub fn serialize_ical<V: CalendarView>(
        &mut self,
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

        if data.expand.is_some() {
            self.expanded_times.sort_unstable_by_key(|a| a.start);
        }

        loop {
            if let Some(component_id) = component_iter.next() {
                let component_id = component_id.child_id();
                let Some(component) = event.components().get(component_id as usize) else {
                    continue;
                };
                let is_todo = component.is_type(ICalendarComponentType::VTodo);

                // Limit recurrence override
                if let Some(limit_recurrence) = &data.limit_recurrence
                    && component.is_recurrence_override()
                    && !self.expanded_times.iter().any(|expansion| {
                        expansion.comp_id == component_id
                            && limit_recurrence.is_in_range(is_todo, expansion.start, expansion.end)
                    })
                {
                    continue;
                }

                // Limit freebusy
                let is_freebusy = component.is_type(ICalendarComponentType::VFreebusy);
                if let Some(limit_freebusy) = &data.limit_freebusy
                    && is_freebusy
                    && !self.expanded_times.iter().any(|expansion| {
                        expansion.comp_id == component_id
                            && limit_freebusy.is_in_range(false, expansion.start, expansion.end)
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
                if let Some(expand) = &data.expand.filter(|_| component.has_time_ranges()) {
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
                    for expansion in &self.expanded_times {
                        if expansion.comp_id == component_id
                            && (!is_recurrent_or_override
                                || expand.is_in_range(is_todo, expansion.start, expansion.end))
                        {
                            if *instances_limit > 0 {
                                *instances_limit -= 1;
                            } else {
                                return None;
                            }
                            let _ = write!(&mut out, "BEGIN:{component_name}\r\n");

                            // Write DTSTART, DTEND and RECURRENCE-ID
                            let mut entry = ICalendarEntry {
                                name: ICalendarProperty::Dtstart,
                                params: vec![],
                                values: vec![ICalendarValue::PartialDateTime(Box::new(
                                    PartialDateTime::from_utc_timestamp(expansion.start),
                                ))],
                            };
                            let _ = entry.write_to(&mut out);
                            if is_recurrent_or_override {
                                entry.name = ICalendarProperty::RecurrenceId;
                                let _ = entry.write_to(&mut out);
                            }
                            if !has_duration {
                                entry.name = ICalendarProperty::Dtend;
                                entry.values = vec![ICalendarValue::PartialDateTime(Box::new(
                                    PartialDateTime::from_utc_timestamp(expansion.end),
                                ))];
                                let _ = entry.write_to(&mut out);
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

#[inline(always)]
fn find_components<'x, V: CalendarView>(
    event: &'x V,
    comp: &'x [ICalendarComponentType],
) -> impl Iterator<Item = (usize, &'x V::Component)> {
    // TODO: Properly expand the component type path
    let comp = comp.last().unwrap_or(&ICalendarComponentType::VCalendar);
    event
        .components()
        .iter()
        .enumerate()
        .filter(move |(_, component)| {
            comp == &ICalendarComponentType::VCalendar || component.component_type() == comp
        })
}

#[inline(always)]
fn find_properties<'x, C: ComponentView>(
    component: &'x C,
    prop: &'x ICalendarProperty,
) -> impl Iterator<Item = &'x C::Entry> {
    component
        .entries()
        .iter()
        .filter(move |entry| entry.is_named(prop))
}
