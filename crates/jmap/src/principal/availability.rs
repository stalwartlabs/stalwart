/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{calendar::Availability, calendar_event::CalendarSyntheticId};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendarClassification, ArchivedICalendarParameterValue,
        ArchivedICalendarParticipationStatus, ArchivedICalendarProperty, ArchivedICalendarStatus,
        ArchivedICalendarTransparency, ArchivedICalendarValue, ICalendarParameterName,
    },
    jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarValue},
};
use common::{Server, TinyCalendarPreferences, auth::AccessToken};
use directory::Permission;
use groupware::{
    cache::GroupwareCache,
    calendar::{CALENDAR_SUBSCRIBED, CalendarEvent},
};
use jmap_proto::{
    method::availability::{
        BusyPeriod, BusyStatus, GetAvailabilityRequest, GetAvailabilityResponse,
    },
    object::calendar::IncludeInAvailability,
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use std::{collections::hash_map::Entry, future::Future};
use store::{ValueKey, ahash::AHashMap, write::{AlignedBytes, Archive}};
use trc::AddContext;
use types::{
    TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    id::Id,
};
use utils::sanitize_email;

pub trait PrincipalGetAvailability: Sync + Send {
    fn principal_get_availability(
        &self,
        request: GetAvailabilityRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetAvailabilityResponse>> + Send;
}

impl PrincipalGetAvailability for Server {
    async fn principal_get_availability(
        &self,
        request: GetAvailabilityRequest,
        access_token: &AccessToken,
    ) -> trc::Result<GetAvailabilityResponse> {
        if !self.core.groupware.allow_directory_query
            && !access_token.has_permission(Permission::IndividualList)
        {
            return Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("The administrator has disabled directory queries.".to_string()));
        }

        // Process parameters
        if !request.id.is_valid() {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("Missing principal id"));
        }
        let properties = request
            .event_properties
            .map(|props| props.into_valid().collect::<Vec<_>>())
            .unwrap_or_default();
        if properties
            .iter()
            .any(|p| !matches!(p, JSCalendarProperty::Id | JSCalendarProperty::BaseEventId))
        {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("Only 'id' and 'baseEventId' properties are supported in results"));
        }
        let return_event_details = !properties.is_empty();
        let max_instances = self.core.groupware.max_ical_instances;
        let filter = TimeRange {
            start: request.utc_start.timestamp(),
            end: request.utc_end.timestamp(),
        };
        let principal_id = request.id.document_id();
        let principal = self
            .get_access_token(principal_id)
            .await
            .caused_by(trc::location!())?;
        let mut periods = Vec::new();

        for account_id in principal.all_ids_by_collection(Collection::Calendar) {
            let resources = self
                .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
                .await
                .caused_by(trc::location!())?;

            // Obtain shared ids
            let is_account_owner = principal_id == account_id;
            let shared_ids = if !access_token.is_member(account_id) {
                // Condition: The user has the "mayReadFreeBusy" permission for the calendar.
                let shared_ids = resources.shared_items(
                    access_token,
                    [Acl::ReadItems, Acl::SchedulingReadFreeBusy],
                    true,
                );
                if shared_ids.is_empty() {
                    continue;
                }

                shared_ids.into()
            } else {
                None
            };

            // Condition: The event finishes after the "utcStart" argument and starts before the "utcEnd" argument.
            let mut preferences_cache: AHashMap<u32, Option<&TinyCalendarPreferences>> =
                AHashMap::default();
            'next_event: for resource in resources.resources.iter().filter(|r| {
                r.event_time_range().is_some_and(|(start, end)| {
                    shared_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(r.document_id))
                        && filter.is_in_range(false, start, end)
                })
            }) {
                // Obtain calendar settings
                let mut include_in_availability = None;
                let mut default_tz = Tz::UTC;
                let mut is_subscribed = is_account_owner;
                for calendar_id in resource
                    .child_names()
                    .unwrap_or_default()
                    .iter()
                    .map(|n| n.parent_id)
                {
                    match preferences_cache.entry(calendar_id) {
                        Entry::Occupied(e) => {
                            if let Some(prefs) = e.get() {
                                default_tz = prefs.tz;
                                is_subscribed |= prefs.flags & CALENDAR_SUBSCRIBED != 0;
                                include_in_availability =
                                    IncludeInAvailability::from_flags(prefs.flags);
                            }
                        }
                        Entry::Vacant(e) => {
                            if let Some(prefs) = resources
                                .container_resource_by_id(calendar_id)
                                .and_then(|r| r.calendar_preferences(principal_id))
                            {
                                default_tz = prefs.tz;
                                is_subscribed |= prefs.flags & CALENDAR_SUBSCRIBED != 0;
                                include_in_availability =
                                    IncludeInAvailability::from_flags(prefs.flags);
                                e.insert(Some(prefs));
                            } else {
                                e.insert(None);
                            }
                        }
                    }
                }
                let include_in_availability = include_in_availability.unwrap_or({
                    if is_account_owner {
                        IncludeInAvailability::All
                    } else {
                        IncludeInAvailability::None
                    }
                });

                if !is_subscribed || include_in_availability == IncludeInAvailability::None {
                    continue 'next_event;
                }

                // Fetch event
                let document_id = resource.document_id;
                let Some(archive) = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    continue;
                };
                let event = archive
                    .unarchive::<CalendarEvent>()
                    .caused_by(trc::location!())?;

                // Find the component ids that match the criteria
                let mut matching_component_ids = AHashMap::new();
                'next_component: for (component_id, component) in
                    event.data.event.components.iter().enumerate()
                {
                    if !component.component_type.is_event_or_todo() {
                        continue 'next_component;
                    }

                    let mut is_cancelled = false;
                    let mut is_main_event = true;
                    let mut busy_status = None;

                    for entry in component.entries.iter() {
                        match (&entry.name, entry.values.first()) {
                            (
                                ArchivedICalendarProperty::Status,
                                Some(ArchivedICalendarValue::Status(
                                    ArchivedICalendarStatus::Cancelled,
                                )),
                            ) => {
                                // The "status" property of the event is not "cancelled".
                                is_cancelled = true;
                            }
                            (ArchivedICalendarProperty::RecurrenceId, _) => {
                                is_main_event = false;
                            }
                            (
                                ArchivedICalendarProperty::Class,
                                Some(ArchivedICalendarValue::Classification(
                                    ArchivedICalendarClassification::Confidential,
                                )),
                            ) => {
                                // Condition: The event's "privacy" property is not "secret".
                                continue 'next_component;
                            }
                            (
                                ArchivedICalendarProperty::Transp,
                                Some(ArchivedICalendarValue::Transparency(
                                    ArchivedICalendarTransparency::Transparent,
                                )),
                            ) => {
                                // Condition: The "freeBusyStatus" property of the event is "busy" (or omitted, as this is the default).
                                continue 'next_component;
                            }
                            (ArchivedICalendarProperty::Attendee, Some(value))
                                if include_in_availability == IncludeInAvailability::Attending =>
                            {
                                if let Some(attendee) = value.as_text().and_then(|attendee| {
                                    sanitize_email(
                                        attendee.strip_prefix("mailto:").unwrap_or(attendee),
                                    )
                                }) {
                                    // Condition: the Principal is a participant of the event, and has a "participationStatus" of "accepted" or "tentative".
                                    if principal.emails.contains(&attendee) {
                                        busy_status = Some(
                                            entry
                                                .parameters(&ICalendarParameterName::Partstat)
                                                .next()
                                                .map(|v| {
                                                    match v {
                                                ArchivedICalendarParameterValue::Partstat(
                                                    ArchivedICalendarParticipationStatus::Accepted,
                                                ) => BusyStatus::Confirmed,
                                                ArchivedICalendarParameterValue::Partstat(
                                                    ArchivedICalendarParticipationStatus::Tentative,
                                                ) => BusyStatus::Tentative,
                                                ArchivedICalendarParameterValue::Partstat(
                                                    ArchivedICalendarParticipationStatus::Declined,
                                                ) => {
                                                    is_cancelled = true;
                                                    BusyStatus::Unavailable
                                                }
                                                _ => BusyStatus::Unavailable,
                                            }
                                                })
                                                .unwrap_or(BusyStatus::Unavailable),
                                        );
                                    }
                                }
                            }
                            _ => (),
                        }
                    }

                    if is_cancelled {
                        if is_main_event {
                            continue 'next_event;
                        } else {
                            continue 'next_component;
                        }
                    }

                    let busy_status = if let Some(busy_status) = busy_status {
                        busy_status
                    } else if include_in_availability == IncludeInAvailability::All {
                        BusyStatus::Confirmed
                    } else {
                        continue 'next_component;
                    };

                    matching_component_ids.insert(component_id as u32, busy_status);
                }

                if matching_component_ids.is_empty() {
                    // No events matched the criteria
                    continue 'next_event;
                }

                for expansion in event.data.expand(default_tz, filter).unwrap_or_default() {
                    let Some(busy_status) = matching_component_ids.get(&expansion.comp_id) else {
                        continue;
                    };
                    if periods.len() < max_instances {
                        periods.push(FreeBusyResult {
                            utc_start: expansion.start,
                            utc_end: expansion.end,
                            busy_status: *busy_status,
                            expansion_id: expansion.comp_id,
                            document_id,
                        });
                    } else {
                        return Err(trc::JmapEvent::RequestTooLarge
                            .into_err()
                            .details("The number of expanded instances exceeds the server limit"));
                    }
                }
            }
        }

        let mut result = GetAvailabilityResponse {
            list: Vec::with_capacity(periods.len()),
        };

        if periods.is_empty() {
            return Ok(result);
        }

        // Sort by busy status and start time
        periods.sort_unstable_by(|a, b| {
            a.busy_status
                .cmp(&b.busy_status)
                .then_with(|| a.utc_start.cmp(&b.utc_start))
        });

        if return_event_details {
            for period in periods {
                result.list.push(period.into());
            }
        } else {
            // Merge intervals with same busy status
            let mut start_time = periods[0].utc_start;
            let mut end_time = periods[0].utc_end;
            let mut current_status = periods[0].busy_status;

            for curr in periods.iter().skip(1) {
                if curr.utc_start <= end_time && curr.busy_status == current_status {
                    end_time = end_time.max(curr.utc_end);
                } else {
                    result.list.push(BusyPeriod {
                        utc_start: UTCDate::from_timestamp(start_time),
                        utc_end: UTCDate::from_timestamp(end_time),
                        busy_status: Some(current_status),
                        event: None,
                    });
                    start_time = curr.utc_start;
                    end_time = curr.utc_end;
                    current_status = curr.busy_status;
                }
            }

            result.list.push(BusyPeriod {
                utc_start: UTCDate::from_timestamp(start_time),
                utc_end: UTCDate::from_timestamp(end_time),
                busy_status: Some(current_status),
                event: None,
            });
        }

        Ok(result)
    }
}

struct FreeBusyResult {
    utc_start: i64,
    utc_end: i64,
    busy_status: BusyStatus,
    expansion_id: u32,
    document_id: u32,
}

impl From<FreeBusyResult> for BusyPeriod {
    fn from(value: FreeBusyResult) -> Self {
        BusyPeriod {
            utc_start: UTCDate::from_timestamp(value.utc_start),
            utc_end: UTCDate::from_timestamp(value.utc_end),
            busy_status: Some(value.busy_status),
            event: JSCalendar(Value::Object(Map::from(vec![
                (
                    Key::Property(JSCalendarProperty::Id),
                    Value::Element(JSCalendarValue::Id(<Id as CalendarSyntheticId>::new(
                        value.expansion_id,
                        value.document_id,
                    ))),
                ),
                (
                    Key::Property(JSCalendarProperty::BaseEventId),
                    Value::Element(JSCalendarValue::Id(Id::from(value.document_id))),
                ),
            ])))
            .into(),
        }
    }
}
