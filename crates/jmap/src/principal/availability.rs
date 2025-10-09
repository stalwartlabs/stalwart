/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::calendar_event::CalendarSyntheticId;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendarClassification, ArchivedICalendarParameterValue,
        ArchivedICalendarParticipationStatus, ArchivedICalendarProperty, ArchivedICalendarStatus,
        ArchivedICalendarTransparency, ArchivedICalendarValue, ICalendarParameterName,
    },
    jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarValue},
};
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent};
use jmap_proto::{
    method::availability::{
        BusyPeriod, BusyStatus, GetAvailabilityRequest, GetAvailabilityResponse,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use std::{future::Future, sync::Arc};
use store::ahash::AHashMap;
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

        let account_id = request.account_id.document_id();
        let principal_id = request.id.document_id();
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;

        // Obtain shared ids
        let shared_ids = if !access_token.is_member(account_id) {
            // Condition: The user has the "mayReadFreeBusy" permission for the calendar.
            resources
                .shared_containers(
                    access_token,
                    [Acl::ReadItems, Acl::SchedulingReadFreeBusy],
                    true,
                )
                .into()
        } else {
            None
        };
        /*

          TODO: Implement the following conditions:

         - The Principal is subscribed to the calendar.
         - The "includeInAvailability" property of the calendar for the Principal is "all" or "attending".
         - If the "includeInAvailability" property of the calendar is "attending",

        */

        // Obtain external principal
        let is_user_account = principal_id == account_id;
        let user_principal = if access_token.primary_id() != principal_id {
            PrincipalAddresses::Owned(
                self.get_access_token(principal_id)
                    .await
                    .caused_by(trc::location!())?,
            )
        } else {
            PrincipalAddresses::Shared(access_token)
        };
        let max_instances = self.core.groupware.max_ical_instances;
        let filter = TimeRange {
            start: request.utc_start.timestamp(),
            end: request.utc_end.timestamp(),
        };

        // Condition: The event finishes after the "utcStart" argument and starts before the "utcEnd" argument.
        let mut periods = Vec::new();
        'next_event: for document_id in resources.resources.iter().filter_map(|r| {
            r.event_time_range().and_then(|(start, end)| {
                (shared_ids
                    .as_ref()
                    .is_none_or(|ids| ids.contains(r.document_id))
                    && ((filter.start < end) || (filter.start <= start))
                    && (filter.end > start || filter.end >= end))
                    .then_some(r.document_id)
            })
        }) {
            let Some(archive) = self
                .get_archive(account_id, Collection::CalendarEvent, document_id)
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
                        (ArchivedICalendarProperty::Attendee, Some(value)) => {
                            if let Some(attendee) = value.as_text().and_then(|attendee| {
                                sanitize_email(attendee.strip_prefix("mailto:").unwrap_or(attendee))
                            }) {
                                // Condition: the Principal is a participant of the event, and has a "participationStatus" of "accepted" or "tentative".
                                if user_principal.is_principal_addresses(&attendee) {
                                    busy_status = Some(
                                        entry
                                            .parameters(&ICalendarParameterName::Partstat)
                                            .next()
                                            .map(|v| match v {
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
                } else if is_user_account {
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

            let default_tz = resources
                .container_resource_by_id(event.names[0].parent_id.to_native())
                .and_then(|r| r.timezone())
                .unwrap_or(Tz::UTC);

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

enum PrincipalAddresses<'x> {
    Owned(Arc<AccessToken>),
    Shared(&'x AccessToken),
}

impl<'x> PrincipalAddresses<'x> {
    fn is_principal_addresses(&self, email: &String) -> bool {
        match self {
            PrincipalAddresses::Owned(token) => token.emails.contains(email),
            PrincipalAddresses::Shared(token) => token.emails.contains(email),
        }
    }
}
