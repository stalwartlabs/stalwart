/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::calendar_event::{
    CalendarSyntheticId,
    get::{EventProjector, ProjectedEvent, ProjectionRequest, ProjectionResults},
};
use calcard::jscalendar::JSCalendar;
use common::{
    KV_RATE_LIMIT_AVAILABILITY, Server,
    auth::{AccessToken, BuildAccessToken},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent,
        availability::{
            AvailabilityCalendars, BusyLevel, ComponentBusy, DefaultFreeBusy, PrincipalRole,
        },
        expand::{MAX_UTC_OFFSET, RecurrenceKey},
        identity::ParticipantIdentityAddresses,
        privacy::EventPrivacy,
        user::BASE_INSTANCE,
        working_hours::WorkingHoursHandler,
    },
};
use jmap_proto::{
    method::availability::{
        BusyPeriod, BusyStatus, GetAvailabilityRequest, GetAvailabilityResponse,
    },
    request::MaybeInvalid,
    types::date::UTCDate,
};
use jmap_tools::Value;
use registry::schema::enums::Permission;
use std::future::Future;
use store::{
    ValueKey,
    ahash::AHashMap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    OverlapRule, TimeRange,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
    id::Id,
};

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
        let account_id = request.account_id.document_id();
        if !access_token.has_account_access(account_id)
            || self
                .try_account(account_id)
                .await
                .caused_by(trc::location!())?
                .is_none()
        {
            return Err(trc::JmapEvent::AccountNotFound
                .into_err()
                .details("Account not found."));
        }

        if !request.id.is_valid() {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("Missing principal id"));
        }
        let filter = request.time_range().ok_or_else(|| {
            trc::JmapEvent::InvalidArguments.into_err().details(
                "utcStart and utcEnd must be valid UTCDate values, with utcEnd after utcStart",
            )
        })?;
        if filter.end - filter.start > self.core.groupware.max_availability_duration as i64 {
            return Err(trc::JmapEvent::TooLarge
                .into_err()
                .details("The requested time span exceeds maxAvailabilityDuration"));
        }
        if let Some(rate) = &self.core.groupware.availability_rate
            && !access_token.has_permission(Permission::UnlimitedRequests)
            && self
                .core
                .storage
                .memory
                .is_rate_allowed(
                    KV_RATE_LIMIT_AVAILABILITY,
                    &access_token.account_id().to_be_bytes(),
                    rate,
                )
                .await
                .caused_by(trc::location!())?
                .is_some()
        {
            return Err(trc::JmapEvent::RateLimit
                .into_err()
                .details("Too many availability requests, please try again later"));
        }
        let principal_id = request.id.document_id();
        let Some(principal_cache) = self
            .try_account(principal_id)
            .await
            .caused_by(trc::location!())?
            .filter(|account| {
                account.is_same_tenant(access_token)
                    || access_token.has_permission(Permission::SysAccountQuery)
            })
        else {
            return Err(trc::JmapEvent::ObjectNotFound
                .into_err()
                .details("Principal not found."));
        };
        let is_resource = principal_cache.resource_kind().is_some();
        let show_details =
            request.show_details && access_token.has_permission(Permission::JmapCalendarEventGet);
        let max_instances = self.core.groupware.max_ical_instances;
        let candidates = TimeRange::new(
            filter.start.saturating_sub(MAX_UTC_OFFSET),
            filter.end.saturating_add(MAX_UTC_OFFSET),
        );
        let principal = self
            .access_token(principal_id)
            .await
            .caused_by(trc::location!())?
            .build();
        let principal_account = self
            .account_info(principal_id)
            .await
            .caused_by(trc::location!())?;
        let identities = self
            .identity_addresses(principal_id, &principal_account)
            .await
            .caused_by(trc::location!())?;
        let mut intervals = Vec::new();
        let mut components = Vec::new();
        let mut events = AHashMap::new();
        let mut can_read_principal = false;
        let projection = show_details
            .then(|| {
                ProjectionRequest::new(
                    request.event_properties.map(|properties| {
                        properties
                            .into_iter()
                            .filter_map(MaybeInvalid::try_unwrap)
                            .collect()
                    }),
                    false,
                    None,
                )
            })
            .transpose()?;

        for account_id in principal.all_ids_by_collection(Collection::Calendar) {
            let resources = self
                .fetch_groupware_resources(
                    access_token.account_id(),
                    account_id,
                    SyncCollection::Calendar,
                )
                .await
                .caused_by(trc::location!())?;
            let calendars = if is_resource && account_id == principal_id {
                Some(AvailabilityCalendars::published(
                    &resources,
                    account_id,
                    access_token,
                ))
            } else {
                let default = if principal.is_member(account_id) {
                    DefaultFreeBusy::resolve(self, access_token, account_id).await?
                } else {
                    DefaultFreeBusy::Denied
                };
                AvailabilityCalendars::new(
                    &resources,
                    account_id,
                    access_token,
                    &principal,
                    default,
                )
            };
            let Some(mut calendars) = calendars else {
                continue;
            };
            can_read_principal |= account_id == principal_id;
            let mut projector = match &projection {
                Some(projection) => {
                    Some(EventProjector::new(self, access_token, account_id, projection).await?)
                }
                None => None,
            };

            for resource in resources.resources.iter() {
                let (Some((start, end)), Some(flags)) =
                    (resource.event_time_range(), resource.event_flags())
                else {
                    continue;
                };
                let privacy = EventPrivacy::from_flags(flags);
                if privacy == EventPrivacy::Secret || !candidates.overlaps(start, end) {
                    continue;
                }
                let names = resource.child_names();
                let Some(calendar) = calendars.relevant_calendar(names) else {
                    continue;
                };

                let document_id = resource.document_id();
                let Some(archive) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    continue;
                };
                let event = archive
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                let preferences = match calendars.role() {
                    PrincipalRole::Owner => None,
                    PrincipalRole::Sharee => event.preferences(principal_id),
                };

                components.clear();
                components.extend(event.data.event.components.iter().map(|component| {
                    ComponentBusy::parse(component, &identities, calendars.role())
                        .filter(|busy| calendar.includes(busy))
                }));
                if components.iter().all(Option::is_none) {
                    continue;
                }

                let may_read_details = show_details
                    && privacy == EventPrivacy::Public
                    && calendars.may_read_items(names);
                let first_interval = intervals.len();
                for expansion in event
                    .data
                    .expand(calendar.tz, filter, OverlapRule::Jmap)
                    .unwrap_or_default()
                {
                    let Some(Some(busy)) = components.get(expansion.comp_id as usize) else {
                        continue;
                    };
                    if expansion.end <= expansion.start {
                        continue;
                    }
                    let recurrence_key = (preferences.is_some()
                        || (may_read_details && busy.is_recurrent_or_override()))
                    .then(|| expansion.recurrence_key())
                    .flatten();
                    if preferences
                        .and_then(|preferences| {
                            preferences.is_free(
                                recurrence_key.map_or(BASE_INSTANCE, RecurrenceKey::prefix),
                            )
                        })
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if intervals.len() == max_instances {
                        return Err(trc::JmapEvent::TooLarge
                            .into_err()
                            .details("The number of expanded instances exceeds the server limit"));
                    }
                    let event_id = match (may_read_details, busy.is_recurrent_or_override()) {
                        (false, _) => None,
                        (true, true) => recurrence_key
                            .map(|key| <Id as CalendarSyntheticId>::new(key, document_id)),
                        (true, false) => Some(Id::from(document_id)),
                    };
                    intervals.push(BusyInterval {
                        start: expansion.start,
                        end: expansion.end,
                        status: busy_status(busy),
                        event: event_id.map(|id| (account_id, id)),
                    });
                }

                if let Some(projector) = projector.as_mut() {
                    let mut detail_ids: Vec<(Id, usize)> = Vec::new();
                    for (_, id) in intervals[first_interval..]
                        .iter()
                        .filter_map(|interval| interval.event)
                    {
                        if !detail_ids.iter().any(|(existing, _)| *existing == id) {
                            detail_ids.push((id, detail_ids.len()));
                        }
                    }
                    if !detail_ids.is_empty() {
                        let mut projected = ProjectionResults::default();
                        projector
                            .project(
                                self,
                                access_token,
                                ProjectedEvent {
                                    cache: &resources,
                                    document_id,
                                    content: Some(event),
                                    flags,
                                    privacy,
                                    calendar_ids: names,
                                    time_zone: calendar.tz,
                                    ids: &detail_ids,
                                },
                                &mut projected,
                            )
                            .await?;
                        events.extend(projected.found.into_iter().filter_map(|(index, object)| {
                            detail_ids.get(index).map(|(id, _)| {
                                ((account_id, *id), JSCalendar(Value::Object(object)))
                            })
                        }));
                    }
                }
            }
        }

        let mut busy_periods = Vec::with_capacity(intervals.len());
        let mut timeline = BusyTimeline::default();
        if can_read_principal
            && let Some(schedule) = self
                .working_schedule(&principal_cache)
                .await
                .caused_by(trc::location!())?
        {
            let mut total_instances = intervals.len();
            for (start, end) in schedule.unavailable(filter.start, filter.end) {
                total_instances += 1;
                if total_instances > max_instances {
                    return Err(trc::JmapEvent::TooLarge
                        .into_err()
                        .details("The number of expanded instances exceeds the server limit"));
                }
                timeline.insert(start, end, BusyStatus::Unavailable);
            }
        }
        for interval in intervals {
            match interval
                .event
                .and_then(|key| events.remove(&key).map(|event| (key.0, event)))
            {
                Some(event) => busy_periods.push(BusyInterval {
                    start: interval.start,
                    end: interval.end,
                    status: interval.status,
                    event: Some(event),
                }),
                None => timeline.insert(interval.start, interval.end, interval.status),
            }
        }
        timeline.merge_into(&mut busy_periods);
        busy_periods.sort_by_key(|period| (period.start, period.end, period.status));

        Ok(GetAvailabilityResponse {
            list: busy_periods.into_iter().map(BusyPeriod::from).collect(),
        })
    }
}

type EventDetails = (u32, JSCalendar<'static, Id, BlobId>);

struct BusyInterval<E> {
    start: i64,
    end: i64,
    status: BusyStatus,
    event: Option<E>,
}

impl From<BusyInterval<EventDetails>> for BusyPeriod {
    fn from(interval: BusyInterval<EventDetails>) -> Self {
        let (account_id, event) = interval.event.unzip();
        BusyPeriod {
            utc_start: UTCDate::from_timestamp(interval.start),
            utc_end: UTCDate::from_timestamp(interval.end),
            busy_status: Some(interval.status),
            event,
            account_id: account_id.map(Id::from),
        }
    }
}

fn busy_status(busy: &ComponentBusy) -> BusyStatus {
    match busy.busy_level() {
        BusyLevel::Confirmed => BusyStatus::Confirmed,
        BusyLevel::Tentative => BusyStatus::Tentative,
        BusyLevel::Unavailable => BusyStatus::Unavailable,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Start,
    End,
}

#[derive(Debug, Clone, Copy)]
struct Boundary {
    time: i64,
    edge: Edge,
    status: BusyStatus,
}

#[derive(Debug, Default)]
struct BusyTimeline {
    boundaries: Vec<Boundary>,
}

#[derive(Debug, Default)]
struct ActiveStatuses {
    tentative: u32,
    unavailable: u32,
    confirmed: u32,
}

impl BusyTimeline {
    fn insert(&mut self, start: i64, end: i64, status: BusyStatus) {
        self.boundaries.extend([
            Boundary {
                time: start,
                edge: Edge::Start,
                status,
            },
            Boundary {
                time: end,
                edge: Edge::End,
                status,
            },
        ]);
    }

    fn merge_into<E>(mut self, intervals: &mut Vec<BusyInterval<E>>) {
        self.boundaries
            .sort_unstable_by_key(|boundary| boundary.time);
        let mut active = ActiveStatuses::default();
        let mut current: Option<(i64, BusyStatus)> = None;
        let mut boundaries = self.boundaries.into_iter().peekable();

        while let Some(boundary) = boundaries.next() {
            let time = boundary.time;
            active.apply(boundary);
            while let Some(boundary) = boundaries.next_if(|next| next.time == time) {
                active.apply(boundary);
            }

            let status = active.top();
            if current.map(|(_, status)| status) != status {
                if let Some((start, status)) = current {
                    intervals.push(BusyInterval {
                        start,
                        end: time,
                        status,
                        event: None,
                    });
                }
                current = status.map(|status| (time, status));
            }
        }
    }
}

impl ActiveStatuses {
    fn apply(&mut self, boundary: Boundary) {
        let count = match boundary.status {
            BusyStatus::Tentative => &mut self.tentative,
            BusyStatus::Unavailable => &mut self.unavailable,
            BusyStatus::Confirmed => &mut self.confirmed,
        };
        match boundary.edge {
            Edge::Start => *count += 1,
            Edge::End => *count -= 1,
        }
    }

    fn top(&self) -> Option<BusyStatus> {
        [
            (self.confirmed, BusyStatus::Confirmed),
            (self.unavailable, BusyStatus::Unavailable),
            (self.tentative, BusyStatus::Tentative),
        ]
        .into_iter()
        .find(|(count, _)| *count > 0)
        .map(|(_, status)| status)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/jmap/src/principal/availability/tests.rs"]
mod tests;
