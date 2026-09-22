/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    calendar::Availability,
    calendar_event::{
        CalendarSyntheticId,
        get::{EventProjector, ProjectedEvent, ProjectionRequest, ProjectionResults},
    },
    principal::get::PrincipalGet,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendarComponent, ArchivedICalendarParameterValue,
        ArchivedICalendarParticipationStatus, ArchivedICalendarProperty, ArchivedICalendarStatus,
        ArchivedICalendarTransparency, ArchivedICalendarValue, ICalendarParameterName,
    },
    jscalendar::JSCalendar,
};
use common::{
    CachedName, GroupwareResources, KV_RATE_LIMIT_AVAILABILITY, Server, TinyCalendarPreferences,
    auth::{AccessToken, BuildAccessToken},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CALENDAR_SUBSCRIBED, CalendarEventContent, default_preference_flags,
        expand::{MAX_UTC_OFFSET, RecurrenceKey},
        identity::{CalendarAddresses, ParticipantIdentityAddresses},
        privacy::EventPrivacy,
        user::BASE_INSTANCE,
    },
};
use jmap_proto::{
    method::availability::{
        BusyPeriod, BusyStatus, GetAvailabilityRequest, GetAvailabilityResponse,
    },
    object::calendar::IncludeInAvailability,
    request::MaybeInvalid,
    types::date::UTCDate,
};
use jmap_tools::Value;
use registry::schema::enums::Permission;
use std::future::Future;
use store::{
    ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    TimeRange,
    acl::Acl,
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
        if !self.core.groupware.allow_directory_query {
            return Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("The administrator has disabled directory queries."));
        }
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
                    false,
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
        if self
            .visible_principal(access_token, principal_id)
            .await?
            .is_none()
        {
            return Err(trc::JmapEvent::ObjectNotFound
                .into_err()
                .details("Principal not found."));
        }
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
            let Some(mut calendars) =
                AvailabilityCalendars::new(&resources, account_id, access_token, &principal)
            else {
                continue;
            };
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
                if privacy == EventPrivacy::Secret || !candidates.is_in_range(false, start, end) {
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
                let preferences = match calendars.role {
                    PrincipalRole::Owner => None,
                    PrincipalRole::Sharee => event.preferences(principal_id),
                };

                components.clear();
                components.extend(event.data.event.components.iter().map(|component| {
                    ComponentBusy::parse(component, &identities, calendars.role)
                        .filter(|busy| calendar.includes(busy))
                }));
                if components.iter().all(Option::is_none) {
                    continue;
                }

                let may_read_details = show_details
                    && privacy == EventPrivacy::Public
                    && calendars.may_read_items(names);
                let first_interval = intervals.len();
                for expansion in event.data.expand(calendar.tz, filter).unwrap_or_default() {
                    let Some(Some(busy)) = components.get(expansion.comp_id as usize) else {
                        continue;
                    };
                    if expansion.end <= expansion.start {
                        continue;
                    }
                    let recurrence_key = (preferences.is_some()
                        || (may_read_details && busy.is_recurrent_or_override))
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
                    let event_id = match (may_read_details, busy.is_recurrent_or_override) {
                        (false, _) => None,
                        (true, true) => recurrence_key
                            .map(|key| <Id as CalendarSyntheticId>::new(key, document_id)),
                        (true, false) => Some(Id::from(document_id)),
                    };
                    intervals.push(BusyInterval {
                        start: expansion.start,
                        end: expansion.end,
                        status: busy.busy_status(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrincipalRole {
    Owner,
    Sharee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Inclusion {
    Attending,
    All,
}

#[derive(Debug, Clone, Copy)]
struct RelevantCalendar {
    inclusion: Inclusion,
    tz: Tz,
}

impl RelevantCalendar {
    fn includes(&self, busy: &ComponentBusy) -> bool {
        self.inclusion == Inclusion::All || busy.is_attending()
    }
}

enum CalendarAccess {
    All,
    Shared(RoaringBitmap),
}

impl CalendarAccess {
    fn contains(&self, calendar_id: u32) -> bool {
        match self {
            CalendarAccess::All => true,
            CalendarAccess::Shared(calendar_ids) => calendar_ids.contains(calendar_id),
        }
    }
}

struct AvailabilityCalendars<'x> {
    resources: &'x GroupwareResources,
    access_token: &'x AccessToken,
    account_id: u32,
    principal_id: u32,
    role: PrincipalRole,
    free_busy: CalendarAccess,
    subscribable: CalendarAccess,
    readable: Option<CalendarAccess>,
    relevance: AHashMap<u32, Option<RelevantCalendar>>,
}

impl<'x> AvailabilityCalendars<'x> {
    fn new(
        resources: &'x GroupwareResources,
        account_id: u32,
        access_token: &'x AccessToken,
        principal: &AccessToken,
    ) -> Option<Self> {
        let free_busy = if access_token.is_member(account_id) {
            CalendarAccess::All
        } else {
            let calendar_ids = resources.shared_containers(
                access_token,
                [Acl::ReadItems, Acl::SchedulingReadFreeBusy],
                true,
            );
            if calendar_ids.is_empty() {
                return None;
            }
            CalendarAccess::Shared(calendar_ids)
        };
        let (role, subscribable) = if principal.is_member(account_id) {
            (PrincipalRole::Owner, CalendarAccess::All)
        } else {
            (
                PrincipalRole::Sharee,
                CalendarAccess::Shared(resources.shared_containers(
                    principal,
                    [Acl::Read, Acl::ReadItems],
                    true,
                )),
            )
        };

        Some(AvailabilityCalendars {
            resources,
            access_token,
            account_id,
            principal_id: principal.account_id(),
            role,
            free_busy,
            subscribable,
            readable: None,
            relevance: AHashMap::new(),
        })
    }

    fn relevant_calendar(&mut self, names: &[CachedName]) -> Option<RelevantCalendar> {
        names
            .iter()
            .filter_map(|name| self.calendar_relevance(name.parent_id))
            .reduce(|best, calendar| {
                if calendar.inclusion > best.inclusion {
                    calendar
                } else {
                    best
                }
            })
    }

    fn calendar_relevance(&mut self, calendar_id: u32) -> Option<RelevantCalendar> {
        if let Some(relevance) = self.relevance.get(&calendar_id) {
            return *relevance;
        }
        let relevance = self.evaluate(calendar_id);
        self.relevance.insert(calendar_id, relevance);
        relevance
    }

    fn evaluate(&self, calendar_id: u32) -> Option<RelevantCalendar> {
        if !self.free_busy.contains(calendar_id) || !self.subscribable.contains(calendar_id) {
            return None;
        }
        let calendar = self.resources.container_resource_by_id(calendar_id)?;
        let preferences = match calendar.personal_calendar_preferences(self.principal_id) {
            Some(preferences) => *preferences,
            None if self.role == PrincipalRole::Owner => TinyCalendarPreferences {
                account_id: self.principal_id,
                flags: default_preference_flags(true),
                tz: calendar.calendar_preferences(self.principal_id)?.tz,
            },
            None => return None,
        };
        if preferences.flags & CALENDAR_SUBSCRIBED == 0 {
            return None;
        }
        let inclusion = match (
            IncludeInAvailability::from_flags(preferences.flags),
            self.role,
        ) {
            (Some(IncludeInAvailability::All), _) | (None, PrincipalRole::Owner) => Inclusion::All,
            (Some(IncludeInAvailability::Attending), _) => Inclusion::Attending,
            (Some(IncludeInAvailability::None), _) | (None, PrincipalRole::Sharee) => {
                return None;
            }
        };

        Some(RelevantCalendar {
            inclusion,
            tz: preferences.tz,
        })
    }

    fn may_read_items(&mut self, names: &[CachedName]) -> bool {
        let AvailabilityCalendars {
            resources,
            access_token,
            account_id,
            readable,
            ..
        } = self;
        let readable = readable.get_or_insert_with(|| {
            if access_token.is_member(*account_id) {
                CalendarAccess::All
            } else {
                CalendarAccess::Shared(resources.shared_containers(
                    access_token,
                    [Acl::ReadItems],
                    true,
                ))
            }
        });
        names.iter().any(|name| readable.contains(name.parent_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Participation {
    Attendee(ParticipationStatus),
    Organizer,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParticipationStatus {
    Accepted,
    Tentative,
    Declined,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventStatus {
    Confirmed,
    Tentative,
    Other,
}

#[derive(Debug, Clone, Copy)]
struct ComponentBusy {
    status: EventStatus,
    participation: Participation,
    has_attendees: bool,
    is_recurrent_or_override: bool,
}

impl ComponentBusy {
    fn parse(
        component: &ArchivedICalendarComponent,
        identities: &CalendarAddresses,
        role: PrincipalRole,
    ) -> Option<Self> {
        if !component.component_type.is_event() {
            return None;
        }
        let is_principal = |value: &ArchivedICalendarValue| {
            value
                .as_text()
                .is_some_and(|address| identities.contains(address))
        };
        let mut busy = ComponentBusy {
            status: EventStatus::Confirmed,
            participation: Participation::None,
            has_attendees: false,
            is_recurrent_or_override: false,
        };

        for entry in component.entries.iter() {
            match (&entry.name, entry.values.first()) {
                (
                    ArchivedICalendarProperty::Status,
                    Some(ArchivedICalendarValue::Status(status)),
                ) => {
                    busy.status = match status {
                        ArchivedICalendarStatus::Cancelled => return None,
                        ArchivedICalendarStatus::Confirmed => EventStatus::Confirmed,
                        ArchivedICalendarStatus::Tentative => EventStatus::Tentative,
                        _ => EventStatus::Other,
                    };
                }
                (
                    ArchivedICalendarProperty::Transp,
                    Some(ArchivedICalendarValue::Transparency(
                        ArchivedICalendarTransparency::Transparent,
                    )),
                ) if role == PrincipalRole::Owner => {
                    return None;
                }
                (ArchivedICalendarProperty::Organizer, Some(value)) => {
                    if busy.participation == Participation::None && is_principal(value) {
                        busy.participation = Participation::Organizer;
                    }
                }
                (ArchivedICalendarProperty::Attendee, Some(value)) => {
                    busy.has_attendees = true;
                    if is_principal(value) {
                        busy.participation = Participation::Attendee(
                            match entry.parameters(&ICalendarParameterName::Partstat).next() {
                                Some(ArchivedICalendarParameterValue::Partstat(
                                    ArchivedICalendarParticipationStatus::Accepted,
                                )) => ParticipationStatus::Accepted,
                                Some(ArchivedICalendarParameterValue::Partstat(
                                    ArchivedICalendarParticipationStatus::Tentative,
                                )) => ParticipationStatus::Tentative,
                                Some(ArchivedICalendarParameterValue::Partstat(
                                    ArchivedICalendarParticipationStatus::Declined,
                                )) => ParticipationStatus::Declined,
                                _ => ParticipationStatus::Other,
                            },
                        );
                    }
                }
                (
                    ArchivedICalendarProperty::Rrule
                    | ArchivedICalendarProperty::Rdate
                    | ArchivedICalendarProperty::RecurrenceId,
                    _,
                ) => {
                    busy.is_recurrent_or_override = true;
                }
                _ => (),
            }
        }

        Some(busy)
    }

    fn is_attending(&self) -> bool {
        matches!(
            self.participation,
            Participation::Organizer
                | Participation::Attendee(
                    ParticipationStatus::Accepted | ParticipationStatus::Tentative
                )
        )
    }

    fn participation_status(&self) -> ParticipationStatus {
        match self.participation {
            Participation::Attendee(status) => status,
            Participation::Organizer => ParticipationStatus::Accepted,
            Participation::None if !self.has_attendees => ParticipationStatus::Accepted,
            Participation::None => ParticipationStatus::Other,
        }
    }

    fn busy_status(&self) -> BusyStatus {
        let participation_status = self.participation_status();
        if self.status == EventStatus::Tentative
            || participation_status == ParticipationStatus::Tentative
        {
            BusyStatus::Tentative
        } else if self.status == EventStatus::Confirmed
            && participation_status == ParticipationStatus::Accepted
        {
            BusyStatus::Confirmed
        } else {
            BusyStatus::Unavailable
        }
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

#[cfg(test)]
mod tests {
    use super::{BusyInterval, BusyTimeline};
    use jmap_proto::method::availability::BusyStatus;

    fn merge(intervals: &[(i64, i64, BusyStatus)]) -> Vec<(i64, i64, BusyStatus)> {
        let mut timeline = BusyTimeline::default();
        for (start, end, status) in intervals {
            timeline.insert(*start, *end, *status);
        }
        let mut merged: Vec<BusyInterval<()>> = Vec::new();
        timeline.merge_into(&mut merged);
        merged
            .into_iter()
            .map(|interval| (interval.start, interval.end, interval.status))
            .collect()
    }

    #[test]
    fn overlapping_periods_split_by_precedence() {
        assert_eq!(
            merge(&[
                (100, 120, BusyStatus::Confirmed),
                (110, 130, BusyStatus::Tentative),
                (125, 140, BusyStatus::Unavailable),
            ]),
            [
                (100, 120, BusyStatus::Confirmed),
                (120, 125, BusyStatus::Tentative),
                (125, 140, BusyStatus::Unavailable),
            ]
        );
        assert_eq!(
            merge(&[
                (0, 100, BusyStatus::Tentative),
                (40, 60, BusyStatus::Confirmed),
            ]),
            [
                (0, 40, BusyStatus::Tentative),
                (40, 60, BusyStatus::Confirmed),
                (60, 100, BusyStatus::Tentative),
            ]
        );
    }

    #[test]
    fn adjacent_periods_merge_unless_status_differs() {
        assert_eq!(
            merge(&[
                (0, 10, BusyStatus::Confirmed),
                (10, 20, BusyStatus::Confirmed),
                (30, 40, BusyStatus::Confirmed),
                (40, 50, BusyStatus::Unavailable),
            ]),
            [
                (0, 20, BusyStatus::Confirmed),
                (30, 40, BusyStatus::Confirmed),
                (40, 50, BusyStatus::Unavailable),
            ]
        );
    }
}
