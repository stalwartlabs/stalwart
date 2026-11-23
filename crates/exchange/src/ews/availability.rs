/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod suggest;

use self::suggest::{Attendee, Suggestions};
use super::{
    config::calendar_work_hours,
    context::{EwsCaller, EwsContext},
    directory::LEGACY_DN_MARKER,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::{folders::default_container, identity::principal_from_dn};
use calcard::{
    common::timezone::Tz,
    icalendar::{ArchivedICalendarComponent, ArchivedICalendarProperty, ICalendarProperty},
};
use common::{KV_RATE_LIMIT_AVAILABILITY, Server, auth::AccessToken};
use exchange_proto::{
    common::{LocalDateTime, SystemTime, XsDateTime, XsZone},
    convert::{blob::TzRule, work_hours::WorkHours},
    ews::{
        Fault, Status,
        requests::availability::GetUserAvailability,
        responses::availability::{
            FreeBusyResponse, GetUserAvailabilityResponse, SuggestionsResponse,
        },
        schema::{DayOfWeek, FreeBusyViewKind, LegacyFreeBusy, MeetingAttendeeType, ResponseCode},
        types::{
            availability::{SerializableTimeZone, SerializableTimeZoneTime},
            generated::{
                CalendarEvent, CalendarEventDetails, FreeBusyView, WorkingHours, WorkingPeriod,
            },
            timezone::TimeZoneDefinition,
            value::{DateTime, List},
        },
        write_fault,
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent,
        availability::{
            AvailabilityCalendars, BusyLevel, ComponentBusy, DefaultFreeBusy, PrincipalRole,
            RelevantCalendar,
        },
        expand::MAX_UTC_OFFSET,
        identity::ParticipantIdentityAddresses,
        privacy::EventPrivacy,
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jiff::{Timestamp, tz::Offset};
use registry::schema::enums::Permission;
use std::{borrow::Cow, str::FromStr};
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{
    OverlapRule, TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, PrincipalField},
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

const MAX_MAILBOXES: usize = 100;
const MAX_WINDOW_SECONDS: i64 = 62 * 86_400;
const DEFAULT_INTERVAL_MINUTES: i32 = 30;
const MIN_INTERVAL_MINUTES: i32 = 5;
const MAX_INTERVAL_MINUTES: i32 = 1440;
const SECONDS_PER_MINUTE: i64 = 60;
const LEVELS: usize = 3;
const MERGED_FREE: u8 = b'0';
const NO_VIEW: &str = "FreeBusyViewOptions or SuggestionsViewOptions is required.";
const VIEW_NONE: &str = "The requested free/busy view type is not valid.";
const TOO_MANY_MAILBOXES: &str = "Too many mailboxes in MailboxDataArray.";
const EMPTY_MAILBOXES: &str = "The MailboxData array is empty.";
const BAD_WINDOW: &str = "The start of the time window must be before its end.";
const WINDOW_TOO_BIG: &str = "The time window is too long.";
const BAD_INTERVAL: &str = "MergedFreeBusyIntervalInMinutes must be between 5 and 1440.";
const RATE_LIMITED: &str = "Too many availability requests, please try again later.";
const NOT_FOUND: &str = "Unable to resolve the email address to a mailbox.";
const NO_ACCESS: &str = "The caller does not have free/busy access to the mailbox.";
const TOO_MANY_EVENTS: &str = "The time window contains too many occurrences.";
const CDO_BUSY_STATUS: &str = "X-MICROSOFT-CDO-BUSYSTATUS";
const CDO_INTENDED_STATUS: &str = "X-MICROSOFT-CDO-INTENDEDSTATUS";

#[derive(Debug, Clone, Copy)]
struct Window {
    start: i64,
    end: i64,
    interval: i64,
    zone: RequestZone,
}

#[derive(Debug, Clone, Copy)]
enum RequestZone {
    Rule(TzRule),
    Named(Tz),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detail {
    FreeBusy,
    Detailed,
}

#[derive(Debug, Clone, Copy)]
struct View {
    detail: Detail,
    merged: bool,
    events: bool,
}

struct Candidate {
    document_id: u32,
    calendar: RelevantCalendar,
    privacy: EventPrivacy,
    readable: bool,
    disclosed: bool,
}

#[derive(Debug, Clone, Copy)]
struct Target {
    free_busy: Option<usize>,
    suggest: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Tentative,
    Busy,
    Oof,
}

struct Busy {
    start: i64,
    end: i64,
    level: Level,
    details: Option<usize>,
}

struct Details {
    subject: Option<String>,
    location: Option<String>,
    is_meeting: bool,
    is_recurring: bool,
    is_exception: bool,
    is_reminder_set: bool,
    is_private: bool,
}

type Refusal = (ResponseCode, &'static str);

struct Mailbox {
    busy: Vec<Busy>,
    details: Vec<Details>,
    detail: Detail,
    work_hours: Option<WorkHours>,
}

pub(crate) async fn get_user_availability(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &GetUserAvailability<'_>,
    header_zone: Option<&TimeZoneDefinition<'_>>,
) -> trc::Result<HttpResponse> {
    let access_token = caller.access_token;
    let zone = RequestZone::new(request.time_zone.as_ref(), header_zone);
    let max_window = i64::try_from(server.core.groupware.max_availability_duration)
        .unwrap_or(i64::MAX)
        .min(MAX_WINDOW_SECONDS);
    let parsed = parse_request(request, zone, max_window).and_then(|query| {
        request
            .suggestions_view_options
            .as_ref()
            .map(|options| Suggestions::parse(options, zone, max_window))
            .transpose()
            .map(|suggestions| (query, suggestions))
    });
    let (query, suggestions) = match parsed {
        Ok(parsed) => parsed,
        Err(refusal) => return Ok(fault_response(ctx, refusal)),
    };
    let suggest_window = suggestions.as_ref().and_then(Suggestions::scan_window);
    if (query.is_some() || suggest_window.is_some()) && rate_limited(server, access_token).await? {
        return Ok(fault_response(
            ctx,
            (ResponseCode::ErrorServerBusy, RATE_LIMITED),
        ));
    }
    let combined = match (query, suggest_window) {
        (Some((_, window)), Some(scan)) if scan.start <= window.end && window.start <= scan.end => {
            Some(Window {
                start: window.start.min(scan.start),
                end: window.end.max(scan.end),
                ..window
            })
        }
        _ => None,
    };
    let allowed = ctx.account.data_types.contains(DataType::CalendarEvent);
    let organizer_index = request
        .mailboxes
        .iter()
        .position(|data| data.attendee_type == MeetingAttendeeType::Organizer)
        .filter(|_| allowed && suggest_window.is_some());
    let organizer = match organizer_index.and_then(|index| request.mailboxes.get(index)) {
        Some(data) => target_account(server, access_token, &data.email.address).await?,
        None => None,
    };
    let mut results: Vec<Result<Mailbox, Refusal>> = Vec::new();
    let mut targets = Vec::new();
    if query.is_some() || suggest_window.is_some() {
        let count = request.mailboxes.len();
        targets.reserve_exact(count);
        let mut scanned: Vec<(u32, Target)> = Vec::with_capacity(count);
        let mut limited = false;
        for (index, data) in request.mailboxes.iter().enumerate() {
            let target = if !allowed {
                Target::refused(
                    &mut results,
                    (ResponseCode::ErrorNoFreeBusyAccess, NO_ACCESS),
                )
            } else if let Some(account_id) = if organizer_index == Some(index) {
                organizer
            } else {
                target_account(server, access_token, &data.email.address).await?
            } {
                if let Some(&(_, target)) = scanned.iter().find(|(id, _)| *id == account_id) {
                    targets.push(target);
                    continue;
                }
                let charged = !scanned.is_empty();
                limited = limited || (charged && rate_limited(server, access_token).await?);
                let target = if limited {
                    Target::refused(&mut results, (ResponseCode::ErrorServerBusy, RATE_LIMITED))
                } else {
                    let hours = organizer == Some(account_id);
                    let free_busy = match query {
                        Some((view, window)) => {
                            let view = View {
                                events: view.events || (hours && combined.is_some()),
                                ..view
                            };
                            let window = combined.unwrap_or(window);
                            Some(push_result(
                                &mut results,
                                mailbox(server, access_token, account_id, view, window).await?,
                            ))
                        }
                        None => None,
                    };
                    let suggest = match suggest_window {
                        Some(_) if combined.is_some() => free_busy,
                        Some(scan) => {
                            let view = View {
                                detail: Detail::FreeBusy,
                                merged: false,
                                events: hours && query.is_none_or(|(view, _)| !view.events),
                            };
                            Some(push_result(
                                &mut results,
                                mailbox(server, access_token, account_id, view, scan).await?,
                            ))
                        }
                        None => None,
                    };
                    Target { free_busy, suggest }
                };
                scanned.push((account_id, target));
                target
            } else {
                Target::refused(
                    &mut results,
                    (ResponseCode::ErrorMailRecipientNotFound, NOT_FOUND),
                )
            };
            targets.push(target);
        }
    }
    let free_busy = match query {
        Some((view, window)) => targets
            .iter()
            .filter_map(|target| target.free_busy.and_then(|index| results.get(index)))
            .map(|mailbox| match mailbox {
                Ok(mailbox) => FreeBusyResponse {
                    status: Status::success(),
                    view: Some(mailbox.render(view, window)),
                },
                Err((code, text)) => FreeBusyResponse {
                    status: Status::error(*code, *text),
                    view: None,
                },
            })
            .collect(),
        None => Vec::new(),
    };
    let suggestions = suggestions.map(|suggestions| {
        let scanned = |target: &Target| {
            target
                .suggest
                .and_then(|index| results.get(index))
                .and_then(|result| result.as_ref().ok())
        };
        let attendees = request
            .mailboxes
            .iter()
            .zip(&targets)
            .map(|(data, target)| Attendee {
                busy: scanned(target).map(|mailbox| mailbox.busy.as_slice()),
                exclude: data.exclude_conflicts.unwrap_or(false),
            })
            .collect::<Vec<_>>();
        let work_hours = organizer_index
            .and_then(|index| targets.get(index))
            .and_then(|target| {
                [target.suggest, target.free_busy]
                    .into_iter()
                    .flatten()
                    .filter_map(|index| results.get(index)?.as_ref().ok())
                    .find_map(|mailbox| mailbox.work_hours.as_ref())
            });
        SuggestionsResponse {
            status: Status::success(),
            days: suggestions.build(&attendees, work_hours),
        }
    });
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&GetUserAvailabilityResponse {
        free_busy,
        suggestions,
    });
    Ok(ews_response(out))
}

fn push_result(
    results: &mut Vec<Result<Mailbox, Refusal>>,
    result: Result<Mailbox, Refusal>,
) -> usize {
    results.push(result);
    results.len() - 1
}

impl Target {
    fn refused(results: &mut Vec<Result<Mailbox, Refusal>>, refusal: Refusal) -> Self {
        let index = Some(push_result(results, Err(refusal)));
        Target {
            free_busy: index,
            suggest: index,
        }
    }
}

fn parse_request(
    request: &GetUserAvailability<'_>,
    zone: RequestZone,
    max_window: i64,
) -> Result<Option<(View, Window)>, Refusal> {
    if request.mailboxes.is_empty() {
        return Err((ResponseCode::ErrorInvalidRequest, EMPTY_MAILBOXES));
    }
    if request.mailboxes.len() > MAX_MAILBOXES {
        return Err((ResponseCode::ErrorInvalidRequest, TOO_MANY_MAILBOXES));
    }
    let Some(options) = &request.free_busy_view_options else {
        return if request.suggestions_view_options.is_some() {
            Ok(None)
        } else {
            Err((ResponseCode::ErrorInvalidFreeBusyViewType, NO_VIEW))
        };
    };
    let view = match options.requested_view.unwrap_or(FreeBusyViewKind::Detailed) {
        FreeBusyViewKind::None => {
            return Err((ResponseCode::ErrorInvalidFreeBusyViewType, VIEW_NONE));
        }
        FreeBusyViewKind::MergedOnly => View {
            detail: Detail::FreeBusy,
            merged: true,
            events: false,
        },
        FreeBusyViewKind::FreeBusyMerged => View {
            detail: Detail::FreeBusy,
            merged: true,
            events: true,
        },
        FreeBusyViewKind::FreeBusy => View {
            detail: Detail::FreeBusy,
            merged: false,
            events: true,
        },
        FreeBusyViewKind::Detailed => View {
            detail: Detail::Detailed,
            merged: false,
            events: true,
        },
        FreeBusyViewKind::DetailedMerged => View {
            detail: Detail::Detailed,
            merged: true,
            events: true,
        },
    };
    let interval = options
        .merged_free_busy_interval_in_minutes
        .unwrap_or(DEFAULT_INTERVAL_MINUTES);
    if !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&interval) {
        return Err((ResponseCode::ErrorInvalidRequest, BAD_INTERVAL));
    }
    let (Some(start), Some(end)) = (
        zone.utc_of(&options.time_window.start_time),
        zone.utc_of(&options.time_window.end_time),
    ) else {
        return Err((ResponseCode::ErrorInvalidTimeInterval, BAD_WINDOW));
    };
    if start >= end {
        return Err((ResponseCode::ErrorInvalidTimeInterval, BAD_WINDOW));
    }
    if end - start > max_window {
        return Err((ResponseCode::ErrorTimeIntervalTooBig, WINDOW_TOO_BIG));
    }
    Ok(Some((
        view,
        Window {
            start,
            end,
            interval: i64::from(interval) * SECONDS_PER_MINUTE,
            zone,
        },
    )))
}

pub(crate) async fn rate_limited(server: &Server, access_token: &AccessToken) -> trc::Result<bool> {
    let Some(rate) = &server.core.groupware.availability_rate else {
        return Ok(false);
    };
    if access_token.has_permission(Permission::UnlimitedRequests) {
        return Ok(false);
    }
    server
        .core
        .storage
        .memory
        .is_rate_allowed(
            KV_RATE_LIMIT_AVAILABILITY,
            &access_token.account_id().to_be_bytes(),
            rate,
        )
        .await
        .caused_by(trc::location!())
        .map(|retry| retry.is_some())
}

async fn mailbox(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    view: View,
    window: Window,
) -> trc::Result<Result<Mailbox, Refusal>> {
    let resources = server
        .fetch_groupware_resources(
            access_token.account_id(),
            account_id,
            SyncCollection::Calendar,
        )
        .await
        .caused_by(trc::location!())?;
    let owner = access_token.is_member(account_id);
    let default = DefaultFreeBusy::resolve(server, access_token, account_id).await?;
    let Some(mut calendars) =
        AvailabilityCalendars::owner(&resources, account_id, access_token, default)
    else {
        return Ok(Err((ResponseCode::ErrorNoFreeBusyAccess, NO_ACCESS)));
    };
    let detail = if view.detail == Detail::Detailed
        && (owner
            || !resources
                .shared_containers(access_token, [Acl::ReadItems], true)
                .is_empty())
    {
        Detail::Detailed
    } else {
        Detail::FreeBusy
    };
    let default_calendar = if view.events {
        default_container(
            server,
            account_id,
            PrincipalField::DefaultCalendarId,
            &resources,
        )
        .await?
    } else {
        None
    };
    let work_hours = match default_calendar {
        Some(calendar_id)
            if owner
                || default == DefaultFreeBusy::Granted
                || resources.has_access_to_container(
                    access_token,
                    calendar_id,
                    Bitmap::from_iter([Acl::ReadItems, Acl::SchedulingReadFreeBusy]),
                ) =>
        {
            calendar_work_hours(server, account_id, calendar_id).await?
        }
        _ => None,
    };
    let candidates_range = TimeRange::new(
        window.start.saturating_sub(MAX_UTC_OFFSET),
        window.end.saturating_add(MAX_UTC_OFFSET),
    );
    let mut candidates = Vec::new();
    for resource in resources.resources.iter() {
        let (Some((start, end)), Some(flags)) =
            (resource.event_time_range(), resource.event_flags())
        else {
            continue;
        };
        let privacy = EventPrivacy::from_flags(flags);
        if (privacy == EventPrivacy::Secret && !owner) || !candidates_range.overlaps(start, end) {
            continue;
        }
        let names = resource.child_names();
        let Some(calendar) = calendars.relevant_calendar(names) else {
            continue;
        };
        let readable = detail == Detail::Detailed && calendars.may_read_items(names);
        candidates.push(Candidate {
            document_id: resource.document_id(),
            calendar,
            privacy,
            readable,
            disclosed: readable && privacy == EventPrivacy::Public,
        });
    }
    if candidates.is_empty() {
        return Ok(Ok(Mailbox {
            busy: Vec::new(),
            details: Vec::new(),
            detail,
            work_hours,
        }));
    }
    candidates.sort_unstable_by_key(|candidate| candidate.document_id);
    let documents = candidates
        .iter()
        .map(|candidate| candidate.document_id)
        .collect::<RoaringBitmap>();
    let identities = server
        .account_identity_addresses(account_id)
        .await
        .caused_by(trc::location!())?;
    let filter = TimeRange::new(window.start, window.end);
    let max_instances = server.core.groupware.max_ical_instances;
    let mut found = Mailbox {
        busy: Vec::new(),
        details: Vec::new(),
        detail,
        work_hours,
    };
    let mut components = Vec::new();
    let mut overflow = false;
    server
        .archives(
            account_id,
            Collection::CalendarEvent,
            CalendarEventField::Content.into(),
            &documents,
            |document_id, archive| {
                let Ok(index) = candidates
                    .binary_search_by_key(&document_id, |candidate| candidate.document_id)
                else {
                    return Ok(true);
                };
                let Some(candidate) = candidates.get(index) else {
                    return Ok(true);
                };
                let event = archive.unarchive::<CalendarEventContent>()?;
                let all = &event.data.event.components;
                components.clear();
                components.extend(all.iter().map(|component| {
                    ComponentBusy::parse(component, &identities, PrincipalRole::Owner)
                        .filter(|busy| candidate.calendar.includes(busy))
                        .and_then(|busy| {
                            Some((busy, intended_level(component, &busy)?, None::<usize>))
                        })
                }));
                if components.iter().all(Option::is_none) {
                    return Ok(true);
                }
                for expansion in event
                    .data
                    .expand(candidate.calendar.tz, filter, OverlapRule::CalDav)
                    .unwrap_or_default()
                {
                    let Ok(comp_id) = usize::try_from(expansion.comp_id) else {
                        continue;
                    };
                    let Some(Some((busy, level, details))) = components.get_mut(comp_id) else {
                        continue;
                    };
                    if expansion.end <= expansion.start {
                        continue;
                    }
                    if found.busy.len() >= max_instances {
                        overflow = true;
                        return Ok(false);
                    }
                    let details = match (candidate.readable, *details) {
                        (false, _) => None,
                        (true, Some(index)) => Some(index),
                        (true, None) => {
                            let index = found.details.len();
                            found.details.push(event_details(
                                all,
                                comp_id,
                                busy.is_recurrent_or_override(),
                                candidate,
                            ));
                            *details = Some(index);
                            Some(index)
                        }
                    };
                    found.busy.push(Busy {
                        start: expansion.start,
                        end: expansion.end,
                        level: *level,
                        details,
                    });
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    if overflow {
        return Ok(Err((
            ResponseCode::ErrorFreeBusyGenerationFailed,
            TOO_MANY_EVENTS,
        )));
    }
    found
        .busy
        .sort_unstable_by_key(|busy| (busy.start, busy.end));
    Ok(Ok(found))
}

pub(crate) async fn account_merged_free_busy(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    start: i64,
    end: i64,
    interval: i64,
) -> trc::Result<Option<String>> {
    let window = Window {
        start,
        end,
        interval,
        zone: RequestZone::Rule(TzRule::default()),
    };
    let view = View {
        detail: Detail::FreeBusy,
        merged: true,
        events: false,
    };
    Ok(mailbox(server, access_token, account_id, view, window)
        .await?
        .ok()
        .map(|mailbox| merged_free_busy(&mailbox.busy, window)))
}

async fn target_account(
    server: &Server,
    access_token: &AccessToken,
    address: &str,
) -> trc::Result<Option<u32>> {
    let address = address.trim();
    let legacy_dn = address.starts_with(LEGACY_DN_MARKER);
    let account_id = if legacy_dn {
        principal_from_dn(address.as_bytes())
    } else {
        server
            .account_id_from_email(address, true)
            .await
            .caused_by(trc::location!())?
    };
    let Some(account_id) = account_id else {
        return Ok(None);
    };
    let query_any = access_token.has_permission(Permission::SysAccountQuery);
    if access_token.is_member(account_id) || (query_any && !legacy_dn) {
        return Ok(Some(account_id));
    }
    Ok(server
        .try_account(account_id)
        .await
        .caused_by(trc::location!())?
        .filter(|account| query_any || account.is_same_tenant(access_token))
        .map(|_| account_id))
}

fn event_details(
    components: &[ArchivedICalendarComponent],
    comp_id: usize,
    is_recurring: bool,
    candidate: &Candidate,
) -> Details {
    let component = components.get(comp_id);
    let is_private = candidate.privacy != EventPrivacy::Public;
    let text = |property| {
        component
            .filter(|_| candidate.disclosed)
            .and_then(|component| component.property(&property))
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_text())
            .map(str::to_string)
    };
    Details {
        subject: text(ICalendarProperty::Summary),
        location: text(ICalendarProperty::Location),
        is_meeting: component
            .is_some_and(|component| component.property(&ICalendarProperty::Attendee).is_some()),
        is_recurring,
        is_exception: component.is_some_and(|component| component.is_recurrence_override()),
        is_reminder_set: component.is_some_and(|component| {
            component.component_ids.iter().any(|id| {
                usize::try_from(id.to_native())
                    .ok()
                    .and_then(|id| components.get(id))
                    .is_some_and(|child| child.component_type.is_alarm())
            })
        }),
        is_private,
    }
}

impl Mailbox {
    fn render(&self, view: View, window: Window) -> FreeBusyView<'_> {
        let kind = match (view.events, self.detail, view.merged) {
            (false, ..) => FreeBusyViewKind::MergedOnly,
            (true, Detail::Detailed, true) => FreeBusyViewKind::DetailedMerged,
            (true, Detail::Detailed, false) => FreeBusyViewKind::Detailed,
            (true, Detail::FreeBusy, true) => FreeBusyViewKind::FreeBusyMerged,
            (true, Detail::FreeBusy, false) => FreeBusyViewKind::FreeBusy,
        };
        let events = view.events.then(|| {
            self.busy
                .iter()
                .filter(|busy| busy.start < window.end && window.start < busy.end)
                .filter_map(|busy| {
                    Some(CalendarEvent {
                        start_time: window.zone.local_of(busy.start)?,
                        end_time: window.zone.local_of(busy.end)?,
                        busy_type: busy.level.legacy(),
                        calendar_event_details: busy
                            .details
                            .and_then(|index| self.details.get(index))
                            .map(Details::render),
                    })
                })
                .collect()
        });
        FreeBusyView {
            free_busy_view_type: kind,
            merged_free_busy: view
                .merged
                .then(|| Cow::Owned(merged_free_busy(&self.busy, window))),
            calendar_event_array: events.map(List),
            working_hours: self
                .work_hours
                .as_ref()
                .filter(|_| view.events)
                .map(working_hours),
        }
    }
}

impl Details {
    fn render(&self) -> CalendarEventDetails<'_> {
        CalendarEventDetails {
            id: None,
            subject: self.subject.as_deref().map(Cow::Borrowed),
            location: self.location.as_deref().map(Cow::Borrowed),
            is_meeting: self.is_meeting,
            is_recurring: self.is_recurring,
            is_exception: self.is_exception,
            is_reminder_set: self.is_reminder_set,
            is_private: self.is_private,
        }
    }
}

fn intended_level(component: &ArchivedICalendarComponent, busy: &ComponentBusy) -> Option<Level> {
    match busy.busy_level() {
        BusyLevel::Tentative => return Some(Level::Tentative),
        BusyLevel::Unavailable => return Some(Level::Busy),
        BusyLevel::Confirmed => {}
    }
    let mut busy_status = None;
    let mut intended_status = None;
    for entry in component.entries.iter() {
        let (ArchivedICalendarProperty::Other(name), Some(value)) =
            (&entry.name, entry.values.first())
        else {
            continue;
        };
        if name.eq_ignore_ascii_case(CDO_BUSY_STATUS) {
            busy_status = value.as_text();
        } else if name.eq_ignore_ascii_case(CDO_INTENDED_STATUS) {
            intended_status = value.as_text();
        }
    }
    match cdo_level(busy_status) {
        Some(Some(Level::Tentative)) => {
            cdo_level(intended_status).unwrap_or(Some(Level::Tentative))
        }
        Some(level) => level,
        None => Some(Level::Busy),
    }
}

fn cdo_level(status: Option<&str>) -> Option<Option<Level>> {
    status
        .and_then(|status| {
            hashify::map_ignore_case!(status.trim().as_bytes(), Option<Level>,
                "BUSY" => Some(Level::Busy),
                "TENTATIVE" => Some(Level::Tentative),
                "OOF" => Some(Level::Oof),
                "FREE" => None,
                "WORKINGELSEWHERE" => None,
            )
        })
        .copied()
}

impl Level {
    const ALL: [Level; LEVELS] = [Level::Tentative, Level::Busy, Level::Oof];

    fn legacy(self) -> LegacyFreeBusy {
        match self {
            Level::Tentative => LegacyFreeBusy::Tentative,
            Level::Busy => LegacyFreeBusy::Busy,
            Level::Oof => LegacyFreeBusy::Oof,
        }
    }

    fn rank(self) -> usize {
        self as usize
    }
}

fn merged_free_busy(busy: &[Busy], window: Window) -> String {
    let span = window.end - window.start;
    let slots = usize::try_from((span + window.interval - 1) / window.interval).unwrap_or(0);
    let mut counts = vec![[0i32; LEVELS]; slots + 1];
    let slot_of = |time: i64, round_up: bool| {
        let offset = (time - window.start).clamp(0, span);
        let slot = if round_up {
            (offset + window.interval - 1) / window.interval
        } else {
            offset / window.interval
        };
        usize::try_from(slot).unwrap_or(0).min(slots)
    };
    for busy in busy {
        let first = slot_of(busy.start, false);
        let last = slot_of(busy.end, true);
        if first >= last {
            continue;
        }
        let rank = busy.level.rank();
        if let Some(count) = counts.get_mut(first).and_then(|count| count.get_mut(rank)) {
            *count += 1;
        }
        if let Some(count) = counts.get_mut(last).and_then(|count| count.get_mut(rank)) {
            *count -= 1;
        }
    }
    let mut merged = String::with_capacity(slots);
    let mut active = [0i32; LEVELS];
    for delta in counts.iter().take(slots) {
        for (active, delta) in active.iter_mut().zip(delta) {
            *active += delta;
        }
        let digit = active
            .iter()
            .rposition(|count| *count > 0)
            .map_or(MERGED_FREE, |rank| MERGED_FREE + 1 + rank as u8);
        merged.push(char::from(digit));
    }
    merged
}

impl RequestZone {
    fn new(
        body: Option<&SerializableTimeZone<'_>>,
        header: Option<&TimeZoneDefinition<'_>>,
    ) -> Self {
        if let Some(zone) = body {
            return RequestZone::Rule(zone_rule(zone));
        }
        header
            .and_then(|definition| definition.id.as_deref())
            .and_then(|id| Tz::from_str(id).ok())
            .filter(|tz| !tz.is_floating())
            .map_or(RequestZone::Rule(TzRule::default()), RequestZone::Named)
    }

    fn utc_of(&self, time: &DateTime) -> Option<i64> {
        match time {
            DateTime::Parsed(XsDateTime {
                local,
                zone: XsZone::Floating,
            }) => self.utc_of_local(*local),
            _ => time.to_utc().map(|seconds| seconds.0),
        }
    }

    fn utc_of_local(&self, local: LocalDateTime) -> Option<i64> {
        let naive = local.to_unix_seconds().0;
        match self {
            RequestZone::Rule(rule) => Some(
                naive
                    .saturating_sub(i64::from(rule.utc_offset_minutes(local)) * SECONDS_PER_MINUTE),
            ),
            RequestZone::Named(tz) => tz
                .from_local(Offset::UTC.to_datetime(Timestamp::from_second(naive).ok()?))
                .map(|zoned| zoned.timestamp()),
        }
    }

    fn local_of(&self, utc: i64) -> Option<DateTime> {
        self.local_naive(utc).map(floating)
    }

    fn local_naive(&self, utc: i64) -> Option<LocalDateTime> {
        match self {
            RequestZone::Rule(rule) => {
                let standard = -i64::from(rule.bias.saturating_add(rule.standard_bias));
                let guess = civil(utc.saturating_add(standard * SECONDS_PER_MINUTE))?;
                let offset = i64::from(rule.utc_offset_minutes(guess));
                civil(utc.saturating_add(offset * SECONDS_PER_MINUTE))
            }
            RequestZone::Named(tz) => civil(
                tz.from_timestamp(Timestamp::from_second(utc).ok()?)
                    .naive_timestamp(),
            ),
        }
    }
}

fn floating(local: LocalDateTime) -> DateTime {
    DateTime::Parsed(XsDateTime {
        local,
        zone: XsZone::Floating,
    })
}

fn working_hours(hours: &WorkHours) -> WorkingHours<'static> {
    WorkingHours {
        time_zone: SerializableTimeZone {
            bias: hours.zone.bias,
            standard_time: Some(zone_time(
                hours.zone.standard_bias,
                &hours.zone.standard_date,
            )),
            daylight_time: Some(zone_time(
                hours.zone.daylight_bias,
                &hours.zone.daylight_date,
            )),
        },
        working_period_array: List(vec![WorkingPeriod {
            day_of_week: hours.days,
            start_time_in_minutes: i32::from(hours.start_minutes),
            end_time_in_minutes: i32::from(hours.end_minutes),
        }]),
    }
}

fn zone_time(bias: i32, date: &SystemTime) -> SerializableTimeZoneTime<'static> {
    SerializableTimeZoneTime {
        bias,
        time: Cow::Owned(format!(
            "{:02}:{:02}:{:02}",
            date.hour, date.minute, date.second
        )),
        day_order: i16::try_from(date.day).unwrap_or_default(),
        month: i16::try_from(date.month).unwrap_or_default(),
        day_of_week: DayOfWeek::ALL
            .get(usize::from(date.day_of_week))
            .copied()
            .unwrap_or(DayOfWeek::Sunday),
        year: (date.year != 0).then(|| Cow::Owned(date.year.to_string())),
    }
}

fn zone_rule(zone: &SerializableTimeZone<'_>) -> TzRule {
    let (standard_bias, standard_date) = transition(zone.standard_time.as_ref());
    let (daylight_bias, daylight_date) = transition(zone.daylight_time.as_ref());
    TzRule {
        bias: zone.bias,
        standard_bias,
        daylight_bias,
        standard_date,
        daylight_date,
        ..TzRule::default()
    }
}

fn transition(time: Option<&SerializableTimeZoneTime<'_>>) -> (i32, SystemTime) {
    let Some(time) = time else {
        return (0, SystemTime::default());
    };
    let mut clock = time
        .time
        .splitn(3, ':')
        .map(|part| part.trim().parse::<u16>().ok());
    let (Some(Some(hour)), Some(Some(minute)), second, Some(day_of_week), Ok(month), Ok(day)) = (
        clock.next(),
        clock.next(),
        clock.next().map(|second| second.unwrap_or(0)).unwrap_or(0),
        weekday_index(time.day_of_week),
        u16::try_from(time.month),
        u16::try_from(time.day_order),
    ) else {
        return (time.bias, SystemTime::default());
    };
    (
        time.bias,
        SystemTime {
            month,
            day_of_week,
            day,
            hour,
            minute,
            second,
            ..SystemTime::default()
        },
    )
}

fn weekday_index(day: DayOfWeek) -> Option<u16> {
    match day {
        DayOfWeek::Sunday => Some(0),
        DayOfWeek::Monday => Some(1),
        DayOfWeek::Tuesday => Some(2),
        DayOfWeek::Wednesday => Some(3),
        DayOfWeek::Thursday => Some(4),
        DayOfWeek::Friday => Some(5),
        DayOfWeek::Saturday => Some(6),
        DayOfWeek::Day | DayOfWeek::Weekday | DayOfWeek::WeekendDay => None,
    }
}

fn civil(seconds: i64) -> Option<LocalDateTime> {
    let civil = Offset::UTC.to_datetime(Timestamp::from_second(seconds).ok()?);
    LocalDateTime::new(
        u16::try_from(civil.year()).ok()?,
        u8::try_from(civil.month()).ok()?,
        u8::try_from(civil.day()).ok()?,
        u8::try_from(civil.hour()).ok()?,
        u8::try_from(civil.minute()).ok()?,
        u8::try_from(civil.second()).ok()?,
        0,
    )
}

fn fault_response(ctx: &EwsContext, (code, text): Refusal) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    write_fault(
        &mut out,
        &ctx.version,
        &Fault {
            code,
            text: Cow::Borrowed(text),
            line: None,
            message_xml: None,
        },
    );
    ews_response(out).with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/ews/availability/tests.rs"]
mod tests;
