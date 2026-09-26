/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::query::CalendarQueryHandler;
use crate::{DavError, calendar::query::EventTimeRange, common::uri::DavUriResource};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ArchivedICalendarComponentType, ArchivedICalendarEntry, ArchivedICalendarParameterName,
        ArchivedICalendarParameterValue, ArchivedICalendarProperty, ArchivedICalendarStatus,
        ArchivedICalendarValue, ICalendar, ICalendarComponent, ICalendarComponentType,
        ICalendarEntry, ICalendarFreeBusyType, ICalendarParameter, ICalendarPeriod,
        ICalendarProperty, ICalendarTransparency, ICalendarValue,
    },
};
use common::{DavResourcePath, GroupwareResources, PROD_ID, Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::FreeBusyQuery};
use groupware::{
    cache::GroupwareCache,
    calendar::{CalendarEventContent, privacy::EventPrivacy},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::str::FromStr;
use store::{
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{now, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{
    OverlapCondition, TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};

pub(crate) trait CalendarFreebusyRequestHandler: Sync + Send {
    fn handle_calendar_freebusy_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: FreeBusyQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn build_freebusy_object(
        &self,
        access_token: &AccessToken,
        request: FreeBusyQuery,
        resources: &GroupwareResources,
        account_id: u32,
        resource: DavResourcePath<'_>,
    ) -> impl Future<Output = crate::Result<ICalendar>> + Send;
}

impl CalendarFreebusyRequestHandler for Server {
    async fn handle_calendar_freebusy_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: FreeBusyQuery,
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
        let resource = resources
            .by_path(
                resource_
                    .resource
                    .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
            )
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if !resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        self.build_freebusy_object(access_token, request, &resources, account_id, resource)
            .await
            .map(|ical| {
                HttpResponse::new(StatusCode::OK)
                    .with_content_type("text/calendar; charset=utf-8")
                    .with_text_body(ical.to_string())
            })
    }

    async fn build_freebusy_object(
        &self,
        access_token: &AccessToken,
        request: FreeBusyQuery,
        resources: &GroupwareResources,
        account_id: u32,
        resource: DavResourcePath<'_>,
    ) -> crate::Result<ICalendar> {
        // Obtain shared ids
        let is_owner = access_token.is_member(account_id);
        let shared_ids = if !is_owner {
            resources
                .shared_items(
                    access_token,
                    [Acl::ReadItems, Acl::SchedulingReadFreeBusy],
                    false,
                )
                .into()
        } else {
            None
        };

        // Build FreeBusy component
        let default_tz = resource
            .resource
            .calendar_preferences(account_id)
            .map(|p| p.tz)
            .unwrap_or(Tz::UTC);
        let mut entries = Vec::with_capacity(6);
        if let Some(range) = request.range {
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtstart,
                params: vec![],
                values: [ICalendarValue::PartialDateTime(
                    PartialDateTime::from_utc_timestamp(range.start),
                )]
                .into(),
            });
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtend,
                params: vec![],
                values: [ICalendarValue::PartialDateTime(
                    PartialDateTime::from_utc_timestamp(range.end),
                )]
                .into(),
            });
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtstamp,
                params: vec![],
                values: [ICalendarValue::PartialDateTime(
                    PartialDateTime::from_utc_timestamp(now() as i64),
                )]
                .into(),
            });

            let mut document_ids = RoaringBitmap::new();
            let mut private_ids = RoaringBitmap::new();
            for resource in resources.children(resource.document_id()) {
                let privacy = if is_owner {
                    EventPrivacy::Public
                } else {
                    EventPrivacy::from_flags(resource.resource.event_flags().unwrap_or_default())
                };
                let document_id = resource.document_id();
                if privacy != EventPrivacy::Secret
                    && shared_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(document_id))
                    && resource.resource.resource.is_in_time_range(&range)
                {
                    document_ids.insert(document_id);
                    if !privacy.is_public() {
                        private_ids.insert(document_id);
                    }
                }
            }

            let mut fb_entries: AHashMap<ICalendarFreeBusyType, Vec<(i64, i64)>> =
                AHashMap::with_capacity(4);
            let max_instances = self.core.groupware.max_ical_instances;
            let mut total_instances: usize = 0;

            if !document_ids.is_empty() {
                self.archives(
                    account_id,
                    Collection::CalendarEvent,
                    CalendarEventField::Content.field(),
                    &document_ids,
                    |document_id, archive| {
                        let privacy = if private_ids.contains(document_id) {
                            EventPrivacy::Private
                        } else {
                            EventPrivacy::Public
                        };
                        let event = archive
                            .unarchive::<CalendarEventContent>()
                            .caused_by(trc::location!())?;

                        /*
                           Only VEVENT components without a TRANSP property or with the TRANSP
                           property set to OPAQUE, and VFREEBUSY components SHOULD be considered
                           in generating the free busy time information.
                        */
                        let mut components = event
                            .data
                            .event
                            .components
                            .iter()
                            .enumerate()
                            .filter(|(_, comp)| {
                                (matches!(
                                    comp.component_type,
                                    ArchivedICalendarComponentType::VEvent
                                ) && comp
                                    .transparency()
                                    .is_none_or(|t| t == &ICalendarTransparency::Opaque))
                                    || matches!(
                                        comp.component_type,
                                        ArchivedICalendarComponentType::VFreebusy
                                    )
                            })
                            .peekable();

                        if components.peek().is_none() {
                            return Ok(true);
                        }

                        let events = CalendarQueryHandler::new(event, Some(range), default_tz)
                            .into_expanded_times();

                        if events.is_empty() {
                            return Ok(true);
                        }

                        total_instances = total_instances.saturating_add(events.len());
                        if total_instances > max_instances {
                            return Ok(false);
                        }

                        for (component_id, component) in components {
                            let component_id = component_id as u32;
                            match component.component_type {
                                ArchivedICalendarComponentType::VEvent => {
                                    let fbtype = match component.status() {
                                        Some(ArchivedICalendarStatus::Cancelled) => continue,
                                        Some(ArchivedICalendarStatus::Tentative)
                                            if privacy.is_public() =>
                                        {
                                            ICalendarFreeBusyType::BusyTentative
                                        }
                                        _ => ICalendarFreeBusyType::Busy,
                                    };

                                    let mut events_in_range = Vec::new();
                                    for event in &events {
                                        if event.comp_id == component_id
                                            && event.start < event.end
                                            && range.is_in_range(
                                                OverlapCondition::Event,
                                                event.start,
                                                event.end,
                                            )
                                        {
                                            events_in_range.push((event.start, event.end));
                                        }
                                    }

                                    if !events_in_range.is_empty() {
                                        fb_entries
                                            .entry(fbtype)
                                            .or_default()
                                            .extend(events_in_range);
                                    }
                                }
                                ArchivedICalendarComponentType::VFreebusy => {
                                    for entry in component.entries.iter() {
                                        if matches!(entry.name, ArchivedICalendarProperty::Freebusy)
                                        {
                                            let mut fb_in_range =
                                                freebusy_in_range_utc(entry, &range, default_tz)
                                                    .peekable();
                                            if fb_in_range.peek().is_some() {
                                                let fb_type = entry
                                                    .params
                                                    .iter()
                                                    .find_map(|param| {
                                                        if let (
                                                            ArchivedICalendarParameterName::Fbtype,
                                                            ArchivedICalendarParameterValue::Fbtype(
                                                                param,
                                                            ),
                                                        ) = (&param.name, &param.value)
                                                        {
                                                            rkyv_deserialize(param).ok()
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .filter(|fb_type| {
                                                        privacy.is_public()
                                                            || *fb_type
                                                                == ICalendarFreeBusyType::Free
                                                    })
                                                    .unwrap_or(ICalendarFreeBusyType::Busy);

                                                fb_entries
                                                    .entry(fb_type)
                                                    .or_default()
                                                    .extend(fb_in_range);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
            }

            if total_instances > max_instances {
                return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
            }

            for (fbtype, events_in_range) in fb_entries {
                entries.push(ICalendarEntry {
                    name: ICalendarProperty::Freebusy,
                    params: vec![ICalendarParameter::fbtype(fbtype)],
                    values: merge_intervals(events_in_range).into(),
                });
            }
        }

        // Build ICalendar
        Ok(ICalendar {
            components: vec![
                ICalendarComponent {
                    component_type: ICalendarComponentType::VCalendar,
                    entries: vec![
                        ICalendarEntry {
                            name: ICalendarProperty::Version,
                            params: vec![],
                            values: [ICalendarValue::Text("2.0".to_string())].into(),
                        },
                        ICalendarEntry {
                            name: ICalendarProperty::Prodid,
                            params: vec![],
                            values: [ICalendarValue::Text(PROD_ID.to_string())].into(),
                        },
                    ],
                    component_ids: vec![1],
                },
                ICalendarComponent {
                    component_type: ICalendarComponentType::VFreebusy,
                    entries,
                    component_ids: vec![],
                },
            ],
        })
    }
}

fn merge_intervals(mut intervals: Vec<(i64, i64)>) -> Vec<ICalendarValue> {
    if intervals.len() > 1 {
        intervals.sort_unstable_by_key(|a| a.0);

        let mut unique_intervals = Vec::new();
        let mut start_time = intervals[0].0;
        let mut end_time = intervals[0].1;

        for &(curr_start, curr_end) in intervals.iter().skip(1) {
            if curr_start <= end_time {
                end_time = end_time.max(curr_end);
            } else {
                unique_intervals.push(build_ical_value(start_time, end_time));
                start_time = curr_start;
                end_time = curr_end;
            }
        }

        unique_intervals.push(build_ical_value(start_time, end_time));
        unique_intervals
    } else {
        intervals
            .into_iter()
            .map(|(start, end)| build_ical_value(start, end))
            .collect()
    }
}

fn build_ical_value(from: i64, to: i64) -> ICalendarValue {
    ICalendarValue::Period(Box::new(ICalendarPeriod::Range {
        start: PartialDateTime::from_utc_timestamp(from),
        end: PartialDateTime::from_utc_timestamp(to),
    }))
}

pub(crate) fn freebusy_in_range(
    entry: &ArchivedICalendarEntry,
    range: &TimeRange,
    default_tz: Tz,
) -> impl Iterator<Item = ICalendarValue> {
    let tz = entry
        .tz_id()
        .and_then(|tz_id| Tz::from_str(tz_id).ok())
        .unwrap_or(default_tz);

    entry.values.iter().filter_map(move |value| {
        if let ArchivedICalendarValue::Period(period) = &value {
            period.time_range(tz).and_then(|(start, end)| {
                let start = start.timestamp();
                let end = end.timestamp();
                if range.overlaps(start, end) {
                    rkyv_deserialize(value).ok()
                } else {
                    None
                }
            })
        } else {
            None
        }
    })
}

fn freebusy_in_range_utc(
    entry: &ArchivedICalendarEntry,
    range: &TimeRange,
    default_tz: Tz,
) -> impl Iterator<Item = (i64, i64)> {
    let tz = entry
        .tz_id()
        .and_then(|tz_id| Tz::from_str(tz_id).ok())
        .unwrap_or(default_tz);

    entry.values.iter().filter_map(move |value| {
        if let ArchivedICalendarValue::Period(period) = &value {
            period.time_range(tz).and_then(|(start, end)| {
                let start = start.timestamp();
                let end = end.timestamp();
                if start < end && range.overlaps(start, end) {
                    Some((start, end))
                } else {
                    None
                }
            })
        } else {
            None
        }
    })
}
