/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavErrorCondition, DavMethod,
    calendar::freebusy::CalendarFreebusyRequestHandler,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use calcard::{
    Entry, Parser,
    icalendar::{
        ICalendarComponentType, ICalendarEntry, ICalendarMethod, ICalendarProperty, ICalendarValue,
        Uri,
    },
};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::{
        property::Rfc1123DateTime,
        request::FreeBusyQuery,
        response::{CalCondition, Href, ScheduleResponse, ScheduleResponseItem},
    },
};
use groupware::{DestroyArchive, cache::GroupwareCache, calendar::CalendarEventNotification};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use store::{ahash::AHashMap, write::BatchBuilder};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};
use utils::sanitize_email;

pub(crate) trait CalendarEventNotificationHandler: Sync + Send {
    fn handle_scheduling_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_scheduling_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_scheduling_post_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarEventNotificationHandler for Server {
    async fn handle_scheduling_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(
                access_token,
                account_id,
                SyncCollection::CalendarEventNotification,
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
        if resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate ACL
        if !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Fetch event
        let event_ = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEventNotification,
                resource.document_id(),
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let event = event_
            .unarchive::<CalendarEventNotification>()
            .caused_by(trc::location!())?;

        // Validate headers
        let etag = event_.etag();
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: Collection::CalendarEventNotification,
                document_id: resource.document_id().into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::GET,
        )
        .await?;

        let response = HttpResponse::new(StatusCode::OK)
            .with_content_type("text/calendar; charset=utf-8")
            .with_etag(etag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(event.modified)).to_string());

        let ical = event.event.to_string();

        if !is_head {
            Ok(response.with_binary_body(ical))
        } else {
            Ok(response.with_content_length(ical.len()))
        }
    }

    async fn handle_scheduling_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let delete_path = resource
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let resources = self
            .fetch_dav_resources(
                access_token,
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .caused_by(trc::location!())?;

        // Check resource type
        let resource = resources
            .by_path(delete_path)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate ACL
        if !access_token.is_member(account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let document_id = resource.document_id();
        let event_ = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEventNotification,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: Collection::CalendarEventNotification,
                document_id: document_id.into(),
                etag: event_.etag().into(),
                path: delete_path,
                ..Default::default()
            }],
            Default::default(),
            DavMethod::DELETE,
        )
        .await?;

        let event = event_
            .to_unarchived::<CalendarEventNotification>()
            .caused_by(trc::location!())?;

        // Delete event
        let mut batch = BatchBuilder::new();
        DestroyArchive(event)
            .delete(access_token, account_id, document_id, &mut batch)
            .caused_by(trc::location!())?;

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }

    async fn handle_scheduling_post_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        if resource.resource.is_none_or(|r| r != "outbox") {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Parse iTIP message
        if bytes.len() > self.core.groupware.max_ical_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::MaxResourceSize(self.core.groupware.max_ical_size as u32),
            )));
        }
        let itip_raw = std::str::from_utf8(&bytes).map_err(|_| {
            DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::BAD_REQUEST,
                    CalCondition::ValidSchedulingMessage,
                )
                .with_details("Invalid UTF-8 in iCalendar data"),
            )
        })?;
        let itip = match Parser::new(itip_raw).entry() {
            Entry::ICalendar(ical) if ical.components.len() > 1 => ical,
            _ => {
                return Err(DavError::Condition(
                    DavErrorCondition::new(
                        StatusCode::BAD_REQUEST,
                        CalCondition::ValidSchedulingMessage,
                    )
                    .with_details("Failed to parse iCalendar data"),
                ));
            }
        };

        // Parse request
        let mut from_date = None;
        let mut to_date = None;
        let mut organizer = None;
        let mut attendees = AHashMap::new();
        let mut uid = None;
        let tz_resolver = itip.build_tz_resolver();
        let mut found_freebusy = false;

        for component in &itip.components {
            if component.component_type != ICalendarComponentType::VFreebusy {
                continue;
            } else if !found_freebusy {
                found_freebusy = true;
            } else {
                return Err(DavError::Condition(
                    DavErrorCondition::new(
                        StatusCode::BAD_REQUEST,
                        CalCondition::ValidSchedulingMessage,
                    )
                    .with_details("Multiple VFREEBUSY components found"),
                ));
            }

            for entry in &component.entries {
                let tz_id = entry.tz_id();
                match (&entry.name, entry.values.first()) {
                    (ICalendarProperty::Dtstart, Some(ICalendarValue::PartialDateTime(dt))) => {
                        from_date = dt.to_date_time_with_tz(tz_resolver.resolve_or_default(tz_id));
                    }
                    (ICalendarProperty::Dtend, Some(ICalendarValue::PartialDateTime(dt))) => {
                        to_date = dt.to_date_time_with_tz(tz_resolver.resolve_or_default(tz_id));
                    }
                    (ICalendarProperty::Uid, Some(ICalendarValue::Text(_))) => {
                        uid = Some(entry);
                    }
                    (
                        ICalendarProperty::Organizer,
                        Some(ICalendarValue::Text(_) | ICalendarValue::Uri(Uri::Location(_))),
                    ) => {
                        organizer = Some(entry);
                    }
                    (
                        ICalendarProperty::Attendee,
                        Some(
                            ICalendarValue::Text(value) | ICalendarValue::Uri(Uri::Location(value)),
                        ),
                    ) => {
                        if let Some(email) =
                            sanitize_email(value.strip_prefix("mailto:").unwrap_or(value.as_str()))
                        {
                            attendees.insert(email, entry);
                        }
                    }
                    _ => {}
                }
            }
        }

        let (Some(from_date), Some(to_date)) = (from_date, to_date) else {
            return Err(DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::BAD_REQUEST,
                    CalCondition::ValidSchedulingMessage,
                )
                .with_details("Missing DTSTART or DTEND in VFREEBUSY component"),
            ));
        };
        let Some(organizer) = organizer else {
            return Err(DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::BAD_REQUEST,
                    CalCondition::ValidSchedulingMessage,
                )
                .with_details("Missing ORGANIZER in VFREEBUSY component"),
            ));
        };
        if attendees.is_empty() {
            return Err(DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::BAD_REQUEST,
                    CalCondition::ValidSchedulingMessage,
                )
                .with_details("Missing ATTENDEE in VFREEBUSY component"),
            ));
        }

        let mut response = ScheduleResponse::default();

        for (email, attendee) in attendees {
            if let Some(account_id) = self
                .directory()
                .email_to_id(&email)
                .await
                .caused_by(trc::location!())?
            {
                let resources = self
                    .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
                    .await
                    .caused_by(trc::location!())?;
                if let Some(resource) = self
                    .core
                    .groupware
                    .default_calendar_name
                    .as_ref()
                    .and_then(|name| resources.by_path(name))
                {
                    let mut free_busy = self
                        .build_freebusy_object(
                            access_token,
                            FreeBusyQuery::new(from_date.timestamp(), to_date.timestamp()),
                            &resources,
                            account_id,
                            resource,
                        )
                        .await?;

                    // Add iTIP method
                    free_busy.components[0].entries.push(ICalendarEntry {
                        name: ICalendarProperty::Method,
                        params: vec![],
                        values: vec![ICalendarValue::Method(ICalendarMethod::Reply)],
                    });

                    // Add properties
                    let component = &mut free_busy.components[1];
                    component.entries.push(organizer.clone());
                    component.entries.push(attendee.clone());
                    if let Some(uid) = uid {
                        component.entries.push(uid.clone());
                    }

                    response.items.0.push(ScheduleResponseItem {
                        recipient: Href(format!("mailto:{email}")),
                        request_status: "2.0;Success".into(),
                        calendar_data: Some(free_busy.to_string()),
                    });
                } else {
                    response.items.0.push(ScheduleResponseItem {
                        recipient: Href(format!("mailto:{email}")),
                        request_status: "3.7;Default calendar not found".into(),
                        calendar_data: None,
                    });
                }
            } else {
                response.items.0.push(ScheduleResponseItem {
                    recipient: Href(format!("mailto:{email}")),
                    request_status: "3.7;Invalid calendar user or insufficient permissions".into(),
                    calendar_data: None,
                });
            }
        }

        Ok(HttpResponse::new(StatusCode::OK).with_xml_body(response.to_string()))
    }
}
