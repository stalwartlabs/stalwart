/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::CalendarEventView;
use crate::{
    DavError, DavErrorCondition, DavMethod,
    common::{
        create::CreateLockHandler,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};
use calcard::{Entry, Parser};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CalCondition},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        alerts::DefaultAlertsResolver,
        write::{EventCreate, EventWrite, EventWriter, ItipMode},
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

pub(crate) trait CalendarUpdateRequestHandler: Sync + Send {
    fn handle_calendar_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: &[u8],
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarUpdateRequestHandler for Server {
    async fn handle_calendar_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: &[u8],
        _is_patch: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let resource_name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;

        if bytes.len() > self.core.groupware.max_ical_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::MaxResourceSize(self.core.groupware.max_ical_size as u32),
            )));
        }
        let ical_raw = std::str::from_utf8(bytes).map_err(|_| {
            DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::SupportedCalendarData,
                )
                .with_details("Invalid UTF-8 in iCalendar data"),
            )
        })?;

        let ical = match Parser::new(ical_raw).entry() {
            Entry::ICalendar(ical) => ical,
            _ => {
                return Err(DavError::Condition(
                    DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CalCondition::SupportedCalendarData,
                    )
                    .with_details("Failed to parse iCalendar data"),
                ));
            }
        };
        let attachments_size = ical.embedded_size();
        if self.core.groupware.max_attachments_size != 0
            && attachments_size > self.core.groupware.max_attachments_size
        {
            return Err(DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::MaxResourceSize(self.core.groupware.max_attachments_size as u32),
                )
                .with_details(format!(
                    "The size of the embedded attachments ({attachments_size} bytes) exceeds the maximum of {} bytes.",
                    self.core.groupware.max_attachments_size
                )),
            ));
        }
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let writer = EventWriter {
            server: self,
            access_token,
            account_id,
            resources: &resources,
            account_info: &account_info,
        };

        if let Some(resource) = resources.by_path(resource_name) {
            if resource.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            let stored = writer
                .prepare_update(resource.parent_id().unwrap(), resource.document_id(), &ical)
                .await?;
            let event = stored.event().caused_by(trc::location!())?;

            match self
                .validate_headers(
                    access_token,
                    headers,
                    vec![ResourceState {
                        account_id,
                        collection: Collection::CalendarEvent,
                        document_id: Some(stored.document_id()),
                        etag: format!("\"{}\"", event.inner.etag.to_native()).into(),
                        path: resource_name,
                        ..Default::default()
                    }],
                    Default::default(),
                    DavMethod::PUT,
                )
                .await
            {
                Ok(_) => {}
                Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
                    if headers.ret == Return::Representation =>
                {
                    let content = stored.content().caused_by(trc::location!())?;
                    let body = match self
                        .calendar_event_view(
                            access_token,
                            account_id,
                            event.inner,
                            content.inner,
                            &mut DefaultAlertsResolver::default(),
                        )
                        .await?
                    {
                        Some((view, _)) => view.data.event.to_string(),
                        None => content.inner.data.event.to_string(),
                    };
                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type("text/calendar; charset=utf-8")
                        .with_etag(format!("\"{}\"", event.inner.etag.to_native()))
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(event.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(body));
                }
                Err(e) => return Err(e),
            }

            match writer
                .update(stored, ical, headers.if_schedule_tag, ItipMode::Send)
                .await?
            {
                EventWrite::Unchanged => Ok(HttpResponse::new(StatusCode::NO_CONTENT)),
                EventWrite::Written(written) => Ok(HttpResponse::new(StatusCode::NO_CONTENT)
                    .with_etag_opt(written.serves_submitted.then_some(written.etag))
                    .with_schedule_tag_opt(written.schedule_tag)),
            }
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name) {
            if !parent.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            let new = writer.prepare_create(parent.document_id(), &ical).await?;

            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    path: resource_name,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            let lock = self
                .lock_create(
                    access_token,
                    account_id,
                    SyncCollection::Calendar,
                    resource_name,
                    headers,
                )
                .await?;
            let written = writer
                .create(
                    new,
                    EventCreate {
                        name: name.to_string(),
                        ical,
                        size: Some(bytes.len()),
                        itip: ItipMode::Send,
                    },
                )
                .await;
            self.release_create_lock(&lock).await;
            let written = written?;

            Ok(HttpResponse::new(StatusCode::CREATED)
                .with_etag_opt(written.serves_submitted.then_some(written.etag))
                .with_schedule_tag_opt(written.schedule_tag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}
