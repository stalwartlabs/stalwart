/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    calendar::CalendarEventView,
    common::{
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::{
    SizeWriter,
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, CalendarEventContent, EVENT_HAS_ALARMS, alerts::DefaultAlertsResolver,
        privacy::EventPrivacy,
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};

pub(crate) trait CalendarGetRequestHandler: Sync + Send {
    fn handle_calendar_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarGetRequestHandler for Server {
    async fn handle_calendar_get_request(
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
        if resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Validate ACL
        let is_owner = access_token.is_member(account_id);
        if !is_owner
            && EventPrivacy::from_flags(resource.resource.event_flags().unwrap_or_default())
                == EventPrivacy::Secret
        {
            return Err(DavError::Code(StatusCode::NOT_FOUND));
        }
        if !is_owner
            && !resources.has_access_to_container(
                access_token,
                resource
                    .parent_id()
                    .ok_or(DavError::Code(StatusCode::NOT_FOUND))?,
                Acl::ReadItems,
            )
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Fetch event
        let event_ = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEvent,
                resource.document_id(),
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let event = event_
            .unarchive::<CalendarEvent>()
            .caused_by(trc::location!())?;

        // Validate headers
        let etag = format!("\"{}\"", event.etag.to_native());
        let schedule_tag = event.schedule_tag.as_ref().map(|tag| tag.to_native());
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: Collection::CalendarEvent,
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
            .with_schedule_tag_opt(schedule_tag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(event.modified)).to_string());

        let has_alarms = event.flags.to_native() & EVENT_HAS_ALARMS != 0;
        if is_head && is_owner && !has_alarms {
            return Ok(response.with_content_length(event.size.to_native() as usize));
        }

        let content_ = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                Collection::CalendarEvent,
                resource.document_id(),
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let content = content_
            .to_unarchived::<CalendarEventContent>()
            .caused_by(trc::location!())?;
        let view = self
            .calendar_event_view(
                access_token,
                account_id,
                event,
                content.inner,
                &mut DefaultAlertsResolver::default(),
            )
            .await?;

        Ok(match (view, is_head) {
            (Some((view, _)), true) => {
                response.with_content_length(SizeWriter::ical(&view.data.event))
            }
            (None, true) => response.with_content_length(event.size.to_native() as usize),
            (Some((view, _)), false) => response.with_binary_body(view.data.event.to_string()),
            (None, false) => response.with_binary_body(content.inner.data.event.to_string()),
        })
    }
}
