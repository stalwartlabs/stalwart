/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use directory::Permission;
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{Calendar, CalendarEvent},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::write::{BatchBuilder, ValueClass};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub(crate) trait CalendarDeleteRequestHandler: Sync + Send {
    fn handle_calendar_delete_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarDeleteRequestHandler for Server {
    async fn handle_calendar_delete_request(
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
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;

        // Check resource type
        let delete_resource = resources
            .by_path(delete_path)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = delete_resource.document_id();
        let send_itip = self.core.groupware.itip_enabled
            && !headers.no_schedule_reply
            && !access_token.emails.is_empty()
            && access_token.has_permission(Permission::CalendarSchedulingSend);

        // Fetch entry
        let mut batch = BatchBuilder::new();
        if delete_resource.is_container() {
            // Deleting the default calendar is not allowed
            #[cfg(not(debug_assertions))]
            if self
                .core
                .groupware
                .default_calendar_name
                .as_ref()
                .is_some_and(|name| name == delete_path)
            {
                return Err(DavError::Condition(crate::DavErrorCondition::new(
                    StatusCode::FORBIDDEN,
                    dav_proto::schema::response::CalCondition::DefaultCalendarNeeded,
                )));
            }

            let calendar_ = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Calendar,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            let calendar = calendar_
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;

            // Validate ACL
            if !access_token.is_member(account_id)
                && !calendar
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains_all([Acl::Delete, Acl::RemoveItems].into_iter())
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::Calendar,
                    document_id: document_id.into(),
                    etag: calendar.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Delete calendar and events
            DestroyArchive(calendar)
                .delete_with_events(
                    self,
                    access_token,
                    account_id,
                    document_id,
                    resources
                        .subtree(delete_path)
                        .filter(|r| !r.is_container())
                        .map(|r| r.document_id())
                        .collect::<Vec<_>>(),
                    resources.format_resource(delete_resource).into(),
                    send_itip,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;

            // Reset default calendar id
            let default_calendar_id = self
                .store()
                .get_value::<u32>(ValueKey {
                    account_id,
                    collection: Collection::Principal.into(),
                    document_id: 0,
                    class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
                })
                .await
                .caused_by(trc::location!())?;
            if default_calendar_id.is_some_and(|id| id == document_id) {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .clear(PrincipalField::DefaultCalendarId);
            }
        } else {
            // Validate ACL
            let calendar_id = delete_resource.parent_id().unwrap();
            if !access_token.is_member(account_id)
                && !resources.has_access_to_container(access_token, calendar_id, Acl::RemoveItems)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            let event_ = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
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
                    collection: Collection::CalendarEvent,
                    document_id: document_id.into(),
                    etag: event_.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Validate schedule tag
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            if headers.if_schedule_tag.is_some()
                && event.inner.schedule_tag.as_ref().map(|t| t.to_native())
                    != headers.if_schedule_tag
            {
                return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
            }

            // Delete event
            DestroyArchive(event)
                .delete(
                    access_token,
                    account_id,
                    document_id,
                    calendar_id,
                    resources.format_resource(delete_resource).into(),
                    send_itip,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
        }

        self.commit_batch(batch).await.caused_by(trc::location!())?;
        self.notify_task_queue();

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}
