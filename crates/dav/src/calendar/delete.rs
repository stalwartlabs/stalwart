/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        ContainerOperation, ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        Calendar, EVENT_HAS_ALARMS,
        privacy::EventViewer,
        write::{EventWriter, ItipMode},
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::write::BatchBuilder;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
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
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;

        // Check resource type
        let delete_resource = resources
            .by_path(delete_path)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = delete_resource.document_id();
        let account_info = self.account_info(account_id).await?;
        let writer = EventWriter {
            server: self,
            access_token,
            account_id,
            resources: &resources,
            account_info: &account_info,
        };
        let itip = if headers.no_schedule_reply {
            ItipMode::Suppress
        } else {
            ItipMode::Send
        };

        if delete_resource.is_container() {
            // Deleting the default calendar is not allowed
            #[cfg(not(any(feature = "dev_mode", stalwart_tests)))]
            if self.default_calendar_id(account_id).await? == Some(document_id) {
                return Err(DavError::Condition(crate::DavErrorCondition::new(
                    StatusCode::FORBIDDEN,
                    dav_proto::schema::response::CalCondition::DefaultCalendarNeeded,
                )));
            }

            let calendar_ = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
            let is_owner = access_token.is_member(account_id);
            if !is_owner
                && !calendar
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains_all(ContainerOperation::Remove.required_acls())
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
            let children_ids = ContainerOperation::Remove.event_ids(
                &resources,
                delete_path,
                EventViewer::new(is_owner),
            )?;

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
            let mut batch = BatchBuilder::new();
            let cleanup = self
                .preload_container_cleanup(
                    account_info.changed_by(),
                    account_id,
                    Collection::CalendarEvent,
                    &children_ids
                        .iter()
                        .copied()
                        .filter(|&document_id| {
                            resources
                                .item_by_id(document_id)
                                .is_some_and(|item| !item.metadata_kinds().is_empty())
                        })
                        .collect(),
                )
                .await
                .caused_by(trc::location!())?;
            DestroyArchive(calendar)
                .delete_with_events(
                    self,
                    access_token,
                    &account_info,
                    account_id,
                    document_id,
                    children_ids,
                    &resources.event_ids_with_flags(EVENT_HAS_ALARMS),
                    &cleanup,
                    resources.format_resource(delete_resource).into(),
                    writer.sends_itip(itip),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;

            // Reset default calendar id
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .clear_if_equals(PrincipalField::DefaultCalendarId, document_id);
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        } else {
            let calendar_id = delete_resource
                .parent_id()
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let deletion = writer.prepare_delete(calendar_id, document_id).await?;

            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::CalendarEvent,
                    document_id: document_id.into(),
                    etag: format!(
                        "\"{}\"",
                        deletion
                            .event()
                            .caused_by(trc::location!())?
                            .inner
                            .etag
                            .to_native()
                    )
                    .into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            writer
                .delete(
                    deletion,
                    headers.if_schedule_tag,
                    itip,
                    resources.format_resource(delete_resource).into(),
                )
                .await?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}
