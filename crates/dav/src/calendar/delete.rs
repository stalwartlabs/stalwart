/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::assert_event_privacy_access;
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
        Calendar, CalendarEvent, CalendarEventContent,
        identity::ParticipantIdentityAddresses,
        notification::{hides_details, may_have_viewers},
        privacy::EventViewer,
        rights::EventAcl,
        storage::{DirectChange, DirectChangeNotification, NotificationQuota},
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::Permission;
use store::write::BatchBuilder;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, PrincipalField},
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
        let send_itip = self.core.groupware.itip_enabled
            && !headers.no_schedule_reply
            && !account_info.addresses().is_empty()
            && access_token.has_permission(Permission::CalendarSchedulingSend);

        // Fetch entry
        let mut batch = BatchBuilder::new();
        if delete_resource.is_container() {
            // Deleting the default calendar is not allowed
            #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
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
            DestroyArchive(calendar)
                .delete_with_events(
                    self,
                    access_token,
                    &account_info,
                    account_id,
                    document_id,
                    children_ids,
                    resources.format_resource(delete_resource).into(),
                    send_itip,
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
        } else {
            // Validate ACL
            let calendar_id = delete_resource
                .parent_id()
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let is_owner = access_token.is_member(account_id);
            assert_event_privacy_access(
                delete_resource.resource.event_flags(),
                EventViewer::new(is_owner),
            )?;
            let may_remove_items = is_owner
                || resources.has_access_to_container(access_token, calendar_id, Acl::RemoveItems);
            if !may_remove_items
                && !EventAcl::for_calendar(&resources, access_token, calendar_id)
                    .may_manage_own_items()
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            let event_ = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let event_flags = event.inner.flags.to_native();
            let may_notify = may_have_viewers(
                access_token,
                account_id,
                &resources,
                &[calendar_id],
                hides_details(event_flags),
            );
            let content_ = if !may_remove_items || may_notify {
                self.store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
            } else {
                None
            };
            let previous_event = content_
                .as_ref()
                .map(|content| content.deserialize::<CalendarEventContent>())
                .transpose()
                .caused_by(trc::location!())?
                .map(|content| content.data.event);
            if !may_remove_items {
                let identities = self
                    .account_identity_addresses(access_token.account_id())
                    .await
                    .caused_by(trc::location!())?;
                if !previous_event
                    .as_ref()
                    .is_some_and(|ical| identities.event_ownership(ical).may_write_own())
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }
            }

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::CalendarEvent,
                    document_id: document_id.into(),
                    etag: format!("\"{}\"", event.inner.etag.to_native()).into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Validate schedule tag
            if headers.if_schedule_tag.is_some()
                && event.inner.schedule_tag.as_ref().map(|t| t.to_native())
                    != headers.if_schedule_tag
            {
                return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
            }

            // Delete event
            if let Some(previous) = previous_event {
                self.notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Destroyed {
                        event_id: document_id,
                        previous,
                        calendar_ids: vec![calendar_id],
                        event_flags,
                    },
                    Some(&resources),
                    &mut NotificationQuota::default(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            }
            DestroyArchive(event)
                .delete(
                    self,
                    &account_info,
                    account_id,
                    document_id,
                    calendar_id,
                    content_,
                    resources.format_resource(delete_resource).into(),
                    send_itip,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}
