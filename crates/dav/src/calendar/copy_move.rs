/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CalendarComponentSupport, assert_event_privacy_access, assert_is_unique_uid};
use crate::{
    DavError, DavMethod,
    common::{
        ContainerOperation, assert_parent_limit,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};
use common::{DavName, GroupwareResources, Server, auth::AccessToken};
use dav_proto::{Depth, RequestHeaders};
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        CALENDAR_SUBSCRIBED, Calendar, CalendarEvent, CalendarEventContent, CalendarPreferences,
        Timezone,
        alerts::{CalendarSettings, DefaultAlertsResolver},
        identity::{CalendarAddresses, ParticipantIdentityAddresses},
        privacy::{EventPrivacy, EventViewer},
        rights::{EventAcl, StoredEventOwnership},
        schedule::{EventAlarmScheduler, EventAlarmUsers},
        storage::{DirectChangeNotification, NotificationQuota},
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::StorageQuota;
use store::write::{BatchBuilder, PendingId, now};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection, VanishedCollection},
    field::{CalendarEventField, PrincipalField},
};

pub(crate) trait CalendarCopyMoveRequestHandler: Sync + Send {
    fn handle_calendar_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarCopyMoveRequestHandler for Server {
    async fn handle_calendar_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let from_account_id = from_resource_.account_id;
        let from_resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let from_resource_name = from_resource_
            .resource
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let from_resource = from_resources
            .by_path(from_resource_name)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        #[cfg(not(any(feature = "dev_mode", feature = "test_mode")))]
        if is_move
            && from_resource.is_container()
            && self
                .core
                .groupware
                .default_calendar_name
                .as_ref()
                .is_some_and(|name| name == from_resource_name)
        {
            return Err(DavError::Condition(crate::DavErrorCondition::new(
                StatusCode::FORBIDDEN,
                dav_proto::schema::response::CalCondition::DefaultCalendarNeeded,
            )));
        }

        // Validate ACL
        let is_from_owner = access_token.is_member(from_account_id);
        if !from_resource.is_container() {
            assert_event_privacy_access(
                from_resource.resource.event_flags(),
                EventViewer::new(is_from_owner),
            )?;
        }
        if !is_from_owner
            && !from_resources.has_access_to_container(
                access_token,
                if from_resource.is_container() {
                    from_resource.document_id()
                } else {
                    from_resource
                        .parent_id()
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
                },
                Acl::ReadItems,
            )
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }
        let container_operation = ContainerOperation::from_move(is_move);

        // Validate destination
        let destination = self
            .validate_uri_with_status(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
                StatusCode::BAD_GATEWAY,
            )
            .await?;
        if destination.collection != Collection::Calendar {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let to_account_id = destination
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let is_to_owner = access_token.is_member(to_account_id);
        if !from_resource.is_container()
            && !is_to_owner
            && !EventPrivacy::from_flags(from_resource.resource.event_flags().unwrap_or_default())
                .is_public()
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }
        let to_resources = if to_account_id == from_account_id {
            from_resources.clone()
        } else {
            self.fetch_groupware_resources(
                access_token.account_id(),
                to_account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?
        };

        // Validate headers
        let destination_resource_name = destination
            .resource
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let to_resource = to_resources.by_path(destination_resource_name);
        let visible_to_resource = to_resource.filter(|resource| {
            is_to_owner
                || EventPrivacy::from_flags(resource.resource.event_flags().unwrap_or_default())
                    != EventPrivacy::Secret
        });
        self.validate_headers(
            access_token,
            headers,
            vec![
                ResourceState {
                    account_id: from_account_id,
                    collection: if from_resource.is_container() {
                        Collection::Calendar
                    } else {
                        Collection::CalendarEvent
                    },
                    document_id: Some(from_resource.document_id()),
                    path: from_resource_name,
                    ..Default::default()
                },
                ResourceState {
                    account_id: to_account_id,
                    collection: visible_to_resource
                        .map(|r| {
                            if r.is_container() {
                                Collection::Calendar
                            } else {
                                Collection::CalendarEvent
                            }
                        })
                        .unwrap_or(Collection::Calendar),
                    document_id: Some(
                        visible_to_resource
                            .map(|r| r.document_id())
                            .unwrap_or(u32::MAX),
                    ),
                    path: destination_resource_name,
                    ..Default::default()
                },
            ],
            Default::default(),
            if is_move {
                DavMethod::MOVE
            } else {
                DavMethod::COPY
            },
        )
        .await?;

        // Map destination
        if let Some(to_resource) = to_resource {
            if from_resource.path() == to_resource.path() {
                // Same resource
                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
            }
            let new_name = destination_resource_name
                .rsplit_once('/')
                .map(|(_, name)| name)
                .unwrap_or(destination_resource_name);

            match (from_resource.is_container(), to_resource.is_container()) {
                (true, true) => {
                    let from_children_ids = container_operation.event_ids(
                        &from_resources,
                        from_resource_name,
                        EventViewer::new(is_from_owner),
                    )?;
                    let to_document_ids = to_resources
                        .subtree(destination_resource_name)
                        .filter(|r| !r.is_container())
                        .map(|r| r.document_id())
                        .collect::<Vec<_>>();

                    // Validate ACLs
                    if !is_to_owner
                        || (!is_from_owner
                            && !from_resources
                                .container_acl(access_token, from_resource.document_id())
                                .contains_all(container_operation.required_acls()))
                    {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }

                    // Overwrite container
                    copy_container(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id(),
                        from_children_ids,
                        from_resources.format_collection(from_resource_name),
                        to_account_id,
                        to_resource.document_id().into(),
                        to_document_ids,
                        new_name,
                        is_move,
                    )
                    .await
                }
                (false, false) => {
                    // Overwrite event
                    let from_calendar_id = from_resource.parent_id().unwrap();
                    let to_calendar_id = to_resource.parent_id().unwrap();

                    // Validate ACL
                    let mut own_events = OwnEventAccess::new(self, access_token);
                    let may_take = access_token.is_member(from_account_id)
                        || from_resources.has_access_to_container(
                            access_token,
                            from_calendar_id,
                            if is_move {
                                Acl::RemoveItems
                            } else {
                                Acl::ReadItems
                            },
                        )
                        || (is_move
                            && own_events
                                .may_manage(
                                    &from_resources,
                                    from_calendar_id,
                                    from_account_id,
                                    from_resource.document_id(),
                                )
                                .await?);
                    let may_overwrite = may_take
                        && (access_token.is_member(to_account_id)
                            || to_resources.has_access_to_container(
                                access_token,
                                to_calendar_id,
                                Acl::RemoveItems,
                            )
                            || (own_events
                                .may_manage(
                                    &to_resources,
                                    to_calendar_id,
                                    to_account_id,
                                    to_resource.document_id(),
                                )
                                .await?
                                && own_events
                                    .may_manage(
                                        &to_resources,
                                        to_calendar_id,
                                        from_account_id,
                                        from_resource.document_id(),
                                    )
                                    .await?));
                    if !may_overwrite {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }
                    assert_event_privacy_access(
                        to_resource.resource.event_flags(),
                        EventViewer::new(is_to_owner),
                    )?;

                    if is_move {
                        move_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id(),
                            from_calendar_id,
                            from_resources.format_item(from_resource_name),
                            to_account_id,
                            to_resource.document_id().into(),
                            to_calendar_id,
                            new_name,
                            headers.if_schedule_tag,
                        )
                        .await
                    } else {
                        copy_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id(),
                            to_account_id,
                            to_resource.document_id().into(),
                            to_calendar_id,
                            new_name,
                        )
                        .await
                    }
                }
                _ => Err(DavError::Code(StatusCode::BAD_GATEWAY)),
            }
        } else if let Some((parent_resource, new_name)) =
            to_resources.map_parent(destination_resource_name)
        {
            if let Some(parent_resource) = parent_resource {
                // Creating items under an event is not allowed
                // Copying/moving containers under a container is not allowed
                if !parent_resource.is_container() || from_resource.is_container() {
                    return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                }

                // Validate ACL
                let from_calendar_id = from_resource.parent_id().unwrap();
                let to_calendar_id = parent_resource.document_id();
                let mut own_events = OwnEventAccess::new(self, access_token);
                let may_take = access_token.is_member(from_account_id)
                    || from_resources.has_access_to_container(
                        access_token,
                        from_calendar_id,
                        if is_move {
                            Acl::RemoveItems
                        } else {
                            Acl::ReadItems
                        },
                    )
                    || (is_move
                        && own_events
                            .may_manage(
                                &from_resources,
                                from_calendar_id,
                                from_account_id,
                                from_resource.document_id(),
                            )
                            .await?);
                let may_add = may_take
                    && (access_token.is_member(to_account_id)
                        || to_resources.has_access_to_container(
                            access_token,
                            to_calendar_id,
                            Acl::AddItems,
                        )
                        || own_events
                            .may_manage(
                                &to_resources,
                                to_calendar_id,
                                from_account_id,
                                from_resource.document_id(),
                            )
                            .await?);
                if !may_add {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Copy/move event
                if is_move {
                    if from_account_id != to_account_id
                        || parent_resource.document_id() != from_calendar_id
                    {
                        move_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id(),
                            from_calendar_id,
                            from_resources.format_item(from_resource_name),
                            to_account_id,
                            None,
                            to_calendar_id,
                            new_name,
                            headers.if_schedule_tag,
                        )
                        .await
                    } else {
                        rename_event(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id(),
                            from_calendar_id,
                            new_name,
                            from_resources.format_item(from_resource_name),
                        )
                        .await
                    }
                } else {
                    copy_event(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id(),
                        to_account_id,
                        None,
                        to_calendar_id,
                        new_name,
                    )
                    .await
                }
            } else {
                // Copying/moving events to the root is not allowed
                if !from_resource.is_container() {
                    return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                }

                // Shared users cannot create containers
                if !is_to_owner {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Validate ACLs
                if !is_from_owner
                    && !from_resources
                        .container_acl(access_token, from_resource.document_id())
                        .contains_all(container_operation.required_acls())
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Copy/move container
                let from_children_ids = container_operation.event_ids(
                    &from_resources,
                    from_resource_name,
                    EventViewer::new(is_from_owner),
                )?;
                if is_move {
                    if from_account_id != to_account_id {
                        copy_container(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id(),
                            if headers.depth != Depth::Zero {
                                from_children_ids
                            } else {
                                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                            },
                            from_resources.format_collection(from_resource_name),
                            to_account_id,
                            None,
                            vec![],
                            new_name,
                            true,
                        )
                        .await
                    } else {
                        rename_container(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id(),
                            new_name,
                            from_resources.format_collection(from_resource_name),
                        )
                        .await
                    }
                } else {
                    copy_container(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id(),
                        if headers.depth != Depth::Zero {
                            from_children_ids
                        } else {
                            vec![]
                        },
                        from_resources.format_collection(from_resource_name),
                        to_account_id,
                        None,
                        vec![],
                        new_name,
                        false,
                    )
                    .await
                }
            }
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))
        }
    }
}

struct OwnEventAccess<'x> {
    server: &'x Server,
    access_token: &'x AccessToken,
    identities: Option<CalendarAddresses>,
}

impl<'x> OwnEventAccess<'x> {
    fn new(server: &'x Server, access_token: &'x AccessToken) -> Self {
        OwnEventAccess {
            server,
            access_token,
            identities: None,
        }
    }

    async fn may_manage(
        &mut self,
        resources: &GroupwareResources,
        calendar_id: u32,
        account_id: u32,
        document_id: u32,
    ) -> crate::Result<bool> {
        if !EventAcl::for_calendar(resources, self.access_token, calendar_id).may_manage_own_items()
        {
            return Ok(false);
        }
        let identities = match self.identities.as_ref() {
            Some(identities) => identities,
            None => self.identities.get_or_insert(
                self.server
                    .account_identity_addresses(self.access_token.account_id())
                    .await
                    .caused_by(trc::location!())?,
            ),
        };

        Ok(self
            .server
            .stored_event_ownership(account_id, document_id, identities)
            .await
            .caused_by(trc::location!())?
            .may_write_own())
    }
}

#[allow(clippy::too_many_arguments)]
async fn copy_event(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_calendar_id: u32,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch event
    let event_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::CalendarEvent,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let event = event_
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();

    // Validate UID
    let to_resources = server
        .fetch_groupware_resources(
            access_token.account_id(),
            to_account_id,
            SyncCollection::Calendar,
        )
        .await
        .caused_by(trc::location!())?;
    assert_is_unique_uid(
        to_resources.as_ref(),
        access_token,
        to_account_id,
        to_calendar_id,
        Some(event.inner.uid.as_str()).filter(|uid| !uid.is_empty()),
    )?;
    server
        .assert_stored_event_supported(
            from_account_id,
            from_document_id,
            to_account_id,
            to_calendar_id,
        )
        .await?;

    let changed_by = access_token.account_tenant_ids();
    let event_flags = event.inner.flags.to_native();
    let mut quota = NotificationQuota::default();
    if from_account_id == to_account_id {
        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names.push(DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        });
        server
            .notify_calendar_addition(
                access_token,
                to_account_id,
                PendingId::Assigned(from_document_id),
                to_calendar_id,
                event_flags,
                (from_account_id, from_document_id),
                &mut quota,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        assert_parent_limit(
            event.inner.names.len(),
            new_event.names.len(),
            server.core.groupware.max_calendars_per_event,
        )?;
        server
            .reschedule_event_alarms(
                from_account_id,
                from_document_id,
                event.inner,
                &new_event
                    .names
                    .iter()
                    .map(DavName::parent_id)
                    .collect::<Vec<_>>(),
                &mut DefaultAlertsResolver::default(),
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        new_event
            .update_meta(
                changed_by,
                event,
                from_account_id,
                from_document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
    } else {
        let content_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                from_account_id,
                Collection::CalendarEvent,
                from_document_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let mut new_content = content_
            .deserialize::<CalendarEventContent>()
            .caused_by(trc::location!())?;
        new_content
            .preferences
            .retain(|preferences| preferences.account_id == access_token.account_id());
        let next_email_alarms = server
            .next_event_alarms(
                to_account_id,
                &EventAlarmUsers::new(to_account_id, &new_content)?
                    .with_event_flags(event.inner.flags.to_native()),
                &new_content.data,
                &[to_calendar_id],
                now() as i64,
                &mut DefaultAlertsResolver::default(),
            )
            .await
            .caused_by(trc::location!())?;
        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names = vec![DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        }];
        if to_document_id.is_none() {
            server.assert_object_quota(
                &*server.account(to_account_id).await?,
                StorageQuota::MaxCalendarEvents,
                1,
                || to_resources.resources.count(false),
            )?;
        }
        let to_document_id = batch.reserve_document_id(to_account_id, Collection::CalendarEvent);
        server
            .notify_calendar_addition(
                access_token,
                to_account_id,
                to_document_id.into(),
                to_calendar_id,
                event_flags,
                (from_account_id, from_document_id),
                &mut quota,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        new_event
            .insert(
                new_content,
                changed_by,
                to_account_id,
                to_document_id,
                None,
                next_email_alarms,
                &mut batch,
            )
            .caused_by(trc::location!())?;
    }

    let response = if let Some(to_document_id) = to_document_id {
        // Overwrite event on destination
        let event_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                to_account_id,
                Collection::CalendarEvent,
                to_document_id,
            ))
            .await
            .caused_by(trc::location!())?;
        if let Some(event_) = event_ {
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let account_info = server
                .account_info(access_token.account_id())
                .await
                .caused_by(trc::location!())?;

            server
                .notify_calendar_removal(
                    access_token,
                    to_account_id,
                    to_document_id,
                    to_calendar_id,
                    event.inner.flags.to_native(),
                    &mut quota,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            DestroyArchive(event)
                .delete(
                    server,
                    &account_info,
                    to_account_id,
                    to_document_id,
                    to_calendar_id,
                    None,
                    None,
                    false,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    } else {
        Ok(HttpResponse::new(StatusCode::CREATED))
    };

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    response
}

#[allow(clippy::too_many_arguments)]
async fn move_event(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    from_calendar_id: u32,
    from_resource_path: String,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_calendar_id: u32,
    new_name: &str,
    if_schedule_tag: Option<u32>,
) -> crate::Result<HttpResponse> {
    // Fetch event
    let event_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::CalendarEvent,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let event = event_
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;

    // Validate headers
    if if_schedule_tag.is_some()
        && event.inner.schedule_tag.as_ref().map(|t| t.to_native()) != if_schedule_tag
    {
        return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
    }

    // Validate UID
    if from_account_id != to_account_id
        || from_calendar_id != to_calendar_id
        || to_document_id.is_none()
    {
        assert_is_unique_uid(
            server
                .fetch_groupware_resources(
                    access_token.account_id(),
                    to_account_id,
                    SyncCollection::Calendar,
                )
                .await
                .caused_by(trc::location!())?
                .as_ref(),
            access_token,
            to_account_id,
            to_calendar_id,
            Some(event.inner.uid.as_str()).filter(|uid| !uid.is_empty()),
        )?;
    }
    if from_account_id != to_account_id || from_calendar_id != to_calendar_id {
        server
            .assert_stored_event_supported(
                from_account_id,
                from_document_id,
                to_account_id,
                to_calendar_id,
            )
            .await?;
    }

    let account_info = server
        .account_info(access_token.account_id())
        .await
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();
    let event_flags = event.inner.flags.to_native();
    let mut quota = NotificationQuota::default();
    if from_calendar_id != to_calendar_id || from_account_id != to_account_id {
        server
            .notify_calendar_removal(
                access_token,
                from_account_id,
                from_document_id,
                from_calendar_id,
                event_flags,
                &mut quota,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
    }
    if from_account_id == to_account_id {
        let name_idx = event
            .inner
            .names
            .iter()
            .position(|name| name.parent_id == from_calendar_id)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names.swap_remove(name_idx);
        new_event.names.push(DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        });
        if from_calendar_id != to_calendar_id {
            server
                .notify_calendar_addition(
                    access_token,
                    to_account_id,
                    PendingId::Assigned(from_document_id),
                    to_calendar_id,
                    event_flags,
                    (from_account_id, from_document_id),
                    &mut quota,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }
        server
            .reschedule_event_alarms(
                from_account_id,
                from_document_id,
                event.inner,
                &new_event
                    .names
                    .iter()
                    .map(DavName::parent_id)
                    .collect::<Vec<_>>(),
                &mut DefaultAlertsResolver::default(),
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        new_event
            .update_meta(
                access_token.account_tenant_ids(),
                event.clone(),
                from_account_id,
                from_document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        batch.log_vanished_item(VanishedCollection::Calendar, from_resource_path);
    } else {
        let content_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                from_account_id,
                Collection::CalendarEvent,
                from_document_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let mut new_content = content_
            .deserialize::<CalendarEventContent>()
            .caused_by(trc::location!())?;
        new_content
            .preferences
            .retain(|preferences| preferences.account_id == access_token.account_id());
        let next_email_alarms = server
            .next_event_alarms(
                to_account_id,
                &EventAlarmUsers::new(to_account_id, &new_content)?
                    .with_event_flags(event.inner.flags.to_native()),
                &new_content.data,
                &[to_calendar_id],
                now() as i64,
                &mut DefaultAlertsResolver::default(),
            )
            .await
            .caused_by(trc::location!())?;
        let mut new_event = event
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        new_event.names = vec![DavName {
            name: new_name.to_string(),
            parent_id: to_calendar_id,
        }];

        DestroyArchive(event)
            .delete(
                server,
                &account_info,
                from_account_id,
                from_document_id,
                from_calendar_id,
                Some(content_),
                from_resource_path.into(),
                false,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;

        let to_account = server.account(to_account_id).await?;
        if to_document_id.is_none()
            && server
                .object_quota_limit(&to_account, StorageQuota::MaxCalendarEvents)
                .is_some()
        {
            let to_resources = server
                .fetch_groupware_resources(
                    access_token.account_id(),
                    to_account_id,
                    SyncCollection::Calendar,
                )
                .await
                .caused_by(trc::location!())?;
            server.assert_object_quota(&to_account, StorageQuota::MaxCalendarEvents, 1, || {
                to_resources.resources.count(false)
            })?;
        }

        let to_document_id = batch.reserve_document_id(to_account_id, Collection::CalendarEvent);
        server
            .notify_calendar_addition(
                access_token,
                to_account_id,
                to_document_id.into(),
                to_calendar_id,
                event_flags,
                (from_account_id, from_document_id),
                &mut quota,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        new_event
            .insert(
                new_content,
                access_token.account_tenant_ids(),
                to_account_id,
                to_document_id,
                None,
                next_email_alarms,
                &mut batch,
            )
            .caused_by(trc::location!())?;
    }

    let response = if let Some(to_document_id) = to_document_id {
        // Overwrite event on destination
        let event_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                to_account_id,
                Collection::CalendarEvent,
                to_document_id,
            ))
            .await
            .caused_by(trc::location!())?;
        if let Some(event_) = event_ {
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;

            server
                .notify_calendar_removal(
                    access_token,
                    to_account_id,
                    to_document_id,
                    to_calendar_id,
                    event.inner.flags.to_native(),
                    &mut quota,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            DestroyArchive(event)
                .delete(
                    server,
                    &account_info,
                    to_account_id,
                    to_document_id,
                    to_calendar_id,
                    None,
                    None,
                    false,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    } else {
        Ok(HttpResponse::new(StatusCode::CREATED))
    };

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    response
}

#[allow(clippy::too_many_arguments)]
async fn rename_event(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    calendar_id: u32,
    new_name: &str,
    from_resource_path: String,
) -> crate::Result<HttpResponse> {
    // Fetch event
    let event_ = server
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

    let name_idx = event
        .inner
        .names
        .iter()
        .position(|n| n.parent_id == calendar_id)
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let mut new_event = event
        .deserialize::<CalendarEvent>()
        .caused_by(trc::location!())?;
    new_event.names[name_idx].name = new_name.to_string();

    let mut batch = BatchBuilder::new();
    new_event
        .update_meta(
            access_token.account_tenant_ids(),
            event,
            account_id,
            document_id,
            None,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    batch.log_vanished_item(VanishedCollection::Calendar, from_resource_path);
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED))
}

#[allow(clippy::too_many_arguments)]
async fn copy_container(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    from_children_ids: Vec<u32>,
    from_resource_path: String,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_children_ids: Vec<u32>,
    new_name: &str,
    remove_source: bool,
) -> crate::Result<HttpResponse> {
    // Fetch calendar
    let calendar_ = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            from_account_id,
            Collection::Calendar,
            from_document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let old_calendar = calendar_
        .to_unarchived::<Calendar>()
        .caused_by(trc::location!())?;
    let mut calendar = old_calendar
        .deserialize::<Calendar>()
        .caused_by(trc::location!())?;

    // Validate quota
    let to_account = server.account(to_account_id).await?;
    let has_container_quota = to_document_id.is_none()
        && server
            .object_quota_limit(&to_account, StorageQuota::MaxCalendars)
            .is_some();
    let has_item_quota = from_account_id != to_account_id
        && server
            .object_quota_limit(&to_account, StorageQuota::MaxCalendarEvents)
            .is_some();
    let to_resources = if has_container_quota || has_item_quota {
        Some(
            server
                .fetch_groupware_resources(
                    access_token.account_id(),
                    to_account_id,
                    SyncCollection::Calendar,
                )
                .await
                .caused_by(trc::location!())?,
        )
    } else {
        None
    };
    if has_container_quota && let Some(to_resources) = &to_resources {
        server.assert_object_quota(&to_account, StorageQuota::MaxCalendars, 1, || {
            to_resources.resources.count(true)
        })?;
    }
    let deleted_events = match &to_resources {
        Some(to_resources) if has_item_quota => to_children_ids
            .iter()
            .filter(|document_id| {
                to_resources
                    .resources
                    .find(**document_id, false)
                    .is_some_and(|item| item.child_names().len() <= 1)
            })
            .count(),
        _ => 0,
    };

    // Prepare write batch
    let mut batch = BatchBuilder::new();

    let personal_id = access_token.personal_id(from_account_id, Collection::Calendar);
    let preference = calendar
        .preferences
        .iter()
        .position(|preferences| preferences.account_id == personal_id)
        .or_else(|| {
            calendar
                .preferences
                .iter()
                .position(|preferences| preferences.account_id == from_account_id)
        })
        .map(|idx| calendar.preferences.swap_remove(idx))
        .unwrap_or_default();
    let mut default_alerts = DefaultAlertsResolver::default();
    calendar.name = new_name.to_string();
    calendar.acls.clear();
    calendar.preferences = vec![CalendarPreferences {
        account_id: to_account_id,
        name: preference.name,
        description: preference.description,
        default_alerts: preference.default_alerts,
        sort_order: 0,
        color: preference.color,
        flags: CALENDAR_SUBSCRIBED,
        time_zone: Timezone::Default,
    }];

    let account_info = server
        .account_info(access_token.account_id())
        .await
        .caused_by(trc::location!())?;
    let is_overwrite = to_document_id.is_some();
    let to_document_id = if let Some(to_document_id) = to_document_id {
        // Overwrite destination
        let calendar_ = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                to_account_id,
                Collection::Calendar,
                to_document_id,
            ))
            .await
            .caused_by(trc::location!())?;
        if let Some(calendar_) = calendar_ {
            let calendar = calendar_
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;

            DestroyArchive(calendar)
                .delete_with_events(
                    server,
                    access_token,
                    &account_info,
                    to_account_id,
                    to_document_id,
                    to_children_ids,
                    None,
                    false,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
        }

        PendingId::Assigned(to_document_id)
    } else {
        PendingId::Slot(batch.reserve_document_id(to_account_id, Collection::Calendar))
    };
    let parent_id = to_document_id;
    let alarm_calendar_id = parent_id.assigned().unwrap_or(u32::MAX);
    default_alerts.set_calendar_settings(
        to_account_id,
        alarm_calendar_id,
        CalendarSettings::from(&calendar),
    );
    calendar
        .insert(
            access_token.account_tenant_ids(),
            to_account_id,
            to_document_id,
            &mut batch,
        )
        .caused_by(trc::location!())?;

    // Copy children
    let mut required_space = 0;
    let mut created_events = 0;
    for from_child_document_id in from_children_ids {
        if let Some(event_) = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                from_account_id,
                Collection::CalendarEvent,
                from_child_document_id,
            ))
            .await?
        {
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_name = None;

            for name in event.inner.names.iter() {
                if parent_id
                    .assigned()
                    .is_some_and(|parent| name.parent_id == parent)
                {
                    continue;
                } else if name.parent_id == from_document_id {
                    new_name = Some(name.name.to_string());
                }
            }
            let new_name = if let Some(new_name) = new_name {
                DavName {
                    name: new_name,
                    parent_id: parent_id.assigned().unwrap_or_default(),
                }
            } else {
                continue;
            };
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_event = event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            if from_account_id == to_account_id {
                if remove_source {
                    new_event
                        .names
                        .retain(|name| name.parent_id != from_document_id);
                }

                let calendar_ids = new_event
                    .names
                    .iter()
                    .map(DavName::parent_id)
                    .chain([alarm_calendar_id])
                    .collect::<Vec<_>>();
                new_event.names.push(new_name);
                assert_parent_limit(
                    event.inner.names.len(),
                    new_event.names.len(),
                    server.core.groupware.max_calendars_per_event,
                )?;
                server
                    .reschedule_event_alarms(
                        from_account_id,
                        from_child_document_id,
                        event.inner,
                        &calendar_ids,
                        &mut default_alerts,
                        &mut batch,
                    )
                    .await
                    .caused_by(trc::location!())?;
                new_event
                    .update_meta(
                        access_token.account_tenant_ids(),
                        event,
                        from_account_id,
                        from_child_document_id,
                        parent_id.slot(),
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
            } else {
                let content_ = server
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        from_account_id,
                        Collection::CalendarEvent,
                        from_child_document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
                    .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
                let mut new_content = content_
                    .deserialize::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                new_content
                    .preferences
                    .retain(|preferences| preferences.account_id == access_token.account_id());
                let next_email_alarms = server
                    .next_event_alarms(
                        to_account_id,
                        &EventAlarmUsers::new(to_account_id, &new_content)?
                            .with_event_flags(event.inner.flags.to_native()),
                        &new_content.data,
                        &[alarm_calendar_id],
                        now() as i64,
                        &mut default_alerts,
                    )
                    .await
                    .caused_by(trc::location!())?;

                if remove_source {
                    DestroyArchive(event)
                        .delete(
                            server,
                            &account_info,
                            from_account_id,
                            from_child_document_id,
                            from_document_id,
                            Some(content_),
                            None,
                            false,
                            &mut batch,
                        )
                        .await
                        .caused_by(trc::location!())?;
                }
                let to_document_id =
                    batch.reserve_document_id(to_account_id, Collection::CalendarEvent);
                new_event.names = vec![new_name];
                required_space += new_event.size as u64;
                created_events += 1;
                new_event
                    .insert(
                        new_content,
                        access_token.account_tenant_ids(),
                        to_account_id,
                        to_document_id,
                        parent_id.slot(),
                        next_email_alarms,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
            }
        }
    }

    if has_item_quota
        && created_events > deleted_events
        && let Some(to_resources) = &to_resources
    {
        server.assert_object_quota(
            &to_account,
            StorageQuota::MaxCalendarEvents,
            created_events - deleted_events,
            || to_resources.resources.count(false),
        )?;
    }

    if from_account_id != to_account_id && required_space > 0 {
        server
            .has_available_quota(&to_account, required_space)
            .await?;
    }

    if remove_source {
        DestroyArchive(old_calendar)
            .delete(
                access_token.account_tenant_ids(),
                from_account_id,
                from_document_id,
                from_resource_path.into(),
                &mut batch,
            )
            .caused_by(trc::location!())?;

        batch
            .with_account_id(from_account_id)
            .with_collection(Collection::Principal)
            .with_document(0)
            .clear_if_equals(PrincipalField::DefaultCalendarId, from_document_id);
    }

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    if !is_overwrite {
        Ok(HttpResponse::new(StatusCode::CREATED))
    } else {
        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}

#[allow(clippy::too_many_arguments)]
async fn rename_container(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    new_name: &str,
    from_resource_path: String,
) -> crate::Result<HttpResponse> {
    // Fetch calendar
    let calendar_ = server
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
    let mut new_calendar = calendar
        .deserialize::<Calendar>()
        .caused_by(trc::location!())?;
    new_calendar.name = new_name.to_string();

    let mut batch = BatchBuilder::new();
    new_calendar
        .update(
            access_token.account_tenant_ids(),
            calendar,
            account_id,
            document_id,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    batch.log_vanished_item(VanishedCollection::Calendar, from_resource_path);
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED))
}
