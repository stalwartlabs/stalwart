/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CalendarComponentSupport, CalendarEventView, assert_event_privacy_access,
    assert_event_privacy_allowed, assert_is_unique_uid, serves_ical, user_data_error,
};
use crate::{
    DavError, DavErrorCondition, DavMethod,
    calendar::ItipPrecondition,
    common::{
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
    fix_percent_encoding,
};
use calcard::{
    Entry, Parser,
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarComponentType},
};
use common::{ArchivedDavName, DavName, Server, auth::AccessToken};
use compact_str::ToCompactString;
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CalCondition},
};
use groupware::{
    SizeWriter,
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, CalendarEventContent, CalendarEventData, SupportedComponent,
        alerts::{DefaultAlertsResolver, DefaultAlertsView, ICalendarDefaultAlerts},
        identity::ParticipantIdentityAddresses,
        itip::ItipSendStatus,
        notification::{hides_details, may_have_viewers},
        privacy::EventViewer,
        rights::{EventAcl, EventChanges},
        schedule::{EventAlarmScheduler, EventAlarmUsers},
        storage::{DirectChange, DirectChangeNotification, NotificationQuota},
        user::{ICalendarUserData, UpdatedPolicy, UserDataSplit, UserDataUpdate, UserDataView},
    },
    scheduling::{
        ItipMessages, event_create::itip_create, event_update::itip_update,
        itip::itip_set_unreachable_status, recipient::RecipientPolicy,
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::StorageQuota;
use std::collections::HashSet;
use store::write::{BatchBuilder, now};
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
use utils::map::bitmap::Bitmap;

pub(crate) trait CalendarUpdateRequestHandler: Sync + Send {
    fn handle_calendar_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarUpdateRequestHandler for Server {
    async fn handle_calendar_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
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
        let resource_name = fix_percent_encoding(
            resource
                .resource
                .ok_or(DavError::Code(StatusCode::CONFLICT))?,
        );

        if bytes.len() > self.core.groupware.max_ical_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::MaxResourceSize(self.core.groupware.max_ical_size as u32),
            )));
        }
        let ical_raw = std::str::from_utf8(&bytes).map_err(|_| {
            DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::SupportedCalendarData,
                )
                .with_details("Invalid UTF-8 in iCalendar data"),
            )
        })?;

        let mut ical = match Parser::new(ical_raw).entry() {
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
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);

        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;

        if let Some(resource) = resources.by_path(resource_name.as_ref()) {
            if resource.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            let parent_id = resource.parent_id().unwrap();
            let document_id = resource.document_id();
            let is_owner = access_token.is_member(account_id);
            if !is_owner
                && !resources.has_access_to_container(
                    access_token,
                    parent_id,
                    Bitmap::from_iter([
                        Acl::ModifyItems,
                        Acl::ModifyItemsOwn,
                        Acl::ModifyPrivateProperties,
                        Acl::ModifyRSVP,
                    ]),
                )
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
            let viewer = EventViewer::new(is_owner);
            assert_event_privacy_access(resource.resource.event_flags(), viewer)?;
            assert_event_privacy_allowed(&ical, viewer)?;

            // Update
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
            let content_ = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                    CalendarEventField::Content,
                ))
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let content = content_
                .to_unarchived::<CalendarEventContent>()
                .caused_by(trc::location!())?;

            // Validate headers
            match self
                .validate_headers(
                    access_token,
                    headers,
                    vec![ResourceState {
                        account_id,
                        collection: Collection::CalendarEvent,
                        document_id: Some(document_id),
                        etag: format!("\"{}\"", event.inner.etag.to_native()).into(),
                        path: resource_name.as_ref(),
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

            if ical == content.inner.data.event {
                // No changes, return existing event
                return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
            }

            // Validate iCal
            let (uid, component) = validate_ical(&ical)?;
            if event.inner.uid.as_str() != uid {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::NoUidConflict(resources.format_resource(resource).into()),
                )));
            }
            self.supported_components(account_id, parent_id)
                .await?
                .assert_supports(component)?;

            // Validate schedule tag
            if headers.if_schedule_tag.is_some()
                && event.inner.schedule_tag.as_ref().map(|t| t.to_native())
                    != headers.if_schedule_tag
            {
                return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
            }

            // Obtain previous alarm
            let now = now() as i64;
            let calendar_ids = event
                .inner
                .names
                .iter()
                .map(ArchivedDavName::parent_id)
                .collect::<Vec<_>>();
            let mut default_alerts_resolver =
                DefaultAlertsResolver::with_resources(account_id, resources.clone());
            let prev_email_alarms = self
                .next_event_alarms(
                    account_id,
                    &EventAlarmUsers::new(account_id, content.inner)?
                        .with_event_flags(event.inner.flags.to_native()),
                    &content.inner.data,
                    &calendar_ids,
                    now,
                    &mut default_alerts_resolver,
                )
                .await
                .caused_by(trc::location!())?;

            // Build event
            let mut new_event = event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_content = content
                .deserialize::<CalendarEventContent>()
                .caused_by(trc::location!())?;

            let writer_default_alerts = default_alerts_resolver
                .resolve_for_content(
                    self,
                    account_id,
                    personal_id,
                    &new_content,
                    event.inner.names.iter().map(ArchivedDavName::parent_id),
                )
                .await
                .caused_by(trc::location!())?;
            let has_default_alerts = writer_default_alerts.is_enabled();
            let submitted_ical = ical.clone();
            ical.strip_default_alerts(&writer_default_alerts);
            let sharee_alerts_view = |content: &CalendarEventContent| {
                let mut view = content.data.event.clone();
                view.apply_user_data(content.preferences(personal_id), UserDataView::AlertsOnly);
                view
            };
            let mut sharee_view = None;
            if has_default_alerts {
                if is_owner {
                    ical.restore_hidden_alerts(&new_content.data.event, &writer_default_alerts);
                } else {
                    ical.restore_hidden_alerts(
                        sharee_view.insert(sharee_alerts_view(&new_content)),
                        &writer_default_alerts,
                    );
                }
            }
            let changes_shared_user_data =
                !is_owner && !ical.has_same_user_data(&new_content.data.event);
            if is_owner || changes_shared_user_data {
                ical.validate_user_data_changes(&new_content.data.event)
                    .map_err(user_data_error)?;
            }

            if !is_owner {
                let identities = self
                    .account_identity_addresses(access_token.account_id())
                    .await
                    .caused_by(trc::location!())?;
                let ownership = identities.event_ownership(&new_content.data.event);
                let acl = EventAcl::for_calendars(
                    &resources,
                    access_token,
                    event.inner.names.iter().map(ArchivedDavName::parent_id),
                );
                if !acl.may_write(ownership) {
                    if changes_shared_user_data {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }
                    let event_flags = event.inner.flags.to_native();
                    let sharee_view =
                        sharee_view.unwrap_or_else(|| sharee_alerts_view(&new_content));
                    let mut changes = EventChanges::between(
                        &sharee_view.into_jscalendar(),
                        &ical.clone().into_jscalendar(),
                        event_flags,
                        event_flags,
                        &identities,
                    );
                    changes.classify_recurrence_sets(&new_content.data.event, &ical);
                    changes
                        .assert_allowed(&acl, ownership, event_flags)
                        .map_err(|_| DavError::Code(StatusCode::FORBIDDEN))?;
                }
            }

            let is_user_data_only = if is_owner {
                false
            } else {
                let stored_preferences = new_content
                    .preferences
                    .iter()
                    .find(|p| p.account_id == personal_id);
                let (preferences, split) = ical
                    .split_user_data(
                        &new_content.data.event,
                        UserDataUpdate {
                            account_id: personal_id,
                            view: UserDataView::AlertsOnly,
                            previous: stored_preferences,
                            current: stored_preferences,
                            updated: UpdatedPolicy::Server(now),
                        },
                    )
                    .map_err(user_data_error)?;
                new_content.set_preferences(preferences);
                split == UserDataSplit::UserDataOnly
            };
            let old_ical = if is_user_data_only {
                None
            } else {
                let old_ical = std::mem::take(&mut new_content.data.event);
                let owner_default_alerts = default_alerts_resolver
                    .resolve_for_content(
                        self,
                        account_id,
                        account_id,
                        &new_content,
                        event.inner.names.iter().map(ArchivedDavName::parent_id),
                    )
                    .await
                    .caused_by(trc::location!())?;
                new_content.data = CalendarEventData::new_with_default_alerts(
                    ical,
                    Tz::Floating,
                    self.core.groupware.max_ical_instances,
                    &owner_default_alerts,
                );
                Some(old_ical)
            };
            let next_email_alarms = self
                .next_event_alarms(
                    account_id,
                    &EventAlarmUsers::new(account_id, &new_content)?
                        .with_event_flags(new_event.flags),
                    &new_content.data,
                    &calendar_ids,
                    now,
                    &mut default_alerts_resolver,
                )
                .await
                .caused_by(trc::location!())?;

            // Scheduling
            let mut itip_messages = None;
            let itip_status = if is_user_data_only {
                ItipSendStatus::NotRequested
            } else {
                ItipSendStatus::resolve(
                    self,
                    access_token,
                    &account_info,
                    new_content.data.event_range_end(),
                )
            };
            if itip_status.is_send() {
                let policy = RecipientPolicy::new(&self.core.groupware, new_event.flags);
                let result = if let Some(old_ical) = old_ical
                    .as_ref()
                    .filter(|_| new_event.schedule_tag.is_some())
                {
                    itip_update(
                        &mut new_content.data.event,
                        old_ical,
                        account_info.addresses(),
                        policy,
                    )
                } else {
                    itip_create(
                        &mut new_content.data.event,
                        account_info.addresses(),
                        policy,
                    )
                };

                match result {
                    Ok(messages) => {
                        let mut is_organizer = false;
                        if messages
                            .iter()
                            .map(|r| {
                                is_organizer = r.from_organizer;
                                r.to.len()
                            })
                            .sum::<usize>()
                            < self.core.groupware.itip_outbound_max_recipients
                        {
                            // Only update schedule tag if the user is the organizer
                            if is_organizer {
                                if let Some(schedule_tag) = &mut new_event.schedule_tag {
                                    *schedule_tag += 1;
                                } else {
                                    new_event.schedule_tag = Some(1);
                                }
                            }

                            itip_messages = Some(ItipMessages::new(messages));
                        } else {
                            return Err(DavError::Condition(DavErrorCondition::new(
                                StatusCode::PRECONDITION_FAILED,
                                CalCondition::MaxAttendeesPerInstance,
                            )));
                        }
                    }
                    Err(err) => {
                        if let Some(failed_precondition) = err.failed_precondition() {
                            return Err(DavError::Condition(
                                DavErrorCondition::new(
                                    StatusCode::PRECONDITION_FAILED,
                                    failed_precondition,
                                )
                                .with_details(err.to_string()),
                            ));
                        }

                        trc::event!(
                            Calendar(trc::CalendarEvent::ItipMessageError),
                            AccountId = account_id,
                            DocumentId = document_id,
                            Reason = err.to_compact_string(),
                        );

                        // Event changed, but there are no iTIP messages to send
                        if let Some(schedule_tag) = &mut new_event.schedule_tag {
                            *schedule_tag += 1;
                        }
                    }
                }

                itip_set_unreachable_status(&mut new_content.data.event, account_info.addresses());
            } else if let Some(reason) = itip_status.reason() {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Reason = reason,
                );
            }

            // Validate quota
            let extra_bytes = (SizeWriter::ical(&new_content.data.event) as u64)
                .saturating_sub(u32::from(event.inner.size) as u64);
            if extra_bytes > 0 {
                self.has_available_quota(self.account(account_id).await?.as_ref(), extra_bytes)
                    .await?;
            }

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let notify_event_flags = new_event.flags | event.inner.flags.to_native();
            if let Some(old_ical) = old_ical.filter(|_| {
                may_have_viewers(
                    access_token,
                    account_id,
                    &resources,
                    &calendar_ids,
                    hides_details(notify_event_flags),
                )
            }) {
                self.notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Updated {
                        event_id: document_id,
                        previous: old_ical,
                        current: new_content.data.event.clone(),
                        calendar_ids: calendar_ids.clone(),
                        event_flags: notify_event_flags,
                    },
                    Some(&resources),
                    &mut NotificationQuota::default(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            }
            let serves_submitted_ical = if is_owner && !has_default_alerts {
                serves_ical(&new_content.data.event, &submitted_ical)
            } else {
                let view_default_alerts = default_alerts_resolver
                    .resolve_for_ical_view(
                        self,
                        account_id,
                        personal_id,
                        &new_content,
                        calendar_ids.iter().copied(),
                    )
                    .await
                    .caused_by(trc::location!())?;
                let mut view = new_content.data.event.clone();
                if !is_owner {
                    view.apply_user_data(
                        new_content.preferences(personal_id),
                        UserDataView::AlertsOnly,
                    );
                }
                view.apply_default_alerts(&view_default_alerts, DefaultAlertsView::ICalendar);
                serves_ical(&view, &submitted_ical)
            };

            let schedule_tag = new_event.schedule_tag;
            let etag = new_event
                .update_full(
                    new_content,
                    access_token.account_tenant_ids(),
                    event,
                    content.inner,
                    account_id,
                    document_id,
                    None,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            self.replace_event_alarms(
                account_id,
                document_id,
                prev_email_alarms,
                next_email_alarms,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
            if let Some(itip_messages) = itip_messages {
                itip_messages
                    .queue(&mut batch)
                    .caused_by(trc::location!())?;
            }
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT)
                .with_etag_opt(serves_submitted_ical.then_some(etag))
                .with_schedule_tag_opt(schedule_tag))
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name.as_ref()) {
            if !parent.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            let is_owner = access_token.is_member(account_id);
            if !is_owner
                && !resources.has_access_to_container(
                    access_token,
                    parent.document_id(),
                    Acl::AddItems,
                )
                && !(EventAcl::for_calendar(&resources, access_token, parent.document_id())
                    .may_manage_own_items()
                    && self
                        .account_identity_addresses(access_token.account_id())
                        .await
                        .caused_by(trc::location!())?
                        .event_ownership(&ical)
                        .may_write_own())
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
            assert_event_privacy_allowed(&ical, EventViewer::new(is_owner))?;
            ical.validate_user_data().map_err(user_data_error)?;

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    path: resource_name.as_ref(),
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            // Validate ical object
            let (uid, component) = validate_ical(&ical)?;
            assert_is_unique_uid(
                &resources,
                access_token,
                account_id,
                parent.document_id(),
                Some(uid),
            )?;
            self.supported_components(account_id, parent.document_id())
                .await?
                .assert_supports(component)?;

            // Validate object quota
            let account = self.account(account_id).await?;
            self.assert_object_quota(&account, StorageQuota::MaxCalendarEvents, 1, || {
                resources.resources.count(false)
            })?;

            let submitted_ical = ical.clone();
            let mut preferences = Vec::new();
            if !is_owner {
                let extracted = ical
                    .extract_user_data(personal_id)
                    .map_err(user_data_error)?;
                ical.apply_user_data(None, UserDataView::Full);
                if !extracted.is_empty() {
                    preferences.push(extracted);
                }
            }

            // Build event
            let mut event = CalendarEvent {
                names: vec![DavName {
                    name: name.to_string(),
                    parent_id: parent.document_id(),
                }],
                ..Default::default()
            };
            let mut content = CalendarEventContent {
                data: CalendarEventData::new(
                    ical,
                    Tz::Floating,
                    self.core.groupware.max_ical_instances,
                ),
                preferences,
                ..Default::default()
            };
            let next_email_alarms = self
                .next_event_alarms(
                    account_id,
                    &EventAlarmUsers::new(account_id, &content)?,
                    &content.data,
                    &[parent.document_id()],
                    now() as i64,
                    &mut DefaultAlertsResolver::with_resources(account_id, resources.clone()),
                )
                .await
                .caused_by(trc::location!())?;

            // Scheduling
            let mut itip_messages = None;
            let itip_status = ItipSendStatus::resolve(
                self,
                access_token,
                &account_info,
                content.data.event_range_end(),
            );
            if itip_status.is_send() {
                match itip_create(
                    &mut content.data.event,
                    account_info.addresses(),
                    RecipientPolicy::new(&self.core.groupware, event.flags),
                ) {
                    Ok(messages) => {
                        if messages.iter().map(|r| r.to.len()).sum::<usize>()
                            < self.core.groupware.itip_outbound_max_recipients
                        {
                            event.schedule_tag = Some(1);
                            itip_messages = Some(ItipMessages::new(messages));
                        } else {
                            return Err(DavError::Condition(DavErrorCondition::new(
                                StatusCode::PRECONDITION_FAILED,
                                CalCondition::MaxAttendeesPerInstance,
                            )));
                        }
                    }
                    Err(err) => {
                        if let Some(failed_precondition) = err.failed_precondition() {
                            return Err(DavError::Condition(
                                DavErrorCondition::new(
                                    StatusCode::PRECONDITION_FAILED,
                                    failed_precondition,
                                )
                                .with_details(err.to_string()),
                            ));
                        }

                        trc::event!(
                            Calendar(trc::CalendarEvent::ItipMessageError),
                            AccountId = account_id,
                            Reason = err.to_compact_string(),
                        );
                    }
                }

                itip_set_unreachable_status(&mut content.data.event, account_info.addresses());
            } else if let Some(reason) = itip_status.reason() {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = account_id,
                    Reason = reason,
                );
            }

            // Validate quota
            if !bytes.is_empty() {
                self.has_available_quota(&account, bytes.len() as u64)
                    .await?;
            }

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = batch.reserve_document_id(account_id, Collection::CalendarEvent);
            let notify_calendar_ids = event.calendar_ids().collect::<Vec<_>>();
            if may_have_viewers(
                access_token,
                account_id,
                &resources,
                &notify_calendar_ids,
                hides_details(event.flags),
            ) {
                self.notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Created {
                        event_id: document_id.into(),
                        current: content.data.event.clone(),
                        calendar_ids: notify_calendar_ids,
                        event_flags: event.flags,
                    },
                    Some(&resources),
                    &mut NotificationQuota::default(),
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            }
            let serves_submitted_ical = if is_owner {
                serves_ical(&content.data.event, &submitted_ical)
            } else {
                let mut view = content.data.event.clone();
                view.apply_user_data(content.preferences(personal_id), UserDataView::AlertsOnly);
                serves_ical(&view, &submitted_ical)
            };

            let schedule_tag = event.schedule_tag;
            let etag = event
                .insert(
                    content,
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    None,
                    next_email_alarms,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            if let Some(itip_messages) = itip_messages {
                itip_messages
                    .queue(&mut batch)
                    .caused_by(trc::location!())?;
            }
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::CREATED)
                .with_etag_opt(serves_submitted_ical.then_some(etag))
                .with_schedule_tag_opt(schedule_tag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}

fn validate_ical(ical: &ICalendar) -> crate::Result<(&str, SupportedComponent)> {
    let mut uids = HashSet::with_capacity(1);
    let mut object_type = None;
    let mut has_mixed_types = false;
    for comp in &ical.components {
        let component = match comp.component_type {
            ICalendarComponentType::VEvent => SupportedComponent::VEvent,
            ICalendarComponentType::VTodo => SupportedComponent::VTodo,
            ICalendarComponentType::VJournal => SupportedComponent::VJournal,
            ICalendarComponentType::VFreebusy => SupportedComponent::VFreebusy,
            ICalendarComponentType::VAvailability => SupportedComponent::VAvailability,
            _ => {
                continue;
            }
        };
        has_mixed_types |= object_type
            .replace(component)
            .is_some_and(|previous| previous != component);

        if let Some(uid) = comp.uid() {
            uids.insert(uid);
        }
    }

    let uid = if uids.len() == 1 {
        uids.into_iter().next()
    } else {
        None
    };
    match (uid, object_type) {
        (Some(uid), Some(object_type)) if !has_mixed_types => Ok((uid, object_type)),
        _ => Err(DavError::Condition(
            DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::ValidCalendarObjectResource,
            )
            .with_details("iCalendar must contain exactly one UID and same component types"),
        )),
    }
}
