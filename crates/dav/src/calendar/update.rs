/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::assert_is_unique_uid;
use crate::{
    DavError, DavErrorCondition, DavMethod,
    calendar::ItipPrecondition,
    common::{
        ETag, ExtractETag,
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
use common::{DavName, Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CalCondition},
};
use directory::Permission;
use groupware::{
    cache::GroupwareCache,
    calendar::{CalendarEvent, CalendarEventData},
    scheduling::{ItipMessages, event_create::itip_create, event_update::itip_update},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::collections::HashSet;
use store::write::{BatchBuilder, now};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

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
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
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

        if let Some(resource) = resources.by_path(resource_name.as_ref()) {
            if resource.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            let parent_id = resource.parent_id().unwrap();
            let document_id = resource.document_id();
            if !access_token.is_member(account_id)
                && !resources.has_access_to_container(access_token, parent_id, Acl::ModifyItems)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Update
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
            let event = event_
                .to_unarchived::<CalendarEvent>()
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
                        etag: event.etag().into(),
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
                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type("text/calendar; charset=utf-8")
                        .with_etag(event.etag())
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(event.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(event.inner.data.event.to_string()));
                }
                Err(e) => return Err(e),
            }

            if ical == event.inner.data.event {
                // No changes, return existing event
                return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
            }

            // Validate iCal
            if event.inner.data.event.uids().next().unwrap_or_default() != validate_ical(&ical)? {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::NoUidConflict(resources.format_resource(resource).into()),
                )));
            }

            // Validate schedule tag
            if headers.if_schedule_tag.is_some()
                && event.inner.schedule_tag.as_ref().map(|t| t.to_native())
                    != headers.if_schedule_tag
            {
                return Err(DavError::Code(StatusCode::PRECONDITION_FAILED));
            }

            // Obtain previous alarm
            let now = now() as i64;
            let prev_email_alarm = event.inner.data.next_alarm(now, Tz::Floating);

            // Build event
            let mut next_email_alarm = None;
            let mut new_event = event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let old_ical = new_event.data.event;
            new_event.size = bytes.len() as u32;
            new_event.data = CalendarEventData::new(
                ical,
                Tz::Floating,
                self.core.groupware.max_ical_instances,
                &mut next_email_alarm,
            );

            // Scheduling
            let mut itip_messages = None;
            if self.core.groupware.itip_enabled
                && !access_token.emails.is_empty()
                && access_token.has_permission(Permission::CalendarSchedulingSend)
                && new_event.data.event_range_end() > now
            {
                let result = if new_event.schedule_tag.is_some() {
                    itip_update(
                        &mut new_event.data.event,
                        &old_ical,
                        access_token.emails.as_slice(),
                    )
                } else {
                    itip_create(&mut new_event.data.event, access_token.emails.as_slice())
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

                        // Event changed, but there are no iTIP messages to send
                        if let Some(schedule_tag) = &mut new_event.schedule_tag {
                            *schedule_tag += 1;
                        }
                    }
                }
            }
            // Validate quota
            let extra_bytes =
                (bytes.len() as u64).saturating_sub(u32::from(event.inner.size) as u64);
            if extra_bytes > 0 {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    extra_bytes,
                )
                .await?;
            }

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let schedule_tag = new_event.schedule_tag;
            let etag = new_event
                .update(access_token, event, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?
                .etag();
            if prev_email_alarm != next_email_alarm {
                if let Some(prev_alarm) = prev_email_alarm {
                    prev_alarm.delete_task(&mut batch);
                }
                if let Some(next_alarm) = next_email_alarm {
                    next_alarm.write_task(&mut batch);
                }
            }
            if let Some(itip_messages) = itip_messages {
                itip_messages
                    .queue(&mut batch)
                    .caused_by(trc::location!())?;
            }
            self.commit_batch(batch).await.caused_by(trc::location!())?;
            self.notify_task_queue();

            Ok(HttpResponse::new(StatusCode::NO_CONTENT)
                .with_etag_opt(etag)
                .with_schedule_tag_opt(schedule_tag))
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name.as_ref()) {
            if !parent.is_container() {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            if !access_token.is_member(account_id)
                && !resources.has_access_to_container(
                    access_token,
                    parent.document_id(),
                    Acl::AddItems,
                )
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

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
            assert_is_unique_uid(
                self,
                &resources,
                account_id,
                parent.document_id(),
                validate_ical(&ical)?.into(),
            )
            .await?;

            // Build event
            let mut next_email_alarm = None;
            let mut event = CalendarEvent {
                names: vec![DavName {
                    name: name.to_string(),
                    parent_id: parent.document_id(),
                }],
                data: CalendarEventData::new(
                    ical,
                    Tz::Floating,
                    self.core.groupware.max_ical_instances,
                    &mut next_email_alarm,
                ),
                size: bytes.len() as u32,
                ..Default::default()
            };

            // Scheduling
            let mut itip_messages = None;
            if self.core.groupware.itip_enabled
                && !access_token.emails.is_empty()
                && access_token.has_permission(Permission::CalendarSchedulingSend)
                && event.data.event_range_end() > now() as i64
            {
                match itip_create(&mut event.data.event, access_token.emails.as_slice()) {
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
                    }
                }
            }

            // Validate quota
            if !bytes.is_empty() {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    bytes.len() as u64,
                )
                .await?;
            }

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::CalendarEvent, 1)
                .await
                .caused_by(trc::location!())?;
            let schedule_tag = event.schedule_tag;
            let etag = event
                .insert(
                    access_token,
                    account_id,
                    document_id,
                    next_email_alarm,
                    &mut batch,
                )
                .caused_by(trc::location!())?
                .etag();
            if let Some(itip_messages) = itip_messages {
                itip_messages
                    .queue(&mut batch)
                    .caused_by(trc::location!())?;
            }
            self.commit_batch(batch).await.caused_by(trc::location!())?;
            self.notify_task_queue();

            Ok(HttpResponse::new(StatusCode::CREATED)
                .with_etag_opt(etag)
                .with_schedule_tag_opt(schedule_tag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}

fn validate_ical(ical: &ICalendar) -> crate::Result<&str> {
    // Validate UIDs
    let mut uids = HashSet::with_capacity(1);

    // Validate component types
    let mut types: [u8; 5] = [0; 5];
    for comp in &ical.components {
        *(match comp.component_type {
            ICalendarComponentType::VEvent => &mut types[0],
            ICalendarComponentType::VTodo => &mut types[1],
            ICalendarComponentType::VJournal => &mut types[2],
            ICalendarComponentType::VFreebusy => &mut types[3],
            ICalendarComponentType::VAvailability => &mut types[4],
            _ => {
                continue;
            }
        }) += 1;

        if let Some(uid) = comp.uid() {
            uids.insert(uid);
        }
    }

    if uids.len() == 1 && types.iter().filter(|&&v| v == 0).count() == 4 {
        Ok(uids.iter().next().unwrap())
    } else {
        Err(DavError::Condition(
            DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::ValidCalendarObjectResource,
            )
            .with_details("iCalendar must contain exactly one UID and same component types"),
        ))
    }
}
