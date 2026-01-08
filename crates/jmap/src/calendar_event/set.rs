/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::calendar_event::{CalendarSyntheticId, assert_is_unique_uid};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarAction, ICalendarComponent, ICalendarComponentType, ICalendarDuration,
        ICalendarEntry, ICalendarParameter, ICalendarParameterValue, ICalendarProperty,
        ICalendarRelated, ICalendarValue,
    },
    jscalendar::{JSCalendar, JSCalendarDateTime, JSCalendarProperty, JSCalendarValue},
};
use chrono::DateTime;
use common::{DavName, DavResources, Server, auth::AccessToken};
use directory::Permission;
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        ALERT_EMAIL, ALERT_RELATIVE_TO_END, ArchivedDefaultAlert, Calendar, CalendarEvent,
        CalendarEventData, EVENT_DRAFT, EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS,
        EVENT_INVITE_SELF,
    },
    scheduling::{ItipMessages, event_create::itip_create, event_update::itip_update},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar_event,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{JsonPointerHandler, JsonPointerItem, Key, Map, Value};
use std::{borrow::Cow, str::FromStr};
use store::{
    ValueKey,
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder, now, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

pub trait CalendarEventSet: Sync + Send {
    fn calendar_event_set(
        &self,
        request: SetRequest<'_, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<calendar_event::CalendarEvent>>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn create_calendar_event(
        &self,
        cache: &DavResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account_id: u32,
        send_scheduling_messages: bool,
        can_add_calendars: &Option<RoaringBitmap>,
        js_calendar_event: JSCalendar<'_, Id, BlobId>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> impl Future<Output = trc::Result<Result<u32, SetError<JSCalendarProperty<Id>>>>>;
}

impl CalendarEventSet for Server {
    async fn calendar_event_set(
        &self,
        mut request: SetRequest<'_, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<calendar_event::CalendarEvent>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Obtain calendarIds
        let (can_add_calendars, can_delete_calendars, can_modify_calendars) =
            if access_token.is_shared(account_id) {
                (
                    cache
                        .shared_containers(access_token, [Acl::AddItems], true)
                        .into(),
                    cache
                        .shared_containers(access_token, [Acl::RemoveItems], true)
                        .into(),
                    cache
                        .shared_containers(access_token, [Acl::ModifyItems], true)
                        .into(),
                )
            } else {
                (None, None, None)
            };

        // Process creates
        let mut batch = BatchBuilder::new();
        let send_scheduling_messages = request.arguments.send_scheduling_messages.unwrap_or(false);
        'create: for (id, object) in request.unwrap_create() {
            match self
                .create_calendar_event(
                    &cache,
                    &mut batch,
                    access_token,
                    account_id,
                    send_scheduling_messages,
                    &can_add_calendars,
                    JSCalendar::default(),
                    object,
                )
                .await?
            {
                Ok(document_id) => {
                    response.created(id, document_id);
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            } else if id.is_synthetic() {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description("Updating synthetic ids is not yet supported."),
                );
                continue 'update;
            }

            // Obtain calendar_event card
            let document_id = id.document_id();
            let calendar_event_ = if let Some(calendar_event_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await?
            {
                calendar_event_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let calendar_event = calendar_event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_calendar_event = calendar_event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut js_calendar_group =
                std::mem::take(&mut new_calendar_event.data.event).into_jscalendar::<Id, BlobId>();

            // Process changes
            if let Err(err) = update_calendar_event(
                access_token,
                object,
                &mut new_calendar_event,
                &mut js_calendar_group,
            ) {
                response.not_updated.append(id, err);
                continue 'update;
            }

            // Convert JSCalendar to iCalendar
            let Some(ical) = js_calendar_group.into_icalendar() else {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("Failed to convert calendar event to iCalendar."),
                );
                continue 'update;
            };
            new_calendar_event.data.event = ical;

            // Validate UID
            match (
                new_calendar_event.data.event.uids().next(),
                calendar_event.inner.data.event.uids().next(),
            ) {
                (Some(old_uid), Some(new_uid)) if old_uid == new_uid => {}
                (None, None) | (None, Some(_)) => {}
                _ => {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::Uid)
                            .with_description("You cannot change the UID of a calendar event."),
                    );
                    continue 'update;
                }
            }

            // Validate new calendarIds
            for calendar_id in new_calendar_event.added_calendar_ids(calendar_event.inner) {
                if !cache.has_container_id(&calendar_id) {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::CalendarIds)
                            .with_description(format!(
                                "calendarId {} does not exist.",
                                Id::from(calendar_id)
                            )),
                    );
                    continue 'update;
                } else if can_add_calendars
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(calendar_id))
                {
                    response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add calendar events to calendar {}.",
                            Id::from(calendar_id)
                        )),
                    );
                    continue 'update;
                }
            }

            // Validate deleted calendarIds
            if let Some(can_delete_calendars) = &can_delete_calendars {
                for calendar_id in new_calendar_event.removed_calendar_ids(calendar_event.inner) {
                    if !can_delete_calendars.contains(calendar_id) {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to remove calendar events from calendar {}.",
                                Id::from(calendar_id)
                            )),
                        );
                        continue 'update;
                    }
                }
            }

            // Validate changed calendarIds
            if let Some(can_modify_calendars) = &can_modify_calendars {
                for calendar_id in new_calendar_event.unchanged_calendar_ids(calendar_event.inner) {
                    if !can_modify_calendars.contains(calendar_id) {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to modify calendar {}.",
                                Id::from(calendar_id)
                            )),
                        );
                        continue 'update;
                    }
                }
            }

            // Check size and quota
            new_calendar_event.size = new_calendar_event.data.event.size() as u32;
            if new_calendar_event.size as usize > self.core.groupware.max_ical_size {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties().with_description(format!(
                        "Event size {} exceeds the maximum allowed size of {} bytes.",
                        new_calendar_event.size, self.core.groupware.max_ical_size
                    )),
                );
                continue 'update;
            }

            // Obtain previous alarm
            let now = now() as i64;
            let prev_email_alarm = calendar_event.inner.data.next_alarm(now, Tz::Floating);

            // Build event
            let mut next_email_alarm = None;
            new_calendar_event.data = CalendarEventData::new(
                new_calendar_event.data.event,
                Tz::Floating,
                self.core.groupware.max_ical_instances,
                &mut next_email_alarm,
            );

            // Scheduling
            let mut itip_messages = None;
            if send_scheduling_messages
                && self.core.groupware.itip_enabled
                && !access_token.emails.is_empty()
                && access_token.has_permission(Permission::CalendarSchedulingSend)
                && new_calendar_event.data.event_range_end() > now
            {
                let result = if new_calendar_event.schedule_tag.is_some() {
                    let old_ical = rkyv_deserialize(&calendar_event.inner.data.event)
                        .caused_by(trc::location!())?;

                    itip_update(
                        &mut new_calendar_event.data.event,
                        &old_ical,
                        access_token.emails.as_slice(),
                    )
                } else {
                    itip_create(
                        &mut new_calendar_event.data.event,
                        access_token.emails.as_slice(),
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
                                if let Some(schedule_tag) = &mut new_calendar_event.schedule_tag {
                                    *schedule_tag += 1;
                                } else {
                                    new_calendar_event.schedule_tag = Some(1);
                                }
                            }

                            itip_messages = Some(ItipMessages::new(messages));
                        } else {
                            response.not_updated.append(
                                id,
                                SetError::invalid_properties()
                                    .with_property(JSCalendarProperty::Participants)
                                    .with_description(concat!(
                                        "The number of scheduling message recipients ",
                                        "exceeds the maximum allowed."
                                    )),
                            );
                            continue 'update;
                        }
                    }
                    Err(err) => {
                        if err.is_jmap_error() {
                            response.not_updated.append(
                                id,
                                SetError::invalid_properties()
                                    .with_property(JSCalendarProperty::Participants)
                                    .with_description(err.to_string()),
                            );
                            continue 'update;
                        }

                        // Event changed, but there are no iTIP messages to send
                        if let Some(schedule_tag) = &mut new_calendar_event.schedule_tag {
                            *schedule_tag += 1;
                        }
                    }
                }
            }

            // Validate quota
            let extra_bytes = (new_calendar_event.size as u64)
                .saturating_sub(u32::from(calendar_event.inner.size) as u64);
            if extra_bytes > 0 {
                match self
                    .has_available_quota(
                        &self.get_resource_token(access_token, account_id).await?,
                        extra_bytes,
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                        response.not_updated.append(id, SetError::over_quota());
                        continue 'update;
                    }
                    Err(err) => return Err(err.caused_by(trc::location!())),
                }
            }

            // Update record
            new_calendar_event
                .update(
                    access_token,
                    calendar_event,
                    account_id,
                    document_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
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

            response.updated.append(id, None);
        }

        // Process deletions
        'destroy: for id in will_destroy {
            let document_id = id.document_id();

            if !cache.has_item_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            } else if id.is_synthetic() {
                response.not_destroyed.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description("Deleting synthetic ids is not yet supported."),
                );
                continue;
            }

            let Some(calendar_event_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let calendar_event = calendar_event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;

            // Validate ACLs
            if let Some(can_delete_calendars) = &can_delete_calendars {
                for name in calendar_event.inner.names.iter() {
                    let parent_id = name.parent_id.to_native();
                    if !can_delete_calendars.contains(parent_id) {
                        response.not_destroyed.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to remove events from calendar {}.",
                                Id::from(parent_id)
                            )),
                        );
                        continue 'destroy;
                    }
                }
            }

            // Delete event
            DestroyArchive(calendar_event)
                .delete_all(
                    access_token,
                    account_id,
                    document_id,
                    send_scheduling_messages,
                    &mut batch,
                )
                .caused_by(trc::location!())?;

            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;
            self.notify_task_queue();

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }

    async fn create_calendar_event(
        &self,
        cache: &DavResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account_id: u32,
        send_scheduling_messages: bool,
        can_add_calendars: &Option<RoaringBitmap>,
        mut js_calendar_group: JSCalendar<'_, Id, BlobId>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> trc::Result<Result<u32, SetError<JSCalendarProperty<Id>>>> {
        // Process changes
        let mut event = CalendarEvent::default();
        let use_default_alerts = match update_calendar_event(
            access_token,
            updates,
            &mut event,
            &mut js_calendar_group,
        ) {
            Ok(use_default_alerts) => use_default_alerts,
            Err(err) => {
                return Ok(Err(err));
            }
        };

        // Convert JSCalendar to iCalendar
        let Some(mut ical) = js_calendar_group.into_icalendar() else {
            return Ok(Err(SetError::invalid_properties().with_description(
                "Failed to convert calendar event to iCalendar.",
            )));
        };

        // Verify that the calendar ids valid
        let default_alert_comp_id = ical.components.len();
        for name in &event.names {
            if !cache.has_container_id(&name.parent_id) {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(JSCalendarProperty::CalendarIds)
                    .with_description(format!(
                        "calendarId {} does not exist.",
                        Id::from(name.parent_id)
                    ))));
            } else if can_add_calendars
                .as_ref()
                .is_some_and(|ids| !ids.contains(name.parent_id))
            {
                return Ok(Err(SetError::forbidden().with_description(format!(
                    "You are not allowed to add calendar events to calendar {}.",
                    Id::from(name.parent_id)
                ))));
            } else if let Some(show_without_time) = use_default_alerts
                && let Some(_calendar) = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::Calendar,
                        name.parent_id,
                    ))
                    .await?
            {
                ical.components.extend(
                    _calendar
                        .unarchive::<Calendar>()
                        .caused_by(trc::location!())?
                        .default_alerts(access_token, !show_without_time)
                        .map(default_alert_to_ical),
                );
            }
        }

        // Add default alarms
        if ical.components.len() > default_alert_comp_id {
            let component_ids = default_alert_comp_id as u32..ical.components.len() as u32;
            for component in &mut ical.components {
                if component.component_type.is_event_or_todo()
                    && !component.is_recurrence_override()
                {
                    component.component_ids.extend(component_ids.clone());
                }
            }
        }

        // Validate UID
        if let Err(err) = assert_is_unique_uid(self, account_id, ical.uids().next()).await? {
            return Ok(Err(err));
        }

        // Check size and quota
        let size = ical.size();
        if size > self.core.groupware.max_ical_size {
            return Ok(Err(SetError::invalid_properties().with_description(
                format!(
                    "Event size {} exceeds the maximum allowed size of {} bytes.",
                    size, self.core.groupware.max_ical_size
                ),
            )));
        }

        // Build event
        let mut next_email_alarm = None;
        event.data = CalendarEventData::new(
            ical,
            Tz::Floating,
            self.core.groupware.max_ical_instances,
            &mut next_email_alarm,
        );
        event.size = size as u32;

        // Scheduling
        let mut itip_messages = None;
        if send_scheduling_messages
            && self.core.groupware.itip_enabled
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
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(JSCalendarProperty::Participants)
                            .with_description(concat!(
                                "The number of scheduling message recipients ",
                                "exceeds the maximum allowed."
                            ))));
                    }
                }
                Err(err) => {
                    if err.is_jmap_error() {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(JSCalendarProperty::Participants)
                            .with_description(err.to_string())));
                    }
                }
            }
        }

        // Validate quota
        match self
            .has_available_quota(
                &self.get_resource_token(access_token, account_id).await?,
                size as u64,
            )
            .await
        {
            Ok(_) => {}
            Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                return Ok(Err(SetError::over_quota()));
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }

        // Insert record
        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::CalendarEvent, 1)
            .await
            .caused_by(trc::location!())?;
        event
            .insert(
                access_token,
                account_id,
                document_id,
                next_email_alarm,
                batch,
            )
            .caused_by(trc::location!())?;

        if let Some(itip_messages) = itip_messages {
            itip_messages.queue(batch).caused_by(trc::location!())?;
        }

        Ok(Ok(document_id))
    }
}

fn update_calendar_event<'x>(
    _access_token: &AccessToken,
    updates: Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    event: &mut CalendarEvent,
    js_calendar_group: &mut JSCalendar<'x, Id, BlobId>,
) -> Result<Option<bool>, SetError<JSCalendarProperty<Id>>> {
    // Extract event
    let js_calendar_events = js_calendar_group
        .0
        .as_object_mut()
        .unwrap()
        .get_mut(&Key::Property(JSCalendarProperty::Entries))
        .unwrap()
        .as_array_mut()
        .unwrap();

    let js_calendar_event = if let Some(js_calendar_event) = js_calendar_events.first_mut() {
        js_calendar_event
    } else {
        js_calendar_events.push(Value::Object(Map::new()));
        js_calendar_events.first_mut().unwrap()
    };

    let mut utc_start = None;
    let mut utc_end = None;
    let mut use_default_alerts = false;
    let mut show_without_time = false;
    let mut entries = js_calendar_event.as_object_mut().unwrap();

    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (JSCalendarProperty::IsDraft, Value::Bool(set)) => {
                if set {
                    event.flags |= EVENT_DRAFT;
                } else {
                    event.flags &= !EVENT_DRAFT;
                }
            }
            (JSCalendarProperty::MayInviteSelf, Value::Bool(set)) => {
                if set {
                    event.flags |= EVENT_INVITE_SELF;
                } else {
                    event.flags &= !EVENT_INVITE_SELF;
                }
            }
            (JSCalendarProperty::MayInviteOthers, Value::Bool(set)) => {
                if set {
                    event.flags |= EVENT_INVITE_OTHERS;
                } else {
                    event.flags &= !EVENT_INVITE_OTHERS;
                }
            }
            (JSCalendarProperty::HideAttendees, Value::Bool(set)) => {
                if set {
                    event.flags |= EVENT_HIDE_ATTENDEES;
                } else {
                    event.flags &= !EVENT_HIDE_ATTENDEES;
                }
            }
            (JSCalendarProperty::UseDefaultAlerts, Value::Bool(set)) => {
                use_default_alerts = set;
            }
            (JSCalendarProperty::UtcStart, Value::Element(JSCalendarValue::DateTime(start))) => {
                utc_start = Some(start.timestamp);
            }
            (JSCalendarProperty::UtcEnd, Value::Element(JSCalendarValue::DateTime(end))) => {
                utc_end = Some(end.timestamp);
            }
            (JSCalendarProperty::CalendarIds, value) => {
                patch_parent_ids(&mut event.names, None, value)?;
            }
            (JSCalendarProperty::Pointer(pointer), value) => {
                if matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(
                        JSCalendarProperty::CalendarIds
                    )))
                ) {
                    let mut pointer = pointer.iter();
                    pointer.next();
                    patch_parent_ids(&mut event.names, pointer.next(), value)?;
                } else if !js_calendar_event.patch_jptr(pointer.iter(), value) {
                    return Err(SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Pointer(pointer))
                        .with_description("Patch operation failed."));
                }
                entries = js_calendar_event.as_object_mut().unwrap();
            }
            (
                property @ (JSCalendarProperty::Id
                | JSCalendarProperty::BaseEventId
                | JSCalendarProperty::IsOrigin
                | JSCalendarProperty::Method),
                _,
            ) => {
                return Err(SetError::invalid_properties()
                    .with_property(property)
                    .with_description("This property is immutable."));
            }
            (
                property @ (JSCalendarProperty::IsDraft
                | JSCalendarProperty::MayInviteSelf
                | JSCalendarProperty::MayInviteOthers
                | JSCalendarProperty::HideAttendees
                | JSCalendarProperty::UseDefaultAlerts
                | JSCalendarProperty::UtcStart
                | JSCalendarProperty::UtcEnd),
                _,
            ) => {
                return Err(SetError::invalid_properties()
                    .with_property(property)
                    .with_description("Invalid value."));
            }
            (
                property @ (JSCalendarProperty::Locations | JSCalendarProperty::Participants),
                Value::Object(values),
            ) => {
                for (_, value) in values.iter() {
                    if let Some(values) = value
                        .as_object_and_get(&Key::Property(JSCalendarProperty::Links))
                        .and_then(|v| v.as_object())
                    {
                        for (_, value) in values.iter() {
                            if value.as_object().is_some_and(|v| {
                                v.keys()
                                    .any(|k| matches!(k, Key::Property(JSCalendarProperty::BlobId)))
                            }) {
                                return Err(SetError::invalid_properties()
                                    .with_property(property)
                                    .with_description("blobIds in links is not supported."));
                            }
                        }
                    }
                }
                entries.insert(property, Value::Object(values));
            }
            (property, value) => {
                if let (JSCalendarProperty::ShowWithoutTime, Value::Bool(set)) = (&property, &value)
                {
                    show_without_time = *set;
                }

                entries.insert(property, value);
            }
        }
    }

    // Validate UTC start/end
    if let (Some(mut start), Some(mut end)) = (utc_start, utc_end) {
        if start >= end {
            return Err(SetError::invalid_properties()
                .with_properties([JSCalendarProperty::UtcStart, JSCalendarProperty::UtcEnd])
                .with_description("utcStart must be before utcEnd."));
        }

        if let Some(timezone) = entries
            .get(&Key::Property(JSCalendarProperty::TimeZone))
            .and_then(|v| v.as_str())
            .and_then(|tz| Tz::from_str(tz.as_ref()).ok())
        {
            if let Some(dt_start) =
                DateTime::from_timestamp(start, 0).map(|dt| dt.with_timezone(&timezone))
            {
                start = dt_start.naive_local().and_utc().timestamp();
            }
            if let Some(dt_end) =
                DateTime::from_timestamp(end, 0).map(|dt| dt.with_timezone(&timezone))
            {
                end = dt_end.naive_local().and_utc().timestamp();
            }
        } else {
            entries.insert(
                Key::Property(JSCalendarProperty::TimeZone),
                Value::Str(Cow::Borrowed("Etc/UTC")),
            );
        }

        entries.insert(
            Key::Property(JSCalendarProperty::Start),
            Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                start, true,
            ))),
        );
        entries.insert(
            Key::Property(JSCalendarProperty::Duration),
            Value::Element(JSCalendarValue::Duration(ICalendarDuration::from_seconds(
                end - start,
            ))),
        );
    } else if utc_start.is_some() || utc_end.is_some() {
        return Err(SetError::invalid_properties()
            .with_properties([JSCalendarProperty::UtcStart, JSCalendarProperty::UtcEnd])
            .with_description("Both utcStart and utcEnd must be provided."));
    }

    // Make sure the calendar_event belongs to at least one calendar
    if event.names.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::CalendarIds)
            .with_description("Event has to belong to at least one calendar."));
    }

    Ok(use_default_alerts.then_some(show_without_time))
}

fn patch_parent_ids(
    current: &mut Vec<DavName>,
    patch: Option<&JsonPointerItem<JSCalendarProperty<Id>>>,
    update: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
) -> Result<(), SetError<JSCalendarProperty<Id>>> {
    match (patch, update) {
        (
            Some(JsonPointerItem::Key(Key::Property(JSCalendarProperty::IdValue(id)))),
            Value::Bool(false) | Value::Null,
        ) => {
            let id = id.document_id();
            current.retain(|name| name.parent_id != id);
            Ok(())
        }
        (
            Some(JsonPointerItem::Key(Key::Property(JSCalendarProperty::IdValue(id)))),
            Value::Bool(true),
        ) => {
            let id = id.document_id();
            if !current.iter().any(|name| name.parent_id == id) {
                current.push(DavName::new_with_rand_name(id));
            }
            Ok(())
        }
        (None, Value::Object(object)) => {
            let mut new_ids = object
                .into_expanded_boolean_set()
                .filter_map(|id| {
                    if let Key::Property(JSCalendarProperty::IdValue(id)) = id {
                        Some(id.document_id())
                    } else {
                        None
                    }
                })
                .collect::<AHashSet<_>>();

            current.retain(|name| new_ids.remove(&name.parent_id));

            for id in new_ids {
                current.push(DavName::new_with_rand_name(id));
            }

            Ok(())
        }
        _ => Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::CalendarIds)
            .with_description("Invalid patch operation for calendarIds.")),
    }
}

fn default_alert_to_ical(alert: &ArchivedDefaultAlert) -> ICalendarComponent {
    let flags = alert.flags.to_native();
    ICalendarComponent {
        component_type: ICalendarComponentType::VAlarm,
        entries: vec![
            ICalendarEntry::new(ICalendarProperty::Action).with_value(
                if flags & ALERT_EMAIL != 0 {
                    ICalendarValue::Action(ICalendarAction::Email)
                } else {
                    ICalendarValue::Action(ICalendarAction::Display)
                },
            ),
            ICalendarEntry::new(ICalendarProperty::Trigger)
                .with_param_opt((flags & ALERT_RELATIVE_TO_END != 0).then_some(
                    ICalendarParameter::related(ICalendarParameterValue::Related(
                        ICalendarRelated::End,
                    )),
                ))
                .with_value(ICalendarValue::Duration(alert.offset.to_native())),
        ],
        component_ids: vec![],
    }
}
