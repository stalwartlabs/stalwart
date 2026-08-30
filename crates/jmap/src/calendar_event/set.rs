/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::pending_creates::PendingCreates;
use crate::calendar_event::{CalendarSyntheticId, assert_is_unique_uid};
use crate::changes::state::JmapCacheState;
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarAction, ICalendarComponent, ICalendarComponentType, ICalendarDuration,
        ICalendarEntry, ICalendarParameter, ICalendarParameterName, ICalendarParameterValue,
        ICalendarProperty, ICalendarRelated, ICalendarValue,
    },
    jscalendar::{JSCalendar, JSCalendarDateTime, JSCalendarProperty, JSCalendarValue},
};
use chrono::DateTime;
use common::{
    DavName, DavResources, Server,
    auth::{AccessToken, AccountInfo},
};
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        ALERT_EMAIL, ALERT_RELATIVE_TO_END, ArchivedDefaultAlert, Calendar, CalendarEvent,
        CalendarEventData, EVENT_DRAFT, EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS,
        EVENT_INVITE_SELF,
        expand::{CalendarEventExpansion, resolve_local},
    },
    scheduling::{
        ItipMessages,
        event_create::itip_create,
        event_update::itip_update,
        itip::{itip_assign_organizer, itip_unreachable_recipient},
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar_event,
    request::MaybeInvalid,
    types::state::State,
};
use jmap_tools::{JsonPointerHandler, JsonPointerItem, Key, Map, Value};
use registry::schema::enums::Permission;
use std::{borrow::Cow, str::FromStr};
use store::{
    ValueKey,
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, Slot, now, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection, VanishedCollection},
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
        account_info: &AccountInfo,
        send_scheduling_messages: bool,
        can_add_calendars: &Option<RoaringBitmap>,
        js_calendar_event: JSCalendar<'_, Id, BlobId>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> impl Future<Output = trc::Result<Result<Slot, SetError<JSCalendarProperty<Id>>>>>;
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
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let account_info = self
            .scheduling_account_info(access_token.account_id(), account_id)
            .await
            .caused_by(trc::location!())?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(cache.assert_state(false, &request.if_in_state)?);
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());

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
        let mut created_slots = PendingCreates::new();
        'create: for (id, object) in request.unwrap_create() {
            match self
                .create_calendar_event(
                    &cache,
                    &mut batch,
                    access_token,
                    account_id,
                    &account_info,
                    send_scheduling_messages,
                    &can_add_calendars,
                    JSCalendar::default(),
                    object,
                )
                .await?
            {
                Ok(document_id) => {
                    created_slots.push(id, document_id);
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Group updates and instance removals by event
        let has_synthetic_ids = will_destroy.iter().any(|id| id.is_synthetic())
            || request.update.as_ref().is_some_and(|update| {
                update
                    .iter()
                    .any(|(id, _)| matches!(id, MaybeInvalid::Value(id) if id.is_synthetic()))
            });
        let is_destroyed_event = |document_id: u32| {
            will_destroy
                .iter()
                .any(|id| !id.is_synthetic() && id.document_id() == document_id)
        };
        let will_be_destroyed = |id: Id| {
            will_destroy.iter().any(|destroy_id| {
                *destroy_id == id
                    || (!destroy_id.is_synthetic() && destroy_id.document_id() == id.document_id())
            })
        };
        let mut updates: Vec<EventUpdate> =
            Vec::with_capacity(request.update.as_ref().map_or(0, |update| update.len()));
        for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue;
                }
            };
            let document_id = id.document_id();
            if will_be_destroyed(id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue;
            }
            let update = EventUpdate::for_document(&mut updates, document_id, has_synthetic_ids);
            if let Some(expansion_id) = id.expansion_id() {
                update.instances.push(InstanceOp {
                    id,
                    expansion_id,
                    patch: Some(object),
                    target: None,
                    is_destroy: false,
                });
            } else if update.base_id.is_none() {
                update.base_id = Some(id);
                update.base_patch = Some(object);
            } else {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description("Duplicate event id."),
                );
            }
        }
        for id in will_destroy.iter().copied() {
            let Some(expansion_id) = id.expansion_id() else {
                continue;
            };
            let document_id = id.document_id();
            if is_destroyed_event(document_id) {
                response.not_destroyed.append(id, SetError::will_destroy());
                continue;
            }
            EventUpdate::for_document(&mut updates, document_id, has_synthetic_ids)
                .instances
                .push(InstanceOp {
                    id,
                    expansion_id,
                    patch: None,
                    target: None,
                    is_destroy: true,
                });
        }
        let mut destroy_events = will_destroy;
        if has_synthetic_ids {
            destroy_events.retain(|id| !id.is_synthetic());
        }

        // Process updates
        'update: for mut update in updates {
            let document_id = update.document_id;
            if update.base_id.is_some() && !update.instances.is_empty() {
                update.fail(
                    &mut response,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description(concat!(
                            "A base event and its instances cannot be modified ",
                            "in the same request."
                        )),
                );
                continue 'update;
            }
            let calendar_event_ = if let Some(calendar_event_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await?
            {
                calendar_event_
            } else {
                update.fail(&mut response, SetError::not_found());
                continue 'update;
            };
            let calendar_event = calendar_event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_calendar_event = calendar_event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            // Resolve synthetic ids into recurrence instances
            let mut has_instances = false;
            if !update.instances.is_empty() {
                match update.plan_instances(&new_calendar_event.data, &mut response) {
                    InstancePlan::Instances => {
                        has_instances = true;
                    }
                    InstancePlan::BaseEvent => {}
                    InstancePlan::DestroyEvent(id) => {
                        destroy_events.push(id);
                        continue 'update;
                    }
                    InstancePlan::Nothing => {
                        continue 'update;
                    }
                }
            }

            let mut js_calendar_group =
                std::mem::take(&mut new_calendar_event.data.event).into_jscalendar::<Id, BlobId>();

            // Apply per-instance changes to the recurrence overrides of the base event
            if has_instances && !update.apply_instances(&mut js_calendar_group, &mut response) {
                continue 'update;
            }

            // Process changes
            if let Err(err) = update_calendar_event(
                access_token,
                update.base_id,
                update.base_patch.take().unwrap_or_default(),
                &mut new_calendar_event,
                &mut js_calendar_group,
            ) {
                update.fail(&mut response, err);
                continue 'update;
            }

            // Convert JSCalendar to iCalendar
            let Some(ical) = js_calendar_group.into_icalendar() else {
                update.fail(
                    &mut response,
                    SetError::invalid_properties()
                        .with_description("Failed to convert calendar event to iCalendar."),
                );
                continue 'update;
            };
            new_calendar_event.data.event = ical;
            stamp_updated(&mut new_calendar_event.data.event, now() as i64);

            // Assign an organizer when participants were added to an event that had none
            if let Some(organizer_address) = account_info.addresses().first() {
                itip_assign_organizer(&mut new_calendar_event.data.event, organizer_address);
            }

            // Validate UID
            match (
                new_calendar_event.data.event.uids().next(),
                calendar_event.inner.data.event.uids().next(),
            ) {
                (Some(old_uid), Some(new_uid)) if old_uid == new_uid => {}
                (None, None) | (None, Some(_)) => {}
                _ => {
                    update.fail(
                        &mut response,
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
                    update.fail(
                        &mut response,
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
                    update.fail(
                        &mut response,
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
                        update.fail(
                            &mut response,
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
                        update.fail(
                            &mut response,
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
                update.fail(
                    &mut response,
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
                && !account_info.addresses().is_empty()
                && access_token.has_permission(Permission::CalendarSchedulingSend)
                && new_calendar_event.data.event_range_end() > now
            {
                if let Some(calendar_address) = itip_unreachable_recipient(
                    &new_calendar_event.data.event,
                    account_info.addresses(),
                ) {
                    update.fail(
                        &mut response,
                        SetError::no_supported_schedule_methods(calendar_address),
                    );
                    continue 'update;
                }

                let result = if new_calendar_event.schedule_tag.is_some() {
                    let old_ical = rkyv_deserialize(&calendar_event.inner.data.event)
                        .caused_by(trc::location!())?;

                    itip_update(
                        &mut new_calendar_event.data.event,
                        &old_ical,
                        account_info.addresses(),
                    )
                } else {
                    itip_create(&mut new_calendar_event.data.event, account_info.addresses())
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
                            update.fail(
                                &mut response,
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
                            update.fail(
                                &mut response,
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
                    .has_available_quota(account_info.account(), extra_bytes)
                    .await
                {
                    Ok(_) => {}
                    Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                        update.fail(&mut response, SetError::over_quota());
                        continue 'update;
                    }
                    Err(err) => return Err(err.caused_by(trc::location!())),
                }
            }

            // Update record
            let vanished_paths = new_calendar_event
                .removed_calendar_ids(calendar_event.inner)
                .filter_map(|calendar_id| {
                    cache.format_resource_path_by_parent(document_id, calendar_id)
                })
                .collect::<Vec<_>>();
            new_calendar_event
                .update(
                    access_token.account_tenant_ids(),
                    calendar_event,
                    account_id,
                    document_id,
                    None,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            for path in vanished_paths {
                batch.log_vanished_item(VanishedCollection::Calendar, path);
            }
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

            update.succeed(&mut response);
        }

        // Process deletions
        'destroy: for id in destroy_events {
            let document_id = id.document_id();

            if !cache.has_item_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            }

            let Some(calendar_event_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                    &account_info,
                    account_id,
                    document_id,
                    send_scheduling_messages,
                    &mut batch,
                )
                .caused_by(trc::location!())?;

            for path in cache.format_resource_paths_by_id(document_id) {
                batch.log_vanished_item(VanishedCollection::Calendar, path);
            }

            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;

            created_slots.resolve(&mut response, &assigned_ids);

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::Calendar))
                    .into();
        }

        Ok(response)
    }

    async fn create_calendar_event(
        &self,
        cache: &DavResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account_id: u32,
        account_info: &AccountInfo,
        send_scheduling_messages: bool,
        can_add_calendars: &Option<RoaringBitmap>,
        mut js_calendar_group: JSCalendar<'_, Id, BlobId>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> trc::Result<Result<Slot, SetError<JSCalendarProperty<Id>>>> {
        // Process changes
        let mut event = CalendarEvent::default();
        let use_default_alerts = match update_calendar_event(
            access_token,
            None,
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
        stamp_updated(&mut ical, now() as i64);

        // Generate a UID when the client omitted one
        if ical.uids().next().is_none() {
            let uid = generate_uid();
            for component in &mut ical.components {
                if component.component_type.is_event_or_todo() {
                    component.add_uid(&uid);
                }
            }
        }

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
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                        .default_alerts(
                            access_token.personal_id(account_id, Collection::Calendar),
                            !show_without_time,
                        )
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

        // Assign an organizer when the event has participants but none was provided
        if let Some(organizer_address) = account_info.addresses().first() {
            itip_assign_organizer(&mut ical, organizer_address);
        }

        // Validate UID
        if let Err(err) = assert_is_unique_uid(cache, ical.uids().next())? {
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
            && !account_info.addresses().is_empty()
            && access_token.has_permission(Permission::CalendarSchedulingSend)
            && event.data.event_range_end() > now() as i64
        {
            if let Some(calendar_address) =
                itip_unreachable_recipient(&event.data.event, account_info.addresses())
            {
                return Ok(Err(SetError::no_supported_schedule_methods(
                    calendar_address,
                )));
            }

            match itip_create(&mut event.data.event, account_info.addresses()) {
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
            .has_available_quota(account_info.account(), size as u64)
            .await
        {
            Ok(_) => {}
            Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                return Ok(Err(SetError::over_quota()));
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }

        // Insert record
        let document_id = batch.reserve_document_id(account_id, Collection::CalendarEvent);
        event
            .insert(
                access_token.account_tenant_ids(),
                account_id,
                document_id,
                None,
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

fn stamp_updated(ical: &mut ICalendar, timestamp: i64) {
    let dtstamp = PartialDateTime::from_utc_timestamp(timestamp);
    for component in &mut ical.components {
        if !component.component_type.is_event_or_todo() {
            continue;
        }
        if let Some(entry) = component
            .entries
            .iter_mut()
            .find(|entry| entry.name == ICalendarProperty::Dtstamp)
        {
            entry.values = vec![ICalendarValue::PartialDateTime(Box::new(dtstamp.clone()))];
        } else {
            component.add_dtstamp(dtstamp.clone());
        }
    }
}

fn update_calendar_event<'x>(
    _access_token: &AccessToken,
    expected_id: Option<Id>,
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
            (JSCalendarProperty::Id, value) => {
                if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                    return Err(SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description("This property is immutable."));
                }
            }
            (
                property @ (JSCalendarProperty::BaseEventId
                | JSCalendarProperty::IsOrigin
                | JSCalendarProperty::Method),
                value,
            ) => {
                if entries.get(&Key::Property(property.clone())) != Some(&value) {
                    return Err(SetError::invalid_properties()
                        .with_property(property)
                        .with_description("This property is immutable."));
                }
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

struct EventUpdate<'x> {
    document_id: u32,
    base_id: Option<Id>,
    base_patch: Option<Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>>,
    instances: Vec<InstanceOp<'x>>,
}

struct InstanceOp<'x> {
    id: Id,
    expansion_id: u32,
    patch: Option<Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>>,
    target: Option<InstanceTarget>,
    is_destroy: bool,
}

struct InstanceTarget {
    is_override: bool,
    recurrence_id: i64,
    recurrence_id_naive: i64,
    start_naive: i64,
    duration: i64,
}

enum InstancePlan {
    Instances,
    BaseEvent,
    DestroyEvent(Id),
    Nothing,
}

enum InstanceResolution {
    Instance(InstanceTarget),
    BaseEvent,
    ThisAndFuture,
    NotFound,
}

trait JSCalendarEvent<'x> {
    fn event_mut(
        &mut self,
    ) -> Option<&mut Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>>;
}

impl<'x> JSCalendarEvent<'x> for JSCalendar<'x, Id, BlobId> {
    fn event_mut(
        &mut self,
    ) -> Option<&mut Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>> {
        self.0
            .as_object_mut()?
            .get_mut(&Key::Property(JSCalendarProperty::Entries))?
            .as_array_mut()?
            .first_mut()
    }
}

impl<'x> EventUpdate<'x> {
    fn for_document<'y>(
        updates: &'y mut Vec<EventUpdate<'x>>,
        document_id: u32,
        has_synthetic_ids: bool,
    ) -> &'y mut EventUpdate<'x> {
        let index = if has_synthetic_ids {
            updates
                .iter()
                .position(|update| update.document_id == document_id)
        } else {
            None
        };

        match index {
            Some(index) => &mut updates[index],
            None => {
                updates.push(EventUpdate {
                    document_id,
                    base_id: None,
                    base_patch: None,
                    instances: Vec::new(),
                });
                updates.last_mut().unwrap()
            }
        }
    }

    fn fail(
        &self,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
        err: SetError<JSCalendarProperty<Id>>,
    ) {
        if let Some(id) = self.base_id {
            response.not_updated.append(id, err.clone());
        }
        for instance in &self.instances {
            instance.fail(response, err.clone());
        }
    }

    fn succeed(&self, response: &mut SetResponse<calendar_event::CalendarEvent>) {
        if let Some(id) = self.base_id {
            response.updated.append(id, None);
        }
        for instance in &self.instances {
            if instance.is_destroy {
                response.destroyed.push(instance.id);
            } else {
                response.updated.append(instance.id, None);
            }
        }
    }

    fn plan_instances(
        &mut self,
        data: &CalendarEventData,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
    ) -> InstancePlan {
        let mut expansion_ids = self
            .instances
            .iter()
            .map(|instance| instance.expansion_id)
            .collect::<AHashSet<_>>();
        let expansions = data
            .expand_from_ids(&mut expansion_ids, Tz::UTC)
            .unwrap_or_default();
        let uid = data.event.uids().next();
        let mut has_base_event = false;

        self.instances.retain_mut(|instance| {
            match expansions
                .iter()
                .find(|expansion| expansion.expansion_id == instance.expansion_id)
                .filter(|expansion| expansion.is_valid())
                .map_or(InstanceResolution::NotFound, |expansion| {
                    InstanceTarget::resolve(expansion, data, uid)
                }) {
                InstanceResolution::Instance(target) => {
                    instance.target = Some(target);
                    true
                }
                InstanceResolution::BaseEvent => {
                    has_base_event = true;
                    true
                }
                InstanceResolution::ThisAndFuture => {
                    instance.fail(
                        response,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::Id)
                            .with_description(concat!(
                                "Occurrences of a this-and-future change cannot be ",
                                "modified individually."
                            )),
                    );
                    false
                }
                InstanceResolution::NotFound => {
                    instance.fail(response, SetError::not_found());
                    false
                }
            }
        });

        if has_base_event {
            if self.instances.len() > 1 {
                self.fail(
                    response,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description(concat!(
                            "A base event and its instances cannot be modified ",
                            "in the same request."
                        )),
                );
                return InstancePlan::Nothing;
            }

            let instance = self.instances.pop().unwrap();
            return if instance.is_destroy {
                InstancePlan::DestroyEvent(instance.id)
            } else {
                self.base_id = Some(instance.id);
                self.base_patch = instance.patch;
                InstancePlan::BaseEvent
            };
        }

        if self.instances.is_empty() {
            InstancePlan::Nothing
        } else {
            InstancePlan::Instances
        }
    }

    fn apply_instances(
        &mut self,
        js_calendar_group: &mut JSCalendar<'x, Id, BlobId>,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
    ) -> bool {
        let Some(js_calendar_event) = js_calendar_group.event_mut() else {
            self.fail(
                response,
                SetError::invalid_properties()
                    .with_description("Failed to convert calendar event to JSCalendar."),
            );
            return false;
        };
        let tz = js_calendar_event
            .as_object_and_get(&Key::Property(JSCalendarProperty::TimeZone))
            .and_then(|tz| tz.as_str())
            .and_then(|tz| Tz::from_str(tz.as_ref()).ok())
            .unwrap_or(Tz::UTC);
        let duration = js_calendar_event
            .as_object_and_get(&Key::Property(JSCalendarProperty::Duration))
            .cloned();

        self.instances.retain_mut(|instance| {
            let Some(target) = instance.target.take() else {
                return false;
            };
            let key = match target.find_override(js_calendar_event, tz) {
                Some(key) => key,
                None if !target.is_override => {
                    JSCalendarDateTime::new(target.recurrence_id_naive, true)
                }
                None => {
                    instance.fail(
                        response,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::RecurrenceOverrides)
                            .with_description(
                                "Failed to resolve the recurrence id of this instance.",
                            ),
                    );
                    return false;
                }
            };

            match target.apply(
                js_calendar_event,
                key,
                duration.as_ref(),
                instance.patch.take(),
                instance.id,
            ) {
                Ok(_) => true,
                Err(err) => {
                    instance.fail(response, err);
                    false
                }
            }
        });

        !self.instances.is_empty()
    }
}

impl InstanceOp<'_> {
    fn fail(
        &self,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
        err: SetError<JSCalendarProperty<Id>>,
    ) {
        if self.is_destroy {
            response.not_destroyed.append(self.id, err);
        } else {
            response.not_updated.append(self.id, err);
        }
    }
}

impl InstanceTarget {
    fn resolve(
        expansion: &CalendarEventExpansion,
        data: &CalendarEventData,
        uid: Option<&str>,
    ) -> InstanceResolution {
        let Some(component) = data.event.components.get(expansion.comp_id as usize) else {
            return InstanceResolution::NotFound;
        };
        if component
            .property(&ICalendarProperty::Uid)
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_text())
            .is_some_and(|value| uid.is_some_and(|uid| uid != value))
        {
            return InstanceResolution::NotFound;
        }

        let is_override = component.is_recurrence_override();
        if !is_override && !component.is_recurrent() {
            return InstanceResolution::BaseEvent;
        }

        let (recurrence_id, recurrence_id_naive) = if is_override {
            match Self::recurrence_id(component, data, expansion.comp_id) {
                Some(recurrence_id) => recurrence_id,
                None => return InstanceResolution::NotFound,
            }
        } else {
            (expansion.start, expansion.start_naive)
        };

        if is_override && !Self::is_own_occurrence(component, data, expansion) {
            return InstanceResolution::ThisAndFuture;
        }

        InstanceResolution::Instance(InstanceTarget {
            is_override,
            recurrence_id,
            recurrence_id_naive,
            start_naive: expansion.start_naive,
            duration: expansion.end - expansion.start,
        })
    }

    fn is_own_occurrence(
        component: &ICalendarComponent,
        data: &CalendarEventData,
        expansion: &CalendarEventExpansion,
    ) -> bool {
        !component
            .property(&ICalendarProperty::RecurrenceId)
            .is_some_and(|entry| {
                entry
                    .parameters(&ICalendarParameterName::Range)
                    .next()
                    .is_some()
            })
            || data
                .expand_single(expansion.comp_id, Tz::UTC)
                .is_some_and(|first| first.start_naive == expansion.start_naive)
    }

    fn recurrence_id(
        component: &ICalendarComponent,
        data: &CalendarEventData,
        comp_id: u32,
    ) -> Option<(i64, i64)> {
        let entry = component.property(&ICalendarProperty::RecurrenceId)?;
        let tz = entry
            .tz_id()
            .and_then(|tz| Tz::from_str(tz).ok())
            .or_else(|| {
                data.time_ranges
                    .iter()
                    .find(|range| range.id as u32 == comp_id)
                    .and_then(|range| Tz::from_id(range.start_tz))
            })
            .unwrap_or(Tz::UTC);
        let date_time = entry
            .values
            .first()?
            .as_partial_date_time()?
            .to_date_time()?
            .to_date_time_with_tz(tz)?;

        Some((
            date_time.timestamp(),
            date_time.naive_local().and_utc().timestamp(),
        ))
    }

    fn find_override(
        &self,
        js_calendar_event: &Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
        tz: Tz,
    ) -> Option<JSCalendarDateTime> {
        js_calendar_event
            .as_object_and_get(&Key::Property(JSCalendarProperty::RecurrenceOverrides))?
            .as_object()?
            .keys()
            .filter_map(|key| match key {
                Key::Property(JSCalendarProperty::DateTime(date_time)) => Some(date_time),
                _ => None,
            })
            .find(|date_time| {
                date_time.timestamp == self.recurrence_id_naive
                    || resolve_local(tz, date_time.timestamp) == Some(self.recurrence_id)
            })
            .cloned()
    }

    fn apply<'x>(
        &self,
        js_calendar_event: &mut Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
        key: JSCalendarDateTime,
        duration: Option<&Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>>,
        patch: Option<Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>>,
        id: Id,
    ) -> Result<(), SetError<JSCalendarProperty<Id>>> {
        let invalid_event =
            || SetError::invalid_properties().with_description("Failed to parse stored event.");
        let key = Key::Property(JSCalendarProperty::DateTime(key));

        let patch = match patch {
            Some(patch) => patch.into_object().ok_or_else(|| {
                SetError::invalid_properties()
                    .with_property(JSCalendarProperty::RecurrenceOverrides)
                    .with_description("Expected a patch object.")
            })?,
            None => {
                js_calendar_event
                    .as_object_mut()
                    .ok_or_else(invalid_event)?
                    .insert_or_get_mut(
                        Key::Property(JSCalendarProperty::RecurrenceOverrides),
                        Value::Object(Map::new()),
                    )
                    .as_object_mut()
                    .ok_or_else(invalid_event)?
                    .insert(
                        key,
                        Value::Object(Map::from(vec![(
                            Key::Property(JSCalendarProperty::Excluded),
                            Value::Bool(true),
                        )])),
                    );

                return Ok(());
            }
        };

        for (property, value) in patch.iter() {
            Self::validate(property, value, id)?;
        }

        let instance = js_calendar_event
            .as_object_mut()
            .ok_or_else(invalid_event)?
            .insert_or_get_mut(
                Key::Property(JSCalendarProperty::RecurrenceOverrides),
                Value::Object(Map::new()),
            )
            .as_object_mut()
            .ok_or_else(invalid_event)?
            .insert_or_get_mut(key, Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(invalid_event)?;

        if !instance.contains_key(&Key::Property(JSCalendarProperty::Start)) {
            instance.insert(
                Key::Property(JSCalendarProperty::Start),
                Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                    self.start_naive,
                    true,
                ))),
            );
        }
        if !instance.contains_key(&Key::Property(JSCalendarProperty::Duration)) {
            instance.insert(
                Key::Property(JSCalendarProperty::Duration),
                duration.cloned().unwrap_or_else(|| {
                    Value::Element(JSCalendarValue::Duration(ICalendarDuration::from_seconds(
                        self.duration,
                    )))
                }),
            );
        }

        for (property, value) in patch.into_vec() {
            if matches!(Self::validate(&property, &value, id), Ok(true)) {
                instance.insert(property, value);
            }
        }

        Ok(())
    }

    fn validate(
        property: &Key<'_, JSCalendarProperty<Id>>,
        value: &Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
        id: Id,
    ) -> Result<bool, SetError<JSCalendarProperty<Id>>> {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };
        let rejected = SetError::invalid_properties()
            .with_property(property.clone())
            .with_description("This property cannot be modified on a single occurrence.");

        match property {
            JSCalendarProperty::Id => {
                if crate::matches_id(value, id) {
                    Ok(false)
                } else {
                    Err(SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description("This property is immutable."))
                }
            }
            JSCalendarProperty::Pointer(pointer) => {
                let mut tokens = pointer.iter();
                let (Some(JsonPointerItem::Key(Key::Property(first))), third) =
                    (tokens.next(), tokens.nth(1))
                else {
                    return Err(rejected);
                };

                if Self::is_event_property(first) {
                    Err(rejected)
                } else {
                    Ok(!Self::is_inherited_property(first)
                        && !matches!(
                            (first, third),
                            (
                                JSCalendarProperty::Participants,
                                Some(JsonPointerItem::Key(Key::Property(
                                    JSCalendarProperty::CalendarAddress
                                )))
                            )
                        ))
                }
            }
            property if Self::is_event_property(property) => Err(rejected),
            property => Ok(!Self::is_inherited_property(property)),
        }
    }

    fn is_event_property(property: &JSCalendarProperty<Id>) -> bool {
        matches!(
            property,
            JSCalendarProperty::BaseEventId
                | JSCalendarProperty::CalendarIds
                | JSCalendarProperty::IsDraft
                | JSCalendarProperty::IsOrigin
                | JSCalendarProperty::UtcStart
                | JSCalendarProperty::UtcEnd
                | JSCalendarProperty::UseDefaultAlerts
                | JSCalendarProperty::MayInviteSelf
                | JSCalendarProperty::MayInviteOthers
                | JSCalendarProperty::HideAttendees
        )
    }

    fn is_inherited_property(property: &JSCalendarProperty<Id>) -> bool {
        matches!(
            property,
            JSCalendarProperty::Type
                | JSCalendarProperty::Method
                | JSCalendarProperty::OrganizerCalendarAddress
                | JSCalendarProperty::Privacy
                | JSCalendarProperty::ProdId
                | JSCalendarProperty::RecurrenceId
                | JSCalendarProperty::RecurrenceIdTimeZone
                | JSCalendarProperty::SentBy
                | JSCalendarProperty::Uid
                | JSCalendarProperty::RecurrenceOverrides
                | JSCalendarProperty::RecurrenceRule
                | JSCalendarProperty::RelatedTo
        )
    }
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

fn generate_uid() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}
