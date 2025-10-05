/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarValue};
use common::{DavName, DavResources, Server, auth::AccessToken};
use groupware::{DestroyArchive, cache::GroupwareCache};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar_event,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{JsonPointerHandler, JsonPointerItem, Key, Value};
use store::{ahash::AHashSet, roaring::RoaringBitmap, write::BatchBuilder};
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
        can_add_address_books: &Option<RoaringBitmap>,
        js_calendar_event: JSCalendar<'_, Id>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id>>,
    ) -> impl Future<Output = trc::Result<Result<u32, SetError<JSCalendarProperty<Id>>>>>;
}

impl CalendarEventSet for Server {
    async fn calendar_event_set(
        &self,
        mut request: SetRequest<'_, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<calendar_event::CalendarEvent>> {
        todo!()
        /*let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Obtain calendarIds
        let (can_add_address_books, can_delete_address_books, can_modify_address_books) =
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
        'create: for (id, object) in request.unwrap_create() {
            match self
                .create_calendar_event(
                    &cache,
                    &mut batch,
                    access_token,
                    account_id,
                    &can_add_address_books,
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
            }

            // Obtain calendar_event card
            let document_id = id.document_id();
            let calendar_event_ = if let Some(calendar_event_) = self
                .get_archive(account_id, Collection::CalendarEvent, document_id)
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
            let mut js_calendar_event = new_calendar_event.card.into_jscalendar();

            // Process changes
            if let Err(err) = update_calendar_event(
                object,
                &mut new_calendar_event.names,
                &mut js_calendar_event,
            ) {
                response.not_updated.append(id, err);
                continue 'update;
            }

            // Convert JSCalendar to vCard
            if let Some(vcard) = js_calendar_event.into_vcard() {
                new_calendar_event.size = vcard.size() as u32;
                new_calendar_event.card = vcard;
            } else {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("Failed to convert calendar_event to vCard."),
                );
                continue 'update;
            }

            // Validate UID
            match (
                new_calendar_event.card.uid(),
                calendar_event.inner.card.uid(),
            ) {
                (Some(old_uid), Some(new_uid)) if old_uid == new_uid => {}
                (None, None) | (None, Some(_)) => {}
                _ => {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::Uid)
                            .with_description("You cannot change the UID of a calendar_event."),
                    );
                    continue 'update;
                }
            }

            // Validate new calendarIds
            for addressbook_id in new_calendar_event.added_addressbook_ids(calendar_event.inner) {
                if !cache.has_container_id(&addressbook_id) {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::CalendarIds)
                            .with_description(format!(
                                "calendarId {} does not exist.",
                                Id::from(addressbook_id)
                            )),
                    );
                    continue 'update;
                } else if can_add_address_books
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(addressbook_id))
                {
                    response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add calendar_events to calendar {}.",
                            Id::from(addressbook_id)
                        )),
                    );
                    continue 'update;
                }
            }

            // Validate deleted calendarIds
            if let Some(can_delete_address_books) = &can_delete_address_books {
                for addressbook_id in
                    new_calendar_event.removed_addressbook_ids(calendar_event.inner)
                {
                    if !can_delete_address_books.contains(addressbook_id) {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to remove calendar_events from calendar {}.",
                                Id::from(addressbook_id)
                            )),
                        );
                        continue 'update;
                    }
                }
            }

            // Validate changed calendarIds
            if let Some(can_modify_address_books) = &can_modify_address_books {
                for addressbook_id in
                    new_calendar_event.unchanged_addressbook_ids(calendar_event.inner)
                {
                    if !can_modify_address_books.contains(addressbook_id) {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to modify calendar {}.",
                                Id::from(addressbook_id)
                            )),
                        );
                        continue 'update;
                    }
                }
            }

            // Check size and quota
            if new_calendar_event.size as usize > self.core.groupware.max_vcard_size {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties().with_description(format!(
                        "Contact size {} exceeds the maximum allowed size of {} bytes.",
                        new_calendar_event.size, self.core.groupware.max_vcard_size
                    )),
                );
                continue 'update;
            }
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
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();

            if !cache.has_container_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let Some(calendar_event_) = self
                .get_archive(account_id, Collection::CalendarEvent, document_id)
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
            if let Some(can_delete_address_books) = &can_delete_address_books {
                for name in calendar_event.inner.names.iter() {
                    let parent_id = name.parent_id.to_native();
                    if !can_delete_address_books.contains(parent_id) {
                        response.not_destroyed.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to remove calendar_events from calendar {}.",
                                Id::from(parent_id)
                            )),
                        );
                        continue;
                    }
                }
            }

            // Delete record
            DestroyArchive(calendar_event)
                .delete_all(access_token, account_id, document_id, &mut batch)
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

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)*/
    }

    async fn create_calendar_event(
        &self,
        cache: &DavResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account_id: u32,
        can_add_address_books: &Option<RoaringBitmap>,
        mut js_calendar_event: JSCalendar<'_, Id>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id>>,
    ) -> trc::Result<Result<u32, SetError<JSCalendarProperty<Id>>>> {
        todo!()
        /*
        // Process changes
        let mut names = Vec::new();
        if let Err(err) = update_calendar_event(updates, &mut names, &mut js_calendar_event) {
            return Ok(Err(err));
        }

        // Verify that the calendar ids valid
        for name in &names {
            if !cache.has_container_id(&name.parent_id) {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(JSCalendarProperty::CalendarIds)
                    .with_description(format!(
                        "calendarId {} does not exist.",
                        Id::from(name.parent_id)
                    ))));
            } else if can_add_address_books
                .as_ref()
                .is_some_and(|ids| !ids.contains(name.parent_id))
            {
                return Ok(Err(SetError::forbidden().with_description(format!(
                    "You are not allowed to add calendar_events to calendar {}.",
                    Id::from(name.parent_id)
                ))));
            }
        }

        // Convert JSCalendar to vCard
        let Some(card) = js_calendar_event.into_vcard() else {
            return Ok(Err(SetError::invalid_properties()
                .with_description("Failed to convert calendar_event to vCard.")));
        };

        // Validate UID
        if let Err(err) = assert_is_unique_uid(self, cache, account_id, &names, card.uid()).await? {
            return Ok(Err(err));
        }

        // Check size and quota
        let size = card.size();
        if size > self.core.groupware.max_vcard_size {
            return Ok(Err(SetError::invalid_properties().with_description(
                format!(
                    "Contact size {} exceeds the maximum allowed size of {} bytes.",
                    size, self.core.groupware.max_vcard_size
                ),
            )));
        }
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
        CalendarEvent {
            names,
            size: size as u32,
            card,
            ..Default::default()
        }
        .insert(access_token, account_id, document_id, batch)
        .caused_by(trc::location!())
        .map(|_| Ok(document_id))*/
    }
}

/*
fn update_calendar_event<'x>(
    updates: Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id>>,
    addressbooks: &mut Vec<DavName>,
    js_calendar_event: &mut JSCalendar<'x, Id>,
) -> Result<(), SetError<JSCalendarProperty<Id>>> {
    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (JSCalendarProperty::CalendarIds, value) => {
                patch_parent_ids(addressbooks, None, value)?;
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
                    patch_parent_ids(addressbooks, pointer.next(), value)?;
                } else if !js_calendar_event.0.patch_jptr(pointer.iter(), value) {
                    return Err(SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Pointer(pointer))
                        .with_description("Patch operation failed."));
                }
            }
            (property, value) => {
                js_calendar_event
                    .0
                    .as_object_mut()
                    .unwrap()
                    .insert(property, value);
            }
        }
    }

    // Make sure the calendar_event belongs to at least one calendar
    if addressbooks.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::CalendarIds)
            .with_description("Contact has to belong to at least one calendar."));
    }

    Ok(())
}

fn patch_parent_ids(
    current: &mut Vec<DavName>,
    patch: Option<&JsonPointerItem<JSCalendarProperty<Id>>>,
    update: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id>>,
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

            current.retain(|name| !new_ids.remove(&name.parent_id));

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

*/
