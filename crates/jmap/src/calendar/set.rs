/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::acl::{JmapAcl, JmapRights};
use calcard::jscalendar::{JSCalendarAlertAction, JSCalendarRelativeTo, JSCalendarType};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        ALERT_EMAIL, ALERT_RELATIVE_TO_END, ALERT_WITH_TIME, CALENDAR_AVAILABILITY_ALL,
        CALENDAR_AVAILABILITY_ATTENDING, CALENDAR_AVAILABILITY_NONE, CALENDAR_INVISIBLE,
        CALENDAR_SUBSCRIBED, Calendar, CalendarEvent, CalendarPreferences, DefaultAlert, Timezone,
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar::{self, CalendarProperty, CalendarValue, IncludeInAvailability},
    request::{IntoValid, reference::MaybeIdReference},
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Map, Value};
use rand::{Rng, distr::Alphanumeric};
use store::{
    SerializeInfallible, ValueKey,
    ahash::AHashSet,
    write::{AlignedBytes, Archive, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub trait CalendarSet: Sync + Send {
    fn calendar_set(
        &self,
        request: SetRequest<'_, calendar::Calendar>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<calendar::Calendar>>> + Send;
}

impl CalendarSet for Server {
    async fn calendar_set(
        &self,
        mut request: SetRequest<'_, calendar::Calendar>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<calendar::Calendar>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        let is_shared = access_token.is_shared(account_id);
        let mut set_default = None;

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            if is_shared {
                response.not_created.append(
                    id,
                    SetError::forbidden()
                        .with_description("Cannot create calendars in a shared account."),
                );
                continue 'create;
            }

            let mut calendar = Calendar {
                name: rand::rng()
                    .sample_iter(Alphanumeric)
                    .take(10)
                    .map(char::from)
                    .collect::<String>(),
                preferences: vec![CalendarPreferences {
                    account_id,
                    name: "".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            };

            // Process changes
            if let Err(err) = update_calendar(object, &mut calendar, access_token) {
                response.not_created.append(id, err);
                continue 'create;
            }

            // Validate ACLs
            if !calendar.acls.is_empty() {
                if let Err(err) = self.acl_validate(&calendar.acls).await {
                    response.not_created.append(id, err.into());
                    continue 'create;
                }

                self.refresh_acls(&calendar.acls, None).await;
            }

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::Calendar, 1)
                .await
                .caused_by(trc::location!())?;
            calendar
                .insert(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;

            if let Some(MaybeIdReference::Reference(id_ref)) =
                &request.arguments.on_success_set_is_default
                && id_ref == &id
            {
                set_default = Some(document_id);
            }

            response.created(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain calendar
            let document_id = id.document_id();
            let calendar_ = if let Some(calendar_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Calendar,
                    document_id,
                ))
                .await?
            {
                calendar_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let calendar = calendar_
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;
            let mut new_calendar = calendar
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;

            // Apply changes
            let has_acl_changes = match update_calendar(object, &mut new_calendar, access_token) {
                Ok(has_acl_changes_) => has_acl_changes_,
                Err(err) => {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            };

            // Validate ACL
            if is_shared {
                let acl = calendar.inner.acls.effective_acl(access_token);
                if !acl.contains(Acl::Modify) || (has_acl_changes && !acl.contains(Acl::Share)) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to modify this calendar."),
                    );
                    continue 'update;
                }
            }
            if has_acl_changes {
                if let Err(err) = self.acl_validate(&new_calendar.acls).await {
                    response.not_updated.append(id, err.into());
                    continue 'update;
                }
                self.refresh_archived_acls(&new_calendar.acls, calendar.inner.acls.as_slice())
                    .await;
            }

            // Update record
            new_calendar
                .update(access_token, calendar, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        let mut reset_default_calendar = false;
        if !will_destroy.is_empty() {
            let mut destroy_children = AHashSet::new();
            let mut destroy_parents = AHashSet::new();
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
            let on_destroy_remove_events =
                request.arguments.on_destroy_remove_events.unwrap_or(false);
            for id in will_destroy {
                let document_id = id.document_id();

                if !cache.has_container_id(&document_id) {
                    response.not_destroyed.append(id, SetError::not_found());
                    continue;
                };

                let Some(calendar_) = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::Calendar,
                        document_id,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    response.not_destroyed.append(id, SetError::not_found());
                    continue;
                };

                let calendar = calendar_
                    .to_unarchived::<Calendar>()
                    .caused_by(trc::location!())?;

                // Validate ACLs
                if is_shared
                    && !calendar
                        .inner
                        .acls
                        .effective_acl(access_token)
                        .contains_all([Acl::Delete, Acl::RemoveItems].into_iter())
                {
                    response.not_destroyed.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to delete this calendar."),
                    );
                    continue;
                }

                // Obtain children ids
                let children_ids = cache.children_ids(document_id).collect::<Vec<_>>();
                if !children_ids.is_empty() && !on_destroy_remove_events {
                    response
                        .not_destroyed
                        .append(id, SetError::calendar_has_event());
                    continue;
                }
                destroy_children.extend(children_ids.iter().copied());
                destroy_parents.insert(document_id);

                // Delete record
                DestroyArchive(calendar)
                    .delete(access_token, account_id, document_id, None, &mut batch)
                    .caused_by(trc::location!())?;

                if default_calendar_id == Some(document_id) {
                    reset_default_calendar = true;
                }

                response.destroyed.push(id);
            }

            // Delete children
            if !destroy_children.is_empty() {
                for document_id in destroy_children {
                    if let Some(event_) = self
                        .store()
                        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                            account_id,
                            Collection::CalendarEvent,
                            document_id,
                        ))
                        .await?
                    {
                        let event = event_
                            .to_unarchived::<CalendarEvent>()
                            .caused_by(trc::location!())?;

                        if event
                            .inner
                            .names
                            .iter()
                            .all(|n| destroy_parents.contains(&n.parent_id.to_native()))
                        {
                            // Event only belongs to calendars being deleted, delete it
                            DestroyArchive(event).delete_all(
                                access_token,
                                account_id,
                                document_id,
                                false,
                                &mut batch,
                            )?;
                        } else {
                            // Unlink calendar id from event
                            let mut new_event = event
                                .deserialize::<CalendarEvent>()
                                .caused_by(trc::location!())?;
                            new_event
                                .names
                                .retain(|n| !destroy_parents.contains(&n.parent_id));
                            new_event.update(
                                access_token,
                                event,
                                account_id,
                                document_id,
                                &mut batch,
                            )?;
                        }
                    }
                }
            }
        }

        // Set default calendar
        if let Some(MaybeIdReference::Id(id)) = &request.arguments.on_success_set_is_default {
            set_default = Some(id.document_id());
        }
        if let Some(default_calendar_id) = set_default {
            if response.not_created.is_empty()
                && response.not_updated.is_empty()
                && response.not_destroyed.is_empty()
            {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .set(
                        PrincipalField::DefaultCalendarId,
                        default_calendar_id.serialize(),
                    );
            }
        } else if reset_default_calendar {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .clear(PrincipalField::DefaultCalendarId);
        }

        // Write changes
        if !batch.is_empty()
            && let Ok(change_id) = self
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?
                .last_change_id(account_id)
        {
            self.notify_task_queue();
            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}

fn update_calendar(
    updates: Value<'_, CalendarProperty, CalendarValue>,
    calendar: &mut Calendar,
    access_token: &AccessToken,
) -> Result<bool, SetError<CalendarProperty>> {
    let mut has_acl_changes = false;

    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (CalendarProperty::Name, Value::Str(value)) if (1..=255).contains(&value.len()) => {
                calendar.preferences_mut(access_token).name = value.into_owned();
            }
            (CalendarProperty::Description, Value::Str(value)) if value.len() < 255 => {
                calendar.preferences_mut(access_token).description = value.into_owned().into();
            }
            (CalendarProperty::Description, Value::Null) => {
                calendar.preferences_mut(access_token).description = None;
            }
            (CalendarProperty::Color, Value::Str(value)) if value.len() < 16 => {
                calendar.preferences_mut(access_token).color = value.into_owned().into();
            }
            (CalendarProperty::Color, Value::Null) => {
                calendar.preferences_mut(access_token).color = None;
            }
            (CalendarProperty::TimeZone, Value::Element(CalendarValue::Timezone(tz))) => {
                calendar.preferences_mut(access_token).time_zone = Timezone::IANA(tz.as_id());
            }
            (CalendarProperty::TimeZone, Value::Null) => {
                calendar.preferences_mut(access_token).time_zone = Timezone::Default;
            }
            (CalendarProperty::SortOrder, Value::Number(value)) => {
                calendar.preferences_mut(access_token).sort_order = value.cast_to_u64() as u32;
            }
            (CalendarProperty::IsSubscribed, Value::Bool(subscribe)) => {
                if subscribe {
                    calendar.preferences_mut(access_token).flags |= CALENDAR_SUBSCRIBED;
                } else {
                    calendar.preferences_mut(access_token).flags &= !CALENDAR_SUBSCRIBED;
                }
            }
            (CalendarProperty::IsVisible, Value::Bool(visible)) => {
                if visible {
                    calendar.preferences_mut(access_token).flags &= !CALENDAR_INVISIBLE;
                } else {
                    calendar.preferences_mut(access_token).flags |= CALENDAR_INVISIBLE;
                }
            }
            (
                CalendarProperty::IncludeInAvailability,
                Value::Element(CalendarValue::IncludeInAvailability(availability)),
            ) => {
                let flags = &mut calendar.preferences_mut(access_token).flags;

                match availability {
                    IncludeInAvailability::All => {
                        *flags &= !(CALENDAR_AVAILABILITY_NONE | CALENDAR_AVAILABILITY_ATTENDING);
                        *flags |= CALENDAR_AVAILABILITY_ALL;
                    }
                    IncludeInAvailability::Attending => {
                        *flags &= !(CALENDAR_AVAILABILITY_NONE | CALENDAR_AVAILABILITY_ALL);
                        *flags |= CALENDAR_AVAILABILITY_ATTENDING;
                    }
                    IncludeInAvailability::None => {
                        *flags &= !(CALENDAR_AVAILABILITY_ATTENDING | CALENDAR_AVAILABILITY_ALL);
                        *flags |= CALENDAR_AVAILABILITY_NONE;
                    }
                }
            }
            (
                property @ (CalendarProperty::DefaultAlertsWithTime
                | CalendarProperty::DefaultAlertsWithoutTime),
                Value::Object(value),
            ) => {
                let with_time = matches!(property, CalendarProperty::DefaultAlertsWithTime);
                let alerts = &mut calendar.preferences_mut(access_token).default_alerts;

                alerts.retain(|alert| (alert.flags & ALERT_WITH_TIME != 0) != with_time);

                for (key, value) in value.into_vec() {
                    if let Value::Object(value) = value {
                        alerts.push(value_to_default_alert(
                            key.to_string().into_owned(),
                            value,
                            with_time,
                        )?);
                    }
                }
            }
            (CalendarProperty::ShareWith, value) => {
                calendar.acls = JmapRights::acl_set::<calendar::Calendar>(value)?;
                has_acl_changes = true;
            }
            (CalendarProperty::Pointer(pointer), value) => {
                let mut ptr_iter = pointer.iter();

                match ptr_iter.next() {
                    Some(JsonPointerItem::Key(Key::Property(CalendarProperty::ShareWith))) => {
                        calendar.acls = JmapRights::acl_patch::<calendar::Calendar>(
                            std::mem::take(&mut calendar.acls),
                            ptr_iter,
                            value,
                        )?;
                        has_acl_changes = true;
                    }
                    Some(JsonPointerItem::Key(Key::Property(
                        property @ (CalendarProperty::DefaultAlertsWithTime
                        | CalendarProperty::DefaultAlertsWithoutTime),
                    ))) => match (ptr_iter.next(), ptr_iter.next()) {
                        (
                            Some(key @ (JsonPointerItem::Key(_) | JsonPointerItem::Number(_))),
                            None,
                        ) => {
                            let id = match key {
                                JsonPointerItem::Key(key) => key.to_string().into_owned(),
                                JsonPointerItem::Number(n) => n.to_string(),
                                _ => unreachable!(),
                            };
                            let with_time =
                                matches!(property, CalendarProperty::DefaultAlertsWithTime);
                            let alerts = &mut calendar.preferences_mut(access_token).default_alerts;
                            alerts.retain(|alert| {
                                (alert.flags & ALERT_WITH_TIME != 0) != with_time || alert.id != id
                            });

                            if let Value::Object(value) = value {
                                alerts.push(value_to_default_alert(id, value, with_time)?);
                            }
                        }
                        _ => {
                            return Err(SetError::invalid_properties()
                                .with_property(CalendarProperty::Pointer(pointer))
                                .with_description("Field could not be patched."));
                        }
                    },
                    _ => {
                        return Err(SetError::invalid_properties()
                            .with_property(CalendarProperty::Pointer(pointer))
                            .with_description("Field could not be patched."));
                    }
                }
            }
            (property, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(property)
                    .with_description("Field could not be set."));
            }
        }
    }

    // Validate name
    if calendar.preferences(access_token).name.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(CalendarProperty::Name)
            .with_description("Missing name."));
    }

    Ok(has_acl_changes)
}

fn value_to_default_alert(
    id: String,
    value: Map<'_, CalendarProperty, CalendarValue>,
    with_time: bool,
) -> Result<DefaultAlert, SetError<CalendarProperty>> {
    let mut alert = DefaultAlert {
        id,
        ..Default::default()
    };
    let mut has_offset = false;

    for (key, value) in value.into_vec() {
        let Key::Property(key) = key else {
            continue;
        };

        match (key, value) {
            (CalendarProperty::Type, Value::Element(CalendarValue::Type(value))) => {
                if value != JSCalendarType::Alert {
                    return Err(SetError::invalid_properties()
                        .with_property(CalendarProperty::Trigger)
                        .with_description("Invalid alert object type."));
                }
            }
            (
                CalendarProperty::Action,
                Value::Element(CalendarValue::Action(JSCalendarAlertAction::Email)),
            ) => {
                alert.flags |= ALERT_EMAIL;
            }
            (CalendarProperty::Trigger, Value::Object(value)) => {
                for (key, value) in value.into_vec() {
                    let Key::Property(key) = key else {
                        continue;
                    };

                    match (key, value) {
                        (
                            CalendarProperty::RelativeTo,
                            Value::Element(CalendarValue::RelativeTo(JSCalendarRelativeTo::End)),
                        ) => {
                            alert.flags |= ALERT_RELATIVE_TO_END;
                        }
                        (
                            CalendarProperty::Offset,
                            Value::Element(CalendarValue::Duration(value)),
                        ) => {
                            alert.offset = value;
                            has_offset = true;
                        }
                        (CalendarProperty::Offset, Value::Element(CalendarValue::Type(value))) => {
                            if value != JSCalendarType::OffsetTrigger {
                                return Err(SetError::invalid_properties()
                                    .with_property(CalendarProperty::Trigger)
                                    .with_description("Invalid alert trigger type."));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if has_offset {
        if with_time {
            alert.flags |= ALERT_WITH_TIME;
        }

        Ok(alert)
    } else {
        Err(SetError::invalid_properties()
            .with_property(CalendarProperty::Trigger)
            .with_description("Missing alert offset."))
    }
}
