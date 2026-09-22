/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::acl::{JmapAcl, JmapRights};
use crate::api::pending_creates::PendingCreates;
use crate::calendar::{Availability, get::default_alert_value};
use crate::changes::state::JmapCacheState;
use calcard::jscalendar::{JSCalendarAlertAction, JSCalendarRelativeTo, JSCalendarType};
use common::{
    GroupwareResources, Server,
    auth::AccessToken,
    sharing::{EffectiveAcl, grants::ShareUpdate},
    storage::quota::ObjectQuotaUsage,
};
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        ALERT_EMAIL, ALERT_RELATIVE_TO_END, ALERT_WITH_TIME, CALENDAR_AVAILABILITY_ALL,
        CALENDAR_AVAILABILITY_ATTENDING, CALENDAR_AVAILABILITY_NONE, CALENDAR_INVISIBLE,
        CALENDAR_SUBSCRIBED, Calendar, CalendarEvent, CalendarPreferences, DefaultAlert,
        MAX_USER_ALERTS, Timezone,
        alerts::{CalendarAlarmsReschedule, CalendarSettings, DefaultAlertsResolver},
        color::CssColor,
        notification::CalendarNotificationReap,
        privacy::EventPrivacy,
        schedule::EventAlarmScheduler,
        storage::{DirectChangeNotification, NotificationQuota},
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar::{self, CalendarProperty, CalendarValue, IncludeInAvailability},
    request::{MaybeInvalid, reference::MaybeIdReference},
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Map, Value};
use rand::{RngExt, distr::Alphanumeric};
use registry::schema::enums::StorageQuota;
use store::{
    ValueKey,
    ahash::AHashSet,
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, ValueClass},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
    field::PrincipalField,
    id::Id,
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
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(cache.assert_state(true, &request.if_in_state)?);
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let is_shared = access_token.is_shared(account_id);
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);
        let mut set_default: Option<PendingId> = None;
        let mut created_slots = PendingCreates::new();
        let mut created_server_set = Vec::new();
        let mut request_alerts = RequestDefaultAlerts::default();

        // Obtain quota
        let quota = if request.has_creates() && !is_shared {
            let account = self.account(account_id).await.caused_by(trc::location!())?;
            self.object_quota_usage(&account, StorageQuota::MaxCalendars, || {
                cache.resources.count(true)
            })
        } else {
            ObjectQuotaUsage::unlimited()
        };

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            if !quota.has_room(created_slots.len()) {
                response.not_created.append(
                    id,
                    SetError::over_quota().with_description(concat!(
                        "There are too many calendars, ",
                        "please delete some before adding a new one."
                    )),
                );
                continue 'create;
            }

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
            let client_properties = object
                .as_object()
                .map(|object| {
                    object
                        .keys()
                        .filter_map(|key| key.as_property().cloned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            calendar.preferences_mut(personal_id).flags |= CALENDAR_SUBSCRIBED;
            let changes =
                match update_calendar(None, object, &mut calendar, access_token, account_id) {
                    Ok(changes) => changes,
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };
            calendar.sync_owner_preferences(account_id, personal_id);
            if changes.default_alerts
                && let Err(err) = self
                    .assert_unique_default_alerts(
                        &cache,
                        account_id,
                        personal_id,
                        None,
                        &calendar,
                        &request_alerts,
                    )
                    .await?
            {
                response.not_created.append(id, err);
                continue 'create;
            }

            // Validate ACLs
            if !calendar.acls.is_empty() {
                if let Err(err) = JmapRights::validate_shares::<calendar::Calendar, _>(
                    ShareUpdate {
                        collection: Collection::Calendar,
                        owner_id: account_id,
                        actor: None,
                        current: &[] as &[AclGrant],
                        max_shares: self.core.groupware.max_shares_per_item,
                    },
                    &calendar.acls,
                ) {
                    response.not_created.append(id, err);
                    continue 'create;
                }
                if let Err(err) = self.acl_validate(&calendar.acls).await {
                    response.not_created.append(id, err.into());
                    continue 'create;
                }
            }

            // Insert record
            let server_set = calendar.server_set_values(personal_id, &client_properties);
            request_alerts.accept(None, &calendar, personal_id);
            let document_id = batch.reserve_document_id(account_id, Collection::Calendar);
            calendar
                .insert(
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;

            if let Some(MaybeIdReference::Reference(id_ref)) =
                &request.arguments.on_success_set_is_default
                && id_ref == &id
            {
                set_default = Some(PendingId::Slot(document_id));
            }

            created_server_set.push((id.clone(), document_id, server_set));
            created_slots.push(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain calendar
            let document_id = id.document_id();
            let calendar_ = if let Some(calendar_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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

            let acl = calendar.inner.acls.effective_acl(access_token);
            if is_shared && !acl.contains_any([Acl::Read, Acl::ReadItems].into_iter()) {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            }

            // Apply changes
            if !is_shared {
                new_calendar.inherit_owner_preferences(account_id, personal_id);
            }
            let changes = match update_calendar(
                Some(id),
                object,
                &mut new_calendar,
                access_token,
                account_id,
            ) {
                Ok(changes) => changes,
                Err(err) => {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            };
            if !is_shared {
                new_calendar.sync_owner_preferences(account_id, personal_id);
            }

            // Validate ACL
            if is_shared
                && ((changes.shared_properties && !acl.contains(Acl::Modify))
                    || (changes.acls && !acl.contains(Acl::Share)))
            {
                response.not_updated.append(
                    id,
                    SetError::forbidden()
                        .with_description("You are not allowed to modify this calendar."),
                );
                continue 'update;
            }
            if changes.default_alerts
                && let Err(err) = self
                    .assert_unique_default_alerts(
                        &cache,
                        account_id,
                        personal_id,
                        Some(document_id),
                        &new_calendar,
                        &request_alerts,
                    )
                    .await?
            {
                response.not_updated.append(id, err);
                continue 'update;
            }
            if changes.acls {
                if let Err(err) = JmapRights::validate_shares::<calendar::Calendar, _>(
                    ShareUpdate {
                        collection: Collection::Calendar,
                        owner_id: account_id,
                        actor: is_shared.then_some(acl),
                        current: &calendar.inner.acls,
                        max_shares: self.core.groupware.max_shares_per_item,
                    },
                    &new_calendar.acls,
                ) {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
                if let Err(err) = self.acl_validate(&new_calendar.acls).await {
                    response.not_updated.append(id, err.into());
                    continue 'update;
                }
            }

            self.reschedule_calendar_alarms(
                &cache,
                account_id,
                document_id,
                CalendarSettings::from(calendar.inner),
                CalendarSettings::from(&new_calendar),
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
            request_alerts.accept(Some(document_id), &new_calendar, personal_id);

            // Update record
            new_calendar
                .update(
                    access_token.account_tenant_ids(),
                    calendar,
                    account_id,
                    document_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        let mut destroyed_calendars: Vec<u32> = Vec::new();
        if !will_destroy.is_empty() {
            let mut destroy_children = AHashSet::new();
            let mut destroy_parents = AHashSet::new();
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
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                        .contains(Acl::Delete)
                {
                    response.not_destroyed.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to delete this calendar."),
                    );
                    continue;
                }

                // Obtain children ids
                let mut has_visible_children = false;
                let mut has_restricted_children = false;
                for flags in cache
                    .children(document_id)
                    .map(|child| child.resource.event_flags().unwrap_or_default())
                {
                    match EventPrivacy::from_flags(flags) {
                        EventPrivacy::Public => has_visible_children = true,
                        EventPrivacy::Private => {
                            has_visible_children = true;
                            has_restricted_children = true;
                        }
                        EventPrivacy::Secret => {
                            has_visible_children |= !is_shared;
                            has_restricted_children = true;
                        }
                    }
                }
                if has_visible_children && !on_destroy_remove_events {
                    response
                        .not_destroyed
                        .append(id, SetError::calendar_has_event());
                    continue;
                }
                if is_shared && has_restricted_children {
                    response.not_destroyed.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to delete this calendar."),
                    );
                    continue;
                }
                destroy_children.extend(cache.children_ids(document_id));
                destroy_parents.insert(document_id);

                // Delete record
                let delete_path = cache
                    .container_resource_path_by_id(document_id)
                    .map(|resource| cache.format_resource(resource));
                DestroyArchive(calendar)
                    .delete(
                        access_token.account_tenant_ids(),
                        account_id,
                        document_id,
                        delete_path,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;

                destroyed_calendars.push(document_id);

                response.destroyed.push(id);
            }

            if !destroy_parents.is_empty() {
                let destroyed_calendar_ids = destroy_parents.iter().copied().collect::<Vec<_>>();
                self.reap_calendar_notifications(
                    access_token,
                    account_id,
                    &destroyed_calendar_ids,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            }

            // Delete children
            if !destroy_children.is_empty() {
                let account_info = self
                    .account_info(access_token.account_id())
                    .await
                    .caused_by(trc::location!())?;
                let mut resolver = DefaultAlertsResolver::with_resources(account_id, cache.clone());
                let mut quota = NotificationQuota::default();
                let notify_children = !access_token.is_member(account_id);
                for document_id in destroy_children {
                    if let Some(event_) = self
                        .store()
                        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                            account_id,
                            Collection::CalendarEvent,
                            document_id,
                        ))
                        .await?
                    {
                        let event = event_
                            .to_unarchived::<CalendarEvent>()
                            .caused_by(trc::location!())?;

                        for calendar_id in event
                            .inner
                            .calendar_ids()
                            .filter(|_| notify_children)
                            .filter(|calendar_id| destroy_parents.contains(calendar_id))
                        {
                            self.notify_calendar_removal(
                                access_token,
                                account_id,
                                document_id,
                                calendar_id,
                                event.inner.flags.to_native(),
                                &mut quota,
                                &mut batch,
                            )
                            .await
                            .caused_by(trc::location!())?;
                        }

                        if event
                            .inner
                            .names
                            .iter()
                            .all(|n| destroy_parents.contains(&n.parent_id.to_native()))
                        {
                            // Event only belongs to calendars being deleted, delete it
                            DestroyArchive(event)
                                .delete_all(
                                    self,
                                    &account_info,
                                    account_id,
                                    document_id,
                                    None,
                                    false,
                                    &mut batch,
                                )
                                .await?;
                        } else {
                            // Unlink calendar id from event
                            let mut new_event = event
                                .deserialize::<CalendarEvent>()
                                .caused_by(trc::location!())?;
                            new_event
                                .names
                                .retain(|n| !destroy_parents.contains(&n.parent_id));
                            self.reschedule_event_alarms(
                                account_id,
                                document_id,
                                event.inner,
                                &new_event
                                    .names
                                    .iter()
                                    .map(|name| name.parent_id)
                                    .collect::<Vec<_>>(),
                                &mut resolver,
                                &mut batch,
                            )
                            .await
                            .caused_by(trc::location!())?;
                            new_event.update_meta(
                                access_token.account_tenant_ids(),
                                event,
                                account_id,
                                document_id,
                                None,
                                &mut batch,
                            )?;
                        }
                    }
                }
            }
        }

        // Set default calendar
        if let Some(MaybeIdReference::Id(id)) = &request.arguments.on_success_set_is_default {
            let document_id = id.document_id();
            let is_visible = if is_shared {
                cache
                    .shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
                    .contains(document_id)
            } else {
                cache.has_container_id(&document_id)
            };
            if is_visible && !destroyed_calendars.contains(&document_id) {
                set_default = Some(PendingId::Assigned(document_id));
            }
        }
        let mut changed_default = None;
        if let Some(default_calendar_id) = set_default.filter(|_| !is_shared) {
            if response.not_created.is_empty()
                && response.not_updated.is_empty()
                && response.not_destroyed.is_empty()
            {
                let previous_default_id = self
                    .store()
                    .get_value::<u32>(ValueKey {
                        account_id,
                        collection: Collection::Principal.into(),
                        document_id: 0,
                        class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
                    })
                    .await
                    .caused_by(trc::location!())?
                    .or_else(|| cache.document_ids(true).min());
                if !matches!(default_calendar_id, PendingId::Assigned(id) if Some(id) == previous_default_id)
                {
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Principal)
                        .with_document(0)
                        .set(PrincipalField::DefaultCalendarId, default_calendar_id);
                    changed_default = Some((default_calendar_id, previous_default_id));
                }
            }
        } else if !destroyed_calendars.is_empty() {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);
            for &document_id in &destroyed_calendars {
                batch.clear_if_equals(PrincipalField::DefaultCalendarId, document_id);
            }
        }

        // Write changes
        if !batch.is_empty() {
            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;

            created_slots.resolve(&mut response, &assigned_ids);
            let default_calendar_id = if created_server_set.is_empty() {
                None
            } else {
                self.store()
                    .get_value::<u32>(ValueKey {
                        account_id,
                        collection: Collection::Principal.into(),
                        document_id: 0,
                        class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
                    })
                    .await
                    .caused_by(trc::location!())?
                    .or_else(|| {
                        cache
                            .document_ids(true)
                            .filter(|id| !destroyed_calendars.contains(id))
                            .chain(
                                created_server_set
                                    .iter()
                                    .map(|(_, slot, _)| assigned_ids.slot(*slot)),
                            )
                            .min()
                    })
            };
            for (create_id, slot, mut server_set) in created_server_set {
                server_set.push((
                    CalendarProperty::IsDefault,
                    Value::Bool(default_calendar_id == Some(assigned_ids.slot(slot))),
                ));
                response.add_created_properties(&create_id, server_set);
            }

            if let Some((default_calendar_id, previous_default_id)) = changed_default {
                let default_calendar_id = match default_calendar_id {
                    PendingId::Assigned(id) => id,
                    PendingId::Slot(slot) => assigned_ids.slot(slot),
                };
                response.add_server_set_property(
                    Id::from(default_calendar_id),
                    CalendarProperty::IsDefault,
                    true,
                );
                if let Some(previous_default_id) = previous_default_id
                    .filter(|id| *id != default_calendar_id && !destroyed_calendars.contains(id))
                {
                    response.add_server_set_property(
                        Id::from(previous_default_id),
                        CalendarProperty::IsDefault,
                        false,
                    );
                }
            }

            if let Some(change_id) = assigned_ids.change_id(account_id, SyncCollection::Calendar) {
                response.new_state = State::Exact(change_id).into();
            }
        }

        Ok(response)
    }
}

#[derive(Debug, Default)]
struct CalendarChanges {
    acls: bool,
    shared_properties: bool,
    default_alerts: bool,
}

#[derive(Debug, Default)]
struct RequestDefaultAlerts {
    updated_calendars: AHashSet<u32>,
    alert_ids: AHashSet<String>,
}

impl RequestDefaultAlerts {
    fn accept(&mut self, document_id: Option<u32>, calendar: &Calendar, personal_id: u32) {
        if let Some(document_id) = document_id {
            self.updated_calendars.insert(document_id);
        }
        self.alert_ids.extend(
            calendar
                .preferences
                .iter()
                .filter(|preferences| preferences.account_id == personal_id)
                .flat_map(|preferences| preferences.default_alerts.iter())
                .map(|alert| alert.id.clone()),
        );
    }
}

trait DefaultAlertValidator {
    fn assert_unique_default_alerts(
        &self,
        cache: &GroupwareResources,
        account_id: u32,
        personal_id: u32,
        document_id: Option<u32>,
        calendar: &Calendar,
        request_alerts: &RequestDefaultAlerts,
    ) -> impl Future<Output = trc::Result<Result<(), SetError<CalendarProperty>>>> + Send;
}

impl DefaultAlertValidator for Server {
    async fn assert_unique_default_alerts(
        &self,
        cache: &GroupwareResources,
        account_id: u32,
        personal_id: u32,
        document_id: Option<u32>,
        calendar: &Calendar,
        request_alerts: &RequestDefaultAlerts,
    ) -> trc::Result<Result<(), SetError<CalendarProperty>>> {
        let alerts = &calendar.preferences(personal_id).default_alerts;
        let mut alert_ids = AHashSet::with_capacity(alerts.len());
        if !alerts.iter().all(|alert| {
            alert_ids.insert(alert.id.as_str()) && !request_alerts.alert_ids.contains(&alert.id)
        }) {
            return Ok(Err(duplicate_default_alert_id()));
        }
        if alert_ids.is_empty() {
            return Ok(Ok(()));
        }

        for other_id in cache.document_ids(true).filter(|other_id| {
            Some(*other_id) != document_id
                && !request_alerts.updated_calendars.contains(other_id)
                && cache
                    .container_resource_by_id(*other_id)
                    .is_some_and(|calendar| {
                        calendar
                            .personal_calendar_preferences(personal_id)
                            .is_some()
                    })
        }) {
            let Some(other) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Calendar,
                    other_id,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                continue;
            };
            if other
                .unarchive::<Calendar>()
                .caused_by(trc::location!())?
                .personal_preferences(personal_id)
                .is_some_and(|preferences| {
                    preferences
                        .default_alerts
                        .iter()
                        .any(|alert| alert_ids.contains(alert.id.as_str()))
                })
            {
                return Ok(Err(duplicate_default_alert_id()));
            }
        }

        Ok(Ok(()))
    }
}

fn duplicate_default_alert_id() -> SetError<CalendarProperty> {
    SetError::invalid_properties()
        .with_properties([
            CalendarProperty::DefaultAlertsWithTime,
            CalendarProperty::DefaultAlertsWithoutTime,
        ])
        .with_description("Default alert ids must be unique across all calendars in the account.")
}

fn update_calendar(
    expected_id: Option<Id>,
    updates: Value<'_, CalendarProperty, CalendarValue>,
    calendar: &mut Calendar,
    access_token: &AccessToken,
    account_id: u32,
) -> Result<CalendarChanges, SetError<CalendarProperty>> {
    let personal_id = access_token.personal_id(account_id, Collection::Calendar);
    if access_token.is_member(account_id) {
        calendar.subscribe_member(personal_id);
    }
    let mut changes = CalendarChanges::default();

    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        if !matches!(
            property,
            CalendarProperty::Id
                | CalendarProperty::Name
                | CalendarProperty::Color
                | CalendarProperty::SortOrder
                | CalendarProperty::IsSubscribed
                | CalendarProperty::IsVisible
                | CalendarProperty::TimeZone
                | CalendarProperty::IncludeInAvailability
                | CalendarProperty::DefaultAlertsWithTime
                | CalendarProperty::DefaultAlertsWithoutTime
                | CalendarProperty::ShareWith
                | CalendarProperty::Pointer(_)
        ) {
            changes.shared_properties = true;
        }

        match (property, value) {
            (CalendarProperty::Name, Value::Str(value)) if (1..=255).contains(&value.len()) => {
                calendar.preferences_mut(personal_id).name = value.into_owned();
            }
            (CalendarProperty::Description, Value::Str(value)) if value.len() < 255 => {
                calendar.preferences_mut(personal_id).description = value.into_owned().into();
            }
            (CalendarProperty::Description, Value::Null) => {
                calendar.preferences_mut(personal_id).description = None;
            }
            (CalendarProperty::Color, Value::Str(value))
                if CssColor::parse(&value).is_some_and(|color| color.is_standard()) =>
            {
                calendar.preferences_mut(personal_id).color = value.into_owned().into();
            }
            (CalendarProperty::Color, Value::Null) => {
                calendar.preferences_mut(personal_id).color = None;
            }
            (CalendarProperty::TimeZone, Value::Element(CalendarValue::Timezone(tz))) => {
                calendar.preferences_mut(personal_id).time_zone = Timezone::IANA(tz.as_id());
            }
            (CalendarProperty::TimeZone, Value::Null) => {
                calendar.preferences_mut(personal_id).time_zone = Timezone::Default;
            }
            (CalendarProperty::SortOrder, Value::Number(value))
                if value.is_u64() && value.cast_to_u64() < 1 << 31 =>
            {
                calendar.preferences_mut(personal_id).sort_order = value.cast_to_u64() as u32;
            }
            (CalendarProperty::IsSubscribed, Value::Bool(subscribe)) => {
                if subscribe {
                    calendar.preferences_mut(personal_id).flags |= CALENDAR_SUBSCRIBED;
                } else {
                    calendar.preferences_mut(personal_id).flags &= !CALENDAR_SUBSCRIBED;
                }
            }
            (CalendarProperty::IsVisible, Value::Bool(visible)) => {
                if visible {
                    calendar.preferences_mut(personal_id).flags &= !CALENDAR_INVISIBLE;
                } else {
                    calendar.preferences_mut(personal_id).flags |= CALENDAR_INVISIBLE;
                }
            }
            (
                CalendarProperty::IncludeInAvailability,
                Value::Element(CalendarValue::IncludeInAvailability(availability)),
            ) => {
                let flags = &mut calendar.preferences_mut(personal_id).flags;

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
                value @ (Value::Object(_) | Value::Null),
            ) => {
                let with_time = matches!(property, CalendarProperty::DefaultAlertsWithTime);
                let alerts = &mut calendar.preferences_mut(personal_id).default_alerts;
                changes.default_alerts = true;

                alerts.retain(|alert| (alert.flags & ALERT_WITH_TIME != 0) != with_time);

                if let Value::Object(value) = value {
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
            }
            (CalendarProperty::ShareWith, value) => {
                calendar.acls = JmapRights::acl_set::<calendar::Calendar>(value)?;
                changes.acls = true;
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
                        changes.acls = true;
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
                            let alerts = &mut calendar.preferences_mut(personal_id).default_alerts;
                            changes.default_alerts = true;
                            alerts.retain(|alert| {
                                (alert.flags & ALERT_WITH_TIME != 0) != with_time || alert.id != id
                            });

                            if let Value::Object(value) = value {
                                alerts.push(value_to_default_alert(id, value, with_time)?);
                            }
                        }
                        _ => {
                            return Err(SetError::invalid_patch()
                                .with_property(CalendarProperty::Pointer(pointer))
                                .with_description("Field could not be patched."));
                        }
                    },
                    _ => {
                        return Err(SetError::invalid_patch()
                            .with_property(CalendarProperty::Pointer(pointer))
                            .with_description("Field could not be patched."));
                    }
                }
            }
            (CalendarProperty::Id, value) => {
                if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                    return Err(SetError::invalid_properties()
                        .with_property(CalendarProperty::Id)
                        .with_description("The id property is immutable."));
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
    let preferences = calendar.preferences(personal_id);
    if preferences.name.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(CalendarProperty::Name)
            .with_description("Missing name."));
    }

    if changes.default_alerts {
        let with_time = preferences
            .default_alerts
            .iter()
            .filter(|alert| alert.flags & ALERT_WITH_TIME != 0)
            .count();
        for (property, count) in [
            (CalendarProperty::DefaultAlertsWithTime, with_time),
            (
                CalendarProperty::DefaultAlertsWithoutTime,
                preferences.default_alerts.len() - with_time,
            ),
        ] {
            if count > MAX_USER_ALERTS {
                return Err(SetError::invalid_properties()
                    .with_property(property)
                    .with_description(format!(
                        "A calendar cannot have more than {MAX_USER_ALERTS} default alerts of each kind."
                    )));
            }
        }
    }

    Ok(changes)
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
            (CalendarProperty::Type, Value::Element(CalendarValue::Type(value)))
                if value != JSCalendarType::Alert =>
            {
                return Err(SetError::invalid_properties()
                    .with_property(CalendarProperty::Trigger)
                    .with_description("Invalid alert object type."));
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
                        (CalendarProperty::Type, Value::Element(CalendarValue::Type(value)))
                            if value != JSCalendarType::OffsetTrigger =>
                        {
                            return Err(SetError::invalid_properties()
                                .with_property(CalendarProperty::Trigger)
                                .with_description("Default alerts must use an OffsetTrigger."));
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

trait CalendarServerSet {
    fn server_set_values(
        &self,
        personal_id: u32,
        client_properties: &[CalendarProperty],
    ) -> Vec<(
        CalendarProperty,
        Value<'static, CalendarProperty, CalendarValue>,
    )>;
}

impl CalendarServerSet for Calendar {
    fn server_set_values(
        &self,
        personal_id: u32,
        client_properties: &[CalendarProperty],
    ) -> Vec<(
        CalendarProperty,
        Value<'static, CalendarProperty, CalendarValue>,
    )> {
        let preferences = self.preferences(personal_id);
        let default_alerts = |with_time: bool| {
            Value::Object(Map::from_iter(
                preferences
                    .default_alerts
                    .iter()
                    .filter(|alert| (alert.flags & ALERT_WITH_TIME != 0) == with_time)
                    .map(|alert| default_alert_value(&alert.id, alert.offset.clone(), alert.flags)),
            ))
        };
        [
            (
                CalendarProperty::SortOrder,
                Value::Number(preferences.sort_order.into()),
            ),
            (
                CalendarProperty::IsSubscribed,
                Value::Bool(preferences.flags & CALENDAR_SUBSCRIBED != 0),
            ),
            (
                CalendarProperty::IsVisible,
                Value::Bool(preferences.flags & CALENDAR_INVISIBLE == 0),
            ),
            (
                CalendarProperty::IncludeInAvailability,
                Value::Element(CalendarValue::IncludeInAvailability(
                    IncludeInAvailability::from_flags(preferences.flags)
                        .unwrap_or(IncludeInAvailability::All),
                )),
            ),
            (
                CalendarProperty::DefaultAlertsWithTime,
                default_alerts(true),
            ),
            (
                CalendarProperty::DefaultAlertsWithoutTime,
                default_alerts(false),
            ),
            (
                CalendarProperty::MyRights,
                JmapRights::all_rights::<calendar::Calendar>(),
            ),
        ]
        .into_iter()
        .filter(|(property, _)| !client_properties.contains(property))
        .collect()
    }
}
