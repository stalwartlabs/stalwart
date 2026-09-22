/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::pending_creates::PendingCreates;
use crate::blob::embedded::EmbeddedExport;
use crate::calendar_event::{
    CalendarSyntheticId, EventMainComponent, EventValue, JSCalendarEntries, UidIndex,
    get::{EventInstanceBuilder, InstanceBinaries},
    is_origin,
    privacy::{
        UidPrivacyConflicts, assert_privacy_access, assert_privacy_allowed, uid_privacy_conflict,
    },
    server_set::{
        BlobProperties, EmbeddedBlobId, ImportedValues, PENDING_DOCUMENT_ID, PendingBlobIds,
        ServerSetValues, TrackedValues,
    },
    user::user_data_error,
    validate::{
        BooleanValue, InstanceMetadata, InstanceView, OverridePatch, OverridePointer, PropertyName,
    },
};
use crate::changes::state::JmapCacheState;
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarDuration, ICalendarProperty, ICalendarValue,
    },
    jscalendar::{JSCalendar, JSCalendarDateTime, JSCalendarProperty, JSCalendarValue},
};
use chrono::DateTime;
use common::{
    ArchivedDavName, DavName, GroupwareResources, Server,
    auth::{AccessToken, AccountInfo},
    storage::quota::ObjectQuotaUsage,
};
use compact_str::ToCompactString;
use groupware::{
    DestroyArchive, SizeWriter,
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, CalendarEventContent, CalendarEventData, EVENT_DRAFT, EVENT_HIDE_ATTENDEES,
        EVENT_INVITE_OTHERS, EVENT_INVITE_SELF,
        alerts::{DefaultAlertsResolver, DefaultAlertsView, ICalendarDefaultAlerts},
        expand::{CalendarEventExpansion, ComponentRecurrenceId, RecurrenceKey, resolve_local},
        identity::{CalendarAddresses, ParticipantIdentityAddresses},
        index::ICalendarObjectUid,
        itip::ItipSendStatus,
        notification::{hides_details, may_have_viewers},
        privacy::{EventPrivacy, EventViewer},
        rights::{EventAcl, EventChanges},
        schedule::{EventAlarmScheduler, EventAlarmUsers},
        sequence::{ICalendarSequence, SCHEDULING_EVENT_FLAGS},
        storage::{DirectChange, DirectChangeNotification, NotificationQuota},
        user::{ICalendarUserData, UpdatedPolicy, UserDataSplit, UserDataUpdate, UserDataView},
    },
    scheduling::{
        ItipError, ItipMessages,
        event_create::{itip_attendee_create, itip_create},
        event_update::itip_update,
        itip::{itip_assign_organizer, itip_unreachable_recipient},
        recipient::RecipientPolicy,
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
use jmap_tools::{Element, JsonPointer, JsonPointerHandler, JsonPointerItem, Key, Map, Value};
use registry::schema::enums::StorageQuota;
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
    field::CalendarEventField,
    id::Id,
};

pub trait CalendarEventSet: Sync + Send {
    fn calendar_event_set(
        &self,
        request: SetRequest<'_, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<calendar_event::CalendarEvent>>> + Send;

    fn create_calendar_event(
        &self,
        context: &mut EventSetContext<'_>,
        batch: &mut BatchBuilder,
        source: EventSource<'_>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> impl Future<Output = trc::Result<CreatedEvent>>;
}

pub(crate) type CreatedEvent = Result<(Slot, ServerSetValues), SetError<JSCalendarProperty<Id>>>;

pub struct EventSetContext<'x> {
    pub cache: &'x GroupwareResources,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub account_info: &'x AccountInfo,
    pub send_scheduling_messages: bool,
    pub can_add_calendars: Option<&'x RoaringBitmap>,
    pub identities: &'x CalendarAddresses,
    pub uid_index: UidIndex<'x>,
    pub will_destroy: Vec<Id>,
    pub default_alerts: DefaultAlertsResolver,
    pub notification_quota: NotificationQuota,
}

pub enum EventSource<'x> {
    Create,
    Copy(CopiedEvent<'x>),
}

pub struct CopiedEvent<'x> {
    pub event: JSCalendar<'x, Id, BlobId>,
    pub flags: u16,
    pub use_default_alerts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventWrite {
    Create,
    Copy,
    Update,
}

#[derive(Debug, Clone, Copy)]
struct PatchTarget {
    write: EventWrite,
    id: Option<Id>,
    is_origin: Option<bool>,
}

const EVENT_METADATA_FLAGS: u16 =
    EVENT_DRAFT | EVENT_INVITE_SELF | EVENT_INVITE_OTHERS | EVENT_HIDE_ATTENDEES;

impl CalendarEventSet for Server {
    async fn calendar_event_set(
        &self,
        mut request: SetRequest<'_, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<calendar_event::CalendarEvent>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(cache.assert_state(false, &request.if_in_state)?);
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let is_owner = access_token.is_member(account_id);
        let identities = if is_owner {
            CalendarAddresses::default()
        } else {
            self.account_identity_addresses(access_token.account_id())
                .await
                .caused_by(trc::location!())?
        };
        let uid_privacy_conflicts = UidPrivacyConflicts::new(
            &cache,
            request.create.as_ref(),
            request.update.as_ref(),
            &will_destroy,
        );

        // Obtain calendarIds
        let is_shared = access_token.is_shared(account_id);
        let (can_add_calendars, can_delete_calendars) = if is_shared {
            (
                cache
                    .shared_containers(access_token, [Acl::AddItems], true)
                    .into(),
                cache
                    .shared_containers(access_token, [Acl::RemoveItems], true)
                    .into(),
            )
        } else {
            (None, None)
        };

        // Obtain quota
        let quota = if request.has_creates() {
            let account = self.account(account_id).await.caused_by(trc::location!())?;
            self.object_quota_usage(&account, StorageQuota::MaxCalendarEvents, || {
                cache.resources.count(false)
            })
        } else {
            ObjectQuotaUsage::unlimited()
        };

        // Process creates
        let mut batch = BatchBuilder::new();
        let send_scheduling_messages = request.arguments.send_scheduling_messages.unwrap_or(false);
        let mut created_slots = PendingCreates::new();
        let mut created_server_set = Vec::new();
        let uid_index = UidIndex::new(
            &cache,
            request
                .create
                .iter()
                .flat_map(|create| create.values())
                .filter_map(|object| {
                    match object.as_object_and_get(&Key::Property(JSCalendarProperty::Uid)) {
                        Some(Value::Str(uid)) => Some(uid.as_ref()),
                        _ => None,
                    }
                }),
        );
        let mut context = EventSetContext {
            cache: &cache,
            access_token,
            account_id,
            account_info: &account_info,
            send_scheduling_messages,
            can_add_calendars: can_add_calendars.as_ref(),
            identities: &identities,
            uid_index,
            will_destroy,
            default_alerts: DefaultAlertsResolver::with_resources(account_id, cache.clone()),
            notification_quota: NotificationQuota::default(),
        };
        'create: for (id, object) in request.unwrap_create() {
            if !quota.has_room(created_slots.len()) {
                response.not_created.append(id, too_many_events());
                continue 'create;
            }
            if uid_privacy_conflicts.creates.contains(&id) {
                response.not_created.append(id, uid_privacy_conflict());
                continue 'create;
            }

            match self
                .create_calendar_event(&mut context, &mut batch, EventSource::Create, object)
                .await?
            {
                Ok((slot, server_set)) => {
                    created_server_set.push((id.clone(), slot, server_set));
                    created_slots.push(id, slot);
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Group updates and instance removals by event
        let has_synthetic_ids = context.will_destroy.iter().any(|id| id.is_synthetic())
            || request.update.as_ref().is_some_and(|update| {
                update
                    .iter()
                    .any(|(id, _)| matches!(id, MaybeInvalid::Value(id) if id.is_synthetic()))
            });
        let is_destroyed_event = |document_id: u32| {
            context
                .will_destroy
                .iter()
                .any(|id| !id.is_synthetic() && id.document_id() == document_id)
        };
        let will_be_destroyed = |id: Id| {
            context.will_destroy.iter().any(|destroy_id| {
                *destroy_id == id
                    || (!destroy_id.is_synthetic() && destroy_id.document_id() == id.document_id())
            })
        };
        let mut updates =
            EventUpdates::with_capacity(request.update.as_ref().map_or(0, |update| update.len()));
        for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue;
                }
            };
            if will_be_destroyed(id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue;
            }
            let op = match id.recurrence_key() {
                Some(recurrence_key) => EventOp::Instance(InstanceOp {
                    id,
                    recurrence_key,
                    target: None,
                    action: InstanceAction::Update {
                        patch: object,
                        server_set: None,
                    },
                }),
                None => EventOp::Base { id, patch: object },
            };
            updates.push(has_synthetic_ids, op, &mut response);
        }
        for id in context.will_destroy.iter().copied() {
            let Some(recurrence_key) = id.recurrence_key() else {
                continue;
            };
            if is_destroyed_event(id.document_id()) {
                response.not_destroyed.append(id, SetError::will_destroy());
                continue;
            }
            updates.push(
                has_synthetic_ids,
                EventOp::Instance(InstanceOp {
                    id,
                    recurrence_key,
                    target: None,
                    action: InstanceAction::Destroy,
                }),
                &mut response,
            );
        }
        let mut destroy_events = std::mem::take(&mut context.will_destroy);
        if has_synthetic_ids {
            destroy_events.retain(|id| !id.is_synthetic());
        }
        let moved_uid_index = if updates
            .pending
            .iter()
            .any(EventUpdate::patches_calendar_ids)
        {
            UidIndex::new(
                &cache,
                updates.pending.iter().filter_map(|update| {
                    cache
                        .item_by_id(update.document_id)
                        .and_then(|resource| resource.uid())
                }),
            )
        } else {
            UidIndex::default()
        };

        // Process updates
        'update: for mut update in updates.pending {
            let document_id = update.document_id;
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
            if let Err(err) = assert_privacy_access(
                EventPrivacy::from_flags(calendar_event.inner.flags.to_native()),
                EventViewer::new(is_owner),
            ) {
                update.fail(&mut response, err);
                continue 'update;
            }
            if update.base_id().is_some() && uid_privacy_conflicts.updates.contains(document_id) {
                update.fail(&mut response, uid_privacy_conflict());
                continue 'update;
            }
            let Some(content_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                    CalendarEventField::Content,
                ))
                .await?
            else {
                update.fail(&mut response, SetError::not_found());
                continue 'update;
            };
            let content = content_
                .to_unarchived::<CalendarEventContent>()
                .caused_by(trc::location!())?;
            let mut new_calendar_event = calendar_event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_content = content
                .deserialize::<CalendarEventContent>()
                .caused_by(trc::location!())?;

            // Resolve synthetic ids into recurrence instances
            let mut has_instances = false;
            if update.has_instances() {
                match update.plan_instances(&new_content.data, &mut response) {
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

            let personal_id = access_token.personal_id(account_id, Collection::Calendar);
            let ownership = identities.event_ownership(&new_content.data.event);
            let was_origin = is_origin(&new_content.data.event, account_info.addresses());
            let view_default_alerts = context
                .default_alerts
                .resolve_for_content(
                    self,
                    account_id,
                    personal_id,
                    &new_content,
                    new_calendar_event.names.iter().map(DavName::parent_id),
                )
                .await
                .caused_by(trc::location!())?;
            let mut view = if is_owner {
                new_content.data.event.clone()
            } else {
                new_content
                    .data
                    .user_data_view(new_content.preferences(personal_id), UserDataView::Full)
            };
            let mut previous_event = std::mem::take(&mut new_content.data.event);
            let previous_preferences = (!is_owner)
                .then(|| new_content.preferences(personal_id).cloned())
                .flatten();
            view.apply_default_alerts(&view_default_alerts, DefaultAlertsView::Merge);
            let mut js_calendar_group = view.into_jscalendar::<Id, BlobId>();
            let tracked_before = update.base_patch().map(|patch| {
                (
                    TrackedValues::from_patch(patch),
                    TrackedValues::from_event(&js_calendar_group, Some(was_origin)),
                )
            });
            let blob_properties = update
                .base_patch()
                .map(|patch| {
                    BlobProperties::from_patch(patch, |blob_id| {
                        !blob_id.is_embedded_in(account_id, document_id)
                    })
                })
                .unwrap_or_default();
            update.track_instance_values(&previous_event, |blob_id| {
                !blob_id.is_embedded_in(account_id, document_id)
            });
            let is_restricted = is_shared
                && !EventAcl::for_calendars(
                    &cache,
                    access_token,
                    calendar_event
                        .inner
                        .names
                        .iter()
                        .map(ArchivedDavName::parent_id),
                )
                .may_write(ownership);
            let per_user_changes = update.per_user_patch_changes();
            let before_group = per_user_changes
                .is_none()
                .then(|| js_calendar_group.clone());

            // Apply per-instance changes to the recurrence overrides of the base event
            if has_instances {
                let metadata = InstanceMetadata {
                    is_origin: was_origin,
                    flags: new_calendar_event.flags,
                    calendar_ids: &new_calendar_event.names,
                    use_default_alerts: new_content
                        .preferences(personal_id)
                        .is_some_and(|preferences| preferences.use_default_alerts()),
                };
                if !update.apply_instances(&mut js_calendar_group, &metadata, &mut response) {
                    continue 'update;
                }
            }

            // Process changes
            let is_use_default_alerts_changed = match update_calendar_event(
                &cache,
                personal_id,
                PatchTarget {
                    write: EventWrite::Update,
                    id: update.base_id(),
                    is_origin: Some(was_origin),
                },
                update.take_base_patch(),
                &mut new_calendar_event,
                &mut new_content,
                &mut js_calendar_group,
            ) {
                Ok(is_changed) => is_changed,
                Err(err) => {
                    update.fail(&mut response, err);
                    continue 'update;
                }
            };

            // Validate calendarIds limit
            let max_calendars = self.core.groupware.max_calendars_per_event;
            if new_calendar_event.names.len() > max_calendars
                && new_calendar_event.names.len() > calendar_event.inner.names.len()
            {
                update.fail(&mut response, too_many_calendars(max_calendars));
                continue 'update;
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
                } else if can_add_calendars.as_ref().is_some_and(|ids| {
                    !ids.contains(calendar_id)
                        && !(EventAcl::for_calendar(&cache, access_token, calendar_id)
                            .may_manage_own_items()
                            && ownership.may_write_own())
                }) {
                    update.fail(&mut response, add_calendar_forbidden(calendar_id));
                    continue 'update;
                }
            }

            // Validate deleted calendarIds
            if let Some(can_delete_calendars) = &can_delete_calendars {
                for calendar_id in new_calendar_event.removed_calendar_ids(calendar_event.inner) {
                    if !can_delete_calendars.contains(calendar_id)
                        && !(EventAcl::for_calendar(&cache, access_token, calendar_id)
                            .may_manage_own_items()
                            && ownership.may_write_own())
                    {
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
            let is_calendar_ids_changed = new_calendar_event
                .added_calendar_ids(calendar_event.inner)
                .next()
                .is_some()
                || new_calendar_event
                    .removed_calendar_ids(calendar_event.inner)
                    .next()
                    .is_some();
            if is_calendar_ids_changed
                && let Err(err) = moved_uid_index
                    .assert_is_unique(
                        self,
                        account_id,
                        &previous_event,
                        &new_calendar_event.names,
                        Some(document_id),
                        &destroy_events,
                    )
                    .await?
            {
                update.fail(&mut response, err);
                continue 'update;
            }
            let is_metadata_changed = is_calendar_ids_changed
                || (calendar_event.inner.flags.to_native() ^ new_calendar_event.flags)
                    & EVENT_METADATA_FLAGS
                    != 0;

            let mut changes = match before_group {
                Some(before_group) => EventChanges::between(
                    &before_group,
                    &js_calendar_group,
                    calendar_event.inner.flags.to_native(),
                    new_calendar_event.flags,
                    &identities,
                ),
                None => per_user_changes.unwrap_or_default(),
            };
            if is_use_default_alerts_changed {
                changes.insert_per_user();
            }
            let tracked = tracked_before.map(|(client, before)| {
                (
                    client,
                    before,
                    TrackedValues::from_dates(&js_calendar_group),
                )
            });

            // Convert JSCalendar to iCalendar
            let ical = match self
                .export_icalendar(access_token, js_calendar_group)
                .await?
            {
                Ok(ical) => ical,
                Err(err) => {
                    update.fail(&mut response, err);
                    continue 'update;
                }
            };
            new_content.data.event = ical;
            changes.classify_recurrence_sets(&previous_event, &new_content.data.event);
            let is_per_user_change = changes.is_per_user_only();
            if let Err(err) =
                assert_privacy_allowed(&new_content.data.event, EventViewer::new(is_owner))
            {
                update.fail(&mut response, err);
                continue 'update;
            }
            let new_default_alerts = context
                .default_alerts
                .resolve_for_content(
                    self,
                    account_id,
                    personal_id,
                    &new_content,
                    new_calendar_event.names.iter().map(DavName::parent_id),
                )
                .await
                .caused_by(trc::location!())?;
            for defaults in [&view_default_alerts, &new_default_alerts] {
                new_content.data.event.strip_default_alerts(defaults);
            }
            if let Err(err) = new_content
                .data
                .event
                .validate_user_data_changes(&previous_event)
            {
                update.fail(&mut response, user_data_error(err));
                continue 'update;
            }

            let mut is_user_data_only = false;
            let mut is_stored_event = false;
            let mut personal_updated = None;
            let mut dropped_overrides = Vec::new();
            if !is_owner {
                let user_data = UserDataUpdate {
                    account_id: personal_id,
                    view: UserDataView::Full,
                    previous: previous_preferences.as_ref(),
                    current: new_content
                        .preferences
                        .iter()
                        .find(|preferences| preferences.account_id == personal_id),
                    updated: if was_origin {
                        UpdatedPolicy::Server(now() as i64)
                    } else {
                        UpdatedPolicy::Client
                    },
                };
                let split = if is_per_user_change {
                    new_content
                        .data
                        .event
                        .extract_user_preferences(&previous_event, user_data)
                        .map(|preferences| (preferences, UserDataSplit::UserDataOnly))
                } else {
                    new_content
                        .data
                        .event
                        .split_user_data(&previous_event, user_data)
                };
                match split {
                    Ok((preferences, split)) => {
                        if was_origin
                            && split == UserDataSplit::UserDataOnly
                            && previous_preferences
                                .as_ref()
                                .map_or(0, |previous| previous.updated)
                                != preferences.updated
                        {
                            personal_updated = Some(preferences.updated);
                        }
                        new_content.set_preferences(preferences);
                        if split == UserDataSplit::UserDataOnly {
                            is_stored_event = true;
                            if is_metadata_changed {
                                new_content.data.event = previous_event.clone();
                            } else {
                                new_content.data.event = std::mem::take(&mut previous_event);
                                is_user_data_only = true;
                            }
                        }
                    }
                    Err(err) => {
                        update.fail(&mut response, user_data_error(err));
                        continue 'update;
                    }
                }
            } else if is_per_user_change {
                let mut event = if is_metadata_changed {
                    previous_event.clone()
                } else {
                    std::mem::take(&mut previous_event)
                };
                dropped_overrides = event.copy_user_data(&new_content.data.event);
                new_content.data.event = event;
                is_user_data_only = !is_metadata_changed;
            }

            // Assign an organizer when participants were added to an event that had none
            let is_organizer_assigned = !is_user_data_only
                && account_info
                    .addresses()
                    .first()
                    .is_some_and(|organizer_address| {
                        itip_assign_organizer(&mut new_content.data.event, organizer_address)
                    });
            let has_scheduling_changes = !is_user_data_only
                && new_content
                    .data
                    .event
                    .has_scheduling_changes(&previous_event);
            if is_owner
                && !is_metadata_changed
                && !is_organizer_assigned
                && !has_scheduling_changes
                && new_content.data.event.has_same_sequences(&previous_event)
            {
                is_user_data_only = true;
            }
            let is_origin_event = is_origin(&new_content.data.event, account_info.addresses());
            if !is_user_data_only && is_origin_event {
                if has_scheduling_changes
                    || (calendar_event.inner.flags.to_native() ^ new_calendar_event.flags)
                        & SCHEDULING_EVENT_FLAGS
                        != 0
                {
                    new_content.data.event.increment_sequence(&previous_event);
                }
                stamp_updated(&mut new_content.data.event, now() as i64);
            }

            if let Err(err) = assert_participants_limit(
                &new_content.data.event,
                self.core.groupware.max_ical_attendees_per_instance,
            ) {
                update.fail(&mut response, err);
                continue 'update;
            }

            // Validate UID
            if !is_user_data_only {
                let description = match (
                    new_content.data.event.object_uid(),
                    previous_event.object_uid(),
                ) {
                    (Some(new_uid), Some(old_uid)) if new_uid == old_uid => None,
                    (None, None) => None,
                    (None, Some(_)) => Some("The UID of a calendar event cannot be removed."),
                    _ => Some("You cannot change the UID of a calendar event."),
                };
                if let Some(description) = description {
                    update.fail(
                        &mut response,
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::Uid)
                            .with_description(description),
                    );
                    continue 'update;
                }
            }

            if is_restricted {
                let mut unchanged = new_calendar_event
                    .unchanged_calendar_ids(calendar_event.inner)
                    .peekable();
                let acl = if unchanged.peek().is_none() {
                    EventAcl::for_calendars(
                        &cache,
                        access_token,
                        new_calendar_event.added_calendar_ids(calendar_event.inner),
                    )
                } else {
                    EventAcl::for_calendars(&cache, access_token, unchanged)
                };
                if let Err(err) =
                    changes.assert_allowed(&acl, ownership, calendar_event.inner.flags.to_native())
                {
                    update.fail(
                        &mut response,
                        SetError::forbidden().with_description(err.description()),
                    );
                    continue 'update;
                }
            }

            // Check size and quota
            new_calendar_event.size = SizeWriter::ical(&new_content.data.event) as u32;
            if new_calendar_event.size as usize > self.core.groupware.max_ical_size {
                update.fail(
                    &mut response,
                    too_large_event(
                        new_calendar_event.size as usize,
                        self.core.groupware.max_ical_size,
                    ),
                );
                continue 'update;
            }

            // Obtain previous alarm
            let now = now() as i64;
            let previous_calendar_ids = calendar_event
                .inner
                .names
                .iter()
                .map(ArchivedDavName::parent_id)
                .collect::<Vec<_>>();
            let prev_email_alarms = self
                .next_event_alarms(
                    account_id,
                    &EventAlarmUsers::new(account_id, content.inner)?
                        .with_event_flags(calendar_event.inner.flags.to_native()),
                    &content.inner.data,
                    &previous_calendar_ids,
                    now,
                    &mut context.default_alerts,
                )
                .await
                .caused_by(trc::location!())?;
            // Build event
            if !is_stored_event || is_calendar_ids_changed {
                let owner_default_alerts = context
                    .default_alerts
                    .resolve_for_content(
                        self,
                        account_id,
                        account_id,
                        &new_content,
                        new_calendar_event.names.iter().map(DavName::parent_id),
                    )
                    .await
                    .caused_by(trc::location!())?;
                new_content.data = CalendarEventData::new_with_default_alerts(
                    new_content.data.event,
                    Tz::Floating,
                    self.core.groupware.max_ical_instances,
                    &owner_default_alerts,
                );
            }
            let next_email_alarms = self
                .next_event_alarms(
                    account_id,
                    &EventAlarmUsers::new(account_id, &new_content)?
                        .with_event_flags(new_calendar_event.flags),
                    &new_content.data,
                    &new_calendar_event
                        .names
                        .iter()
                        .map(DavName::parent_id)
                        .collect::<Vec<_>>(),
                    now,
                    &mut context.default_alerts,
                )
                .await
                .caused_by(trc::location!())?;

            // Scheduling
            let mut itip_messages = None;
            let itip_status = if send_scheduling_messages
                && !is_user_data_only
                && new_calendar_event.flags & EVENT_DRAFT == 0
            {
                ItipSendStatus::resolve(
                    self,
                    access_token,
                    &account_info,
                    new_content.data.event_range_end(),
                )
            } else {
                ItipSendStatus::NotRequested
            };
            if itip_status.is_send() {
                if let Some(calendar_address) =
                    itip_unreachable_recipient(&new_content.data.event, account_info.addresses())
                {
                    update.fail(
                        &mut response,
                        SetError::no_supported_schedule_methods(calendar_address),
                    );
                    continue 'update;
                }

                let policy = RecipientPolicy::new(&self.core.groupware, new_calendar_event.flags);
                let result = if new_calendar_event.schedule_tag.is_some() {
                    itip_update(
                        &mut new_content.data.event,
                        &previous_event,
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

                        trc::event!(
                            Calendar(trc::CalendarEvent::ItipMessageError),
                            AccountId = account_id,
                            DocumentId = document_id,
                            Reason = err.to_compact_string(),
                        );

                        // Event changed, but there are no iTIP messages to send
                        if let Some(schedule_tag) = &mut new_calendar_event.schedule_tag {
                            *schedule_tag += 1;
                        }
                    }
                }
            } else if let Some(reason) = itip_status.reason() {
                if itip_status.is_denied() {
                    update.fail(
                        &mut response,
                        SetError::forbidden().with_description(reason),
                    );
                    continue 'update;
                }

                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Reason = reason,
                );
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

            let server_set = tracked.map(|(client, before, dates)| {
                let mut server_set = dates
                    .with_component(new_content.data.event.main_component())
                    .with_origin(is_origin_event)
                    .server_set(&client, Some(&before));
                let imported = ImportedValues {
                    participants: is_organizer_assigned,
                    blob_properties: &blob_properties,
                    every_blob_property: false,
                };
                if imported.is_requested() {
                    server_set.extend(imported.values(
                        &new_content.data.event,
                        account_id,
                        document_id,
                    ));
                }
                server_set
            });
            let mut instance_server_set = Vec::with_capacity(update.instances_mut().len());
            for instance in update.instances_mut() {
                let (id, recurrence_key) = (instance.id, instance.recurrence_key);
                let Some(tracked) = instance.take_server_set() else {
                    continue;
                };
                let mut values = TrackedValues::default()
                    .with_component(
                        new_content
                            .data
                            .event
                            .instance_component(tracked.recurrence_id),
                    )
                    .server_set(&tracked.client, Some(&tracked.before));
                if !tracked.blob_properties.is_empty() {
                    values.extend(instance_blob_values(
                        &new_content.data,
                        recurrence_key,
                        &tracked.blob_properties,
                        account_id,
                        document_id,
                    ));
                }
                instance_server_set.push((id, values));
            }

            let notify_calendar_ids = if is_user_data_only {
                Vec::new()
            } else {
                new_calendar_event.all_calendar_ids(calendar_event.inner)
            };
            let notify_event_flags =
                new_calendar_event.flags | calendar_event.inner.flags.to_native();
            if !is_user_data_only
                && may_have_viewers(
                    access_token,
                    account_id,
                    &cache,
                    &notify_calendar_ids,
                    hides_details(notify_event_flags),
                )
            {
                self.notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Updated {
                        event_id: document_id,
                        previous: previous_event,
                        current: new_content.data.event.clone(),
                        calendar_ids: notify_calendar_ids,
                        event_flags: notify_event_flags,
                    },
                    Some(&cache),
                    &mut context.notification_quota,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            }

            // Update record
            let vanished_paths = new_calendar_event
                .removed_calendar_ids(calendar_event.inner)
                .filter_map(|calendar_id| {
                    cache.format_resource_path_by_parent(document_id, calendar_id)
                })
                .collect::<Vec<_>>();
            new_calendar_event
                .update_full(
                    new_content,
                    access_token.account_tenant_ids(),
                    calendar_event,
                    content.inner,
                    account_id,
                    document_id,
                    None,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            for path in vanished_paths {
                batch.log_vanished_item(VanishedCollection::Calendar, path);
            }
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

            update.succeed(&mut response);
            if let (Some(base_id), Some(server_set)) = (update.base_id(), server_set) {
                response.add_server_set_properties(base_id, server_set);
            }
            if let Some(base_id) = update.base_id().filter(|_| !dropped_overrides.is_empty()) {
                response.add_server_set_properties(
                    base_id,
                    dropped_overrides.into_iter().map(|recurrence_id| {
                        (
                            JSCalendarProperty::Pointer(JsonPointer::new(vec![
                                JsonPointerItem::Key(Key::Property(
                                    JSCalendarProperty::RecurrenceOverrides,
                                )),
                                JsonPointerItem::Key(Key::Property(JSCalendarProperty::DateTime(
                                    JSCalendarDateTime::new(recurrence_id, true),
                                ))),
                            ])),
                            Value::Null,
                        )
                    }),
                );
            }
            if let (Some(base_id), Some(updated)) = (update.base_id(), personal_updated) {
                response.add_server_set_property(
                    base_id,
                    JSCalendarProperty::Updated,
                    Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                        updated, false,
                    ))),
                );
            }
            for (id, server_set) in instance_server_set {
                response.add_server_set_properties(id, server_set);
            }
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
            if let Err(err) = assert_privacy_access(
                EventPrivacy::from_flags(calendar_event.inner.flags.to_native()),
                EventViewer::new(is_owner),
            ) {
                response.not_destroyed.append(id, err);
                continue 'destroy;
            }
            let notify_calendar_ids = calendar_event.inner.calendar_ids().collect::<Vec<_>>();
            let notify_event_flags = calendar_event.inner.flags.to_native();
            let may_notify = may_have_viewers(
                access_token,
                account_id,
                &cache,
                &notify_calendar_ids,
                hides_details(notify_event_flags),
            );
            let stored_content = if is_owner && !may_notify {
                None
            } else {
                self.store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
            };
            let stored_event = stored_content
                .as_ref()
                .map(|content| {
                    content
                        .unarchive::<CalendarEventContent>()
                        .and_then(|content| rkyv_deserialize::<_, ICalendar>(&content.data.event))
                })
                .transpose()
                .caused_by(trc::location!())?;
            if let Some(can_delete_calendars) = &can_delete_calendars {
                let mut may_write_own = None;
                for name in calendar_event.inner.names.iter() {
                    let parent_id = name.parent_id.to_native();
                    if can_delete_calendars.contains(parent_id)
                        || (EventAcl::for_calendar(&cache, access_token, parent_id)
                            .may_manage_own_items()
                            && *may_write_own.get_or_insert_with(|| {
                                stored_event.as_ref().is_some_and(|event| {
                                    identities.event_ownership(event).may_write_own()
                                })
                            }))
                    {
                        continue;
                    }
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

            // Scheduling
            let itip_status = if send_scheduling_messages {
                ItipSendStatus::resolve(
                    self,
                    access_token,
                    &account_info,
                    calendar_event.inner.event_range_end(),
                )
            } else {
                ItipSendStatus::NotRequested
            };
            if let Some(reason) = itip_status.reason() {
                if itip_status.is_denied() {
                    response
                        .not_destroyed
                        .append(id, SetError::forbidden().with_description(reason));
                    continue 'destroy;
                }

                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Reason = reason,
                );
            }

            // Delete event
            if let Some(previous) = stored_event.filter(|_| may_notify) {
                self.notify_direct_change(
                    access_token,
                    account_id,
                    DirectChange::Destroyed {
                        event_id: document_id,
                        previous,
                        calendar_ids: notify_calendar_ids,
                        event_flags: notify_event_flags,
                    },
                    Some(&cache),
                    &mut context.notification_quota,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;
            }
            DestroyArchive(calendar_event)
                .delete_all(
                    self,
                    &account_info,
                    account_id,
                    document_id,
                    stored_content,
                    itip_status.is_send(),
                    &mut batch,
                )
                .await
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
            for (create_id, slot, mut server_set) in created_server_set {
                server_set.resolve_document_id(assigned_ids.slot(slot));
                response.add_created_properties(&create_id, server_set);
            }

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::Calendar))
                    .into();
        }

        Ok(response)
    }

    async fn create_calendar_event(
        &self,
        context: &mut EventSetContext<'_>,
        batch: &mut BatchBuilder,
        source: EventSource<'_>,
        updates: Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    ) -> trc::Result<CreatedEvent> {
        let cache = context.cache;
        let access_token = context.access_token;
        let account_id = context.account_id;
        let account_info = context.account_info;
        let send_scheduling_messages = context.send_scheduling_messages;
        let can_add_calendars = context.can_add_calendars;
        let identities = context.identities;
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);
        let is_member = access_token.is_member(account_id);

        // Process changes
        let client_values = TrackedValues::from_patch(&updates);
        let blob_properties = BlobProperties::from_patch(&updates, |_| true);
        let mut event = CalendarEvent::default();
        let mut content = CalendarEventContent::default();
        let (write, mut js_calendar_group, before) = match source {
            EventSource::Create => (EventWrite::Create, JSCalendar::new_event(), None),
            EventSource::Copy(copied) => {
                event.flags = copied.flags & EVENT_METADATA_FLAGS;
                if copied.use_default_alerts
                    && let Err(err) = content
                        .preferences_mut(personal_id)
                        .set_use_default_alerts(true)
                {
                    return Ok(Err(user_data_error(err)));
                }
                let before = TrackedValues::from_event(&copied.event, None);
                (EventWrite::Copy, copied.event, Some(before))
            }
        };
        if let Err(err) = update_calendar_event(
            cache,
            personal_id,
            PatchTarget {
                write,
                id: None,
                is_origin: None,
            },
            updates,
            &mut event,
            &mut content,
            &mut js_calendar_group,
        ) {
            return Ok(Err(err));
        }
        if event.names.len() > self.core.groupware.max_calendars_per_event {
            return Ok(Err(too_many_calendars(
                self.core.groupware.max_calendars_per_event,
            )));
        }

        // Verify that the calendar ids valid
        if let Some(name) = event
            .names
            .iter()
            .find(|name| !cache.has_container_id(&name.parent_id))
        {
            return Ok(Err(SetError::invalid_properties()
                .with_property(JSCalendarProperty::CalendarIds)
                .with_description(format!(
                    "calendarId {} does not exist.",
                    Id::from(name.parent_id)
                ))));
        }
        if let Some(ids) = can_add_calendars
            && let Some(name) = event.names.iter().find(|name| {
                !ids.contains(name.parent_id)
                    && !EventAcl::for_calendar(cache, access_token, name.parent_id)
                        .may_manage_own_items()
            })
        {
            return Ok(Err(add_calendar_forbidden(name.parent_id)));
        }
        let dates = TrackedValues::from_dates(&js_calendar_group);

        // Convert JSCalendar to iCalendar
        let mut ical = match self
            .export_icalendar(access_token, js_calendar_group)
            .await?
        {
            Ok(ical) => ical,
            Err(err) => return Ok(Err(err)),
        };
        if let Err(err) = assert_privacy_allowed(&ical, EventViewer::new(is_member)) {
            return Ok(Err(err));
        }

        // Generate a UID when the client omitted one
        if ical.object_uid().is_none() {
            let uid = generate_uid();
            for component in &mut ical.components {
                if component.component_type.is_event_or_todo() {
                    component.add_uid(&uid);
                }
            }
        }

        content.data.event = ical;
        let user_default_alerts = context
            .default_alerts
            .resolve_for_content(
                self,
                account_id,
                personal_id,
                &content,
                event.names.iter().map(DavName::parent_id),
            )
            .await
            .caused_by(trc::location!())?;
        let mut ical = std::mem::take(&mut content.data.event);
        ical.strip_default_alerts(&user_default_alerts);

        if let Err(err) = ical.validate_user_data() {
            return Ok(Err(user_data_error(err)));
        }
        if !is_member {
            match ical
                .extract_user_data(personal_id)
                .and_then(|mut preferences| {
                    preferences.inherit_default_alerts(content.preferences(personal_id))?;
                    Ok(preferences)
                }) {
                Ok(preferences) => {
                    content.set_preferences(preferences);
                    ical.apply_user_data(None, UserDataView::Full);
                }
                Err(err) => {
                    return Ok(Err(user_data_error(err)));
                }
            }
        }

        // Assign an organizer when the event has participants but none was provided
        let is_organizer_assigned = account_info
            .addresses()
            .first()
            .is_some_and(|organizer_address| itip_assign_organizer(&mut ical, organizer_address));
        if let Some(ids) = can_add_calendars
            && let Some(name) = event
                .names
                .iter()
                .find(|name| !ids.contains(name.parent_id))
            && !identities.event_ownership(&ical).may_write_own()
        {
            return Ok(Err(add_calendar_forbidden(name.parent_id)));
        }
        let now = now() as i64;
        stamp_created(&mut ical, now);
        if is_origin(&ical, account_info.addresses()) {
            stamp_updated(&mut ical, now);
            clamp_created(&mut ical, now);
        }

        if let Err(err) =
            assert_participants_limit(&ical, self.core.groupware.max_ical_attendees_per_instance)
        {
            return Ok(Err(err));
        }

        // Validate UID
        if let Err(err) = context
            .uid_index
            .assert_is_unique(
                self,
                account_id,
                &ical,
                &event.names,
                None,
                &context.will_destroy,
            )
            .await?
        {
            return Ok(Err(err));
        }

        // Check size and quota
        let size = SizeWriter::ical(&ical);
        if size > self.core.groupware.max_ical_size {
            return Ok(Err(too_large_event(
                size,
                self.core.groupware.max_ical_size,
            )));
        }

        // Build event
        content.data.event = ical;
        let owner_default_alerts = context
            .default_alerts
            .resolve_for_content(
                self,
                account_id,
                account_id,
                &content,
                event.names.iter().map(DavName::parent_id),
            )
            .await
            .caused_by(trc::location!())?;
        content.data = CalendarEventData::new_with_default_alerts(
            std::mem::take(&mut content.data.event),
            Tz::Floating,
            self.core.groupware.max_ical_instances,
            &owner_default_alerts,
        );
        let next_email_alarms = self
            .next_event_alarms(
                account_id,
                &EventAlarmUsers::new(account_id, &content)?.with_event_flags(event.flags),
                &content.data,
                &event
                    .names
                    .iter()
                    .map(DavName::parent_id)
                    .collect::<Vec<_>>(),
                now,
                &mut context.default_alerts,
            )
            .await
            .caused_by(trc::location!())?;

        // Scheduling
        let mut itip_messages = None;
        let itip_status = if send_scheduling_messages && event.flags & EVENT_DRAFT == 0 {
            ItipSendStatus::resolve(
                self,
                access_token,
                account_info,
                content.data.event_range_end(),
            )
        } else {
            ItipSendStatus::NotRequested
        };
        if itip_status.is_send() {
            if let Some(calendar_address) =
                itip_unreachable_recipient(&content.data.event, account_info.addresses())
            {
                return Ok(Err(SetError::no_supported_schedule_methods(
                    calendar_address,
                )));
            }

            match itip_create(
                &mut content.data.event,
                account_info.addresses(),
                RecipientPolicy::new(&self.core.groupware, event.flags),
            )
            .or_else(|err| {
                if matches!(err, ItipError::NotOrganizer) {
                    itip_attendee_create(&mut content.data.event, account_info.addresses())
                } else {
                    Err(err)
                }
            }) {
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

                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        AccountId = account_id,
                        Reason = err.to_compact_string(),
                    );
                }
            }
        } else if let Some(reason) = itip_status.reason() {
            if itip_status.is_denied() {
                return Ok(Err(SetError::forbidden().with_description(reason)));
            }

            trc::event!(
                Calendar(trc::CalendarEvent::ItipMessageError),
                AccountId = account_id,
                Reason = reason,
            );
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

        let mut server_set = dates
            .with_component(content.data.event.main_component())
            .with_origin(is_origin(&content.data.event, account_info.addresses()))
            .server_set(&client_values, before.as_ref());
        let imported = ImportedValues {
            participants: is_organizer_assigned,
            blob_properties: &blob_properties,
            every_blob_property: write == EventWrite::Copy
                && content.data.event.embedded_size() > 0,
        };
        if imported.is_requested() {
            server_set.extend(imported.values(
                &content.data.event,
                account_id,
                PENDING_DOCUMENT_ID,
            ));
        }

        // Insert record
        let document_id = batch.reserve_document_id(account_id, Collection::CalendarEvent);
        let notify_calendar_ids = event.calendar_ids().collect::<Vec<_>>();
        context
            .uid_index
            .record(&content.data.event, &notify_calendar_ids);
        if may_have_viewers(
            access_token,
            account_id,
            cache,
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
                Some(cache),
                &mut context.notification_quota,
                batch,
            )
            .await
            .caused_by(trc::location!())?;
        }
        event
            .insert(
                content,
                access_token.account_tenant_ids(),
                account_id,
                document_id,
                None,
                next_email_alarms,
                batch,
            )
            .caused_by(trc::location!())?;

        if let Some(itip_messages) = itip_messages {
            itip_messages.queue(batch).caused_by(trc::location!())?;
        }

        Ok(Ok((document_id, server_set)))
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

fn stamp_created(ical: &mut ICalendar, timestamp: i64) {
    for component in &mut ical.components {
        if component.component_type.is_event_or_todo()
            && component.property(&ICalendarProperty::Created).is_none()
        {
            component.add_property(
                ICalendarProperty::Created,
                ICalendarValue::PartialDateTime(Box::new(PartialDateTime::from_utc_timestamp(
                    timestamp,
                ))),
            );
        }
    }
}

fn clamp_created(ical: &mut ICalendar, timestamp: i64) {
    for entry in ical
        .components
        .iter_mut()
        .filter(|component| component.component_type.is_event_or_todo())
        .flat_map(|component| component.entries.iter_mut())
        .filter(|entry| entry.name == ICalendarProperty::Created)
    {
        if entry
            .values
            .first()
            .and_then(|value| value.as_partial_date_time())
            .and_then(|dt| dt.to_timestamp())
            .is_none_or(|created| created > timestamp)
        {
            entry.values = vec![ICalendarValue::PartialDateTime(Box::new(
                PartialDateTime::from_utc_timestamp(timestamp),
            ))];
        }
    }
}

fn assert_participants_limit(
    ical: &ICalendar,
    max_participants: usize,
) -> Result<(), SetError<JSCalendarProperty<Id>>> {
    if ical.components.iter().any(|component| {
        component
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Attendee)
            .count()
            > max_participants
    }) {
        Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::Participants)
            .with_description(format!(
                "An event cannot have more than {max_participants} participants."
            )))
    } else {
        Ok(())
    }
}

pub(crate) fn too_many_events() -> SetError<JSCalendarProperty<Id>> {
    SetError::over_quota().with_description(concat!(
        "There are too many calendar events, ",
        "please delete some before adding a new one."
    ))
}

fn too_many_calendars(max: usize) -> SetError<JSCalendarProperty<Id>> {
    SetError::invalid_properties()
        .with_property(JSCalendarProperty::CalendarIds)
        .with_description(format!(
            "A calendar event cannot belong to more than {max} calendars."
        ))
}

fn too_large_event(size: usize, max_size: usize) -> SetError<JSCalendarProperty<Id>> {
    SetError::too_large().with_description(format!(
        "Event size {size} exceeds the maximum allowed size of {max_size} bytes."
    ))
}

fn add_calendar_forbidden(calendar_id: u32) -> SetError<JSCalendarProperty<Id>> {
    SetError::forbidden().with_description(format!(
        "You are not allowed to add calendar events to calendar {}.",
        Id::from(calendar_id)
    ))
}

fn immutable_property(property: JSCalendarProperty<Id>) -> SetError<JSCalendarProperty<Id>> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description("This property is immutable.")
}

fn update_calendar_event<'x>(
    cache: &GroupwareResources,
    personal_id: u32,
    target: PatchTarget,
    updates: Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    event: &mut CalendarEvent,
    content: &mut CalendarEventContent,
    js_calendar_group: &mut JSCalendar<'x, Id, BlobId>,
) -> Result<bool, SetError<JSCalendarProperty<Id>>> {
    let Some(js_calendar_event) = js_calendar_group.first_entry_mut() else {
        return Err(SetError::invalid_properties()
            .with_description("Failed to convert calendar event to JSCalendar."));
    };

    let previous_use_default_alerts = content
        .preferences(personal_id)
        .is_some_and(|preferences| preferences.use_default_alerts());
    let mut use_default_alerts = previous_use_default_alerts;
    let mut utc_start = None;
    let mut utc_end = None;
    let mut has_start = false;
    let mut has_duration = false;
    let mut has_recurrence_changes = false;

    for (key, value) in updates.into_expanded_object() {
        if target.write == EventWrite::Create && value.is_null() {
            continue;
        }

        let property = match key {
            Key::Property(property) => property,
            key => {
                if !key.to_string().is_valid_property_name() {
                    return Err(SetError::invalid_properties()
                        .with_property(key.to_owned())
                        .with_description("Invalid property."));
                }
                if let Value::Object(entries) = js_calendar_event {
                    if value.is_null() {
                        entries.remove(&key);
                    } else {
                        entries.insert(key, value);
                    }
                }
                continue;
            }
        };

        match (property, value) {
            (JSCalendarProperty::IsDraft, value @ (Value::Bool(_) | Value::Null)) => {
                if matches!(value, Value::Bool(true)) {
                    if target.write == EventWrite::Update && event.flags & EVENT_DRAFT == 0 {
                        return Err(SetError::invalid_properties()
                            .with_property(JSCalendarProperty::IsDraft)
                            .with_description(
                                "isDraft cannot be set to true on an event that is not a draft.",
                            ));
                    }
                    event.flags |= EVENT_DRAFT;
                } else {
                    event.flags &= !EVENT_DRAFT;
                }
            }
            (
                property @ (JSCalendarProperty::MayInviteSelf
                | JSCalendarProperty::MayInviteOthers
                | JSCalendarProperty::HideAttendees),
                value @ (Value::Bool(_) | Value::Null),
            ) => {
                let flag = match property {
                    JSCalendarProperty::MayInviteSelf => EVENT_INVITE_SELF,
                    JSCalendarProperty::MayInviteOthers => EVENT_INVITE_OTHERS,
                    _ => EVENT_HIDE_ATTENDEES,
                };
                if value.is_same_boolean(true) {
                    event.flags |= flag;
                } else {
                    event.flags &= !flag;
                }
            }
            (JSCalendarProperty::UseDefaultAlerts, value @ (Value::Bool(_) | Value::Null)) => {
                use_default_alerts = value.is_same_boolean(true);
                content
                    .preferences_mut(personal_id)
                    .set_use_default_alerts(use_default_alerts)
                    .map_err(user_data_error)?;
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
                let (pointer, value) = match pointer.first() {
                    Some(JsonPointerItem::Key(Key::Property(JSCalendarProperty::CalendarIds))) => {
                        patch_parent_ids(&mut event.names, pointer.as_slice().get(1), value)?;
                        continue;
                    }
                    Some(JsonPointerItem::Key(Key::Property(
                        JSCalendarProperty::RecurrenceOverrides,
                    ))) => {
                        has_recurrence_changes = true;
                        pointer.validate_override_pointer(&value)?;
                        match js_calendar_event.acknowledged_alert_pointer(&pointer) {
                            Some(alert_pointer) => (alert_pointer, value.into_acknowledged()),
                            None => (pointer, value),
                        }
                    }
                    Some(JsonPointerItem::Key(Key::Property(
                        JSCalendarProperty::RecurrenceRule,
                    ))) => {
                        has_recurrence_changes = true;
                        (pointer, value)
                    }
                    _ => (pointer, value),
                };
                if !js_calendar_event.patch_jptr(pointer.iter(), value) {
                    return Err(if target.write == EventWrite::Update {
                        SetError::invalid_patch()
                    } else {
                        SetError::invalid_properties()
                    }
                    .with_property(JSCalendarProperty::Pointer(pointer))
                    .with_description("Patch operation failed."));
                }
            }
            (JSCalendarProperty::Id, value) => {
                if !target
                    .id
                    .is_some_and(|expected| crate::matches_id(&value, expected))
                {
                    return Err(immutable_property(JSCalendarProperty::Id));
                }
            }
            (JSCalendarProperty::IsOrigin, value) => {
                if !value.is_null()
                    && !matches!(
                        (value.as_bool(), target.is_origin),
                        (Some(value), Some(is_origin)) if value == is_origin
                    )
                {
                    return Err(immutable_property(JSCalendarProperty::IsOrigin));
                }
            }
            (property @ (JSCalendarProperty::BaseEventId | JSCalendarProperty::Method), value) => {
                if !value.is_null() {
                    return Err(immutable_property(property));
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
            (property, value) => {
                match &property {
                    JSCalendarProperty::Start => {
                        has_start = true;
                    }
                    JSCalendarProperty::Duration => {
                        has_duration = true;
                    }
                    JSCalendarProperty::RecurrenceOverrides => {
                        has_recurrence_changes = true;
                        match &value {
                            Value::Object(overrides) => overrides
                                .values()
                                .try_for_each(OverridePatch::validate_override_patch)?,
                            Value::Null => {}
                            _ => {
                                return Err(SetError::invalid_properties()
                                    .with_property(JSCalendarProperty::RecurrenceOverrides)
                                    .with_description("Invalid value."));
                            }
                        }
                    }
                    JSCalendarProperty::RecurrenceId | JSCalendarProperty::RecurrenceRule => {
                        has_recurrence_changes = true;
                    }
                    _ => {}
                }

                if let Value::Object(entries) = js_calendar_event {
                    entries.insert(property, value);
                }
            }
        }
    }

    let Value::Object(entries) = js_calendar_event else {
        return Err(SetError::invalid_properties()
            .with_description("Failed to convert calendar event to JSCalendar."));
    };

    if has_recurrence_changes
        && entries
            .get(&Key::Property(JSCalendarProperty::RecurrenceId))
            .is_some_and(|value| !value.is_null())
    {
        let recurrence_rule = entries
            .get(&Key::Property(JSCalendarProperty::RecurrenceRule))
            .is_some_and(|value| !value.is_null());
        let recurrence_overrides = entries
            .get(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
            .is_some_and(|value| {
                value
                    .as_object()
                    .is_some_and(|overrides| !overrides.is_empty())
            });
        if recurrence_rule || recurrence_overrides {
            return Err(SetError::invalid_properties()
                .with_properties([
                    JSCalendarProperty::RecurrenceId,
                    if recurrence_rule {
                        JSCalendarProperty::RecurrenceRule
                    } else {
                        JSCalendarProperty::RecurrenceOverrides
                    },
                ])
                .with_description(
                    "recurrenceId cannot be set together with recurrenceRule or recurrenceOverrides.",
                ));
        }
    }

    // Validate UTC start/end
    if utc_start.is_some() && has_start {
        return Err(SetError::invalid_properties()
            .with_properties([JSCalendarProperty::UtcStart, JSCalendarProperty::Start])
            .with_description("utcStart cannot be set together with start."));
    }
    if utc_end.is_some() && has_duration {
        return Err(SetError::invalid_properties()
            .with_properties([JSCalendarProperty::UtcEnd, JSCalendarProperty::Duration])
            .with_description("utcEnd cannot be set together with duration."));
    }
    if utc_start.is_some() || utc_end.is_some() {
        let tz = match entries
            .get(&Key::Property(JSCalendarProperty::TimeZone))
            .and_then(|v| v.as_str())
            .and_then(|tz| Tz::from_str(tz.as_ref()).ok())
        {
            Some(tz) => tz,
            None => {
                let tz = calendars_time_zone(cache, personal_id, &event.names);
                entries.insert(
                    Key::Property(JSCalendarProperty::TimeZone),
                    Value::Str(tz.name().unwrap_or(Cow::Borrowed("Etc/UTC"))),
                );
                tz
            }
        };

        if let Some(start) = utc_start {
            let local_start = DateTime::from_timestamp(start, 0)
                .map(|dt| dt.with_timezone(&tz).naive_local().and_utc().timestamp())
                .ok_or_else(|| {
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::UtcStart)
                        .with_description("Invalid utcStart value.")
                })?;
            entries.insert(
                Key::Property(JSCalendarProperty::Start),
                Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                    local_start,
                    true,
                ))),
            );
        }

        if let Some(end) = utc_end {
            let start = match utc_start {
                Some(start) => start,
                None => entries
                    .get(&Key::Property(JSCalendarProperty::Start))
                    .and_then(|v| v.as_element())
                    .and_then(|v| match v {
                        JSCalendarValue::DateTime(start) => resolve_local(tz, start.timestamp),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        SetError::invalid_properties()
                            .with_property(JSCalendarProperty::UtcEnd)
                            .with_description("utcEnd requires the event to have a start.")
                    })?,
            };
            if end < start {
                return Err(SetError::invalid_properties()
                    .with_properties([JSCalendarProperty::UtcStart, JSCalendarProperty::UtcEnd])
                    .with_description("utcEnd cannot be before the start of the event."));
            }
            entries.insert(
                Key::Property(JSCalendarProperty::Duration),
                Value::Element(JSCalendarValue::Duration(ICalendarDuration::from_seconds(
                    end - start,
                ))),
            );
        }
    }

    // Make sure the calendar_event belongs to at least one calendar
    if event.names.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::CalendarIds)
            .with_description("Event has to belong to at least one calendar."));
    }

    Ok(use_default_alerts != previous_use_default_alerts)
}

fn calendars_time_zone(cache: &GroupwareResources, personal_id: u32, names: &[DavName]) -> Tz {
    let mut time_zones = names.iter().map(|name| {
        cache
            .container_resource_by_id(name.parent_id)
            .and_then(|resource| {
                resource
                    .calendar_preferences(personal_id)
                    .map(|preferences| preferences.tz)
            })
    });
    let first = time_zones.next().flatten();
    first
        .filter(|tz| time_zones.all(|other| other == Some(*tz)))
        .unwrap_or(Tz::UTC)
}

struct EventUpdates<'x> {
    pending: Vec<EventUpdate<'x>>,
    failed: Vec<u32>,
}

struct EventUpdate<'x> {
    document_id: u32,
    ops: EventOps<'x>,
}

enum EventOps<'x> {
    Base { id: Id, patch: EventValue<'x> },
    Instances(Vec<InstanceOp<'x>>),
}

enum EventOp<'x> {
    Base { id: Id, patch: EventValue<'x> },
    Instance(InstanceOp<'x>),
}

struct InstanceOp<'x> {
    id: Id,
    recurrence_key: RecurrenceKey,
    target: Option<InstanceTarget>,
    action: InstanceAction<'x>,
}

enum InstanceAction<'x> {
    Update {
        patch: EventValue<'x>,
        server_set: Option<InstanceServerSet>,
    },
    Destroy,
}

struct InstanceServerSet {
    recurrence_id: i64,
    client: TrackedValues,
    before: TrackedValues,
    blob_properties: BlobProperties,
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

trait AlertAcknowledgement {
    fn acknowledged_alert_pointer(
        &self,
        pointer: &JsonPointer<JSCalendarProperty<Id>>,
    ) -> Option<JsonPointer<JSCalendarProperty<Id>>>;

    fn overrides_alerts(&self, recurrence_id: &Key<'_, JSCalendarProperty<Id>>) -> Option<bool>;

    fn into_acknowledged(self) -> Self;
}

impl AlertAcknowledgement for Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>> {
    fn acknowledged_alert_pointer(
        &self,
        pointer: &JsonPointer<JSCalendarProperty<Id>>,
    ) -> Option<JsonPointer<JSCalendarProperty<Id>>> {
        match pointer.as_slice() {
            [
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::RecurrenceOverrides)),
                JsonPointerItem::Key(recurrence_id),
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::Pointer(alert_pointer))),
            ] if alert_pointer.is_acknowledgement()
                && matches!(
                    recurrence_id,
                    Key::Property(JSCalendarProperty::DateTime(_))
                )
                && self.overrides_alerts(recurrence_id) != Some(true) =>
            {
                Some(alert_pointer.clone())
            }
            _ => None,
        }
    }

    fn overrides_alerts(&self, recurrence_id: &Key<'_, JSCalendarProperty<Id>>) -> Option<bool> {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
            .and_then(|overrides| overrides.as_object_and_get(recurrence_id))
            .and_then(Value::as_object)
            .map(|instance| {
                instance.keys().any(|property| match property {
                    Key::Property(JSCalendarProperty::Alerts) => true,
                    Key::Property(JSCalendarProperty::Pointer(pointer)) => matches!(
                        pointer.first(),
                        Some(JsonPointerItem::Key(Key::Property(
                            JSCalendarProperty::Alerts
                        )))
                    ),
                    _ => false,
                })
            })
    }

    fn into_acknowledged(self) -> Self {
        if let Value::Str(text) = &self
            && let Some(acknowledged) = <JSCalendarValue<Id, BlobId> as Element>::try_parse::<
                JSCalendarProperty<Id>,
            >(
                &Key::Property(JSCalendarProperty::Acknowledged), text
            )
        {
            Value::Element(acknowledged)
        } else {
            self
        }
    }
}

trait ComponentSequences {
    fn has_same_sequences(&self, other: &ICalendar) -> bool;
}

impl ComponentSequences for ICalendar {
    fn has_same_sequences(&self, other: &ICalendar) -> bool {
        let sequence = |component: &ICalendarComponent| {
            component
                .property(&ICalendarProperty::Sequence)
                .and_then(|entry| entry.values.first())
                .and_then(ICalendarValue::as_integer)
        };
        self.scheduling_components()
            .map(sequence)
            .eq(other.scheduling_components().map(sequence))
    }
}

trait AcknowledgementPointer {
    fn is_acknowledgement(&self) -> bool;
}

impl AcknowledgementPointer for JsonPointer<JSCalendarProperty<Id>> {
    fn is_acknowledgement(&self) -> bool {
        matches!(
            self.as_slice(),
            [
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::Alerts)),
                JsonPointerItem::Key(_),
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::Acknowledged)),
            ]
        )
    }
}

impl<'x> EventUpdates<'x> {
    fn with_capacity(capacity: usize) -> Self {
        EventUpdates {
            pending: Vec::with_capacity(capacity),
            failed: Vec::new(),
        }
    }

    fn push(
        &mut self,
        has_synthetic_ids: bool,
        op: EventOp<'x>,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
    ) {
        let document_id = op.id().document_id();
        if self.failed.contains(&document_id) {
            op.fail(response, mixed_base_and_instances());
            return;
        }
        let index = has_synthetic_ids
            .then(|| {
                self.pending
                    .iter()
                    .position(|update| update.document_id == document_id)
            })
            .flatten();
        let Some(index) = index else {
            self.pending.push(EventUpdate {
                document_id,
                ops: op.into_ops(),
            });
            return;
        };

        let is_base_op = matches!(op, EventOp::Base { .. });
        if matches!(self.pending[index].ops, EventOps::Base { .. }) != is_base_op {
            self.failed.push(document_id);
            self.pending
                .remove(index)
                .fail(response, mixed_base_and_instances());
            op.fail(response, mixed_base_and_instances());
        } else if is_base_op {
            response.not_updated.append(
                op.id(),
                SetError::invalid_properties()
                    .with_property(JSCalendarProperty::Id)
                    .with_description("Duplicate event id."),
            );
        } else if let (EventOps::Instances(instances), EventOp::Instance(instance)) =
            (&mut self.pending[index].ops, op)
        {
            instances.push(instance);
        }
    }
}

impl<'x> EventUpdate<'x> {
    fn base_id(&self) -> Option<Id> {
        match &self.ops {
            EventOps::Base { id, .. } => Some(*id),
            EventOps::Instances(_) => None,
        }
    }

    fn base_patch(&self) -> Option<&EventValue<'x>> {
        match &self.ops {
            EventOps::Base { patch, .. } => Some(patch),
            EventOps::Instances(_) => None,
        }
    }

    fn take_base_patch(&mut self) -> EventValue<'x> {
        match &mut self.ops {
            EventOps::Base { patch, .. } => std::mem::take(patch),
            EventOps::Instances(_) => EventValue::Null,
        }
    }

    fn has_instances(&self) -> bool {
        matches!(&self.ops, EventOps::Instances(instances) if !instances.is_empty())
    }

    fn patches_calendar_ids(&self) -> bool {
        let EventOps::Base { patch, .. } = &self.ops else {
            return false;
        };
        patch.as_object().is_some_and(|patch| {
            patch.keys().any(|key| match key {
                Key::Property(JSCalendarProperty::CalendarIds) => true,
                Key::Property(JSCalendarProperty::Pointer(pointer)) => matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(
                        JSCalendarProperty::CalendarIds
                    )))
                ),
                _ => false,
            })
        })
    }

    fn per_user_patch_changes(&self) -> Option<EventChanges> {
        match &self.ops {
            EventOps::Base { patch, .. } => EventChanges::from_per_user_patch(patch),
            EventOps::Instances(instances) => {
                let mut changes = EventChanges::default();
                for instance in instances {
                    let InstanceAction::Update { patch, .. } = &instance.action else {
                        return None;
                    };
                    if !EventChanges::from_per_user_patch(patch)?.is_empty() {
                        changes.insert_per_user();
                    }
                }
                Some(changes)
            }
        }
    }

    fn instances_mut(&mut self) -> &mut [InstanceOp<'x>] {
        match &mut self.ops {
            EventOps::Instances(instances) => instances.as_mut_slice(),
            EventOps::Base { .. } => &mut [],
        }
    }

    fn track_instance_values(
        &mut self,
        previous_event: &ICalendar,
        is_stored_blob_id: impl Fn(&BlobId) -> bool,
    ) {
        for instance in self.instances_mut() {
            let Some(recurrence_id) = instance.target.as_ref().map(|target| target.recurrence_id)
            else {
                continue;
            };
            if let InstanceAction::Update { patch, server_set } = &mut instance.action {
                *server_set = Some(InstanceServerSet {
                    recurrence_id,
                    client: TrackedValues::from_patch(patch),
                    before: TrackedValues::default()
                        .with_component(previous_event.instance_component(recurrence_id)),
                    blob_properties: BlobProperties::from_patch(patch, &is_stored_blob_id),
                });
            }
        }
    }

    fn fail(
        &self,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
        err: SetError<JSCalendarProperty<Id>>,
    ) {
        match &self.ops {
            EventOps::Base { id, .. } => response.not_updated.append(*id, err),
            EventOps::Instances(instances) => {
                for instance in instances {
                    instance.fail(response, err.clone());
                }
            }
        }
    }

    fn succeed(&self, response: &mut SetResponse<calendar_event::CalendarEvent>) {
        match &self.ops {
            EventOps::Base { id, .. } => response.updated.append(*id, None),
            EventOps::Instances(instances) => {
                for instance in instances {
                    match instance.action {
                        InstanceAction::Destroy => response.destroyed.push(instance.id),
                        InstanceAction::Update { .. } => response.updated.append(instance.id, None),
                    }
                }
            }
        }
    }

    fn plan_instances(
        &mut self,
        data: &CalendarEventData,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
    ) -> InstancePlan {
        let EventOps::Instances(instances) = &mut self.ops else {
            return InstancePlan::BaseEvent;
        };
        let mut recurrence_keys = instances
            .iter()
            .map(|instance| instance.recurrence_key)
            .collect::<AHashSet<_>>();
        let expansions = data
            .expand_from_ids(&mut recurrence_keys, Tz::UTC)
            .unwrap_or_default();
        let uid = data.event.object_uid();
        let mut has_base_event = false;

        instances.retain_mut(|instance| {
            let mut matches = expansions
                .iter()
                .filter(|expansion| expansion.recurrence_key() == Some(instance.recurrence_key));
            let resolution = match (matches.next(), matches.next()) {
                (Some(expansion), None) => InstanceTarget::resolve(expansion, data, uid),
                _ => InstanceResolution::NotFound,
            };

            match resolution {
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
            if instances.len() > 1 {
                self.fail(response, mixed_base_and_instances());
                return InstancePlan::Nothing;
            }

            let Some(instance) = instances.pop() else {
                return InstancePlan::Nothing;
            };
            return match instance.action {
                InstanceAction::Destroy => InstancePlan::DestroyEvent(instance.id),
                InstanceAction::Update { patch, .. } => {
                    self.ops = EventOps::Base {
                        id: instance.id,
                        patch,
                    };
                    InstancePlan::BaseEvent
                }
            };
        }

        if instances.is_empty() {
            InstancePlan::Nothing
        } else {
            InstancePlan::Instances
        }
    }

    fn apply_instances(
        &mut self,
        js_calendar_group: &mut JSCalendar<'x, Id, BlobId>,
        metadata: &InstanceMetadata<'_>,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
    ) -> bool {
        let EventOps::Instances(instances) = &mut self.ops else {
            return false;
        };
        let Some(js_calendar_event) = js_calendar_group.first_entry_mut() else {
            for instance in instances.iter() {
                instance.fail(
                    response,
                    SetError::invalid_properties()
                        .with_description("Failed to convert calendar event to JSCalendar."),
                );
            }
            return false;
        };
        let tz = js_calendar_event
            .as_object_and_get(&Key::Property(JSCalendarProperty::TimeZone))
            .and_then(|tz| tz.as_str())
            .and_then(|tz| Tz::from_str(tz.as_ref()).ok())
            .unwrap_or(Tz::UTC);
        let base_duration = js_calendar_event
            .as_object_and_get(&Key::Property(JSCalendarProperty::Duration))
            .and_then(Value::as_element)
            .and_then(|duration| match duration {
                JSCalendarValue::Duration(duration) => Some(duration.as_seconds()),
                _ => None,
            })
            .unwrap_or_default();

        instances.retain_mut(|instance| {
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
                base_duration,
                metadata,
                instance.take_patch(),
                instance.id,
            ) {
                Ok(_) => true,
                Err(err) => {
                    instance.fail(response, err);
                    false
                }
            }
        });

        !instances.is_empty()
    }
}

impl<'x> EventOp<'x> {
    fn id(&self) -> Id {
        match self {
            EventOp::Base { id, .. } => *id,
            EventOp::Instance(instance) => instance.id,
        }
    }

    fn into_ops(self) -> EventOps<'x> {
        match self {
            EventOp::Base { id, patch } => EventOps::Base { id, patch },
            EventOp::Instance(instance) => EventOps::Instances(vec![instance]),
        }
    }

    fn fail(
        &self,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
        err: SetError<JSCalendarProperty<Id>>,
    ) {
        match self {
            EventOp::Base { id, .. } => response.not_updated.append(*id, err),
            EventOp::Instance(instance) => instance.fail(response, err),
        }
    }
}

impl<'x> InstanceOp<'x> {
    fn fail(
        &self,
        response: &mut SetResponse<calendar_event::CalendarEvent>,
        err: SetError<JSCalendarProperty<Id>>,
    ) {
        match self.action {
            InstanceAction::Destroy => response.not_destroyed.append(self.id, err),
            InstanceAction::Update { .. } => response.not_updated.append(self.id, err),
        }
    }

    fn take_patch(&mut self) -> Option<EventValue<'x>> {
        match &mut self.action {
            InstanceAction::Update { patch, .. } => Some(std::mem::take(patch)),
            InstanceAction::Destroy => None,
        }
    }

    fn take_server_set(&mut self) -> Option<InstanceServerSet> {
        match &mut self.action {
            InstanceAction::Update { server_set, .. } => server_set.take(),
            InstanceAction::Destroy => None,
        }
    }
}

fn instance_blob_values(
    data: &CalendarEventData,
    recurrence_key: RecurrenceKey,
    blob_properties: &BlobProperties,
    account_id: u32,
    document_id: u32,
) -> ServerSetValues {
    let mut recurrence_keys = AHashSet::from_iter([recurrence_key]);
    let Some(ical) = data
        .expand_from_ids(&mut recurrence_keys, Tz::Floating)
        .unwrap_or_default()
        .iter()
        .find(|expansion| expansion.recurrence_key() == Some(recurrence_key))
        .and_then(|expansion| data.instance(expansion, None, InstanceBinaries::Keep))
    else {
        return ServerSetValues::new();
    };

    ImportedValues {
        participants: false,
        blob_properties,
        every_blob_property: false,
    }
    .values(&ical, account_id, document_id)
    .collect()
}

fn mixed_base_and_instances() -> SetError<JSCalendarProperty<Id>> {
    SetError::invalid_properties()
        .with_property(JSCalendarProperty::Id)
        .with_description(concat!(
            "A base event and its instances cannot be modified ",
            "in the same request."
        ))
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

        if is_override && expansion.own_recurrence_id.is_none() {
            return if data
                .component_tz(expansion.comp_id)
                .and_then(|component_tz| component.recurrence_id(component_tz))
                .is_none()
            {
                InstanceResolution::NotFound
            } else {
                InstanceResolution::ThisAndFuture
            };
        }
        let recurrence_id = expansion.recurrence_id();

        InstanceResolution::Instance(InstanceTarget {
            is_override,
            recurrence_id: recurrence_id.utc,
            recurrence_id_naive: recurrence_id.naive,
            start_naive: expansion.start_naive,
            duration: expansion.end - expansion.start,
        })
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
        base_duration: i64,
        metadata: &InstanceMetadata<'_>,
        patch: Option<Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>>,
        id: Id,
    ) -> Result<(), SetError<JSCalendarProperty<Id>>> {
        let invalid_event =
            || SetError::invalid_properties().with_description("Failed to parse stored event.");
        let key_timestamp = key.timestamp;
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

        let redirects_acknowledgements = js_calendar_event.overrides_alerts(&key) != Some(true);
        let view = InstanceView {
            event: js_calendar_event.as_object().ok_or_else(invalid_event)?,
            metadata,
            id,
            recurrence_ids: [self.recurrence_id_naive, key_timestamp],
        };
        let mut overrides = Vec::with_capacity(patch.len());
        let mut acknowledgements = Vec::new();
        for (property, value) in patch.into_vec() {
            if !view.is_override_key(&property, &value)? {
                continue;
            }
            match property {
                Key::Property(JSCalendarProperty::Pointer(pointer))
                    if redirects_acknowledgements && pointer.is_acknowledgement() =>
                {
                    acknowledgements.push((pointer, value));
                }
                property => overrides.push((property, value)),
            }
        }

        for (pointer, value) in acknowledgements {
            if !js_calendar_event.patch_jptr(pointer.iter(), value) {
                return Err(SetError::invalid_patch()
                    .with_property(JSCalendarProperty::Pointer(pointer))
                    .with_description("Patch operation failed."));
            }
        }
        if overrides.is_empty() {
            return Ok(());
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

        if self.start_naive != key_timestamp
            && !instance.contains_key(&Key::Property(JSCalendarProperty::Start))
        {
            instance.insert(
                Key::Property(JSCalendarProperty::Start),
                Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                    self.start_naive,
                    true,
                ))),
            );
        }
        if self.duration != base_duration
            && !instance.contains_key(&Key::Property(JSCalendarProperty::Duration))
        {
            instance.insert(
                Key::Property(JSCalendarProperty::Duration),
                Value::Element(JSCalendarValue::Duration(ICalendarDuration::from_seconds(
                    self.duration,
                ))),
            );
        }

        for (property, value) in overrides {
            instance.insert(property, value);
        }

        Ok(())
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
