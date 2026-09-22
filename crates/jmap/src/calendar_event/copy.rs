/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    calendar_event::{
        CalendarSyntheticId, UidIndex,
        privacy::assert_privacy_access,
        server_set::{PendingBlobIds, ServerSetValues},
        set::{CalendarEventSet, CopiedEvent, EventSetContext, EventSource, too_many_events},
    },
    changes::state::JmapCacheState,
};
use calcard::{icalendar::ICalendar, jscalendar::JSCalendarProperty};
use common::{Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent, CalendarEventData, EVENT_SECRET, EventPreferences,
        alerts::DefaultAlertsResolver,
        identity::{CalendarAddresses, ParticipantIdentityAddresses},
        privacy::{EventPrivacy, EventViewer},
        storage::NotificationQuota,
        user::UserDataView,
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse, CopySourceId},
        set::SetRequest,
    },
    object::calendar_event,
    request::{
        Call, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
    types::state::State,
};
use jmap_tools::{Key, Value};
use registry::schema::enums::StorageQuota;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, Slot, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};
use utils::map::vec_map::VecMap;

pub trait JmapCalendarEventCopy: Sync + Send {
    fn calendar_event_copy<'x>(
        &self,
        request: CopyRequest<'x, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse<calendar_event::CalendarEvent>>> + Send;
}

impl JmapCalendarEventCopy for Server {
    async fn calendar_event_copy<'x>(
        &self,
        request: CopyRequest<'x, calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        _session: &HttpSessionData,
    ) -> trc::Result<CopyResponse<calendar_event::CalendarEvent>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let old_state = cache.assert_state(false, &request.if_in_state)?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
        };

        let from_cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        from_cache.assert_state(false, &request.if_from_in_state)?;
        let is_from_owner = access_token.is_member(from_account_id);
        let from_personal_id = access_token.personal_id(from_account_id, Collection::Calendar);
        let from_calendar_event_ids = if is_from_owner {
            from_cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            let mut shared_ids = from_cache.shared_items(access_token, [Acl::ReadItems], true);
            shared_ids -= from_cache.event_ids_with_flags(EVENT_SECRET);
            shared_ids
        };

        let is_shared = access_token.is_shared(account_id);
        let can_add_calendars =
            is_shared.then(|| cache.shared_containers(access_token, [Acl::AddItems], true));
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();
        let mut created_slots: Vec<(String, Slot, ServerSetValues)> = Vec::new();

        // Obtain account info
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let identities = if is_shared {
            self.account_identity_addresses(access_token.account_id())
                .await
                .caused_by(trc::location!())?
        } else {
            CalendarAddresses::default()
        };
        let mut creates = Vec::with_capacity(request.create.len());
        for (create_id, mut create) in request.create {
            let source_id = create.take_source_id(JSCalendarProperty::Id);
            creates.push((create_id, source_id, create));
        }
        let uid_index = UidIndex::new(
            &cache,
            creates.iter().filter_map(|(_, source_id, create)| {
                match create.as_object_and_get(&Key::Property(JSCalendarProperty::Uid)) {
                    Some(Value::Str(uid)) => Some(uid.as_ref()),
                    _ => source_id.as_ref().ok().and_then(|source_id| {
                        from_cache
                            .resources
                            .find(source_id.document_id(), false)
                            .and_then(|resource| resource.uid())
                    }),
                }
            }),
        );

        // Obtain quota
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let quota = self.object_quota_usage(&account, StorageQuota::MaxCalendarEvents, || {
            cache.resources.count(false)
        });

        // Prepare batch
        let mut batch = BatchBuilder::new();
        let mut context = EventSetContext {
            cache: &cache,
            access_token,
            account_id,
            account_info: &account_info,
            send_scheduling_messages: false,
            can_add_calendars: can_add_calendars.as_ref(),
            identities: &identities,
            uid_index,
            will_destroy: Vec::new(),
            default_alerts: DefaultAlertsResolver::with_resources(account_id, cache.clone()),
            notification_quota: NotificationQuota::default(),
        };

        'create: for (create_id, source_id, create) in creates {
            if !quota.has_room(created_slots.len()) {
                response.not_created.append(create_id, too_many_events());
                continue;
            }
            let source_id = match source_id {
                Ok(source_id) => source_id,
                Err(err) => {
                    response.not_created.append(create_id, err);
                    continue;
                }
            };

            let from_calendar_event_id = source_id.document_id();
            if !from_calendar_event_ids.contains(from_calendar_event_id) {
                response.not_created.append(
                    create_id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        source_id, response.from_account_id
                    )),
                );
                continue;
            }
            if source_id.is_synthetic() {
                response.not_created.append(
                    create_id,
                    SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Id)
                        .with_description(format!(
                            "Item {source_id} is a synthetic id and cannot be copied."
                        )),
                );
                continue;
            }

            let Some(flags) = from_cache
                .resources
                .find(from_calendar_event_id, false)
                .and_then(|resource| resource.event_flags())
            else {
                response.not_created.append(
                    create_id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        source_id, response.from_account_id
                    )),
                );
                continue;
            };
            if let Err(err) = assert_privacy_access(
                EventPrivacy::from_flags(flags),
                EventViewer::new(is_from_owner),
            ) {
                response.not_created.append(create_id, err);
                continue;
            }
            let Some(content) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    from_account_id,
                    Collection::CalendarEvent,
                    from_calendar_event_id,
                    CalendarEventField::Content,
                ))
                .await?
            else {
                response.not_created.append(
                    create_id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        source_id, response.from_account_id
                    )),
                );
                continue;
            };

            let content = content
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?;
            let preferences = content.preferences(from_personal_id);
            let use_default_alerts =
                preferences.is_some_and(|preferences| preferences.use_default_alerts());
            let event = if is_from_owner {
                rkyv_deserialize::<_, ICalendar>(&content.data.event)
            } else {
                preferences
                    .map(rkyv_deserialize::<_, EventPreferences>)
                    .transpose()
                    .and_then(|preferences| {
                        rkyv_deserialize::<_, CalendarEventData>(&content.data).map(|mut data| {
                            data.apply_user_data(preferences.as_ref(), UserDataView::Full);
                            data.event
                        })
                    })
            }
            .caused_by(trc::location!())?;
            let source = EventSource::Copy(CopiedEvent {
                event: event.into_jscalendar(),
                flags,
                use_default_alerts,
            });

            match self
                .create_calendar_event(&mut context, &mut batch, source, create)
                .await?
            {
                Ok((slot, server_set)) => {
                    created_slots.push((create_id, slot, server_set));

                    // Add to destroy list
                    if on_success_delete {
                        destroy_ids.push(MaybeInvalid::Value(source_id));
                    }
                }
                Err(err) => {
                    response.not_created.append(create_id, err);
                    continue 'create;
                }
            }
        }

        // Write changes
        if !batch.is_empty() {
            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;

            for (create_id, slot, mut server_set) in created_slots {
                let document_id = assigned_ids.slot(slot);
                server_set.resolve_document_id(document_id);
                response.created_with_properties(create_id, document_id, server_set);
            }

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::Calendar));
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::CalendarEvent, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::CalendarEvent(Box::new(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                }))),
            }
            .into();
        }

        Ok(response)
    }
}
