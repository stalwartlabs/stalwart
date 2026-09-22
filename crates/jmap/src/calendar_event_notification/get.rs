/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::embedded::import_error;
use crate::calendar_event_notification::{NotificationTypeFlags, patch::JSCalendarPatch};
use crate::changes::state::JmapCacheState;
use calcard::{
    icalendar::{ArchivedICalendar, ArchivedICalendarProperty, ICalendar},
    jscalendar::{JSCalendar, import::ImportOptions},
};
use common::{Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ArchivedChangedBy, CalendarEventNotification, CalendarEventNotificationContent,
        EVENT_NOTIFICATION_IS_CHANGE, EVENT_NOTIFICATION_IS_DRAFT,
        notification::CalendarNotificationViewers,
    },
};
use jmap_proto::{
    method::get::GetRequest,
    object::calendar_event_notification::{
        self, CalendarEventNotificationGetResponse, CalendarEventNotificationObject,
        CalendarEventNotificationProperty, CalendarEventNotificationType, PersonObject,
    },
    types::date::UTCDate,
};
use store::{
    ValueKey,
    ahash::AHashMap,
    write::{Archive, ArchiveBytes, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{
    blob::BlobId,
    collection::{Collection, SyncCollection},
    field::CalendarNotificationField,
    id::Id,
};

pub trait CalendarEventNotificationGet: Sync + Send {
    fn calendar_event_notification_get(
        &self,
        request: GetRequest<calendar_event_notification::CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<CalendarEventNotificationGetResponse>> + Send;
}

impl CalendarEventNotificationGet for Server {
    async fn calendar_event_notification_get(
        &self,
        mut request: GetRequest<calendar_event_notification::CalendarEventNotification>,
        access_token: &AccessToken,
    ) -> trc::Result<CalendarEventNotificationGetResponse> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            CalendarEventNotificationProperty::Id,
            CalendarEventNotificationProperty::Created,
            CalendarEventNotificationProperty::ChangedBy,
            CalendarEventNotificationProperty::Comment,
            CalendarEventNotificationProperty::Type,
            CalendarEventNotificationProperty::CalendarEventId,
            CalendarEventNotificationProperty::IsDraft,
            CalendarEventNotificationProperty::Event,
            CalendarEventNotificationProperty::EventPatch,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .caused_by(trc::location!())?;

        let viewer = self
            .notification_viewer(access_token, account_id)
            .await
            .caused_by(trc::location!())?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            viewer
                .visible_notifications(&cache)
                .into_iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = CalendarEventNotificationGetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        let mut changed_by_cache: AHashMap<u32, PersonObject> = AHashMap::new();
        let mut needs_meta = false;
        let mut needs_content = false;
        let mut wants_event = false;
        let mut wants_patch = false;
        for property in &properties {
            match property {
                CalendarEventNotificationProperty::Id
                | CalendarEventNotificationProperty::Created
                | CalendarEventNotificationProperty::CalendarEventId => (),
                CalendarEventNotificationProperty::Type
                | CalendarEventNotificationProperty::IsDraft
                | CalendarEventNotificationProperty::ChangedBy => {
                    needs_meta = true;
                }
                _ => {
                    needs_meta = true;
                    needs_content = true;
                    wants_event |= *property == CalendarEventNotificationProperty::Event;
                    wants_patch |= *property == CalendarEventNotificationProperty::EventPatch;
                }
            }
        }

        for id in ids {
            // Obtain the event object
            let document_id = id.document_id();
            let Some(resource) = cache.item_by_id(document_id).filter(|resource| {
                resource
                    .notification()
                    .is_some_and(|notification| viewer.can_view(&notification))
            }) else {
                response.push_not_found(id);
                continue;
            };

            let _event;
            let event = if needs_meta {
                _event = match self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                        account_id,
                        Collection::CalendarEventNotification,
                        document_id,
                    ))
                    .await?
                {
                    Some(event) => event,
                    None => {
                        response.push_not_found(id);
                        continue;
                    }
                };
                Some(
                    _event
                        .unarchive::<CalendarEventNotification>()
                        .caused_by(trc::location!())?,
                )
            } else {
                None
            };

            let _content;
            let content = if needs_content {
                _content = match self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEventNotification,
                        document_id,
                        CalendarNotificationField::Content,
                    ))
                    .await?
                {
                    Some(content) => content,
                    None => {
                        response.push_not_found(id);
                        continue;
                    }
                };
                Some(
                    _content
                        .unarchive::<CalendarEventNotificationContent>()
                        .caused_by(trc::location!())?,
                )
            } else {
                None
            };
            let mut result = CalendarEventNotificationObject {
                id,
                ..Default::default()
            };
            for property in &properties {
                match property {
                    CalendarEventNotificationProperty::Id
                    | CalendarEventNotificationProperty::Event
                    | CalendarEventNotificationProperty::EventPatch => {}
                    CalendarEventNotificationProperty::Created => {
                        result.created = resource.created_at().map(UTCDate::from_timestamp).into();
                    }
                    CalendarEventNotificationProperty::CalendarEventId => {
                        result.calendar_event_id = resource
                            .event_id()
                            .filter(|id| *id != u32::MAX)
                            .map(Id::from)
                            .into();
                    }
                    CalendarEventNotificationProperty::ChangedBy => {
                        let changed_by = match event.map(|event| &event.changed_by) {
                            Some(ArchivedChangedBy::PrincipalId(id)) => {
                                let principal_id = id.to_native();
                                let changed_by = match changed_by_cache.get(&principal_id) {
                                    Some(changed_by) => changed_by.clone(),
                                    None => {
                                        let mut changed_by = PersonObject {
                                            principal_id: Some(principal_id.into()),
                                            ..Default::default()
                                        };
                                        if let Ok(account) = self.account_info(principal_id).await {
                                            changed_by.name = account
                                                .description()
                                                .unwrap_or(account.name())
                                                .to_string();
                                            changed_by.email = account.addresses().first().cloned();
                                            changed_by.calendar_address = changed_by
                                                .email
                                                .as_ref()
                                                .map(|email| format!("mailto:{email}"));
                                        }
                                        changed_by_cache.insert(principal_id, changed_by.clone());
                                        changed_by
                                    }
                                };
                                Some(changed_by)
                            }
                            Some(ArchivedChangedBy::CalendarAddress(email)) => Some(PersonObject {
                                name: email.to_string(),
                                email: Some(email.to_string()),
                                principal_id: None,
                                calendar_address: Some(format!("mailto:{email}")),
                            }),
                            None => None,
                        };
                        result.changed_by = changed_by.into();
                    }
                    CalendarEventNotificationProperty::Comment => {
                        result.comment = content
                            .and_then(|content| content.itip_message())
                            .and_then(|message| {
                                message
                                    .components
                                    .iter()
                                    .filter(|c| c.component_type.is_scheduling_object())
                                    .flat_map(|c| c.entries.iter())
                                    .find(|e| matches!(e.name, ArchivedICalendarProperty::Comment))
                                    .and_then(|e| e.values.first().and_then(|v| v.as_text()))
                            })
                            .map(|v| v.to_string())
                            .into();
                    }
                    CalendarEventNotificationProperty::Type => {
                        result.notification_type = event
                            .map(|event| {
                                CalendarEventNotificationType::from_flags(event.flags.to_native())
                            })
                            .into();
                    }
                    CalendarEventNotificationProperty::IsDraft => {
                        result.is_draft = event
                            .map(|event| event.flags & EVENT_NOTIFICATION_IS_DRAFT != 0)
                            .into();
                    }
                }
            }

            if wants_event || wants_patch {
                let (snapshot, patch) = match event.zip(content) {
                    Some((event, content)) => {
                        let is_change = event.flags.to_native() & EVENT_NOTIFICATION_IS_CHANGE != 0;
                        let snapshot = content.previous().or_else(|| content.current());
                        let snapshot = (wants_event || is_change)
                            .then_some(snapshot)
                            .flatten()
                            .map(to_jscalendar)
                            .transpose()?;
                        let patch = match (&snapshot, content.current()) {
                            (Some(previous), Some(current)) if wants_patch && is_change => {
                                Some(previous.patch_to(&to_jscalendar(current)?))
                            }
                            _ => None,
                        };
                        (snapshot, patch)
                    }
                    None => (None, None),
                };
                if wants_event {
                    result.event = snapshot.into();
                }
                if wants_patch {
                    result.event_patch = patch.into();
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }
}

fn to_jscalendar(ical: &ArchivedICalendar) -> trc::Result<JSCalendar<'static, Id, BlobId>> {
    rkyv_deserialize::<_, ICalendar>(ical)
        .caused_by(trc::location!())?
        .into_jscalendar_with::<Id, BlobId, _>(
            ImportOptions::new()
                .include_ical_components(false)
                .return_first(true),
        )
        .map_err(import_error)
}
