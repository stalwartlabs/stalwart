/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::JmapCacheState;
use calcard::{
    icalendar::{ArchivedICalendarProperty, ICalendar},
    jscalendar::import::ConversionOptions,
};
use common::{Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ArchivedChangedBy, CalendarEventNotification, CalendarEventNotificationContent,
        EVENT_NOTIFICATION_IS_CHANGE, EVENT_NOTIFICATION_IS_DRAFT,
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
            CalendarEventNotificationProperty::Type,
            CalendarEventNotificationProperty::ChangedBy,
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

        let ids = if let Some(ids) = ids {
            ids
        } else {
            cache
                .document_ids(false)
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

        let mut needs_meta = false;
        let mut needs_content = false;
        for property in &properties {
            match property {
                CalendarEventNotificationProperty::Id
                | CalendarEventNotificationProperty::Created
                | CalendarEventNotificationProperty::CalendarEventId => (),
                CalendarEventNotificationProperty::Comment
                | CalendarEventNotificationProperty::Event
                | CalendarEventNotificationProperty::EventPatch => {
                    needs_content = true;
                }
                CalendarEventNotificationProperty::Type => {
                    needs_meta = true;
                    needs_content = true;
                }
                _ => {
                    needs_meta = true;
                }
            }
        }

        for id in ids {
            // Obtain the event object
            let document_id = id.document_id();
            let Some(resource) = cache.item_by_id(document_id) else {
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
                    CalendarEventNotificationProperty::Id => {}
                    CalendarEventNotificationProperty::Created => {
                        result.created = resource.created_at().map(UTCDate::from_timestamp);
                    }
                    CalendarEventNotificationProperty::CalendarEventId => {
                        result.calendar_event_id = resource
                            .event_id()
                            .filter(|id| *id != u32::MAX)
                            .map(|id| id.into());
                    }
                    CalendarEventNotificationProperty::ChangedBy if let Some(event) = event => {
                        let mut changed_by = PersonObject::default();

                        match &event.changed_by {
                            ArchivedChangedBy::PrincipalId(id) => {
                                if let Ok(account) = self.account(id.to_native()).await {
                                    changed_by.name =
                                        account.description().unwrap_or(account.name()).to_string();
                                    changed_by.email = account.name().to_string().into();
                                }
                                changed_by.principal_id = Some(id.to_native().into());
                            }
                            ArchivedChangedBy::CalendarAddress(email) => {
                                changed_by.email = Some(email.to_string());
                                changed_by.calendar_address = Some(format!("mailto:{email}"));
                            }
                        }

                        result.changed_by = Some(changed_by);
                    }
                    CalendarEventNotificationProperty::Comment if let Some(content) = content => {
                        result.comment = content
                            .event
                            .components
                            .iter()
                            .filter(|c| c.component_type.is_scheduling_object())
                            .flat_map(|c| c.entries.iter())
                            .find(|e| matches!(e.name, ArchivedICalendarProperty::Comment))
                            .and_then(|e| e.values.first().and_then(|v| v.as_text()))
                            .map(|v| v.to_string());
                    }
                    CalendarEventNotificationProperty::Type
                        if let (Some(event), Some(content)) = (event, content) =>
                    {
                        result.notification_type =
                            Some(if event.flags & EVENT_NOTIFICATION_IS_CHANGE != 0 {
                                CalendarEventNotificationType::Updated
                            } else if !content.event.components.is_empty() {
                                CalendarEventNotificationType::Created
                            } else {
                                CalendarEventNotificationType::Destroyed
                            });
                    }
                    CalendarEventNotificationProperty::IsDraft if let Some(event) = event => {
                        result.is_draft = Some(event.flags & EVENT_NOTIFICATION_IS_DRAFT != 0);
                    }
                    CalendarEventNotificationProperty::Event
                        if let (Some(event), Some(content)) = (event, content) =>
                    {
                        if event.flags & EVENT_NOTIFICATION_IS_CHANGE == 0 && result.event.is_none()
                        {
                            let js_event = rkyv_deserialize::<_, ICalendar>(&content.event)
                                .caused_by(trc::location!())?
                                .into_jscalendar_with_opt::<Id, BlobId>(
                                    ConversionOptions::default()
                                        .include_ical_components(false)
                                        .return_first(true),
                                );
                            result.event = js_event.into();
                        }
                    }
                    CalendarEventNotificationProperty::EventPatch
                        if let (Some(event), Some(content)) = (event, content)
                            && event.flags & EVENT_NOTIFICATION_IS_CHANGE != 0
                            && result.event_patch.is_none() =>
                    {
                        let js_event = rkyv_deserialize::<_, ICalendar>(&content.event)
                            .caused_by(trc::location!())?
                            .into_jscalendar_with_opt::<Id, BlobId>(
                                ConversionOptions::default()
                                    .include_ical_components(false)
                                    .return_first(true),
                            );
                        result.event_patch = js_event.into();
                    }
                    _ => {}
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }
}
