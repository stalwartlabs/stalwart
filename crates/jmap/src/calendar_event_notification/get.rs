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
        ArchivedChangedBy, CalendarEventNotification, EVENT_NOTIFICATION_IS_CHANGE,
        EVENT_NOTIFICATION_IS_DRAFT,
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
use store::{ValueKey, write::{AlignedBytes, Archive, serialize::rkyv_deserialize}};
use trc::AddContext;
use types::{
    blob::BlobId,
    collection::{Collection, SyncCollection},
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
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            CalendarEventNotificationProperty::Id,
            CalendarEventNotificationProperty::Created,
            CalendarEventNotificationProperty::Type,
            CalendarEventNotificationProperty::ChangedBy,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(
                access_token,
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
            not_found: vec![],
        };

        for id in ids {
            // Obtain the event object
            let document_id = id.document_id();
            let _event = if let Some(event) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEventNotification,
                    document_id,
                ))
                .await?
            {
                event
            } else {
                response.not_found.push(id);
                continue;
            };
            let event = _event
                .unarchive::<CalendarEventNotification>()
                .caused_by(trc::location!())?;
            let mut result = CalendarEventNotificationObject {
                id,
                ..Default::default()
            };
            for property in &properties {
                match property {
                    CalendarEventNotificationProperty::Id => {}
                    CalendarEventNotificationProperty::Created => {
                        result.created = Some(UTCDate::from_timestamp(event.created.to_native()));
                    }
                    CalendarEventNotificationProperty::CalendarEventId => {
                        result.calendar_event_id =
                            event.event_id.as_ref().map(|id| id.to_native().into());
                    }
                    CalendarEventNotificationProperty::ChangedBy => {
                        let mut changed_by = PersonObject::default();

                        match &event.changed_by {
                            ArchivedChangedBy::PrincipalId(id) => {
                                if let Ok(token) = self.get_access_token(id.to_native()).await {
                                    changed_by.name = token.description.clone().unwrap_or_default();
                                    changed_by.email = token.emails.first().cloned();
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
                    CalendarEventNotificationProperty::Comment => {
                        result.comment = event
                            .event
                            .components
                            .iter()
                            .filter(|c| c.component_type.is_scheduling_object())
                            .flat_map(|c| c.entries.iter())
                            .find(|e| matches!(e.name, ArchivedICalendarProperty::Comment))
                            .and_then(|e| e.values.first().and_then(|v| v.as_text()))
                            .map(|v| v.to_string());
                    }
                    CalendarEventNotificationProperty::Type => {
                        result.notification_type =
                            Some(if event.flags & EVENT_NOTIFICATION_IS_CHANGE != 0 {
                                CalendarEventNotificationType::Updated
                            } else if !event.event.components.is_empty() {
                                CalendarEventNotificationType::Created
                            } else {
                                CalendarEventNotificationType::Destroyed
                            });
                    }
                    CalendarEventNotificationProperty::IsDraft => {
                        result.is_draft = Some(event.flags & EVENT_NOTIFICATION_IS_DRAFT != 0);
                    }
                    CalendarEventNotificationProperty::Event => {
                        if event.flags & EVENT_NOTIFICATION_IS_CHANGE == 0 && result.event.is_none()
                        {
                            let js_event = rkyv_deserialize::<_, ICalendar>(&event.event)
                                .caused_by(trc::location!())?
                                .into_jscalendar_with_opt::<Id, BlobId>(
                                    ConversionOptions::default()
                                        .include_ical_components(false)
                                        .return_first(true),
                                );
                            result.event = js_event.into();
                        }
                    }
                    CalendarEventNotificationProperty::EventPatch => {
                        if event.flags & EVENT_NOTIFICATION_IS_CHANGE != 0
                            && result.event_patch.is_none()
                        {
                            let js_event = rkyv_deserialize::<_, ICalendar>(&event.event)
                                .caused_by(trc::location!())?
                                .into_jscalendar_with_opt::<Id, BlobId>(
                                    ConversionOptions::default()
                                        .include_ical_components(false)
                                        .return_first(true),
                                );
                            result.event_patch = js_event.into();
                        }
                    }
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }
}
