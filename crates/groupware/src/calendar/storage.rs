/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, Calendar, CalendarEvent, CalendarPreferences,
    alarm::CalendarAlarm,
};
use crate::{
    DavResourceName, DestroyArchive, RFC_3986,
    calendar::{
        ArchivedCalendarEventNotification, CalendarEventNotification, alarm::CalendarAlarmType,
    },
    scheduling::{ItipMessages, event_cancel::itip_cancel},
};
use calcard::common::timezone::Tz;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use store::{
    IterateParams, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, Archive, BatchBuilder, IndexPropertyClass, TaskEpoch, TaskQueueClass,
        ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, VanishedCollection},
    field::CalendarNotificationField,
};

pub trait ItipAutoExpunge: Sync + Send {
    fn itip_ids(&self, account_id: u32) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn itip_auto_expunge(
        &self,
        account_id: u32,
        hold_period: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl ItipAutoExpunge for Server {
    async fn itip_ids(&self, account_id: u32) -> trc::Result<RoaringBitmap> {
        let mut document_ids = RoaringBitmap::new();
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: CalendarNotificationField::CreatedToId.into(),
                            value: 0,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: CalendarNotificationField::CreatedToId.into(),
                            value: u64::MAX,
                        }),
                    },
                )
                .no_values()
                .ascending(),
                |key, _| {
                    document_ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| document_ids)
    }

    async fn itip_auto_expunge(&self, account_id: u32, hold_period: u64) -> trc::Result<()> {
        let mut destroy_ids = RoaringBitmap::new();
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: CalendarNotificationField::CreatedToId.into(),
                            value: 0,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: CalendarNotificationField::CreatedToId.into(),
                            value: now().saturating_sub(hold_period),
                        }),
                    },
                )
                .no_values()
                .ascending(),
                |key, _| {
                    destroy_ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::AutoExpunge),
            AccountId = account_id,
            Collection = Collection::CalendarEventNotification.as_str(),
            Total = destroy_ids.len(),
        );

        // Tombstone messages
        let mut batch = BatchBuilder::new();
        let access_token = self
            .get_access_token(account_id)
            .await
            .caused_by(trc::location!())?;

        for document_id in destroy_ids {
            // Fetch event
            if let Some(event_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEventNotification,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let event = event_
                    .to_unarchived::<CalendarEventNotification>()
                    .caused_by(trc::location!())?;
                DestroyArchive(event)
                    .delete(&access_token, account_id, document_id, &mut batch)
                    .caused_by(trc::location!())?;
            }
        }

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(())
    }
}

impl CalendarEvent {
    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        event: Archive<&ArchivedCalendarEvent>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        let mut new_event = self;

        // Build event
        new_event.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(event)
                    .with_changes(new_event)
                    .with_access_token(access_token),
            )
            .map(|b| b.commit_point())
    }

    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        next_alarm: Option<CalendarAlarm>,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build event
        let mut event = self;
        let now = now() as i64;
        event.modified = now;
        event.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(event)
                    .with_access_token(access_token),
            )
            .map(|batch| {
                if let Some(next_alarm) = next_alarm {
                    next_alarm.write_task(batch);
                }

                batch.commit_point()
            })
    }
}

impl Calendar {
    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address calendar
        let mut calendar = self;
        let now = now() as i64;
        calendar.modified = now;
        calendar.created = now;

        if calendar.preferences.is_empty() {
            calendar.preferences.push(CalendarPreferences {
                account_id,
                name: "default".to_string(),
                ..Default::default()
            });
        }

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Calendar)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(calendar)
                    .with_access_token(access_token),
            )
            .map(|b| b.commit_point())
    }

    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        calendar: Archive<&ArchivedCalendar>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address calendar
        let mut new_calendar = self;
        new_calendar.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Calendar)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(calendar)
                    .with_changes(new_calendar)
                    .with_access_token(access_token),
            )
            .map(|b| b.commit_point())
    }
}

impl CalendarEventNotification {
    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build event
        let mut event = self;
        let now = now() as i64;
        event.modified = now;
        event.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEventNotification)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(event)
                    .with_access_token(access_token),
            )
            .map(|batch| batch.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendar>> {
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_with_events(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        children_ids: Vec<u32>,
        delete_path: Option<String>,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        // Process deletions
        let calendar_id = document_id;
        for document_id in children_ids {
            if let Some(event_) = server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await?
            {
                DestroyArchive(
                    event_
                        .to_unarchived::<CalendarEvent>()
                        .caused_by(trc::location!())?,
                )
                .delete(
                    access_token,
                    account_id,
                    document_id,
                    calendar_id,
                    None,
                    send_itip,
                    batch,
                )?;
            }
        }

        self.delete(access_token, account_id, document_id, delete_path, batch)
    }

    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let calendar = self.0;
        // Delete calendar
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Calendar)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_access_token(access_token)
                    .with_current(calendar),
            )
            .caused_by(trc::location!())?;
        if let Some(delete_path) = delete_path {
            batch.log_vanished_item(VanishedCollection::Calendar, delete_path);
        }
        batch.commit_point();

        Ok(())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendarEvent>> {
    #[allow(clippy::too_many_arguments)]
    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        calendar_id: u32,
        delete_path: Option<String>,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if let Some(delete_idx) = self
            .0
            .inner
            .names
            .iter()
            .position(|name| name.parent_id == calendar_id)
        {
            if self.0.inner.names.len() > 1 {
                // Unlink calendar id from event
                let event = self.0;
                let mut new_event = event
                    .deserialize::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                new_event.names.swap_remove(delete_idx);
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::CalendarEvent)
                    .with_document(document_id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_access_token(access_token)
                            .with_current(event)
                            .with_changes(new_event),
                    )
                    .caused_by(trc::location!())?;
            } else {
                self.delete_all(access_token, account_id, document_id, send_itip, batch)?;
            }

            if let Some(delete_path) = delete_path {
                batch.log_vanished_item(VanishedCollection::Calendar, delete_path);
            }

            batch.commit_point();
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delete_all(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let event = self.0;
        // Delete event
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id);

        // Remove next alarm if it exists
        let now = now() as i64;
        if let Some(next_alarm) = event.inner.data.next_alarm(now, Tz::Floating) {
            next_alarm.delete_task(batch);
        }

        // Scheduling
        if send_itip
            && event.inner.schedule_tag.is_some()
            && event.inner.data.event_range_end() > now
        {
            let event = event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            if let Ok(messages) =
                itip_cancel(&event.data.event, access_token.emails.as_slice(), true)
            {
                ItipMessages::new(vec![messages])
                    .queue(batch)
                    .caused_by(trc::location!())?;
            }
        }

        batch
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_access_token(access_token)
                    .with_current(event),
            )
            .caused_by(trc::location!())?;

        Ok(())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendarEventNotification>> {
    #[allow(clippy::too_many_arguments)]
    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        // Delete event
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEventNotification)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_access_token(access_token)
                    .with_current(self.0),
            )
            .caused_by(trc::location!())?
            .commit_point();

        Ok(())
    }
}

impl CalendarAlarm {
    pub fn write_task(&self, batch: &mut BatchBuilder) {
        match &self.typ {
            CalendarAlarmType::Email {
                event_start,
                event_start_tz,
                event_end,
                event_end_tz,
            } => {
                batch.set(
                    ValueClass::TaskQueue(TaskQueueClass::SendAlarm {
                        due: TaskEpoch::new(self.alarm_time as u64),
                        event_id: self.event_id,
                        alarm_id: self.alarm_id,
                        is_email_alert: true,
                    }),
                    KeySerializer::new((U64_LEN * 2) + (U16_LEN * 2))
                        .write(*event_start as u64)
                        .write(*event_end as u64)
                        .write(*event_start_tz)
                        .write(*event_end_tz)
                        .finalize(),
                );
            }
            CalendarAlarmType::Display { recurrence_id } => {
                batch.set(
                    ValueClass::TaskQueue(TaskQueueClass::SendAlarm {
                        due: TaskEpoch::new(self.alarm_time as u64),
                        event_id: self.event_id,
                        alarm_id: self.alarm_id,
                        is_email_alert: false,
                    }),
                    KeySerializer::new(U64_LEN)
                        .write(recurrence_id.unwrap_or_default() as u64)
                        .finalize(),
                );
            }
        }
    }

    pub fn delete_task(&self, batch: &mut BatchBuilder) {
        batch.clear(ValueClass::TaskQueue(TaskQueueClass::SendAlarm {
            due: TaskEpoch::new(self.alarm_time as u64),
            event_id: self.event_id,
            alarm_id: self.alarm_id,
            is_email_alert: matches!(self.typ, CalendarAlarmType::Email { .. }),
        }));
    }
}

impl ArchivedCalendarEvent {
    pub async fn webcal_uri(
        &self,
        server: &Server,
        access_token: &AccessToken,
    ) -> trc::Result<String> {
        for event_name in self.names.iter() {
            if let Some(calendar_) = server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    access_token.primary_id,
                    Collection::Calendar,
                    event_name.parent_id.to_native(),
                ))
                .await
                .caused_by(trc::location!())?
            {
                let calendar = calendar_
                    .unarchive::<Calendar>()
                    .caused_by(trc::location!())?;
                return Ok(format!(
                    "webcal://{}{}/{}/{}/{}",
                    server.core.network.server_name,
                    DavResourceName::Cal.base_path(),
                    percent_encoding::utf8_percent_encode(&access_token.name, RFC_3986),
                    calendar.name,
                    event_name.name
                ));
            }
        }

        Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Event is not linked to any calendar"))
    }
}
