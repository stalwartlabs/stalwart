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
        ArchivedCalendarEventContent, ArchivedCalendarEventNotification, CalendarEventContent,
        CalendarEventNotification, CalendarEventNotificationContent, EVENT_HAS_ALARMS,
        alarm::CalendarAlarmType,
    },
    scheduling::{ItipMessages, event_cancel::itip_cancel},
};
use calcard::common::timezone::Tz;
use common::{
    Server,
    auth::{AccountInfo, AccountTenantIds},
    storage::index::{GroupwareWrite, ObjectIndexBuilder, SplitCurrent, SplitUpdate},
};
use registry::{
    schema::structs::{Task, TaskCalendarAlarmEmail, TaskCalendarAlarmNotification, TaskStatus},
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime},
};
use store::{
    IndexKey, IterateParams, SerializeInfallible, U32_LEN, ValueKey,
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, BatchBuilder, Operation, PendingId, SetValue, Slot, TaskId,
        TaskQueueClass, ValueClass, ValueOp, key::DeserializeBigEndian, now,
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, VanishedCollection},
    field::{CalendarEventField, CalendarNotificationField},
    id::Id,
};

pub trait ItipAutoExpunge: Sync + Send {
    fn itip_auto_expunge(
        &self,
        account_id: u32,
        hold_period: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl ItipAutoExpunge for Server {
    async fn itip_auto_expunge(&self, account_id: u32, hold_period: u64) -> trc::Result<()> {
        let mut destroy_ids = RoaringBitmap::new();
        let expire_before = (now().saturating_sub(hold_period) as i64).to_be_bytes();
        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        field: CalendarNotificationField::Created.into(),
                        key: &[][..],
                    },
                    IndexKey {
                        account_id,
                        collection: Collection::CalendarEventNotification.into(),
                        document_id: 0,
                        field: CalendarNotificationField::Created.into(),
                        key: &expire_before[..],
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
            Store(trc::StoreEvent::AutoExpunge),
            AccountId = account_id,
            Collection = Collection::CalendarEventNotification.as_str(),
            Total = destroy_ids.len(),
        );

        // Tombstone messages
        let mut batch = BatchBuilder::new();
        let changed_by = self
            .account(account_id)
            .await
            .caused_by(trc::location!())?
            .account_tenant_ids();

        for document_id in destroy_ids {
            // Fetch event
            if let Some(event_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                    .delete(changed_by, account_id, document_id, &mut batch)
                    .caused_by(trc::location!())?;
            }
        }

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(())
    }
}

impl CalendarEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn update_full(
        self,
        content: CalendarEventContent,
        changed_by: AccountTenantIds,
        event: Archive<&ArchivedCalendarEvent>,
        event_content: &ArchivedCalendarEventContent,
        account_id: u32,
        document_id: u32,
        parent_id: Option<Slot>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<String> {
        let mut new_event = self;
        new_event.modified = now() as i64;

        let update = SplitUpdate::full(event, event_content, new_event, content, ())?;
        let etag = update.etag();

        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id)
            .custom(update.into_builder(changed_by, parent_id))?
            .commit_point();

        Ok(etag)
    }

    pub fn update_meta(
        self,
        changed_by: AccountTenantIds,
        event: Archive<&ArchivedCalendarEvent>,
        account_id: u32,
        document_id: u32,
        parent_id: Option<Slot>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<String> {
        let mut new_event = self;
        new_event.modified = now() as i64;

        let update = SplitUpdate::meta_only(event, new_event);
        let etag = update.etag();

        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id)
            .custom(update.into_builder(changed_by, parent_id))?
            .commit_point();

        Ok(etag)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        self,
        content: CalendarEventContent,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: impl Into<PendingId>,
        parent_id: Option<Slot>,
        next_alarm: Option<CalendarAlarm>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<String> {
        let mut event = self;
        let now = now() as i64;
        event.modified = now;
        event.created = now;

        let changes = GroupwareWrite::full(event, content, ())?;
        let etag = format!("\"{}\"", changes.meta().etag);

        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_pending_document(document_id.into())
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(changes)
                    .with_changed_by(changed_by)
                    .with_pending_id_opt(parent_id),
            )?;

        if let Some(next_alarm) = next_alarm {
            next_alarm.write_task(batch);
        }
        batch.commit_point();

        Ok(etag)
    }
}

impl Calendar {
    pub fn insert(
        self,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: impl Into<PendingId>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<&mut BatchBuilder> {
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
            .with_pending_document(document_id.into())
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(calendar)
                    .with_changed_by(changed_by),
            )
            .map(|b| b.commit_point())
    }

    pub fn update<'x>(
        self,
        changed_by: AccountTenantIds,
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
                    .with_changed_by(changed_by),
            )
            .map(|b| b.commit_point())
    }
}

impl CalendarEventNotification {
    pub fn insert(
        self,
        content: CalendarEventNotificationContent,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: impl Into<PendingId>,
        event_id: Option<Slot>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<&mut BatchBuilder> {
        // Build event
        let mut event = self;
        let now = now() as i64;
        event.modified = now;
        event.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEventNotification)
            .with_pending_document(document_id.into())
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(GroupwareWrite::full(event, content, ())?)
                    .with_changed_by(changed_by)
                    .with_pending_id_opt(event_id),
            )
            .map(|batch| batch.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendar>> {
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_with_events(
        self,
        server: &Server,
        account_info: &AccountInfo,
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
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                    server,
                    account_info,
                    account_id,
                    document_id,
                    calendar_id,
                    None,
                    send_itip,
                    batch,
                )
                .await?;
            }
        }

        self.delete(
            account_info.account_tenant_ids(),
            account_id,
            document_id,
            delete_path,
            batch,
        )
    }

    pub fn delete(
        self,
        changed_by: AccountTenantIds,
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
                    .with_changed_by(changed_by)
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
    pub async fn delete(
        self,
        server: &Server,
        account_info: &AccountInfo,
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
                let update = SplitUpdate::meta_only(event, new_event);
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::CalendarEvent)
                    .with_document(document_id)
                    .custom(update.into_builder(account_info.account_tenant_ids(), None))
                    .caused_by(trc::location!())?;
            } else {
                self.delete_all(
                    server,
                    account_info,
                    account_id,
                    document_id,
                    send_itip,
                    batch,
                )
                .await?;
            }

            if let Some(delete_path) = delete_path {
                batch.log_vanished_item(VanishedCollection::Calendar, delete_path);
            }

            batch.commit_point();
        }

        Ok(())
    }

    pub async fn delete_all(
        self,
        server: &Server,
        account_info: &AccountInfo,
        account_id: u32,
        document_id: u32,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let event = self.0;
        let now = now() as i64;

        let has_alarms = event.inner.flags.to_native() & EVENT_HAS_ALARMS != 0;
        let send_itip =
            send_itip && event.inner.schedule_tag.is_some() && event.inner.event_range_end() > now;

        let content_ = if has_alarms || send_itip {
            server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                    CalendarEventField::Content,
                ))
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };

        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id);

        if let Some(content_) = &content_ {
            let content = content_
                .to_unarchived::<CalendarEventContent>()
                .caused_by(trc::location!())?;

            if has_alarms && let Some(next_alarm) = content.inner.data.next_alarm(now, Tz::Floating)
            {
                next_alarm.delete_task(batch);
            }

            if send_itip {
                let content = content
                    .deserialize::<CalendarEventContent>()
                    .caused_by(trc::location!())?;

                if let Ok(messages) =
                    itip_cancel(&content.data.event, account_info.addresses(), true)
                {
                    ItipMessages::new(vec![messages])
                        .queue(batch)
                        .caused_by(trc::location!())?;
                }
            }
        }

        batch
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_changed_by(account_info.account_tenant_ids())
                    .with_current(SplitCurrent::<ArchivedCalendarEvent>::MetaOnly(event)),
            )
            .caused_by(trc::location!())?;

        Ok(())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendarEventNotification>> {
    #[allow(clippy::too_many_arguments)]
    pub fn delete(
        self,
        changed_by: AccountTenantIds,
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
                    .with_changed_by(changed_by)
                    .with_current(SplitCurrent::<ArchivedCalendarEventNotification>::MetaOnly(
                        self.0,
                    )),
            )
            .caused_by(trc::location!())?
            .commit_point();

        Ok(())
    }
}

impl CalendarAlarm {
    pub fn task(&self, account_id: u32) -> Task {
        match &self.typ {
            CalendarAlarmType::Email {
                event_start,
                event_start_tz,
                event_end,
                event_end_tz,
            } => Task::CalendarAlarmEmail(TaskCalendarAlarmEmail {
                account_id: account_id.into(),
                document_id: Id::default(),
                alarm_id: self.alarm_id.into(),
                event_id: self.event_id.into(),
                event_end: UTCDateTime::from_timestamp(*event_end),
                event_end_tz: (*event_end_tz).into(),
                event_start: UTCDateTime::from_timestamp(*event_start),
                event_start_tz: (*event_start_tz).into(),
                status: TaskStatus::at(self.alarm_time),
            }),
            CalendarAlarmType::Display { recurrence_id } => {
                Task::CalendarAlarmNotification(TaskCalendarAlarmNotification {
                    account_id: account_id.into(),
                    document_id: Id::default(),
                    alarm_id: self.alarm_id.into(),
                    event_id: self.event_id.into(),
                    recurrence_id: *recurrence_id,
                    status: TaskStatus::at(self.alarm_time),
                })
            }
        }
    }

    pub fn build_write_ops(&self, account_id: u32, document_id: u32) -> [Operation; 2] {
        let mut task = self.task(account_id);
        task.set_document_id(Id::from(document_id));
        let id = TaskId::Assigned(Id::from_parts(account_id, document_id).id());
        [
            Operation::Value {
                class: ValueClass::TaskQueue(TaskQueueClass::Due {
                    id,
                    due: self.alarm_time as u64,
                }),
                op: ValueOp::Set(SetValue::Fixed(task.object_type().to_id().serialize())),
            },
            Operation::Value {
                class: ValueClass::TaskQueue(TaskQueueClass::Task { id }),
                op: ValueOp::Set(SetValue::Fixed(task.to_pickled_vec())),
            },
        ]
    }

    pub fn write_task(&self, batch: &mut BatchBuilder) {
        let account_id = batch.last_account_id().unwrap();
        batch.schedule_document_task(self.task(account_id));
    }

    pub fn delete_task(&self, batch: &mut BatchBuilder) {
        batch.clear_document_task(self.alarm_time as u64);
    }
}

impl ArchivedCalendarEvent {
    pub async fn webcal_uri(
        &self,
        server: &Server,
        account_info: &AccountInfo,
    ) -> trc::Result<String> {
        for event_name in self.names.iter() {
            if let Some(calendar_) = server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_info.account_id(),
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
                    percent_encoding::utf8_percent_encode(account_info.name(), RFC_3986),
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
