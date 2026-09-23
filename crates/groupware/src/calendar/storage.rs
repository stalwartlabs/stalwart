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
    DavResourceName, DestroyArchive, RFC_3986, SizeWriter,
    cache::GroupwareCache,
    calendar::{
        ArchivedCalendarEventContent, ArchivedCalendarEventNotification, CalendarEventContent,
        CalendarEventNotification, CalendarEventNotificationContent, ChangedBy, EVENT_DRAFT,
        EVENT_HAS_ALARMS, EVENT_NOTIFICATION_IS_CHANGE, EVENT_NOTIFICATION_IS_DESTROY,
        EVENT_NOTIFICATION_IS_DIRECT, EVENT_NOTIFICATION_IS_DRAFT, EVENT_NOTIFICATION_OWNER_ONLY,
        alarm::{AlarmTarget, CalendarAlarmType},
        alerts::DefaultAlertsResolver,
        notification::{
            AccountViewers, CalendarNotificationReap, CalendarNotificationViewers, has_viewers,
            hides_details, may_have_viewers,
        },
        privacy::ICalendarPrivacy,
        schedule::{EventAlarmScheduler, EventAlarmUsers, EventAlarms},
    },
    scheduling::{ItipMessages, event_cancel::itip_cancel, recipient::RecipientPolicy},
};
use calcard::icalendar::ICalendar;
use common::{
    DavName, GroupwareResources, Server,
    auth::{AccessToken, AccountCache, AccountInfo, AccountTenantIds},
    storage::index::{GroupwareWrite, ObjectIndexBuilder, SplitCurrent, SplitUpdate},
};
use registry::{
    schema::enums::StorageQuota,
    schema::structs::{Task, TaskCalendarAlarmEmail, TaskCalendarAlarmNotification, TaskStatus},
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime},
};
use std::sync::Arc;
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
        next_alarms: EventAlarms,
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

        for next_alarm in next_alarms {
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
    pub fn update_meta(
        self,
        changed_by: AccountTenantIds,
        notification: Archive<&ArchivedCalendarEventNotification>,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let mut updated = self;
        updated.modified = now() as i64;

        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEventNotification)
            .with_document(document_id)
            .custom(SplitUpdate::meta_only(notification, updated).into_builder(changed_by, None))?
            .commit_point();

        Ok(())
    }

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
        access_token: &AccessToken,
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
        let mut resolver = DefaultAlertsResolver::default();
        let mut quota = NotificationQuota::default();
        server
            .reap_calendar_notifications(access_token, account_id, &[calendar_id], batch)
            .await
            .caused_by(trc::location!())?;
        let calendars = if !access_token.is_member(account_id) {
            server
                .calendars_if_any(access_token, account_id)
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
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
                let event = event_
                    .to_unarchived::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                let event_flags = event.inner.flags.to_native();
                let mut content = None;
                if let Some(calendars) = calendars.as_ref()
                    && let Some(previous) = server
                        .stored_event_if_notifiable(
                            access_token,
                            account_id,
                            calendars,
                            &[calendar_id],
                            event_flags,
                            (account_id, document_id),
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    content = previous.content;
                    server
                        .notify_direct_change(
                            access_token,
                            account_id,
                            DirectChange::Destroyed {
                                event_id: document_id,
                                previous: previous.event,
                                calendar_ids: vec![calendar_id],
                                event_flags,
                            },
                            Some(calendars),
                            &mut quota,
                            batch,
                        )
                        .await
                        .caused_by(trc::location!())?;
                }
                DestroyArchive(event)
                    .delete_from_calendar(
                        server,
                        account_info,
                        account_id,
                        document_id,
                        calendar_id,
                        content,
                        None,
                        send_itip,
                        &mut resolver,
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
        content: Option<Archive<ArchiveBytes>>,
        delete_path: Option<String>,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        self.delete_from_calendar(
            server,
            account_info,
            account_id,
            document_id,
            calendar_id,
            content,
            delete_path,
            send_itip,
            &mut DefaultAlertsResolver::default(),
            batch,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn delete_from_calendar(
        self,
        server: &Server,
        account_info: &AccountInfo,
        account_id: u32,
        document_id: u32,
        calendar_id: u32,
        content: Option<Archive<ArchiveBytes>>,
        delete_path: Option<String>,
        send_itip: bool,
        resolver: &mut DefaultAlertsResolver,
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
                server
                    .reschedule_event_alarms(
                        account_id,
                        document_id,
                        event.inner,
                        &new_event
                            .names
                            .iter()
                            .map(DavName::parent_id)
                            .collect::<Vec<_>>(),
                        resolver,
                        batch,
                    )
                    .await
                    .caused_by(trc::location!())?;
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
                    content,
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

    #[allow(clippy::too_many_arguments)]
    pub async fn delete_all(
        self,
        server: &Server,
        account_info: &AccountInfo,
        account_id: u32,
        document_id: u32,
        content: Option<Archive<ArchiveBytes>>,
        send_itip: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let event = self.0;
        let now = now() as i64;

        let has_alarms = event.inner.flags.to_native() & EVENT_HAS_ALARMS != 0;
        let send_itip =
            send_itip && event.inner.schedule_tag.is_some() && event.inner.event_range_end() > now;

        let content_ = match content {
            Some(content) => Some(content),
            None if send_itip || has_alarms => server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                    CalendarEventField::Content,
                ))
                .await
                .caused_by(trc::location!())?,
            None => None,
        };

        let content = content_
            .as_ref()
            .map(|content_| content_.to_unarchived::<CalendarEventContent>())
            .transpose()
            .caused_by(trc::location!())?;

        if has_alarms {
            let targets = match &content {
                Some(content) => EventAlarmUsers::targets(account_id, content.inner).collect(),
                None => vec![AlarmTarget::Owner],
            };
            server
                .clear_event_alarms(account_id, document_id, targets, batch)
                .await
                .caused_by(trc::location!())?;
        }
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id);

        if send_itip && let Some(content) = content {
            let content = content
                .deserialize::<CalendarEventContent>()
                .caused_by(trc::location!())?;

            if let Ok(messages) = itip_cancel(
                &content.data.event,
                account_info.addresses(),
                true,
                RecipientPolicy::new(&server.core.groupware, event.inner.flags.to_native()),
            ) {
                ItipMessages::new(messages)
                    .queue(batch)
                    .caused_by(trc::location!())?;
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
                recurrence_id,
            } => Task::CalendarAlarmEmail(TaskCalendarAlarmEmail {
                account_id: account_id.into(),
                document_id: Id::default(),
                alarm_id: self.alarm_id.to_task_id(),
                event_id: self.event_id.into(),
                event_end: UTCDateTime::from_timestamp(*event_end),
                event_end_tz: (*event_end_tz).into(),
                event_start: UTCDateTime::from_timestamp(*event_start),
                event_start_tz: (*event_start_tz).into(),
                target_account_id: self.target.sharee_id().map(Id::from),
                recurrence_id: *recurrence_id,
                status: TaskStatus::at(self.alarm_time),
            }),
            CalendarAlarmType::Display { recurrence_id } => {
                Task::CalendarAlarmNotification(TaskCalendarAlarmNotification {
                    account_id: account_id.into(),
                    document_id: Id::default(),
                    alarm_id: self.alarm_id.to_task_id(),
                    event_id: self.event_id.into(),
                    recurrence_id: *recurrence_id,
                    target_account_id: self.target.sharee_id().map(Id::from),
                    status: TaskStatus::at(self.alarm_time),
                })
            }
        }
    }

    pub fn build_write_ops(&self, account_id: u32, document_id: u32) -> [Operation; 2] {
        let mut task = self.task(account_id);
        task.set_document_id(Id::from(document_id));
        let id = TaskId::Assigned(self.target.task_id().resolve(account_id, document_id));
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
        batch.schedule_document_task(self.target.task_id(), self.task(account_id));
    }

    pub fn delete_task(&self, batch: &mut BatchBuilder) {
        batch.clear_document_task(self.target.task_id(), self.alarm_time as u64);
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

pub struct NotifiableEvent {
    pub event: ICalendar,
    pub content: Option<Archive<ArchiveBytes>>,
}

pub enum DirectChange {
    Created {
        event_id: PendingId,
        current: ICalendar,
        calendar_ids: Vec<u32>,
        event_flags: u16,
    },
    Updated {
        event_id: u32,
        previous: ICalendar,
        current: ICalendar,
        calendar_ids: Vec<u32>,
        event_flags: u16,
    },
    Destroyed {
        event_id: u32,
        previous: ICalendar,
        calendar_ids: Vec<u32>,
        event_flags: u16,
    },
}

fn draft_flag(event_flags: u16) -> u16 {
    if event_flags & EVENT_DRAFT != 0 {
        EVENT_NOTIFICATION_IS_DRAFT
    } else {
        0
    }
}

impl DirectChange {
    fn into_notification(
        self,
        changed_by: u32,
    ) -> (
        CalendarEventNotification,
        CalendarEventNotificationContent,
        Option<Slot>,
    ) {
        let (flags, event_id, pending_event_id, previous, current, calendar_ids, event_flags) =
            match self {
                DirectChange::Created {
                    event_id,
                    current,
                    calendar_ids,
                    event_flags,
                } => {
                    let (assigned_id, pending_id) = match event_id {
                        PendingId::Assigned(event_id) => (Some(event_id), None),
                        PendingId::Slot(slot) => (None, Some(slot)),
                    };

                    (
                        draft_flag(event_flags),
                        assigned_id,
                        pending_id,
                        None,
                        Some(current),
                        calendar_ids,
                        event_flags,
                    )
                }
                DirectChange::Updated {
                    event_id,
                    previous,
                    current,
                    calendar_ids,
                    event_flags,
                } => (
                    EVENT_NOTIFICATION_IS_CHANGE | draft_flag(event_flags),
                    Some(event_id),
                    None,
                    Some(previous),
                    Some(current),
                    calendar_ids,
                    event_flags,
                ),
                DirectChange::Destroyed {
                    event_id,
                    previous,
                    calendar_ids,
                    event_flags,
                } => (
                    EVENT_NOTIFICATION_IS_DESTROY,
                    Some(event_id),
                    None,
                    Some(previous),
                    None,
                    calendar_ids,
                    event_flags,
                ),
            };
        let flags = if hides_details(event_flags)
            || [previous.as_ref(), current.as_ref()]
                .into_iter()
                .flatten()
                .any(|snapshot| !snapshot.privacy().is_public())
        {
            flags | EVENT_NOTIFICATION_OWNER_ONLY
        } else {
            flags
        };

        (
            CalendarEventNotification {
                event_id,
                changed_by: ChangedBy::PrincipalId(changed_by),
                calendar_ids,
                flags: flags | EVENT_NOTIFICATION_IS_DIRECT,
                ..Default::default()
            },
            CalendarEventNotificationContent::Direct { previous, current },
            pending_event_id,
        )
    }
}

#[derive(Default)]
pub struct NotificationQuota {
    usage: Option<NotificationUsage>,
}

struct NotificationUsage {
    account: Arc<AccountCache>,
    limit: Option<usize>,
    stored: usize,
    created: usize,
    expired: Vec<u32>,
}

impl NotificationQuota {
    pub(crate) async fn reserve(
        &mut self,
        server: &Server,
        account_id: u32,
        size: u64,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        let usage = match &mut self.usage {
            Some(usage) => usage,
            usage @ None => usage.insert(NotificationUsage::load(server, account_id).await?),
        };

        match server.has_available_quota(&usage.account, size).await {
            Ok(()) => {}
            Err(err)
                if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                    || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota)) =>
            {
                return Ok(false);
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }

        if let Some(limit) = usage.limit
            && usage.stored + usage.created >= limit + usage.expired.len()
        {
            if limit == 0 {
                return Ok(false);
            }
            let Some(document_id) = server
                .oldest_notification(account_id, &usage.expired)
                .await?
            else {
                return Ok(false);
            };
            if let Some(notification) = server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEventNotification,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                DestroyArchive(
                    notification
                        .to_unarchived::<CalendarEventNotification>()
                        .caused_by(trc::location!())?,
                )
                .delete(
                    usage.account.account_tenant_ids(),
                    account_id,
                    document_id,
                    batch,
                )
                .caused_by(trc::location!())?;
            }
            usage.expired.push(document_id);
        }

        usage.created += 1;
        Ok(true)
    }
}

impl NotificationUsage {
    async fn load(server: &Server, account_id: u32) -> trc::Result<Self> {
        let account = server
            .account(account_id)
            .await
            .caused_by(trc::location!())?;
        let limit =
            server.object_quota_limit(&account, StorageQuota::MaxCalendarEventNotifications);
        let stored = match limit {
            Some(limit) => server
                .count_documents(account_id, Collection::CalendarEventNotification, limit)
                .await
                .caused_by(trc::location!())?,
            None => 0,
        };
        Ok(NotificationUsage {
            account,
            limit,
            stored,
            created: 0,
            expired: Vec::new(),
        })
    }
}

pub trait DirectChangeNotification: Sync + Send {
    fn notify_direct_change(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        change: DirectChange,
        calendars: Option<&GroupwareResources>,
        quota: &mut NotificationQuota,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn oldest_notification(
        &self,
        account_id: u32,
        expired: &[u32],
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn may_have_notification_viewers(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        notification: &CalendarEventNotification,
        calendars: Option<&GroupwareResources>,
    ) -> impl Future<Output = trc::Result<bool>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn notify_calendar_removal(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        calendar_id: u32,
        event_flags: u16,
        quota: &mut NotificationQuota,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn notify_calendar_addition(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        event_id: PendingId,
        calendar_id: u32,
        event_flags: u16,
        source: (u32, u32),
        quota: &mut NotificationQuota,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn stored_event_if_notifiable(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        calendars: &GroupwareResources,
        calendar_ids: &[u32],
        event_flags: u16,
        source: (u32, u32),
    ) -> impl Future<Output = trc::Result<Option<NotifiableEvent>>> + Send;
}

impl DirectChangeNotification for Server {
    async fn notify_direct_change(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        change: DirectChange,
        calendars: Option<&GroupwareResources>,
        quota: &mut NotificationQuota,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let (notification, content, pending_event_id) =
            change.into_notification(access_token.account_id());
        if !self
            .may_have_notification_viewers(access_token, account_id, &notification, calendars)
            .await
            .caused_by(trc::location!())?
        {
            return Ok(());
        }
        let size = content
            .snapshots()
            .into_iter()
            .flatten()
            .map(SizeWriter::ical)
            .sum::<usize>();
        if !quota
            .reserve(self, account_id, size as u64, batch)
            .await
            .caused_by(trc::location!())?
        {
            return Ok(());
        }

        let document_id =
            batch.reserve_document_id(account_id, Collection::CalendarEventNotification);
        notification
            .insert(
                content,
                access_token.account_tenant_ids(),
                account_id,
                document_id,
                pending_event_id,
                batch,
            )
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn notify_calendar_removal(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        calendar_id: u32,
        event_flags: u16,
        quota: &mut NotificationQuota,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let Some(calendars) = self
            .calendars_if_any(access_token, account_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let Some(previous) = self
            .stored_event_if_notifiable(
                access_token,
                account_id,
                &calendars,
                &[calendar_id],
                event_flags,
                (account_id, document_id),
            )
            .await
            .caused_by(trc::location!())?
            .map(|notifiable| notifiable.event)
        else {
            return Ok(());
        };

        self.notify_direct_change(
            access_token,
            account_id,
            DirectChange::Destroyed {
                event_id: document_id,
                previous,
                calendar_ids: vec![calendar_id],
                event_flags,
            },
            Some(&calendars),
            quota,
            batch,
        )
        .await
        .caused_by(trc::location!())
    }

    async fn notify_calendar_addition(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        event_id: PendingId,
        calendar_id: u32,
        event_flags: u16,
        source: (u32, u32),
        quota: &mut NotificationQuota,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let Some(calendars) = self
            .calendars_if_any(access_token, account_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let Some(current) = self
            .stored_event_if_notifiable(
                access_token,
                account_id,
                &calendars,
                &[calendar_id],
                event_flags,
                source,
            )
            .await
            .caused_by(trc::location!())?
            .map(|notifiable| notifiable.event)
        else {
            return Ok(());
        };

        self.notify_direct_change(
            access_token,
            account_id,
            DirectChange::Created {
                event_id,
                current,
                calendar_ids: vec![calendar_id],
                event_flags,
            },
            Some(&calendars),
            quota,
            batch,
        )
        .await
        .caused_by(trc::location!())
    }

    async fn stored_event_if_notifiable(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        calendars: &GroupwareResources,
        calendar_ids: &[u32],
        event_flags: u16,
        source: (u32, u32),
    ) -> trc::Result<Option<NotifiableEvent>> {
        if !may_have_viewers(
            access_token,
            account_id,
            calendars,
            calendar_ids,
            hides_details(event_flags),
        ) {
            return Ok(None);
        }

        let (source_account_id, source_document_id) = source;
        let Some(content) = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                source_account_id,
                Collection::CalendarEvent,
                source_document_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };

        content
            .deserialize::<CalendarEventContent>()
            .map(|event| {
                Some(NotifiableEvent {
                    event: event.data.event,
                    content: Some(content),
                })
            })
            .caused_by(trc::location!())
    }

    async fn may_have_notification_viewers(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        notification: &CalendarEventNotification,
        calendars: Option<&GroupwareResources>,
    ) -> trc::Result<bool> {
        let is_owner_only = notification.flags & EVENT_NOTIFICATION_OWNER_ONLY != 0;
        let account_viewers = AccountViewers::of(
            self.account(account_id)
                .await
                .caused_by(trc::location!())?
                .as_ref(),
        );
        let viewers = |calendars: &GroupwareResources| {
            has_viewers(
                access_token,
                account_id,
                calendars,
                &notification.calendar_ids,
                is_owner_only,
                account_viewers,
            )
        };

        match calendars {
            Some(calendars) => Ok(viewers(calendars)),
            None => Ok(self
                .calendars_if_any(access_token, account_id)
                .await
                .caused_by(trc::location!())?
                .is_some_and(|calendars| viewers(&calendars))),
        }
    }

    async fn oldest_notification(
        &self,
        account_id: u32,
        expired: &[u32],
    ) -> trc::Result<Option<u32>> {
        let mut oldest = None;
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
                        document_id: u32::MAX,
                        field: CalendarNotificationField::Created.into(),
                        key: &u64::MAX.to_be_bytes()[..],
                    },
                )
                .no_values()
                .ascending(),
                |key, _| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if expired.contains(&document_id) {
                        Ok(true)
                    } else {
                        oldest = Some(document_id);
                        Ok(false)
                    }
                },
            )
            .await
            .caused_by(trc::location!())?;
        Ok(oldest)
    }
}
