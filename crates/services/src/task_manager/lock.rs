/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::*;

pub(crate) trait TaskLockManager: Sync + Send {
    fn try_lock_task(
        &self,
        account_id: u32,
        document_id: u32,
        lock_key: Vec<u8>,
        lock_expiry: u64,
    ) -> impl Future<Output = bool> + Send;
    fn remove_index_lock(&self, lock_key: Vec<u8>) -> impl Future<Output = ()> + Send;
}

impl TaskLockManager for Server {
    async fn try_lock_task(
        &self,
        account_id: u32,
        document_id: u32,
        lock_key: Vec<u8>,
        lock_expiry: u64,
    ) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_TASK, &lock_key, lock_expiry)
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::TaskLocked),
                        AccountId = account_id,
                        DocumentId = document_id,
                        Expires = trc::Value::Timestamp(now() + lock_expiry),
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .document_id(document_id)
                        .details("Failed to lock task")
                );

                false
            }
        }
    }

    async fn remove_index_lock(&self, lock_key: Vec<u8>) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_TASK, &lock_key)
            .await
        {
            trc::error!(
                err.details("Failed to unlock task")
                    .ctx(trc::Key::Key, lock_key)
                    .caused_by(trc::location!())
            );
        }
    }
}

pub(crate) trait TaskLock {
    fn account_id(&self) -> u32;
    fn document_id(&self) -> u32;
    fn lock_key(&self) -> Vec<u8>;
    fn lock_expiry(&self) -> u64;
    fn value_classes(&self) -> impl Iterator<Item = ValueClass>;
}

impl TaskLock for Task<IndexAction> {
    fn account_id(&self) -> u32 {
        self.account_id
    }

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn lock_key(&self) -> Vec<u8> {
        KeySerializer::new((U32_LEN * 2) + U64_LEN + 2)
            .write(0u8)
            .write(self.due.inner())
            .write_leb128(self.account_id)
            .write_leb128(self.document_id)
            .write(self.action.index.to_u8())
            .finalize()
    }

    fn lock_expiry(&self) -> u64 {
        INDEX_EXPIRY
    }

    fn value_classes(&self) -> impl Iterator<Item = ValueClass> {
        std::iter::once(ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
            due: self.due,
            index: self.action.index,
            is_insert: self.action.is_insert,
        }))
    }
}

impl TaskLock for Task<CalendarAlarm> {
    fn account_id(&self) -> u32 {
        self.account_id
    }

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn lock_key(&self) -> Vec<u8> {
        KeySerializer::new((U32_LEN * 2) + U64_LEN + 1)
            .write(2u8)
            .write(self.due.inner())
            .write_leb128(self.account_id)
            .write_leb128(self.document_id)
            .finalize()
    }

    fn lock_expiry(&self) -> u64 {
        ALARM_EXPIRY
    }

    fn value_classes(&self) -> impl Iterator<Item = ValueClass> {
        std::iter::once(ValueClass::TaskQueue(TaskQueueClass::SendAlarm {
            event_id: self.action.event_id,
            alarm_id: self.action.alarm_id,
            due: self.due,
            is_email_alert: matches!(self.action.typ, CalendarAlarmType::Email { .. }),
        }))
    }
}

impl TaskLock for Task<ImipAction> {
    fn account_id(&self) -> u32 {
        self.account_id
    }

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn lock_key(&self) -> Vec<u8> {
        KeySerializer::new((U32_LEN * 2) + U64_LEN + 1)
            .write(3u8)
            .write(self.due.inner())
            .write_leb128(self.account_id)
            .write_leb128(self.document_id)
            .finalize()
    }

    fn lock_expiry(&self) -> u64 {
        ALARM_EXPIRY
    }

    fn value_classes(&self) -> impl Iterator<Item = ValueClass> {
        [
            ValueClass::TaskQueue(TaskQueueClass::SendImip {
                due: self.due,
                is_payload: false,
            }),
            ValueClass::TaskQueue(TaskQueueClass::SendImip {
                due: self.due,
                is_payload: true,
            }),
        ]
        .into_iter()
    }
}

impl TaskLock for Task<MergeThreadIds<AHashSet<u32>>> {
    fn account_id(&self) -> u32 {
        self.account_id
    }

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn lock_key(&self) -> Vec<u8> {
        KeySerializer::new((U32_LEN * 2) + U64_LEN + 1)
            .write(4u8)
            .write(self.due.inner())
            .write_leb128(self.account_id)
            .write_leb128(self.document_id)
            .finalize()
    }

    fn lock_expiry(&self) -> u64 {
        ALARM_EXPIRY
    }

    fn value_classes(&self) -> impl Iterator<Item = ValueClass> {
        std::iter::once(ValueClass::TaskQueue(TaskQueueClass::MergeThreads {
            due: self.due,
        }))
    }
}

impl Task<TaskAction> {
    pub(crate) fn lock_expiry(&self) -> u64 {
        match &self.action {
            TaskAction::UpdateIndex(_) => INDEX_EXPIRY,
            TaskAction::SendAlarm(_) => ALARM_EXPIRY,
            _ => ALARM_EXPIRY,
        }
    }

    pub fn deserialize(key: &[u8], value: &[u8]) -> trc::Result<Self> {
        let document_id = key.deserialize_be_u32(U64_LEN + U32_LEN + 1)?;

        Ok(Task {
            due: TaskEpoch::from_inner(key.deserialize_be_u64(0)?),
            account_id: key.deserialize_be_u32(U64_LEN)?,
            document_id,
            action: match key.get(U64_LEN + U32_LEN) {
                Some(v @ (7 | 8)) => TaskAction::UpdateIndex(IndexAction {
                    index: key
                        .last()
                        .copied()
                        .and_then(SearchIndex::try_from_u8)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?,
                    is_insert: *v == 7,
                }),
                Some(3) => TaskAction::SendAlarm(CalendarAlarm {
                    event_id: key.deserialize_be_u16(U64_LEN + U32_LEN + U32_LEN + 1)?,
                    alarm_id: key.deserialize_be_u16(U64_LEN + U32_LEN + U32_LEN + U16_LEN + 1)?,
                    alarm_time: 0,
                    typ: CalendarAlarmType::Email {
                        event_start: value.deserialize_be_u64(0)? as i64,
                        event_end: value.deserialize_be_u64(U64_LEN)? as i64,
                        event_start_tz: value.deserialize_be_u16(U64_LEN * 2)?,
                        event_end_tz: value.deserialize_be_u16((U64_LEN * 2) + U16_LEN)?,
                    },
                }),
                Some(6) => {
                    let recurrence_id = value.deserialize_be_u64(0)? as i64;

                    TaskAction::SendAlarm(CalendarAlarm {
                        event_id: key.deserialize_be_u16(U64_LEN + U32_LEN + U32_LEN + 1)?,
                        alarm_id: key
                            .deserialize_be_u16(U64_LEN + U32_LEN + U32_LEN + U16_LEN + 1)?,
                        alarm_time: 0,
                        typ: CalendarAlarmType::Display {
                            recurrence_id: if recurrence_id != 0 {
                                Some(recurrence_id)
                            } else {
                                None
                            },
                        },
                    })
                }
                Some(4) => TaskAction::SendImip,
                Some(9) => {
                    TaskAction::MergeThreads(MergeThreadIds::deserialize(value).ok_or_else(
                        || trc::Error::corrupted_key(key, value.into(), trc::location!()),
                    )?)
                }
                _ => return Err(trc::Error::corrupted_key(key, None, trc::location!())),
            },
        })
    }
}
