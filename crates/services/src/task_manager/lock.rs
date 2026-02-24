/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::*;

pub(crate) trait TaskLockManager: Sync + Send {
    fn try_lock_task(&self, task: u64) -> impl Future<Output = bool> + Send;
    fn remove_index_lock(&self, id: u64) -> impl Future<Output = ()> + Send;
}

impl TaskLockManager for Server {
    async fn try_lock_task(&self, id: u64) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_TASK, &id.to_be_bytes(), DEFAULT_LOCK_EXPIRY)
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::TaskLocked),
                        Id = id,
                        Details = "Task details not available",
                        Expires = trc::Value::Timestamp(now() + DEFAULT_LOCK_EXPIRY),
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(err.id(id).details("Failed to lock task"));

                false
            }
        }
    }

    async fn remove_index_lock(&self, id: u64) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_TASK, &id.to_be_bytes())
            .await
        {
            trc::error!(
                err.details("Failed to unlock task")
                    .ctx(trc::Key::Id, id)
                    .caused_by(trc::location!())
            );
        }
    }
}
