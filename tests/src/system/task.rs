/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, server::TestServer};
use registry::{
    schema::{
        enums::TaskStoreMaintenanceType,
        prelude::{ObjectType, Property},
        structs::{
            Task, TaskManager, TaskRetryStrategy, TaskRetryStrategyFixed, TaskStatus,
            TaskStatusFailed, TaskStatusPending, TaskStatusRetry, TaskStoreMaintenance,
        },
    },
    types::datetime::UTCDateTime,
};
use serde_json::json;
use store::write::now;
use types::id::Id;

const TASK_SUCCESS: u64 = 0;
const TASK_TEMP_FAIL: u64 = 1;
const TASK_PERM_FAIL: u64 = 2;

pub async fn test(test: &mut TestServer) {
    println!("Running Task manager tests...");
    let admin = test.account("admin@example.org");

    // Make sure there are no existing tasks
    admin.assert_no_tasks().await;

    // Create a successful task for immediate execution
    admin.schedule_test_task(TASK_SUCCESS, 0).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    admin.assert_no_tasks().await;

    // Create a successful task for future execution
    admin.schedule_test_task(TASK_SUCCESS, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    admin.assert_has_tasks(1).await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    admin.assert_no_tasks().await;

    // Create a permanent failure task for immediate execution
    admin.schedule_test_task(TASK_PERM_FAIL, 0).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let task = admin.assert_has_tasks(1).await.into_iter().next().unwrap();
    assert_eq!(
        task.task.status().unwrap_failed().failure_reason,
        "Simulated permanent failure"
    );

    // Reschedule the failed task for retry
    admin
        .registry_update_object(
            ObjectType::Task,
            task.id,
            json!({
                Property::ShardIndex: TASK_SUCCESS,
                Property::Status: {
                    "@type": "Pending",
                    "due": UTCDateTime::from_timestamp((now() + 1) as i64),
                }
            }),
        )
        .await;
    test.wait_for_tasks().await;
    admin.assert_no_tasks().await;

    // Test attempt limits strategy
    admin
        .registry_update_setting(
            TaskManager {
                max_attempts: 3,
                strategy: TaskRetryStrategy::FixedDelay(TaskRetryStrategyFixed {
                    delay: 1_000u64.into(),
                }),
                total_deadline: 86_400_000u64.into(), // 24 hours
            },
            &[],
        )
        .await;
    admin.reload_settings().await;

    // Create a temporary failure task for immediate execution
    admin.schedule_test_task(TASK_TEMP_FAIL, 0).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let task = admin.assert_has_tasks(1).await.into_iter().next().unwrap();
    let task_status = task.task.status().unwrap_retry();
    assert_eq!(task_status.failure_reason, "Simulated temporary failure");
    assert_eq!(task_status.attempt_number, 1);

    // Wait until the max attempts is reached
    test.wait_for_tasks_skip_failures().await;
    let task = admin.assert_has_tasks(1).await.into_iter().next().unwrap();
    let task_status = task.task.status().unwrap_failed();
    assert_eq!(task_status.failure_reason, "Simulated temporary failure");
    assert_eq!(task_status.failed_attempt_number, 3);
    admin
        .registry_destroy(ObjectType::Task, [task.id])
        .await
        .assert_destroyed(&[task.id]);

    // Test attempt limits strategy
    admin
        .registry_update_setting(
            TaskManager {
                max_attempts: 100,
                strategy: TaskRetryStrategy::FixedDelay(TaskRetryStrategyFixed {
                    delay: 1_000u64.into(),
                }),
                total_deadline: 2_000u64.into(), // 2 seconds
            },
            &[],
        )
        .await;
    admin.reload_settings().await;

    // Create a temporary failure task for immediate execution
    admin.schedule_test_task(TASK_TEMP_FAIL, 0).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let task = admin.assert_has_tasks(1).await.into_iter().next().unwrap();
    let task_status = task.task.status().unwrap_retry();
    assert_eq!(task_status.failure_reason, "Simulated temporary failure");
    assert_eq!(task_status.attempt_number, 1);

    // Wait until 2 seconds deadline is reached
    test.wait_for_tasks_skip_failures().await;
    let task = admin.assert_has_tasks(1).await.into_iter().next().unwrap();
    let task_status = task.task.status().unwrap_failed();
    assert_eq!(task_status.failure_reason, "Simulated temporary failure");
    assert_eq!(task_status.failed_attempt_number, 2);
    admin
        .registry_destroy(ObjectType::Task, [task.id])
        .await
        .assert_destroyed(&[task.id]);

    pagination_test(test).await;

    test.cleanup().await;
}

async fn pagination_test(test: &mut TestServer) {
    println!("Running Task pagination tests...");
    let admin = test.account("admin@example.org");

    admin.assert_no_tasks().await;

    let mut created = Vec::with_capacity(12);
    for i in 0..12u64 {
        created.push(admin.schedule_test_task(TASK_SUCCESS, 3600 + i).await);
    }

    let asc_order: Vec<Id> = admin
        .registry_query_paginated(ObjectType::Task, "due", true, None, None, None, None, false)
        .await
        .object_ids()
        .collect();
    assert_eq!(asc_order.len(), 12, "expected 12 tasks, got {}", asc_order.len());

    let desc_order: Vec<Id> = asc_order.iter().rev().copied().collect();

    for chunk_start in [0usize, 5, 10] {
        let chunk_size = std::cmp::min(5, 12 - chunk_start);

        let asc = admin
            .registry_query_paginated(
                ObjectType::Task,
                "due",
                true,
                Some(chunk_start as i32),
                Some(5),
                None,
                None,
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            asc,
            asc_order[chunk_start..chunk_start + chunk_size],
            "ascending position={chunk_start} limit=5",
        );

        let desc = admin
            .registry_query_paginated(
                ObjectType::Task,
                "due",
                false,
                Some(chunk_start as i32),
                Some(5),
                None,
                None,
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            desc,
            desc_order[chunk_start..chunk_start + chunk_size],
            "descending position={chunk_start} limit=5",
        );
    }

    for anchor_idx in [4usize, 9] {
        let chunk_size = std::cmp::min(5, 12 - anchor_idx - 1);

        let asc = admin
            .registry_query_paginated(
                ObjectType::Task,
                "due",
                true,
                None,
                Some(5),
                Some(asc_order[anchor_idx]),
                Some(1),
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            asc,
            asc_order[anchor_idx + 1..anchor_idx + 1 + chunk_size],
            "ascending anchor={} offset=1 limit=5",
            asc_order[anchor_idx],
        );

        let desc = admin
            .registry_query_paginated(
                ObjectType::Task,
                "due",
                false,
                None,
                Some(5),
                Some(desc_order[anchor_idx]),
                Some(1),
                false,
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(
            desc,
            desc_order[anchor_idx + 1..anchor_idx + 1 + chunk_size],
            "descending anchor={} offset=1 limit=5",
            desc_order[anchor_idx],
        );
    }

    let response = admin
        .registry_query_paginated(
            ObjectType::Task,
            "due",
            true,
            Some(0),
            Some(5),
            None,
            None,
            true,
        )
        .await;
    let total = response
        .pointer("/methodResponses/0/1/total")
        .and_then(|v| v.as_u64());
    assert_eq!(total, Some(12), "expected calculateTotal=12");

    admin
        .registry_destroy(ObjectType::Task, created.clone())
        .await
        .assert_destroyed(&created);
    admin.assert_no_tasks().await;
}

impl Account {
    async fn schedule_test_task(&self, test_type: u64, schedule_in: u64) -> Id {
        self.registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::RemoveLockDav,
            shard_index: Some(test_type),
            status: TaskStatus::at((now() + schedule_in) as i64),
        }))
        .await
    }

    pub async fn task_ids(&self) -> Vec<Id> {
        self.registry_query_ids(
            ObjectType::Task,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
    }

    pub async fn tasks(&self) -> Vec<TaskId> {
        let ids = self.task_ids().await;
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let sample = self.registry_get::<Task>(id).await;
            results.push(TaskId { id, task: sample });
        }
        results
    }

    async fn assert_no_tasks(&self) {
        let tasks = self.tasks().await;
        assert!(
            tasks.is_empty(),
            "Expected no tasks, found {}: {:?}",
            tasks.len(),
            tasks
        );
    }

    async fn assert_has_tasks(&self, count: usize) -> Vec<TaskId> {
        let tasks = self.tasks().await;
        assert!(
            tasks.len() == count,
            "Expected {} tasks, found {}: {:?}",
            count,
            tasks.len(),
            tasks
        );
        tasks
    }
}

#[derive(Debug)]
pub struct TaskId {
    pub id: Id,
    pub task: Task,
}

#[allow(dead_code)]
trait UnwrapTaskStatus {
    fn unwrap_pending(&self) -> &TaskStatusPending;
    fn unwrap_retry(&self) -> &TaskStatusRetry;
    fn unwrap_failed(&self) -> &TaskStatusFailed;
}

impl UnwrapTaskStatus for TaskStatus {
    fn unwrap_pending(&self) -> &TaskStatusPending {
        match self {
            TaskStatus::Pending(status) => status,
            _ => panic!("Expected TaskStatus::Pending, found {:?}", self),
        }
    }

    fn unwrap_retry(&self) -> &TaskStatusRetry {
        match self {
            TaskStatus::Retry(status) => status,
            _ => panic!("Expected TaskStatus::Retry, found {:?}", self),
        }
    }

    fn unwrap_failed(&self) -> &TaskStatusFailed {
        match self {
            TaskStatus::Failed(status) => status,
            _ => panic!("Expected TaskStatus::Failed, found {:?}", self),
        }
    }
}
