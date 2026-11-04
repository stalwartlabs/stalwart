/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{
    Dispatch, LEASE_RENEW_INTERVAL, StoredTask, TaskDone, TaskInfo, TaskJob, TaskTypeLimits,
    lock::{TaskLock, TaskLockManager},
    outcome::{Commit, Outcome, commit},
    tasks::{
        acme::AcmeTask,
        alarm::SendAlarmTask,
        blob_recode::BlobRecodeTask,
        destroy_account::DestroyAccountTask,
        dkim::DkimManagementTask,
        dns::DnsManagementTask,
        external_public_keys::ExternalPublicKeyMaintenance,
        grantee_cleanup::GranteeCleanupTask,
        imip::SendImipTask,
        maintenance::MaintenanceTask,
        merge_threads::MergeThreadsTask,
        report::{ReportId, SubmitReportTask},
        spam_classifier::SpamFilterMaintenanceTask,
    },
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::task_manager::tasks::restore_item::RestoreItemTask;
// SPDX-SnippetEnd
use common::{BuildServer, Inner, Server, network::ServerInstance};
use compact_str::CompactString;
use registry::schema::{enums::TaskType, structs::Task};
use std::{any::Any, future::Future, pin::pin, sync::Arc};
use store::{
    ValueKey,
    write::{BatchBuilder, TaskId, TaskQueueClass, TaskTypes, ValueClass, assert::AssertValue},
};
use tokio::{
    sync::mpsc,
    task::{self, JoinError, JoinSet},
    time::{Instant, sleep},
};
use trc::TaskManagerEvent;

struct JobResult {
    done: TaskDone,
    written: TaskTypes,
}

pub(crate) fn spawn_worker(
    inner: Arc<Inner>,
    typ: TaskType,
    mut rx: mpsc::Receiver<Dispatch>,
    done_tx: mpsc::UnboundedSender<TaskDone>,
    server_instance: Arc<ServerInstance>,
) {
    tokio::spawn(async move {
        let concurrency = typ.concurrency();
        let mut running = JoinSet::new();
        let mut in_flight: Vec<(task::Id, Dispatch)> = Vec::with_capacity(concurrency);

        loop {
            let result = tokio::select! {
                dispatch = rx.recv(), if running.len() < concurrency => {
                    let Some(dispatch) = dispatch else {
                        break;
                    };
                    let handle = running.spawn(run_job(
                        inner.clone(),
                        dispatch,
                        server_instance.clone(),
                    ));
                    in_flight.push((handle.id(), dispatch));
                    continue;
                }
                Some(joined) = running.join_next_with_id() => joined,
                else => break,
            };

            let result = match result {
                Ok((id, result)) => {
                    take_in_flight(&mut in_flight, id);
                    Some(result)
                }
                Err(err) => match take_in_flight(&mut in_flight, err.id()) {
                    Some(dispatch) => Some(recover(&inner, dispatch, err).await),
                    None => None,
                },
            };

            if let Some(result) = result {
                let _ = done_tx.send(result.done);
                if !result.written.is_empty() || rx.is_empty() {
                    inner.build_server().notify_task_types(result.written);
                }
            }
        }
    });
}

fn take_in_flight(in_flight: &mut Vec<(task::Id, Dispatch)>, id: task::Id) -> Option<Dispatch> {
    in_flight
        .iter()
        .position(|(running_id, _)| *running_id == id)
        .map(|idx| in_flight.swap_remove(idx).1)
}

async fn run_job(
    inner: Arc<Inner>,
    dispatch: Dispatch,
    server_instance: Arc<ServerInstance>,
) -> JobResult {
    let server = inner.build_server();
    let Dispatch {
        job,
        lock,
        dispatched_at,
    } = dispatch;

    if dispatched_at.elapsed() >= LEASE_RENEW_INTERVAL && !server.renew_task_lock(lock).await {
        return JobResult {
            done: job.done(false),
            written: TaskTypes::default(),
        };
    }

    match server
        .store()
        .get_value::<StoredTask>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task {
                id: TaskId::Assigned(job.id),
            },
        )))
        .await
    {
        Ok(Some(StoredTask { task, hash })) if task.due_timestamp() != job.due => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskIgnored),
                TaskId = job.id,
                Name = task.name(),
                Reason = "Task was rescheduled, removing its previous due date.",
            );

            clear_stale_due(&server, &job, lock, AssertValue::Hash(hash)).await
        }
        Ok(Some(StoredTask { task, hash })) => {
            let outcome = with_lease(&server, lock, execute(&server, &task, server_instance)).await;
            finish(
                &server,
                &job,
                lock,
                commit(&server, &job, task, hash, outcome).await,
            )
            .await
        }
        Ok(None) => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskIgnored),
                TaskId = job.id,
                Reason = "Task not found in store, likely already processed.",
            );

            clear_stale_due(&server, &job, lock, AssertValue::None).await
        }
        Err(err) => {
            trc::error!(
                err.ctx(trc::Key::TaskId, job.id)
                    .details("Failed to retrieve task details.")
                    .caused_by(trc::location!())
            );

            finish(&server, &job, lock, Commit::Failed).await
        }
    }
}

async fn recover(inner: &Arc<Inner>, dispatch: Dispatch, err: JoinError) -> JobResult {
    let server = inner.build_server();
    let Dispatch { job, lock, .. } = dispatch;
    let reason = if err.is_panic() {
        format!(
            "Task handler panicked: {}",
            panic_message(err.into_panic().as_ref())
        )
    } else {
        "Task handler was cancelled".to_string()
    };

    trc::event!(
        Server(trc::ServerEvent::ThreadError),
        Details = "Task handler terminated abnormally.",
        TaskId = job.id,
        Reason = CompactString::from(reason.as_str()),
        CausedBy = trc::location!()
    );

    match server
        .store()
        .get_value::<StoredTask>(ValueKey::from(ValueClass::TaskQueue(
            TaskQueueClass::Task {
                id: TaskId::Assigned(job.id),
            },
        )))
        .await
    {
        Ok(Some(StoredTask { task, hash })) if task.due_timestamp() == job.due => {
            let result = commit(&server, &job, task, hash, Outcome::transient(reason)).await;
            finish(&server, &job, lock, result).await
        }
        Ok(_) => finish(&server, &job, lock, Commit::Conflict).await,
        Err(err) => {
            trc::error!(
                err.ctx(trc::Key::TaskId, job.id)
                    .details("Failed to retrieve task details.")
                    .caused_by(trc::location!())
            );

            finish(&server, &job, lock, Commit::Failed).await
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic")
}

async fn finish(server: &Server, job: &TaskJob, lock: TaskLock, result: Commit) -> JobResult {
    match result {
        Commit::Committed(written) => {
            server.unlock_task(lock).await;
            JobResult {
                done: job.done(true),
                written,
            }
        }
        Commit::Conflict => {
            server.unlock_task(lock).await;
            JobResult {
                done: job.done(false),
                written: TaskTypes::default(),
            }
        }
        Commit::Failed => JobResult {
            done: job.done(false),
            written: TaskTypes::default(),
        },
    }
}

async fn clear_stale_due(
    server: &Server,
    job: &TaskJob,
    lock: TaskLock,
    task: AssertValue,
) -> JobResult {
    let id = TaskId::Assigned(job.id);
    let mut batch = BatchBuilder::new();
    batch
        .assert_value(ValueClass::TaskQueue(TaskQueueClass::Task { id }), task)
        .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            typ: job.typ,
            due: job.due,
        }));

    let result = match server.store().write_batch(&mut batch).await {
        Ok(_) => Commit::Committed(TaskTypes::default()),
        Err(err) if err.is_assertion_failure() => Commit::Conflict,
        Err(err) => {
            trc::error!(
                err.ctx(trc::Key::TaskId, job.id)
                    .details("Failed to remove stale task due date from queue.")
            );
            Commit::Failed
        }
    };

    finish(server, job, lock, result).await
}

async fn with_lease(
    server: &Server,
    lock: TaskLock,
    task: impl Future<Output = Outcome>,
) -> Outcome {
    let mut task = pin!(task);
    let mut renew = pin!(sleep(LEASE_RENEW_INTERVAL));
    let mut lease_lost = false;

    loop {
        tokio::select! {
            outcome = &mut task => return outcome,
            _ = &mut renew => {
                match lock.extend(server.in_memory_store()).await {
                    Ok(true) => lease_lost = false,
                    Ok(false) | Err(_) if lease_lost => {}
                    Ok(false) => {
                        lease_lost = true;
                        trc::event!(
                            TaskManager(TaskManagerEvent::TaskLocked),
                            TaskId = lock.id(),
                            Details = "Task lease was lost while the task was running",
                        );
                    }
                    Err(err) => {
                        lease_lost = true;
                        trc::error!(
                            err.ctx(trc::Key::TaskId, lock.id())
                                .details("Failed to renew task lease")
                        );
                    }
                }
                renew.as_mut().reset(Instant::now() + LEASE_RENEW_INTERVAL);
            }
        }
    }
}

async fn execute(server: &Server, task: &Task, server_instance: Arc<ServerInstance>) -> Outcome {
    match task {
        Task::CalendarAlarmEmail(task) => server.send_email_alarm(task, server_instance).await,
        Task::CalendarAlarmNotification(task) => server.send_display_alarm(task).await,
        Task::CalendarItipMessage(task) => server.send_imip(task, server_instance).await,
        Task::MergeThreads(task) => server.merge_threads(task).await,
        Task::DmarcReport(task) => {
            server
                .submit_report(ReportId::Dmarc(task.report_id.id()))
                .await
        }
        Task::TlsReport(task) => {
            server
                .submit_report(ReportId::Tls(task.report_id.id()))
                .await
        }
        Task::DmarcReportWindow(task) => {
            server
                .submit_report(ReportId::DmarcWindow(task.window_end))
                .await
        }
        Task::TlsReportWindow(task) => {
            server
                .submit_report(ReportId::TlsWindow(task.window_end))
                .await
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        Task::RestoreArchivedItem(task) => server.restore_item(task).await,
        // SPDX-SnippetEnd
        Task::DestroyAccount(task) => server.destroy_account(task).await,
        Task::AccountMaintenance(task) => server.account_maintenance(task).await,
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        Task::TenantMaintenance(task) => server.tenant_maintenance(task).await,
        // SPDX-SnippetEnd
        Task::StoreMaintenance(task) => server.store_maintenance(task).await,
        Task::SpamFilterMaintenance(task) => server.spam_filter_maintenance(task).await,
        Task::AcmeRenewal(task) => server.acme_management(task).await,
        Task::DkimManagement(task) => server.dkim_management(task).await,
        Task::DnsManagement(task) => server.dns_management(task).await,
        Task::ShareRevokeCleanup(task) => server.share_revoke_cleanup(task).await,
        Task::ExternalPublicKeyMaintenance(task) => {
            server.external_public_key_maintenance(task).await
        }
        Task::BlobRecode(task) => server.blob_recode(task).await,
    }
}
