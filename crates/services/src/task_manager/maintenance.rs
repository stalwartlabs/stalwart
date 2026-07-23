/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::task_manager::{
    TaskResult,
    index::{reindex_account, reindex_telemetry},
};
use common::{
    KV_ACME, KV_GREYLIST, KV_LOCK_DAV, KV_LOCK_QUEUE_MESSAGE, KV_LOCK_TASK, KV_OAUTH,
    KV_QUOTA_BLOB, KV_RATE_LIMIT_AUTH, KV_RATE_LIMIT_CONTACT, KV_RATE_LIMIT_HTTP_ANONYMOUS,
    KV_RATE_LIMIT_HTTP_AUTHENTICATED, KV_RATE_LIMIT_IMAP, KV_RATE_LIMIT_LOITER, KV_RATE_LIMIT_RCPT,
    KV_RATE_LIMIT_SCAN, KV_RATE_LIMIT_SMTP, KV_SIEVE_ID, Server,
    storage::index::ObjectIndexBuilder,
};
use email::{
    cache::MessageCacheFetch,
    message::{delete::EmailDeletion, ingest::EmailIngest, metadata::MessageData},
    sieve::SieveScript,
};
use groupware::{
    calendar::{Calendar, CalendarEvent, CalendarEventNotification},
    contact::{AddressBook, ContactCard},
    file::FileNode,
};
use registry::{
    schema::{
        enums::{TaskAccountMaintenanceType, TaskStoreMaintenanceType, TaskTenantMaintenanceType},
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::{
            Task, TaskAccountMaintenance, TaskStatus, TaskStoreMaintenance, TaskTenantMaintenance,
        },
    },
    types::EnumImpl,
};
use smtp::reporting::index::ExternalReportIndex;
use store::{
    Serialize, ValueKey,
    rand::{self},
    registry::{RegistryFilter, RegistryQuery},
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, RegistryClass, ValueClass, now},
};
use trc::{AddContext, StoreEvent};
use types::{
    collection::Collection,
    field::{EmailField, MailboxField},
    id::Id,
};

pub(crate) trait MaintenanceTask: Sync + Send {
    fn store_maintenance(
        &self,
        task: &TaskStoreMaintenance,
    ) -> impl Future<Output = TaskResult> + Send;
    fn account_maintenance(
        &self,
        task: &TaskAccountMaintenance,
    ) -> impl Future<Output = TaskResult> + Send;
    fn tenant_maintenance(
        &self,
        task: &TaskTenantMaintenance,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl MaintenanceTask for Server {
    async fn store_maintenance(&self, task: &TaskStoreMaintenance) -> TaskResult {
        match store_maintenance(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(err.details("Failed to perform store maintenance task"));
                result
            }
        }
    }

    async fn account_maintenance(&self, task: &TaskAccountMaintenance) -> TaskResult {
        match account_maintenance(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to perform account maintenance task")
                );
                result
            }
        }
    }

    async fn tenant_maintenance(&self, task: &TaskTenantMaintenance) -> TaskResult {
        match tenant_maintenance(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(err.details("Failed to perform tenant maintenance task"));
                result
            }
        }
    }
}

async fn store_maintenance(
    server: &Server,
    task: &TaskStoreMaintenance,
) -> trc::Result<TaskResult> {
    match task.maintenance_type {
        TaskStoreMaintenanceType::ReindexAccounts
        | TaskStoreMaintenanceType::PurgeAccounts
        | TaskStoreMaintenanceType::ResetUserQuotas => {
            let mut batch = BatchBuilder::new();
            let now = now() as i64;
            let maintenance_type = match task.maintenance_type {
                TaskStoreMaintenanceType::ReindexAccounts => TaskAccountMaintenanceType::Reindex,
                TaskStoreMaintenanceType::PurgeAccounts => TaskAccountMaintenanceType::Purge,
                TaskStoreMaintenanceType::ResetUserQuotas => {
                    TaskAccountMaintenanceType::RecalculateQuota
                }
                _ => unreachable!(),
            };
            for account_id in server
                .registry()
                .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Account))
                .await?
            {
                #[cfg(feature = "test_mode")]
                let status = TaskStatus::at(now);

                #[cfg(not(feature = "test_mode"))]
                let status =
                    TaskStatus::at(now + rand::Rng::random_range(&mut rand::rng(), 0..=300));

                batch.schedule_task(Task::AccountMaintenance(TaskAccountMaintenance {
                    account_id: account_id.into(),
                    maintenance_type,
                    status,
                }));

                if batch.is_large_batch() {
                    server.core.storage.data.write(batch.build_all()).await?;
                    server.notify_task_queue();
                    batch = BatchBuilder::new();
                }
            }

            if !batch.is_empty() {
                server.core.storage.data.write(batch.build_all()).await?;
                server.notify_task_queue();
            }
        }
        TaskStoreMaintenanceType::ReindexTelemetry => {
            reindex_telemetry(server).await?;
        }
        TaskStoreMaintenanceType::PurgeData => {
            // Delete expired external reports
            let now = now();
            let mut batch = BatchBuilder::new();
            for object in [
                ObjectType::DmarcExternalReport,
                ObjectType::TlsExternalReport,
                ObjectType::ArfExternalReport,
            ] {
                let ids = server
                    .registry()
                    .query::<Vec<Id>>(RegistryQuery::new(object).filter(RegistryFilter::less_than(
                        Property::ExpiresAt,
                        now,
                        false,
                    )))
                    .await?;
                let object_id = object.to_id();
                for id in ids {
                    let item_id = id.id();
                    if let Some(report) = server
                        .store()
                        .get_value::<Object>(ValueKey::from(ValueClass::Registry(
                            RegistryClass::Item { object_id, item_id },
                        )))
                        .await?
                    {
                        match &report.inner {
                            ObjectInner::DmarcExternalReport(report) => {
                                report.write_ops(&mut batch, item_id, false);
                            }
                            ObjectInner::TlsExternalReport(report) => {
                                report.write_ops(&mut batch, item_id, false);
                            }
                            ObjectInner::ArfExternalReport(report) => {
                                report.write_ops(&mut batch, item_id, false);
                            }
                            _ => {}
                        }

                        if batch.is_large_batch() {
                            server.store().write(batch.build_all()).await?;
                            batch = BatchBuilder::new();
                        }
                    }
                }
            }
            if !batch.is_empty() {
                server.store().write(batch.build_all()).await?;
            }

            let started = Instant::now();

            server
                .store()
                .purge_store()
                .await
                .caused_by(trc::location!())?;

            server
                .in_memory_store()
                .purge_in_memory_store()
                .await
                .caused_by(trc::location!())?;

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            {
                use common::telemetry::metrics::store::MetricsStore;
                use common::telemetry::tracers::store::TracingStore;

                if let Some(trace_retention) = server
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.trace_retention)
                    && server.tracing_store().is_active()
                {
                    server
                        .tracing_store()
                        .purge_spans(trace_retention, server.search_store().into())
                        .await
                        .caused_by(trc::location!())?;
                }

                if let Some(metrics_retention) = server
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.metrics_retention)
                    && server.metrics_store().is_active()
                {
                    server
                        .metrics_store()
                        .purge_metrics(metrics_retention)
                        .await
                        .caused_by(trc::location!())?;
                }
            }
            // SPDX-SnippetEnd

            trc::event!(
                Store(StoreEvent::DataStorePurged),
                Elapsed = started.elapsed()
            );
        }
        TaskStoreMaintenanceType::PurgeBlob => {
            if let Some(shard_index) = task.shard_index {
                server
                    .store()
                    .purge_blobs(server.blob_store().clone(), shard_index as u8)
                    .await
                    .caused_by(trc::location!())?;
            } else {
                let mut batch = BatchBuilder::new();
                let now = now() as i64;
                for shard_index in 0..=u8::MAX {
                    batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                        maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
                        shard_index: Some(shard_index as u64),
                        status: TaskStatus::at(now),
                    }));

                    if batch.is_large_batch() {
                        server.core.storage.data.write(batch.build_all()).await?;
                        server.notify_task_queue();
                        batch = BatchBuilder::new();
                    }
                }

                if !batch.is_empty() {
                    server.core.storage.data.write(batch.build_all()).await?;
                    server.notify_task_queue();
                }
            }
        }
        TaskStoreMaintenanceType::RemoveGreylist
        | TaskStoreMaintenanceType::RemoveLockQueueMessage
        | TaskStoreMaintenanceType::RemoveLockTask
        | TaskStoreMaintenanceType::RemoveLockDav
        | TaskStoreMaintenanceType::RemoveSieveId
        | TaskStoreMaintenanceType::ResetRateLimiters
        | TaskStoreMaintenanceType::ResetBlobQuotas
        | TaskStoreMaintenanceType::RemoveAuthTokens => {
            #[cfg(feature = "test_mode")]
            if let Some(test_var) = task.shard_index {
                use crate::task_manager::TaskFailureType;

                // Simulate success for testing purposes
                match test_var {
                    0 => {
                        return Ok(TaskResult::Success(vec![]));
                    }
                    1 => {
                        return Ok(TaskResult::temporary(
                            "Simulated temporary failure".to_string(),
                        ));
                    }
                    2 => {
                        return Ok(TaskResult::permanent("Simulated permanent failure"));
                    }

                    retry => {
                        return Ok(TaskResult::Failure {
                            typ: TaskFailureType::Retry(retry),
                            message: "Simulated retry failure".to_string(),
                            max_attempts: None,
                        });
                    }
                }
            }

            let prefixes = match task.maintenance_type {
                TaskStoreMaintenanceType::RemoveGreylist => &[KV_GREYLIST][..],
                TaskStoreMaintenanceType::RemoveLockQueueMessage => &[KV_LOCK_QUEUE_MESSAGE][..],
                TaskStoreMaintenanceType::RemoveLockTask => &[KV_LOCK_TASK][..],
                TaskStoreMaintenanceType::RemoveLockDav => &[KV_LOCK_DAV][..],
                TaskStoreMaintenanceType::RemoveSieveId => &[KV_SIEVE_ID][..],
                TaskStoreMaintenanceType::ResetRateLimiters => &[
                    KV_RATE_LIMIT_RCPT,
                    KV_RATE_LIMIT_SCAN,
                    KV_RATE_LIMIT_LOITER,
                    KV_RATE_LIMIT_AUTH,
                    KV_RATE_LIMIT_SMTP,
                    KV_RATE_LIMIT_CONTACT,
                    KV_RATE_LIMIT_HTTP_AUTHENTICATED,
                    KV_RATE_LIMIT_HTTP_ANONYMOUS,
                    KV_RATE_LIMIT_IMAP,
                ][..],
                TaskStoreMaintenanceType::ResetBlobQuotas => &[KV_QUOTA_BLOB][..],
                TaskStoreMaintenanceType::RemoveAuthTokens => &[KV_ACME, KV_OAUTH][..],
                _ => unreachable!(),
            };

            for &prefix in prefixes {
                server
                    .in_memory_store()
                    .key_delete_prefix(&[prefix])
                    .await?;
            }
        }
        TaskStoreMaintenanceType::ResetTenantQuotas => {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            {
                let mut batch = BatchBuilder::new();
                let now = now() as i64;

                for tenant_id in server
                    .registry()
                    .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Tenant))
                    .await?
                {
                    #[cfg(feature = "test_mode")]
                    let status = TaskStatus::at(now);

                    #[cfg(not(feature = "test_mode"))]
                    let status =
                        TaskStatus::at(now + rand::Rng::random_range(&mut rand::rng(), 0..=300));

                    batch.schedule_task(Task::TenantMaintenance(TaskTenantMaintenance {
                        tenant_id: tenant_id.into(),
                        maintenance_type: TaskTenantMaintenanceType::RecalculateQuota,
                        status,
                    }));

                    if batch.is_large_batch() {
                        server.core.storage.data.write(batch.build_all()).await?;
                        server.notify_task_queue();
                        batch = BatchBuilder::new();
                    }
                }

                if !batch.is_empty() {
                    server.core.storage.data.write(batch.build_all()).await?;
                    server.notify_task_queue();
                }
            }
            // SPDX-SnippetEnd
        }
    }

    Ok(TaskResult::Success(vec![]))
}

async fn account_maintenance(
    server: &Server,
    task: &TaskAccountMaintenance,
) -> trc::Result<TaskResult> {
    match task.maintenance_type {
        TaskAccountMaintenanceType::Purge => {
            server.purge_account(task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::Reindex => {
            reindex_account(server, task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::RecalculateImapUid => {
            reset_imap_uids(server, task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::RecalculateQuota => {
            recalculate_quota(server, task.account_id.document_id()).await?;
        }
    }

    Ok(TaskResult::Success(vec![]))
}

async fn tenant_maintenance(
    server: &Server,
    task: &TaskTenantMaintenance,
) -> trc::Result<TaskResult> {
    match task.maintenance_type {
        TaskTenantMaintenanceType::RecalculateQuota => {
            recalculate_tenant_quota(server, task.tenant_id.document_id()).await?;
        }
    }

    Ok(TaskResult::Success(vec![]))
}

async fn recalculate_quota(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut quota = 0;

    for collection in [
        Collection::Email,
        Collection::Calendar,
        Collection::CalendarEvent,
        Collection::CalendarEventNotification,
        Collection::AddressBook,
        Collection::ContactCard,
        Collection::FileNode,
        Collection::SieveScript,
    ] {
        server
            .archives(account_id, collection, &(), |_, archive| {
                match collection {
                    Collection::Email => {
                        quota += archive.unarchive::<MessageData>()?.size.to_native() as i64;
                    }
                    Collection::Calendar => {
                        quota += archive.unarchive::<Calendar>()?.size() as i64;
                    }
                    Collection::CalendarEvent => {
                        quota += archive.unarchive::<CalendarEvent>()?.size() as i64;
                    }
                    Collection::CalendarEventNotification => {
                        quota += archive.unarchive::<CalendarEventNotification>()?.size() as i64;
                    }
                    Collection::AddressBook => {
                        quota += archive.unarchive::<AddressBook>()?.size() as i64;
                    }
                    Collection::ContactCard => {
                        quota += archive.unarchive::<ContactCard>()?.size() as i64;
                    }
                    Collection::FileNode => {
                        quota += archive.unarchive::<FileNode>()?.size() as i64;
                    }
                    Collection::SieveScript => {
                        quota += u32::from(archive.unarchive::<SieveScript>()?.size) as i64;
                    }
                    _ => {}
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .clear(ValueClass::Quota)
        .add(ValueClass::Quota, quota);
    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
async fn recalculate_tenant_quota(server: &Server, tenant_id: u32) -> trc::Result<()> {
    let mut quota = 0;
    for account_id in server
        .registry()
        .query::<RoaringBitmap>(
            RegistryQuery::new(ObjectType::Account).with_tenant(tenant_id.into()),
        )
        .await?
    {
        quota += server
            .get_used_quota_account(account_id)
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    batch
        .clear(ValueClass::TenantQuota(tenant_id))
        .add(ValueClass::TenantQuota(tenant_id), quota);
    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}
// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
async fn recalculate_tenant_quota(_server: &Server, _tenant_id: u32) -> trc::Result<()> {
    Ok(())
}

async fn reset_imap_uids(server: &Server, account_id: u32) -> trc::Result<(u32, u32)> {
    let mut mailbox_count = 0;
    let mut email_count = 0;

    let cache = server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?;

    for &mailbox_id in cache.mailboxes.index.keys() {
        let mailbox = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Mailbox,
                mailbox_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| trc::ImapEvent::Error.into_err().caused_by(trc::location!()))?
            .into_deserialized::<email::mailbox::Mailbox>()
            .caused_by(trc::location!())?;
        let mut new_mailbox = mailbox.inner.clone();
        new_mailbox.uid_validity = rand::random::<u32>();
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox)
            .with_document(mailbox_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(mailbox)
                    .with_changes(new_mailbox),
            )
            .caused_by(trc::location!())?
            .clear(MailboxField::UidCounter);
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        mailbox_count += 1;
    }

    // Reset all UIDs
    for message_id in cache.emails.items.iter().map(|i| i.document_id) {
        let data = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Email,
                message_id,
            ))
            .await
            .caused_by(trc::location!())?;
        let data_ = if let Some(data) = data {
            data
        } else {
            continue;
        };
        let data = data_
            .to_unarchived::<MessageData>()
            .caused_by(trc::location!())?;
        let mut new_data = data
            .deserialize::<MessageData>()
            .caused_by(trc::location!())?;

        let ids = server
            .assign_email_ids(
                account_id,
                new_data.mailboxes.iter().map(|m| m.mailbox_id),
                false,
            )
            .await
            .caused_by(trc::location!())?;

        for (uid_mailbox, uid) in new_data.mailboxes.iter_mut().zip(ids) {
            uid_mailbox.uid = uid;
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(message_id)
            .assert_value(ValueClass::Property(EmailField::Archive.into()), &data)
            .set(
                EmailField::Archive,
                Archiver::new(new_data)
                    .serialize()
                    .caused_by(trc::location!())?,
            );
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        email_count += 1;
    }

    Ok((mailbox_count, email_count))
}
