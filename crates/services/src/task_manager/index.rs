/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{IndexAction, Task};
use common::{Server, auth::AccessToken};
use directory::{Type, backend::internal::manage::ManageDirectory};
use email::{cache::MessageCacheFetch, message::metadata::MessageMetadata};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent, contact::ContactCard};
use std::cmp::Ordering;
use store::{
    IterateParams, SerializeInfallible, ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{IndexDocument, SearchField, SearchFilter, SearchQuery},
    write::{
        AlignedBytes, Archive, BatchBuilder, SearchIndex, TaskEpoch, TaskQueueClass,
        TelemetryClass, ValueClass, key::DeserializeBigEndian,
    },
};
use trc::{AddContext, TaskQueueEvent};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::EmailField,
};

pub(crate) trait SearchIndexTask: Sync + Send {
    fn index(
        &self,
        tasks: &[Task<IndexAction>],
    ) -> impl Future<Output = Vec<IndexTaskResult>> + Send;
}

pub trait ReindexIndexTask: Sync + Send {
    fn reindex(
        &self,
        index: SearchIndex,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

const NUM_INDEXES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskType {
    Insert,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskStatus {
    Success,
    Failed,
    Ignored,
}

#[derive(Debug)]
pub(crate) struct IndexTaskResult {
    index: SearchIndex,
    task_type: TaskType,
    status: TaskStatus,
}

impl SearchIndexTask for Server {
    async fn index(&self, tasks: &[Task<IndexAction>]) -> Vec<IndexTaskResult> {
        let mut results: Vec<IndexTaskResult> = Vec::with_capacity(tasks.len());
        let mut batch = BatchBuilder::new();
        let mut document_insertions = Vec::new();
        let mut document_deletions: [AHashMap<u32, Vec<u32>>; NUM_INDEXES] =
            std::array::from_fn(|_| AHashMap::new());

        for task in tasks {
            if task.action.is_insert {
                let document = match task.action.index {
                    SearchIndex::Email => {
                        build_email_document(self, task.account_id, task.document_id).await
                    }
                    SearchIndex::Calendar => {
                        build_calendar_document(self, task.account_id, task.document_id).await
                    }
                    SearchIndex::Contacts => {
                        build_contact_document(self, task.account_id, task.document_id).await
                    }
                    SearchIndex::File => {
                        // File indexing not implemented yet
                        continue;
                    }
                    SearchIndex::Tracing => {
                        build_tracing_span_document(self, task.account_id, task.document_id).await
                    }
                    SearchIndex::InMemory => unreachable!(),
                };

                let result = match document {
                    Ok(Some(doc)) if !doc.is_empty() => {
                        document_insertions.push(doc);
                        TaskStatus::Success
                    }
                    Err(err) => {
                        trc::error!(
                            err.account_id(task.account_id)
                                .document_id(task.document_id)
                                .caused_by(trc::location!())
                                .ctx(trc::Key::Collection, task.action.index.name())
                                .details("Failed to build document for indexing")
                        );
                        TaskStatus::Failed
                    }
                    _ => {
                        trc::event!(
                            TaskQueue(TaskQueueEvent::TaskIgnored),
                            Collection = task.action.index.name(),
                            Reason = "Nothing to index",
                            AccountId = task.account_id,
                            DocumentId = task.document_id,
                        );
                        TaskStatus::Ignored
                    }
                };

                results.push(IndexTaskResult {
                    task_type: TaskType::Insert,
                    index: task.action.index,
                    status: result,
                });
            } else {
                let idx = match task.action.index {
                    SearchIndex::Email => {
                        if let Err(err) = delete_email_metadata(
                            self,
                            &mut batch,
                            task.account_id,
                            task.document_id,
                        )
                        .await
                        {
                            trc::error!(
                                err.account_id(task.account_id)
                                    .document_id(task.document_id)
                                    .caused_by(trc::location!())
                                    .details("Failed to delete email metadata from index")
                            );
                            results.push(IndexTaskResult {
                                task_type: TaskType::Delete,
                                index: task.action.index,
                                status: TaskStatus::Failed,
                            });
                            continue;
                        }
                        0
                    }
                    SearchIndex::Calendar => 1,
                    SearchIndex::Contacts => 2,
                    SearchIndex::File => 3,
                    SearchIndex::Tracing | SearchIndex::InMemory => unreachable!(),
                };

                document_deletions[idx]
                    .entry(task.account_id)
                    .or_default()
                    .push(task.document_id);

                results.push(IndexTaskResult {
                    task_type: TaskType::Delete,
                    index: task.action.index,
                    status: TaskStatus::Success,
                });
            }
        }

        // Commit deletion batch to data store
        if !batch.is_empty()
            && let Err(err) = self.store().write(batch.build_all()).await
        {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to commit index deletions to data store")
            );
            for r in results.iter_mut() {
                if r.task_type == TaskType::Delete
                    && r.status == TaskStatus::Success
                    && r.index == SearchIndex::Email
                {
                    r.status = TaskStatus::Failed;
                }
            }
            return results;
        }

        // Index documents
        if !document_insertions.is_empty()
            && let Err(err) = self.search_store().index(document_insertions).await
        {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to index documents")
            );
            for r in results.iter_mut() {
                if r.task_type == TaskType::Insert && r.status == TaskStatus::Success {
                    r.status = TaskStatus::Failed;
                }
            }
            return results;
        }

        // Delete documents
        for (accounts, index) in document_deletions.into_iter().zip([
            SearchIndex::Email,
            SearchIndex::Calendar,
            SearchIndex::Contacts,
        ]) {
            let multi_account = match accounts.len().cmp(&1) {
                Ordering::Greater => true,
                Ordering::Equal => false,
                Ordering::Less => continue,
            };

            let mut query = SearchQuery::new(index);
            if multi_account {
                query.add_filter(SearchFilter::Or);
            }

            for (account_id, document_ids) in accounts {
                let multi_document = document_ids.len() > 1;
                query
                    .add_filter(SearchFilter::And)
                    .add_filter(SearchFilter::eq(SearchField::AccountId, account_id));

                if multi_document {
                    query.add_filter(SearchFilter::Or);
                }

                for document_id in document_ids {
                    query.add_filter(SearchFilter::eq(SearchField::DocumentId, document_id));
                }

                if multi_document {
                    query.add_filter(SearchFilter::End);
                }
                query.add_filter(SearchFilter::End);
            }

            if multi_account {
                query.add_filter(SearchFilter::End);
            }

            if let Err(err) = self.search_store().unindex(query).await {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to delete documents from index")
                        .ctx(trc::Key::Collection, index.name())
                );
                for r in results.iter_mut() {
                    if r.task_type == TaskType::Delete && r.status == TaskStatus::Success {
                        r.status = TaskStatus::Failed;
                    }
                }
                return results;
            }
        }

        results
    }
}

impl ReindexIndexTask for Server {
    async fn reindex(
        &self,
        index: SearchIndex,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> trc::Result<()> {
        let accounts = if let Some(account_id) = account_id {
            RoaringBitmap::from_sorted_iter([account_id]).unwrap()
        } else {
            let mut accounts = RoaringBitmap::new();
            for principal in self
                .core
                .storage
                .data
                .list_principals(
                    None,
                    tenant_id,
                    &[Type::Individual, Type::Group],
                    false,
                    0,
                    0,
                )
                .await
                .caused_by(trc::location!())?
                .items
            {
                accounts.insert(principal.id());
            }
            accounts
        };
        let due = TaskEpoch::now();

        match index {
            SearchIndex::Email => {
                for account_id in accounts {
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email);

                    for document_id in self
                        .get_cached_messages(account_id)
                        .await
                        .caused_by(trc::location!())?
                        .emails
                        .items
                        .iter()
                        .map(|v| v.document_id)
                    {
                        batch.with_document(document_id).set(
                            ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                due,
                                index: SearchIndex::Email,
                                is_insert: true,
                            }),
                            0u64.serialize(),
                        );

                        if batch.len() >= 2000 {
                            self.core.storage.data.write(batch.build_all()).await?;
                            batch = BatchBuilder::new();
                            batch
                                .with_account_id(account_id)
                                .with_collection(Collection::Email);
                        }
                    }

                    if !batch.is_empty() {
                        self.core.storage.data.write(batch.build_all()).await?;
                    }
                }
            }
            SearchIndex::Calendar | SearchIndex::Contacts => {
                for account_id in accounts {
                    let cache = self
                        .fetch_dav_resources(
                            &AccessToken::from_id(account_id).with_tenant_id(tenant_id),
                            account_id,
                            if index == SearchIndex::Calendar {
                                SyncCollection::Calendar
                            } else {
                                SyncCollection::AddressBook
                            },
                        )
                        .await
                        .caused_by(trc::location!())?;
                    let mut batch = BatchBuilder::new();
                    batch.with_account_id(account_id);

                    for document_id in cache.document_ids(false) {
                        batch.with_document(document_id).set(
                            ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                due,
                                index,
                                is_insert: true,
                            }),
                            0u64.serialize(),
                        );

                        if batch.len() >= 2000 {
                            self.core.storage.data.write(batch.build_all()).await?;
                            batch = BatchBuilder::new();
                            batch.with_account_id(account_id);
                        }
                    }

                    if !batch.is_empty() {
                        self.core.storage.data.write(batch.build_all()).await?;
                    }
                }
            }
            SearchIndex::Tracing => {
                let mut spans = Vec::new();
                self.store()
                    .iterate(
                        IterateParams::new(
                            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span {
                                span_id: 0,
                            })),
                            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span {
                                span_id: u64::MAX,
                            })),
                        )
                        .no_values(),
                        |key, _| {
                            spans.push(key.deserialize_be_u64(0)?);
                            Ok(true)
                        },
                    )
                    .await
                    .caused_by(trc::location!())?;

                let mut batch = BatchBuilder::new();
                for span_id in spans {
                    batch
                        .with_account_id((span_id >> 32) as u32) // TODO: This is hacky, improve
                        .with_document(span_id as u32)
                        .set(
                            ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                due: TaskEpoch::now(),
                                index: SearchIndex::Tracing,
                                is_insert: true,
                            }),
                            vec![],
                        );
                    if batch.len() >= 2000 {
                        self.core.storage.data.write(batch.build_all()).await?;
                        batch = BatchBuilder::new();
                    }
                }

                if !batch.is_empty() {
                    self.core.storage.data.write(batch.build_all()).await?;
                }
            }
            SearchIndex::File | SearchIndex::InMemory => (),
        }

        // Request indexing
        self.notify_task_queue();

        Ok(())
    }
}

async fn build_email_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.jmap.index_fields.get(&SearchIndex::Email) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await?
    {
        Some(metadata_) => {
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;

            let raw_message = server
                .blob_store()
                .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| {
                    trc::StoreEvent::NotFound
                        .into_err()
                        .details("Blob not found")
                })?;

            Ok(Some(metadata.index_document(
                account_id,
                document_id,
                &raw_message,
                index_fields,
                server.core.jmap.default_language,
            )))
        }
        None => Ok(None),
    }
}

async fn build_calendar_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.jmap.index_fields.get(&SearchIndex::Calendar) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<CalendarEvent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.jmap.default_language,
                ),
        )),
        None => Ok(None),
    }
}

async fn build_contact_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.jmap.index_fields.get(&SearchIndex::Contacts) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::ContactCard,
            document_id,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<ContactCard>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.jmap.default_language,
                ),
        )),
        None => Ok(None),
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL

#[cfg(feature = "enterprise")]
async fn build_tracing_span_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    use common::telemetry::tracers::store::{TracingStore, build_span_document};

    let Some(index_fields) = server.core.jmap.index_fields.get(&SearchIndex::Tracing) else {
        return Ok(None);
    };

    let span_id = ((account_id as u64) << 32) | document_id as u64;
    let span = server.store().get_span(span_id).await?;

    if !span.is_empty() {
        Ok(Some(build_span_document(span_id, span, index_fields)))
    } else {
        Ok(None)
    }
}

// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
async fn build_tracing_span_document(
    _: &Server,
    _: u32,
    _: u32,
) -> trc::Result<Option<IndexDocument>> {
    Ok(None)
}

async fn delete_email_metadata(
    server: &Server,
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
) -> trc::Result<()> {
    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await?
    {
        Some(metadata_) => {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .with_document(document_id);
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;
            metadata.unindex(batch);

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL

            // Hold blob for undeletion
            #[cfg(feature = "enterprise")]
            {
                use common::enterprise::undelete::DeletedItemType;
                use email::message::metadata::ArchivedMetadataHeaderName;

                if let Some(undelete) = server
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.undelete.as_ref())
                {
                    use common::enterprise::undelete::DeletedItem;
                    use email::message::metadata::MESSAGE_RECEIVED_MASK;
                    use store::{
                        Serialize,
                        write::{Archiver, BlobLink, BlobOp, now},
                    };

                    let root_part = metadata.root_part();
                    let from: Option<Box<str>> = root_part.headers.iter().find_map(|h| {
                        if let ArchivedMetadataHeaderName::From = &h.name {
                            h.value.as_single_address().and_then(|addr| {
                                match (addr.address.as_ref(), addr.name.as_ref()) {
                                    (Some(address), Some(name)) => {
                                        Some(format!("{} <{}>", name, address).into_boxed_str())
                                    }
                                    (Some(address), None) => Some(address.as_ref().into()),
                                    (None, Some(name)) => Some(name.as_ref().into()),
                                    (None, None) => None,
                                }
                            })
                        } else {
                            None
                        }
                    });
                    let subject: Option<Box<str>> = root_part.headers.iter().rev().find_map(|h| {
                        if let ArchivedMetadataHeaderName::Subject = &h.name {
                            h.value.as_text().map(Into::into)
                        } else {
                            None
                        }
                    });
                    let now = now();
                    let until = now + undelete.retention.as_secs();
                    let blob_hash = BlobHash::from(&metadata.blob_hash);
                    batch
                        .set(
                            BlobOp::Link {
                                hash: blob_hash.clone(),
                                to: BlobLink::Temporary { until },
                            },
                            vec![BlobLink::UNDELETE_LINK],
                        )
                        .set(
                            BlobOp::Undelete {
                                hash: blob_hash,
                                until,
                            },
                            Archiver::new(DeletedItem {
                                typ: DeletedItemType::Email {
                                    from: from.unwrap_or_default(),
                                    subject: subject.unwrap_or_default(),
                                    received_at: metadata.rcvd_attach.to_native()
                                        & MESSAGE_RECEIVED_MASK,
                                },
                                size: root_part.offset_end.to_native(),
                                deleted_at: now,
                            })
                            .serialize()
                            .caused_by(trc::location!())?,
                        );
                }
            }

            // SPDX-SnippetEnd
        }
        None => {
            trc::event!(
                TaskQueue(TaskQueueEvent::MetadataNotFound),
                Details = "E-mail metadata not found",
                AccountId = account_id,
                DocumentId = document_id,
            );
        }
    }

    Ok(())
}

impl IndexTaskResult {
    pub fn is_done(&self) -> bool {
        self.status != TaskStatus::Failed
    }
}
