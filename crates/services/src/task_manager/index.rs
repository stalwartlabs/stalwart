/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{Task, TaskDetails, TaskResult};
use common::Server;
use email::{cache::MessageCacheFetch, message::metadata::MessageMetadata};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent, contact::ContactCard};
use registry::{
    schema::{
        enums::IndexDocumentType,
        prelude::{ObjectType, Property},
        structs::{TaskIndexDocument, TaskIndexTrace, TaskStatus},
    },
    types::EnumImpl,
};
use std::cmp::Ordering;
use store::{
    IterateParams, ValueKey,
    ahash::AHashMap,
    rand::{self, Rng},
    registry::RegistryQuery,
    roaring::RoaringBitmap,
    search::{IndexDocument, SearchField, SearchFilter, SearchQuery},
    write::{
        AlignedBytes, Archive, BatchBuilder, SearchIndex, TelemetryClass, ValueClass,
        key::DeserializeBigEndian, now,
    },
};
use trc::{AddContext, TaskQueueEvent};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::EmailField,
};

pub(crate) trait SearchIndexTask: Sync + Send {
    fn index(&self, tasks: &[TaskDetails]) -> impl Future<Output = Vec<IndexTaskResult>> + Send;
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

#[derive(Debug)]
pub(crate) struct IndexTaskResult {
    index: IndexDocumentType,
    task_type: TaskType,
    pub result: TaskResult,
}

impl SearchIndexTask for Server {
    async fn index(&self, tasks: &[TaskDetails]) -> Vec<IndexTaskResult> {
        let mut results: Vec<IndexTaskResult> = Vec::with_capacity(tasks.len());
        let mut batch = BatchBuilder::new();
        let mut document_insertions = Vec::new();
        let mut document_deletions: [AHashMap<u32, Vec<u32>>; NUM_INDEXES] =
            std::array::from_fn(|_| AHashMap::new());

        for task in tasks {
            match &task.task {
                Task::IndexDocument(task) => {
                    let account_id = task.account_id.document_id();
                    let document_id = task.document_id.document_id();

                    let document = match task.document_type {
                        IndexDocumentType::Email => {
                            build_email_document(self, account_id, document_id).await
                        }
                        IndexDocumentType::Calendar => {
                            build_calendar_document(self, account_id, document_id).await
                        }
                        IndexDocumentType::Contacts => {
                            build_contact_document(self, account_id, document_id).await
                        }
                        IndexDocumentType::File => {
                            // File indexing not implemented yet
                            continue;
                        }
                    };

                    let result = match document {
                        Ok(Some(doc)) if !doc.is_empty() => {
                            document_insertions.push(doc);
                            TaskResult::Success
                        }
                        Err(err) => {
                            let result = TaskResult::temporary(err.to_string());
                            trc::error!(
                                err.account_id(account_id)
                                    .document_id(document_id)
                                    .caused_by(trc::location!())
                                    .ctx(trc::Key::Collection, task.document_type.as_str())
                                    .details("Failed to build document for indexing")
                            );
                            result
                        }
                        _ => {
                            trc::event!(
                                TaskQueue(TaskQueueEvent::TaskIgnored),
                                Collection = task.document_type.as_str(),
                                Reason = "Nothing to index",
                                AccountId = account_id,
                                DocumentId = document_id,
                            );
                            TaskResult::Ignored
                        }
                    };

                    results.push(IndexTaskResult {
                        task_type: TaskType::Insert,
                        index: task.document_type,
                        result,
                    });
                }
                Task::IndexTrace(task) => {
                    let result = match build_tracing_span_document(self, task.trace_id.id()).await {
                        Ok(Some(doc)) if !doc.is_empty() => {
                            document_insertions.push(doc);
                            TaskResult::Success
                        }
                        Err(err) => {
                            let result = TaskResult::temporary(err.to_string());
                            trc::error!(
                                err.id(task.trace_id.id())
                                    .caused_by(trc::location!())
                                    .details("Failed to build document for indexing")
                            );
                            result
                        }
                        _ => {
                            trc::event!(
                                TaskQueue(TaskQueueEvent::TaskIgnored),
                                Reason = "Nothing to index",
                                Id = task.trace_id.id(),
                            );
                            TaskResult::Ignored
                        }
                    };

                    results.push(IndexTaskResult {
                        task_type: TaskType::Insert,
                        index: IndexDocumentType::File, // use File index for tracing spans to avoid creating a new index type
                        result,
                    });
                }
                Task::UnindexDocument(task) => {
                    let account_id = task.account_id.document_id();
                    let document_id = task.document_id.document_id();
                    let idx = match task.document_type {
                        IndexDocumentType::Email => {
                            if let Err(err) =
                                delete_email_metadata(self, &mut batch, account_id, document_id)
                                    .await
                            {
                                trc::error!(
                                    err.account_id(account_id)
                                        .document_id(document_id)
                                        .caused_by(trc::location!())
                                        .details("Failed to delete email metadata from index")
                                );
                                results.push(IndexTaskResult {
                                    task_type: TaskType::Delete,
                                    index: task.document_type,
                                    result: TaskResult::temporary(
                                        "Failed to delete email metadata from index",
                                    ),
                                });
                                continue;
                            }
                            0
                        }
                        IndexDocumentType::Calendar => 1,
                        IndexDocumentType::Contacts => 2,
                        IndexDocumentType::File => 3,
                    };

                    document_deletions[idx]
                        .entry(account_id)
                        .or_default()
                        .push(document_id);

                    results.push(IndexTaskResult {
                        task_type: TaskType::Delete,
                        index: task.document_type,
                        result: TaskResult::Success,
                    });
                }
                _ => unreachable!(),
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
                    && r.result == TaskResult::Success
                    && r.index == IndexDocumentType::Email
                {
                    r.result =
                        TaskResult::temporary("Failed to commit index deletions to data store");
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
                if r.task_type == TaskType::Insert && r.result == TaskResult::Success {
                    r.result = TaskResult::temporary("Failed to index documents");
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
                    if r.task_type == TaskType::Delete && r.result == TaskResult::Success {
                        r.result = TaskResult::temporary("Failed to delete documents from index");
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
            self.registry()
                .query(
                    RegistryQuery::new(ObjectType::Account)
                        .equal_opt(Property::MemberTenantId, tenant_id),
                )
                .await
                .caused_by(trc::location!())?
        };

        let now = now() as i64;
        match index {
            SearchIndex::Email => {
                for account_id in accounts {
                    let mut batch = BatchBuilder::new();

                    for document_id in self
                        .get_cached_messages(account_id)
                        .await
                        .caused_by(trc::location!())?
                        .emails
                        .items
                        .iter()
                        .map(|v| v.document_id)
                    {
                        batch.schedule_task(Task::IndexDocument(TaskIndexDocument {
                            account_id: account_id.into(),
                            document_id: document_id.into(),
                            document_type: IndexDocumentType::Email,
                            status: TaskStatus::at(now + rand::rng().random_range(0..=300)),
                        }));

                        if batch.len() >= 2000 {
                            self.core.storage.data.write(batch.build_all()).await?;
                            batch = BatchBuilder::new();
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
                            account_id,
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

                    for document_id in cache.document_ids(false) {
                        batch.schedule_task(Task::IndexDocument(TaskIndexDocument {
                            account_id: account_id.into(),
                            document_id: document_id.into(),
                            document_type: if index == SearchIndex::Calendar {
                                IndexDocumentType::Calendar
                            } else {
                                IndexDocumentType::Contacts
                            },
                            status: TaskStatus::at(now + rand::rng().random_range(0..=300)),
                        }));

                        if batch.len() >= 2000 {
                            self.core.storage.data.write(batch.build_all()).await?;
                            batch = BatchBuilder::new();
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
                    batch.schedule_task(Task::IndexTrace(TaskIndexTrace {
                        trace_id: span_id.into(),
                        status: TaskStatus::at(now + rand::rng().random_range(0..=300)),
                    }));
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
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Email) else {
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
                server.core.email.default_language,
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
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Calendar) else {
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
                    server.core.email.default_language,
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
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Contacts) else {
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
                    server.core.email.default_language,
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
    span_id: u64,
) -> trc::Result<Option<IndexDocument>> {
    use common::telemetry::tracers::store::{TracingStore, build_span_document};

    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Tracing) else {
        return Ok(None);
    };

    let span = server.tracing_store().get_span(span_id).await?;

    if !span.is_empty() {
        Ok(Some(build_span_document(span_id, span, index_fields)))
    } else {
        Ok(None)
    }
}

// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
async fn build_tracing_span_document(_: &Server, _: u64) -> trc::Result<Option<IndexDocument>> {
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
                use email::message::metadata::ArchivedMetadataHeaderName;

                if let Some(undelete_retention) = server
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.undelete_retention.as_ref())
                {
                    use email::message::metadata::MESSAGE_RECEIVED_MASK;
                    use registry::{
                        pickle::Pickle,
                        schema::structs::{DeletedEmail, DeletedItem},
                        types::{datetime::UTCDateTime, id::ObjectId},
                    };
                    use store::{
                        SerializeInfallible,
                        write::{BlobLink, BlobOp, RegistryClass, now},
                        xxhash_rust,
                    };
                    use types::blob::BlobId;
                    use utils::snowflake::SnowflakeIdGenerator;

                    let root_part = metadata.root_part();
                    let from: Option<String> = root_part.headers.iter().find_map(|h| {
                        if let ArchivedMetadataHeaderName::From = &h.name {
                            h.value.as_single_address().and_then(|addr| {
                                match (addr.address.as_ref(), addr.name.as_ref()) {
                                    (Some(address), Some(name)) => {
                                        Some(format!("{} <{}>", name, address))
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
                    let subject: Option<String> = root_part.headers.iter().rev().find_map(|h| {
                        if let ArchivedMetadataHeaderName::Subject = &h.name {
                            h.value.as_text().map(Into::into)
                        } else {
                            None
                        }
                    });
                    let now = now();
                    let until = now + undelete_retention.as_secs();
                    let blob_hash = BlobHash::from(&metadata.blob_hash);

                    let item = DeletedItem::Email(DeletedEmail {
                        account_id: account_id.into(),
                        blob_id: BlobId::new(blob_hash.clone(), Default::default()),
                        cleanup_at: UTCDateTime::from_timestamp(until as i64),
                        deleted_at: UTCDateTime::now(),
                        from: from.unwrap_or_default(),
                        received_at: UTCDateTime::from_timestamp(
                            (metadata.rcvd_attach.to_native() & MESSAGE_RECEIVED_MASK) as i64,
                        ),
                        subject: subject.unwrap_or_default(),
                        size: root_part.offset_end.to_native() as u64,
                    })
                    .to_pickled_vec();
                    let object_id = ObjectType::DeletedItem.to_id();
                    let item_id = SnowflakeIdGenerator::from_sequence_id(
                        xxhash_rust::xxh3::xxh3_64(item.as_slice()),
                    )
                    .unwrap_or_default();

                    batch
                        .set(
                            BlobOp::Link {
                                hash: blob_hash,
                                to: BlobLink::Temporary { until },
                            },
                            ObjectId::new(ObjectType::DeletedItem, item_id.into()).serialize(),
                        )
                        .set(
                            ValueClass::Registry(RegistryClass::Index {
                                index_id: Property::AccountId.to_id(),
                                object_id,
                                item_id,
                                key: account_id.serialize(),
                            }),
                            vec![],
                        )
                        .set(
                            ValueClass::Registry(RegistryClass::Id { object_id, item_id }),
                            item,
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
