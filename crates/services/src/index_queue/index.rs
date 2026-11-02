/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::index_queue::document::{
    build_calendar_document, build_contact_document, build_email_document,
    build_tracing_span_document, is_email_indexed,
};
use crate::index_queue::file::build_file_document;
use crate::index_queue::{
    BULK_LINGER, BulkRequest, Deletion, ITEM_OVERSCAN, LOCK_EXPIRY, LOCK_MARGIN,
    MAX_DELETE_CLAUSES, MAX_FLUSH_TEXT_BYTES, Partition, PartitionFailure, PartitionOutcome,
    PendingItem, QueuedItem, Sink,
};
use common::{BuildServer, Inner, Server, storage::batch::MAX_BATCH_BYTES};
use email::message::{messagedata::EmailMessageData, metadata::MetadataRow, thread::ThreadSubject};
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use store::ahash::AHashMap;
use store::{
    Deserialize, IterateParams, U32_LEN, ValueKey,
    search::{IndexDocument, SearchField, SearchFilter, SearchQuery},
    write::{
        BatchBuilder, QueueDocumentId, SearchIndex, SearchIndexClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use tokio::sync::{mpsc, oneshot};
use trc::{AddContext, SearchIndexEvent};
use types::collection::Collection;

#[derive(Clone, Copy)]
enum Consumed {
    All,
    Through { id_prefix: u32, id_suffix: u32 },
}

#[derive(Default)]
struct FlushBudget(usize);

pub(crate) trait SearchIndexTask: Sync + Send {
    fn process_partition(
        &self,
        partition: Partition,
        sink: &Sink,
        batch_size: usize,
        is_clustered: bool,
    ) -> impl Future<Output = PartitionOutcome> + Send;
}

impl SearchIndexTask for Server {
    async fn process_partition(
        &self,
        partition: Partition,
        sink: &Sink,
        batch_size: usize,
        is_clustered: bool,
    ) -> PartitionOutcome {
        // Tthe distributed lock is only needed when other nodes may be indexing as well
        if is_clustered
            && !self
                .try_lock_search_index(partition.index, partition.partition, LOCK_EXPIRY)
                .await
        {
            trc::event!(
                SearchIndex(SearchIndexEvent::PartitionLocked),
                Index = partition.index.name(),
                Partition = partition.partition,
            );

            return PartitionOutcome::Locked;
        }

        let mut has_cleared_index = false;
        let mut outcome = drain_partition(
            self,
            partition,
            sink,
            batch_size,
            is_clustered,
            &mut has_cleared_index,
        )
        .await;

        // Restore the queue index
        if has_cleared_index
            && !matches!(outcome, PartitionOutcome::Completed)
            && let Err(err) = set_queue_index(self, partition).await
        {
            outcome = PartitionOutcome::Failed(err);
        }

        if is_clustered {
            self.unlock_search_index(partition.index, partition.partition)
                .await;
        }

        outcome
    }
}

async fn drain_partition(
    server: &Server,
    partition: Partition,
    sink: &Sink,
    batch_size: usize,
    is_clustered: bool,
    has_cleared_index: &mut bool,
) -> PartitionOutcome {
    let mut lease = Instant::now() + Duration::from_secs(LOCK_EXPIRY);
    let mut from_document = None;

    loop {
        if is_clustered {
            let now = Instant::now();

            if lease.saturating_duration_since(now) <= LOCK_MARGIN {
                if !server
                    .renew_search_index_lock(partition.index, partition.partition, LOCK_EXPIRY)
                    .await
                {
                    return PartitionOutcome::Incomplete;
                }

                lease = now + Duration::from_secs(LOCK_EXPIRY);
            }
        }

        let (items, is_exhausted) = match read_queue(
            server,
            partition,
            batch_size,
            sink.counts_deletions(),
            from_document,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                return PartitionOutcome::Failed(err);
            }
        };

        if items.is_empty() {
            if from_document.is_some() {
                // Documents may have been queued below the cursor
                from_document = None;
                continue;
            } else if *has_cleared_index {
                return PartitionOutcome::Completed;
            } else if let Err(err) = clear_queue_index(server, partition).await {
                return PartitionOutcome::Failed(err);
            }

            *has_cleared_index = true;
            continue;
        }

        if *has_cleared_index && !is_exhausted {
            if let Err(err) = set_queue_index(server, partition).await {
                return PartitionOutcome::Failed(err);
            }

            *has_cleared_index = false;
        }

        let consumed = match process_items(server, partition, &items, sink, is_exhausted).await {
            Ok(consumed) => consumed,
            Err(err) => return PartitionOutcome::Failed(err),
        };
        let is_drained = is_exhausted && consumed == items.len();

        from_document = if is_drained {
            None
        } else {
            consumed
                .checked_sub(1)
                .and_then(|last| items.get(last))
                .map(|item| (item.id_prefix, item.id_suffix))
        };

        *has_cleared_index |= is_drained;
    }
}

async fn process_items(
    server: &Server,
    partition: Partition,
    items: &[QueuedItem],
    sink: &Sink,
    clear_index: bool,
) -> Result<usize, PartitionFailure> {
    let started = Instant::now();
    let mut documents = Vec::new();
    let mut deletions = Vec::new();
    let mut batch = BatchBuilder::new();
    let mut budget = FlushBudget::default();

    let consumed = if matches!(partition.index, SearchIndex::Email) {
        process_email_items(
            server,
            partition,
            items,
            &mut documents,
            &mut deletions,
            &mut batch,
            &mut budget,
        )
        .await?
    } else {
        let mut consumed = Consumed::All;
        for item in pending_items(items) {
            if item.insert {
                let document = match partition.index {
                    SearchIndex::Calendar => {
                        build_calendar_document(server, item.id_prefix, item.id_suffix).await
                    }
                    SearchIndex::Contacts => {
                        build_contact_document(server, item.id_prefix, item.id_suffix).await
                    }
                    SearchIndex::Tracing => {
                        build_tracing_span_document(server, item.document_id()).await
                    }
                    SearchIndex::File => {
                        build_file_document(server, item.id_prefix, item.id_suffix).await
                    }
                    SearchIndex::Email | SearchIndex::InMemory => Ok(None),
                };

                match document {
                    Ok(Some(document)) if !document.is_empty() => {
                        let fits = budget.admit(&document);
                        documents.push(document);
                        if !fits {
                            consumed = Consumed::Through {
                                id_prefix: item.id_prefix,
                                id_suffix: item.id_suffix,
                            };
                            break;
                        }
                    }
                    Ok(_) => {
                        nothing_to_index(partition, item.id_prefix, item.id_suffix);
                    }
                    Err(err) => {
                        return Err(build_failure(
                            partition,
                            err.account_id(item.id_prefix).document_id(item.id_suffix),
                        ));
                    }
                }
            } else if !matches!(
                partition.index,
                SearchIndex::Tracing | SearchIndex::InMemory
            ) {
                batch.commit_point();
                deletions.push(Deletion {
                    index: partition.index,
                    account_id: item.id_prefix,
                    document_id: item.id_suffix,
                });
            }
        }
        consumed
    };
    let consumed = consumed.items(items);
    let (processed, remaining) = items.split_at_checked(consumed).unwrap_or((items, &[]));

    // Update the search index
    let total = documents.len();
    sink.flush(server, partition, documents, deletions).await?;
    if total > 0 {
        trc::event!(
            SearchIndex(SearchIndexEvent::BatchIndexed),
            Index = partition.index.name(),
            Partition = partition.partition,
            Total = total,
            Elapsed = started.elapsed(),
        );
    }

    // Delete the processed items together with any metadata scheduled for deletion
    for item in processed {
        batch.clear(partition.queue_class(item)).commit_point();
    }

    if clear_index && remaining.is_empty() {
        batch.clear(partition.index_class());
    }

    if let Err(err) = server.store().write_batch(&mut batch).await {
        let reason = err.to_string();
        trc::error!(
            err.details("Failed to delete processed search index queue items")
                .caused_by(trc::location!())
        );

        return Err(reason.into());
    }

    Ok(consumed)
}

async fn process_email_items(
    server: &Server,
    partition: Partition,
    items: &[QueuedItem],
    documents: &mut Vec<IndexDocument>,
    deletions: &mut Vec<Deletion>,
    batch: &mut BatchBuilder,
    budget: &mut FlushBudget,
) -> Result<Consumed, PartitionFailure> {
    let account_id = partition.partition;
    let is_indexed = is_email_indexed(server);
    let pending = pending_items(items).collect::<Vec<_>>();
    let mut remaining = pending.as_slice();

    while !remaining.is_empty() {
        let (rows, settled) = read_email_metadata(server, account_id, remaining, is_indexed)
            .await
            .map_err(|err| {
                let reason = err.to_string();
                trc::error!(
                    err.account_id(account_id)
                        .ctx(trc::Key::Index, partition.index.name())
                        .details("Failed to read email metadata for indexing")
                        .caused_by(trc::location!())
                );
                PartitionFailure::from(reason)
            })?;
        let (round, rest) = remaining
            .split_at_checked(settled)
            .unwrap_or((remaining, &[]));
        remaining = rest;

        let mut rows = rows.into_iter().peekable();
        for item in round {
            let row = rows
                .next_if(|(document_id, _)| *document_id == item.id_suffix)
                .map(|(_, row)| row);

            if item.insert {
                let Some(row) = row else {
                    nothing_to_index(partition, account_id, item.id_suffix);
                    continue;
                };
                let document = build_email_document(server, account_id, item.id_suffix, row)
                    .await
                    .map_err(|err| {
                        build_failure(
                            partition,
                            err.account_id(account_id).document_id(item.id_suffix),
                        )
                    })?;
                match document {
                    Some(document) if !document.is_empty() => {
                        let fits = budget.admit(&document);
                        documents.push(document);
                        if !fits {
                            return Ok(Consumed::Through {
                                id_prefix: account_id,
                                id_suffix: item.id_suffix,
                            });
                        }
                    }
                    _ => nothing_to_index(partition, account_id, item.id_suffix),
                }
            } else {
                if let Err(err) =
                    delete_email_metadata(server, batch, account_id, item.id_suffix, row.as_ref())
                {
                    let reason = err.to_string();
                    trc::error!(
                        err.account_id(account_id)
                            .document_id(item.id_suffix)
                            .details("Failed to delete email metadata from index")
                            .caused_by(trc::location!())
                    );

                    return Err(reason.into());
                }

                batch.commit_point();
                deletions.push(Deletion {
                    index: partition.index,
                    account_id,
                    document_id: item.id_suffix,
                });
            }
        }
    }

    Ok(Consumed::All)
}

impl Consumed {
    fn items(self, items: &[QueuedItem]) -> usize {
        match self {
            Consumed::All => items.len(),
            Consumed::Through {
                id_prefix,
                id_suffix,
            } => items
                .partition_point(|item| (item.id_prefix, item.id_suffix) <= (id_prefix, id_suffix)),
        }
    }
}

impl FlushBudget {
    fn admit(&mut self, document: &IndexDocument) -> bool {
        self.0 = self.0.saturating_add(document.text_len());
        self.0 < MAX_FLUSH_TEXT_BYTES
    }
}

async fn read_email_metadata(
    server: &Server,
    account_id: u32,
    items: &[PendingItem],
    is_indexed: bool,
) -> trc::Result<(Vec<(u32, MetadataRow)>, usize)> {
    let document_ids = items
        .iter()
        .filter(|item| is_indexed || !item.insert)
        .map(|item| item.id_suffix)
        .collect::<Vec<_>>();
    if document_ids.is_empty() {
        return Ok((Vec::new(), items.len()));
    }

    let mut rows = Vec::with_capacity(document_ids.len());
    let mut bytes = 0usize;
    server
        .message_metadata(account_id, &document_ids, |document_id, value| {
            let row =
                MetadataRow::deserialize(value).map_err(|err| err.document_id(document_id))?;
            bytes = bytes.saturating_add(row.decoded_len());
            rows.push((document_id, row));
            Ok(bytes < MAX_BATCH_BYTES)
        })
        .await?;

    let settled = match rows.last() {
        Some((last, _)) if bytes >= MAX_BATCH_BYTES => {
            items.partition_point(|item| item.id_suffix <= *last)
        }
        _ => items.len(),
    };

    Ok((rows, settled))
}

fn nothing_to_index(partition: Partition, account_id: u32, document_id: u32) {
    trc::event!(
        SearchIndex(SearchIndexEvent::DocumentIgnored),
        Index = partition.index.name(),
        AccountId = account_id,
        DocumentId = document_id,
        Reason = "Nothing to index",
    );
}

#[cold]
fn build_failure(partition: Partition, err: trc::Error) -> PartitionFailure {
    let reason = err.to_string();
    trc::error!(
        err.ctx(trc::Key::Index, partition.index.name())
            .details("Failed to build document for indexing")
            .caused_by(trc::location!())
    );
    reason.into()
}

impl Sink {
    fn counts_deletions(&self) -> bool {
        matches!(self, Sink::Internal)
    }

    async fn flush(
        &self,
        server: &Server,
        partition: Partition,
        documents: Vec<IndexDocument>,
        deletions: Vec<Deletion>,
    ) -> Result<(), PartitionFailure> {
        if documents.is_empty() && deletions.is_empty() {
            return Ok(());
        }

        match self {
            Sink::Internal => flush_partition(server, partition, documents, deletions).await,
            Sink::Bulk(tx) => {
                let (ack, ack_rx) = oneshot::channel();

                match tx
                    .send(BulkRequest {
                        documents,
                        deletions,
                        ack,
                    })
                    .await
                {
                    Ok(_) => ack_rx.await.unwrap_or_else(|_| {
                        Err("Bulk indexer is no longer available".to_string().into())
                    }),
                    Err(_) => Err("Bulk indexer is no longer available".to_string().into()),
                }
            }
        }
    }
}

pub(crate) fn spawn_bulk_indexer(
    inner: Arc<Inner>,
    batch_size: usize,
    active: Arc<AtomicUsize>,
) -> mpsc::Sender<BulkRequest> {
    let (tx, mut rx) = mpsc::channel::<BulkRequest>(1);

    tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            let mut num_documents = request.documents.len();
            let mut pending = vec![request];

            while num_documents < batch_size
                && pending.len() < std::cmp::max(active.load(Ordering::Relaxed), 1)
            {
                match tokio::time::timeout(BULK_LINGER, rx.recv()).await {
                    Ok(Some(request)) => {
                        num_documents += request.documents.len();
                        pending.push(request);
                    }
                    Ok(None) | Err(_) => break,
                }
            }

            let mut documents = Vec::with_capacity(num_documents);
            let mut deletions = Vec::new();
            for request in pending.iter_mut() {
                documents.append(&mut request.documents);
                deletions.append(&mut request.deletions);
            }

            let result = flush_documents(&inner.build_server(), documents, deletions).await;
            for request in pending {
                let _ = request.ack.send(result.clone());
            }
        }
    });

    tx
}

async fn flush_partition(
    server: &Server,
    partition: Partition,
    documents: Vec<IndexDocument>,
    deletions: Vec<Deletion>,
) -> Result<(), PartitionFailure> {
    let Some(store) = server.search_store().internal_fts() else {
        return flush_documents(server, documents, deletions).await;
    };

    // The internal store indexes and deletes a single partition at a time
    let result = if matches!(partition.index, SearchIndex::Tracing) {
        store.index_trace(documents).await
    } else {
        store
            .index_account_documents(
                partition.partition,
                partition.index,
                documents,
                deletions
                    .into_iter()
                    .map(|deletion| deletion.document_id)
                    .collect(),
            )
            .await
    };

    result.map_err(|err| {
        let reason = err.to_string();
        let failure = PartitionFailure::deferred(reason, &err);
        trc::error!(
            err.details("Failed to update the search index")
                .ctx(trc::Key::Index, partition.index.name())
                .ctx(trc::Key::Partition, partition.partition)
                .caused_by(trc::location!())
        );
        failure
    })
}

async fn flush_documents(
    server: &Server,
    documents: Vec<IndexDocument>,
    deletions: Vec<Deletion>,
) -> Result<(), PartitionFailure> {
    if !documents.is_empty()
        && let Err(err) = server.search_store().index(documents).await
    {
        let failure = PartitionFailure::deferred(err.to_string(), &err);
        trc::error!(
            err.details("Failed to index documents")
                .caused_by(trc::location!())
        );

        return Err(failure);
    }

    if !deletions.is_empty() {
        let mut indexes: AHashMap<SearchIndex, AHashMap<u32, Vec<u32>>> = AHashMap::new();
        for deletion in deletions {
            indexes
                .entry(deletion.index)
                .or_default()
                .entry(deletion.account_id)
                .or_default()
                .push(deletion.document_id);
        }

        for (index, accounts) in indexes {
            // Native stores limit the number of clauses a delete query may contain
            for chunk in delete_chunks(accounts) {
                let multi_account = chunk.len() > 1;
                let mut query = SearchQuery::new(index);

                if multi_account {
                    query.add_filter(SearchFilter::Or);
                }

                for (account_id, document_ids) in chunk {
                    let multi_document = document_ids.len() > 1;
                    query
                        .add_filter(SearchFilter::And)
                        .add_filter(SearchFilter::integer_eq(SearchField::AccountId, account_id));

                    if multi_document {
                        query.add_filter(SearchFilter::Or);
                    }

                    for document_id in document_ids {
                        query.add_filter(SearchFilter::integer_eq(
                            SearchField::DocumentId,
                            document_id,
                        ));
                    }

                    if multi_document {
                        query.add_filter(SearchFilter::End);
                    }
                    query.add_filter(SearchFilter::End);
                }

                if multi_account {
                    query.add_filter(SearchFilter::End);
                }

                if let Err(err) = server.search_store().unindex(query).await {
                    let failure = PartitionFailure::deferred(err.to_string(), &err);
                    trc::error!(
                        err.details("Failed to delete documents from index")
                            .ctx(trc::Key::Index, index.name())
                            .caused_by(trc::location!())
                    );

                    return Err(failure);
                }
            }
        }
    }

    Ok(())
}

async fn read_queue(
    server: &Server,
    partition: Partition,
    batch_size: usize,
    count_deletions: bool,
    from_document: Option<(u32, u32)>,
) -> Result<(Vec<QueuedItem>, bool), PartitionFailure> {
    let (mut from_class, to_class) =
        SearchIndexClass::queue_range(partition.index, partition.partition);

    // Resume after the last document of the previous batch
    if let Some((id_prefix, id_suffix)) = from_document
        && let SearchIndexClass::Queue {
            id_prefix: from_prefix,
            id_suffix: from_suffix,
            created_at,
            ..
        } = &mut from_class
    {
        *from_prefix = id_prefix;
        *from_suffix = QueueDocumentId::Assigned(id_suffix);
        *created_at = u64::MAX;
    }

    let max_items = batch_size * ITEM_OVERSCAN;
    let mut items: Vec<QueuedItem> = Vec::new();
    let mut documents = 0;
    let mut is_insert = false;
    let mut is_exhausted = true;

    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::SearchIndex(from_class)),
                ValueKey::from(ValueClass::SearchIndex(to_class)),
            )
            .ascending()
            .expect_rows(max_items),
            |key, value| {
                let item = QueuedItem {
                    id_prefix: key.deserialize_be_u32(1)?,
                    id_suffix: key.deserialize_be_u32(1 + U32_LEN)?,
                    created_at: key.deserialize_be_u64(1 + (U32_LEN * 2))?,
                    insert: value.first().is_some_and(|action| *action != 0),
                };

                match items.last() {
                    Some(last) if last.is_same_document(&item) => {
                        // A deletion turns the document into a deletion for good
                        if !item.insert && is_insert {
                            is_insert = false;
                            if !count_deletions {
                                documents -= 1;
                            }
                        }
                    }
                    _ => {
                        if documents >= batch_size || items.len() >= max_items {
                            is_exhausted = false;
                            return Ok(false);
                        }

                        is_insert = item.insert;
                        if count_deletions || is_insert {
                            documents += 1;
                        }
                    }
                }

                items.push(item);

                Ok(true)
            },
        )
        .await
        .map_err(|err| {
            let reason = err.to_string();
            trc::error!(
                err.details("Failed to iterate over the search index queue")
                    .ctx(trc::Key::Index, partition.index.name())
                    .ctx(trc::Key::Partition, partition.partition)
                    .caused_by(trc::location!())
            );
            PartitionFailure::from(reason)
        })?;

    Ok((items, is_exhausted))
}

fn delete_chunks(accounts: AHashMap<u32, Vec<u32>>) -> Vec<Vec<(u32, Vec<u32>)>> {
    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    let mut chunk_len = 0;

    for (account_id, document_ids) in accounts {
        for document_ids in document_ids.chunks(MAX_DELETE_CLAUSES) {
            if chunk_len + document_ids.len() > MAX_DELETE_CLAUSES && !chunk.is_empty() {
                chunks.push(std::mem::take(&mut chunk));
                chunk_len = 0;
            }

            chunk_len += document_ids.len();
            chunk.push((account_id, document_ids.to_vec()));
        }
    }

    if !chunk.is_empty() {
        chunks.push(chunk);
    }

    chunks
}

fn pending_items(items: &[QueuedItem]) -> impl Iterator<Item = PendingItem> {
    items
        .chunk_by(|prev, next| prev.is_same_document(next))
        .map(|documents| PendingItem {
            id_prefix: documents[0].id_prefix,
            id_suffix: documents[0].id_suffix,
            insert: documents.iter().all(|item| item.insert),
        })
}

async fn clear_queue_index(server: &Server, partition: Partition) -> Result<(), PartitionFailure> {
    let mut batch = BatchBuilder::new();
    batch.clear(partition.index_class());
    write_queue_index(server, batch).await
}

async fn set_queue_index(server: &Server, partition: Partition) -> Result<(), PartitionFailure> {
    let mut batch = BatchBuilder::new();
    batch.set(partition.index_class(), vec![]);
    write_queue_index(server, batch).await
}

async fn write_queue_index(
    server: &Server,
    mut batch: BatchBuilder,
) -> Result<(), PartitionFailure> {
    server
        .store()
        .write_batch(&mut batch)
        .await
        .map(|_| ())
        .map_err(|err| {
            let reason = err.to_string();
            trc::error!(
                err.details("Failed to update the search index queue")
                    .caused_by(trc::location!())
            );
            reason.into()
        })
}

fn delete_email_metadata(
    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))] server: &Server,
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    row: Option<&MetadataRow>,
) -> trc::Result<()> {
    match row {
        Some(row) => {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .with_document(document_id);
            let metadata = row.unarchive().caused_by(trc::location!())?;
            let headers;
            let thread_subject = match metadata.thread_subject() {
                ThreadSubject::Resolved(name) => Cow::Borrowed(name),
                ThreadSubject::InHeaders => {
                    headers = row.raw_headers().caused_by(trc::location!())?;
                    metadata.thread_subject_in(&headers)
                }
            };
            metadata.unindex(batch, &thread_subject);

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL

            // Hold blob for undeletion
            #[cfg(feature = "enterprise")]
            {
                if let Some(undelete_retention) = server
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.deleted_items_retention.as_ref())
                {
                    use email::message::metadata::{AddressHeader, Mailbox, Occurrence};
                    use registry::{
                        schema::{
                            prelude::{ObjectType, Property},
                            structs::{ArchivedEmail, ArchivedItem},
                        },
                        types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
                    };
                    use store::{
                        SerializeInfallible,
                        write::{BlobLink, BlobOp, RegistryClass, blob::BlobLinkValue, now},
                    };
                    use types::blob::BlobId;

                    let envelope = metadata.root().envelope();
                    let describe = |mailbox: Mailbox<'_>| match (mailbox.address, mailbox.name) {
                        (Some(address), Some(name)) => Some(format!("{name} <{address}>")),
                        (Some(address), None) => Some(address.into()),
                        (None, Some(name)) => Some(name.into()),
                        (None, None) => None,
                    };
                    let from = envelope
                        .addresses(AddressHeader::From, Occurrence::Last)
                        .first()
                        .and_then(describe);
                    let subject = envelope.subject().map(Into::into);
                    let date = envelope.datetime().map(|date| date.to_timestamp());

                    let now = now();
                    let until = now + undelete_retention.as_secs();
                    let blob_hash = metadata.blob_hash();
                    let blob_size = metadata.blob_size() as u64;

                    let item = ArchivedItem::Email(ArchivedEmail {
                        account_id: account_id.into(),
                        blob_id: BlobId::new(blob_hash.clone(), Default::default()),
                        archived_until: UTCDateTime::from_timestamp(until as i64),
                        archived_at: UTCDateTime::now(),
                        from: from.unwrap_or_default(),
                        received_at: date
                            .map(UTCDateTime::from_timestamp)
                            .unwrap_or_else(UTCDateTime::now),
                        subject: subject.unwrap_or_default(),
                        size: blob_size,
                    })
                    .to_pickled_vec();
                    let object_id = ObjectType::ArchivedItem.to_id();
                    let item_id = server.inner.data.registry_id_gen.generate();

                    batch
                        .set(
                            BlobOp::Link {
                                hash: blob_hash,
                                to: BlobLink::Temporary { until },
                            },
                            BlobLinkValue::new(blob_size).with_object_id(ObjectId::new(
                                ObjectType::ArchivedItem,
                                item_id.into(),
                            )),
                        )
                        .set(
                            ValueClass::Registry(RegistryClass::Index {
                                index_id: Property::AccountId.to_id(),
                                object_id,
                                item_id,
                                key: (account_id as u64).serialize(),
                            }),
                            vec![],
                        )
                        .set(
                            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                            item,
                        );
                }
            }

            // SPDX-SnippetEnd
        }
        None => {
            trc::event!(
                SearchIndex(SearchIndexEvent::MetadataNotFound),
                Details = "E-mail metadata not found",
                AccountId = account_id,
                DocumentId = document_id,
            );
        }
    }

    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/index_queue/index/tests.rs"]
mod tests;
