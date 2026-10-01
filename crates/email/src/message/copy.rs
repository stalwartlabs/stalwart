/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ingest::{EmailIngest, IngestedEmail};
use crate::cache::MessageCacheFetch;
use crate::message::{
    index::extractors::VisitText,
    ingest::ThreadInfo,
    ingest_metadata::IngestMetadata,
    messagedata::{MessageData, PendingMessageData},
    metadata::{HeaderId, MetadataRow},
    sortkeys::MessageSortKeys,
};
use common::{
    MessageUid, Server,
    storage::{index::ObjectIndexBuilder, metadata::PrivateMetadataCommit},
};
use mail_parser::HeaderForm;
use registry::{
    schema::{
        enums::StorageQuota,
        structs::{Task, TaskMergeThreads, TaskStatus},
    },
    types::map::Map,
};
use store::{
    Deserialize, ValueKey,
    write::{PendingId, QueueDocumentId, SearchIndex, serialize::RawValue},
};
use store::{
    write::{BatchBuilder, IndexPropertyClass, ValueClass},
    xxhash_rust::xxh3::xxh3_128,
};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId},
    collection::{Collection, SyncCollection},
    field::EmailField,
    keyword::Keyword,
};

pub enum CopyMessageError {
    NotFound,
    OverQuota,
    AlreadyExists(u32),
}

pub trait EmailCopy: Sync + Send {
    #[allow(clippy::too_many_arguments)]
    fn copy_message(
        &self,
        from_account_id: u32,
        from_message_id: u32,
        to_account_id: u32,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: u64,
        containers: Option<Box<IngestMetadata>>,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<Result<IngestedEmail, CopyMessageError>>> + Send;
}

impl EmailCopy for Server {
    #[allow(clippy::too_many_arguments)]
    async fn copy_message(
        &self,
        from_account_id: u32,
        from_message_id: u32,
        to_account_id: u32,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: u64,
        mut containers: Option<Box<IngestMetadata>>,
        session_id: u64,
    ) -> trc::Result<Result<IngestedEmail, CopyMessageError>> {
        // Obtain the metadata and sort key rows verbatim
        let (metadata_bytes, sort_keys_bytes) = tokio::try_join!(
            self.store().get_value::<RawValue>(ValueKey::immutable(
                from_account_id,
                Collection::Email,
                from_message_id,
                EmailField::Metadata,
            )),
            self.store().get_value::<RawValue>(ValueKey::immutable(
                from_account_id,
                Collection::Email,
                from_message_id,
                EmailField::SortKeys,
            )),
        )?;
        let Some(metadata_bytes) = metadata_bytes else {
            return Ok(Err(CopyMessageError::NotFound));
        };
        let row = MetadataRow::deserialize(&metadata_bytes.0).caused_by(trc::location!())?;
        let metadata = row.unarchive().caused_by(trc::location!())?;
        if let Some(containers) = containers.as_deref_mut() {
            containers.shared = containers
                .shared
                .take()
                .filter(|container| container.kinds().intersects(MessageData::TRACKED_METADATA));
        }

        // Check quota
        let size = u32::try_from(metadata.size()).unwrap_or(u32::MAX);
        let quota_size = u64::from(size)
            + containers
                .as_deref()
                .and_then(|containers| containers.shared.as_ref())
                .map_or(0, |container| container.len() as u64);
        let to_account = self.account(to_account_id).await?;
        let quota_result = match self.has_available_quota(&to_account, quota_size).await {
            Ok(_) => match self.object_quota_limit(&to_account, StorageQuota::MaxEmails) {
                Some(limit) => {
                    let used = self
                        .count_emails(to_account_id, limit)
                        .await
                        .caused_by(trc::location!())?;
                    self.assert_object_quota(&to_account, StorageQuota::MaxEmails, 1, || used)
                }
                None => Ok(()),
            },
            result => result,
        };
        match quota_result {
            Ok(_) => (),
            Err(err) => {
                if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                    || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota))
                {
                    trc::error!(err.account_id(to_account_id).span_id(session_id));
                    return Ok(Err(CopyMessageError::OverQuota));
                } else {
                    return Err(err);
                }
            }
        }

        // Obtain threadId
        let headers = row.raw_headers().caused_by(trc::location!())?;
        let mut message_ids = Vec::new();
        let root_headers = metadata.root().root_part().headers();
        for header in root_headers.iter() {
            if matches!(
                header.id(),
                HeaderId::MESSAGE_ID
                    | HeaderId::IN_REPLY_TO
                    | HeaderId::REFERENCES
                    | HeaderId::RESENT_MESSAGE_ID
            ) && let Some(raw) = headers.get(header.value_range())
            {
                HeaderForm::MessageIds.parse(raw).value().visit_text(|id| {
                    if !id.is_empty() {
                        message_ids.push(xxh3_128(id.as_bytes()));
                    }
                });
            }
        }
        let envelope = metadata.root().envelope();
        let subject = metadata.thread_subject_with(root_headers, &headers);
        let sent_at = envelope.datetime().map(|date| date.to_timestamp());

        message_ids.sort_unstable();
        message_ids.dedup();

        // Obtain threadId
        let thread_result = self
            .find_thread_id(to_account_id, &subject, &message_ids)
            .await
            .caused_by(trc::location!())?;

        if let Some(&existing) = thread_result.duplicate_ids.first() {
            return Ok(Err(CopyMessageError::AlreadyExists(existing)));
        }

        // Assign id
        let mut email = IngestedEmail {
            size: size as usize,
            ..Default::default()
        };
        let blob_hash = metadata.blob_hash();

        let mut keywords_flags = 0;
        let mut keywords_extra = Vec::new();
        for keyword in keywords {
            match keyword.into_id() {
                Ok(id) => keywords_flags |= 1 << id,
                Err(name) => keywords_extra.push(name),
            }
        }

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch.with_account_id(to_account_id);

        // Reserve a document id and one IMAP UID per target mailbox
        let document_slot = batch.reserve_document_id(to_account_id, Collection::Email);
        let uid_slots = batch.reserve_uids(to_account_id, mailboxes.iter().copied());
        let mailbox_ids: TinyVec<[MessageUid; 2]> = mailboxes
            .iter()
            .copied()
            .map(MessageUid::new_unassigned)
            .collect();

        // Determine thread id
        let tenant_id = to_account.tenant_id();
        let thread_slot = if thread_result.thread_id.is_none() {
            batch
                .with_collection(Collection::Thread)
                .create_document(document_slot)
                .log_container_insert(SyncCollection::Thread);
            Some(document_slot)
        } else {
            None
        };

        let mut data = PendingMessageData {
            data: MessageData {
                mailboxes: mailbox_ids,
                keywords: keywords_flags,
                thread_id: thread_result.thread_id.unwrap_or_default(),
                size,
                keywords_extra,
                received_at,
                sent_at: MessageData::sent_at_offset(sent_at, received_at),
                change_id: 0,
            },
            uid_slots,
            thread_slot,
            change_id: None,
        };
        if let Some(container) = containers
            .as_deref()
            .and_then(|containers| containers.shared.as_ref())
        {
            data.data.set_metadata_kinds(container.kinds());
        }
        let thread_info = ThreadInfo {
            thread_id: data.thread_id(),
            ref_ids: &message_ids,
        };

        batch
            .with_collection(Collection::Email)
            .create_document(document_slot)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_tenant_id(tenant_id)
                    .with_changes(data),
            )
            .caused_by(trc::location!())?
            .set(
                ValueClass::IndexProperty(IndexPropertyClass::Hash {
                    property: EmailField::Threading.into(),
                    hash: thread_result.thread_hash,
                }),
                thread_info,
            )
            .queue_document_index(SearchIndex::Email, to_account_id, QueueDocumentId::Current);

        let mut private_commit = PrivateMetadataCommit::default();
        if let Some(containers) = containers {
            containers
                .build(
                    &mut batch,
                    to_account_id,
                    tenant_id,
                    PendingId::Slot(document_slot),
                    &mut private_commit,
                )
                .caused_by(trc::location!())?;
        }

        // Merge threads if necessary
        if !thread_result.merge_ids.is_empty() {
            batch.schedule_task(Task::MergeThreads(TaskMergeThreads {
                account_id: to_account_id.into(),
                status: TaskStatus::now(),
                thread_name: thread_result.thread_hash.to_string(),
                message_ids: Map::new(message_ids.into_iter().map(|id| id.to_string()).collect()),
            }));
        }

        let sort_keys = match sort_keys_bytes {
            Some(sort_keys) => sort_keys.0,
            None => MessageSortKeys::from_envelope(envelope).serialize(),
        };

        metadata.index_verbatim(&mut batch, metadata_bytes.0, sort_keys);

        // Insert and obtain ids
        let queues = batch.queue_notify();
        let assigned_ids = self
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        self.inner.mark_caches_stale_from(&assigned_ids);
        self.private_metadata_committed(private_commit, &assigned_ids)
            .await;
        let document_id = assigned_ids.slot(document_slot);

        // Request indexing
        self.notify_queues(queues).await;

        // Update response
        email.document_id = document_id;
        email.thread_id = thread_result.thread_id.unwrap_or(document_id);
        email.change_id = assigned_ids.last_change_id(to_account_id, SyncCollection::Email);
        email.imap_uids = assigned_ids.slots(uid_slots).collect();
        email.blob_id = BlobId::new(
            blob_hash,
            BlobClass::Linked {
                account_id: to_account_id,
                collection: Collection::Email.into(),
                document_id,
            },
        );

        Ok(Ok(email))
    }
}
