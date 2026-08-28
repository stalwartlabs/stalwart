/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ingest::{EmailIngest, IngestedEmail},
    metadata::MessageMetadata,
};
use crate::message::{
    index::extractors::VisitTextArchived,
    ingest::ThreadInfo,
    messagedata::{MessageData, PendingMessageData},
    metadata::{ArchivedMetadataHeaderName, ArchivedMetadataHeaderValue},
    sortkeys::MessageSortKeys,
};
use common::{MessageUid, Server, storage::index::ObjectIndexBuilder};
use mail_parser::{DateTime, parsers::fields::thread::thread_name};
use registry::{
    schema::structs::{Task, TaskMergeThreads, TaskStatus},
    types::map::Map,
};
use store::{
    Deserialize, ValueKey,
    write::{Archive, ArchiveBytes, SearchIndex, serialize::RawValue},
};
use store::{
    write::{BatchBuilder, IndexPropertyClass, ValueClass},
    xxhash_rust::xxh3::xxh3_128,
};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
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
        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(&metadata_bytes.0)
            .caused_by(trc::location!())?;
        let metadata = archive
            .unarchive::<MessageMetadata>()
            .caused_by(trc::location!())?;

        // Check quota
        let size = metadata.root_part().offset_end.to_native();
        let to_account = self.account(to_account_id).await?;
        match self.has_available_quota(&to_account, size as u64).await {
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
        let mut message_ids = Vec::new();
        let mut subject = "";
        let mut sent_at = None;
        for header in metadata.root_part().headers.iter() {
            match &header.name {
                ArchivedMetadataHeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.push(xxh3_128(id.as_bytes()));
                        }
                    });
                }
                ArchivedMetadataHeaderName::InReplyTo
                | ArchivedMetadataHeaderName::References
                | ArchivedMetadataHeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.push(xxh3_128(id.as_bytes()));
                        }
                    });
                }
                ArchivedMetadataHeaderName::Subject if subject.is_empty() => {
                    subject = thread_name(match &header.value {
                        ArchivedMetadataHeaderValue::Text(text) => text.as_ref(),
                        ArchivedMetadataHeaderValue::TextList(list) if !list.is_empty() => {
                            list.first().unwrap().as_ref()
                        }
                        _ => "",
                    });
                }
                ArchivedMetadataHeaderName::Date => {
                    if let ArchivedMetadataHeaderValue::DateTime(date) = &header.value {
                        sent_at = Some(DateTime::from(date).to_timestamp());
                    }
                }
                _ => (),
            }
        }

        message_ids.sort_unstable();
        message_ids.dedup();

        // Obtain threadId
        let thread_result = self
            .find_thread_id(to_account_id, subject, &message_ids)
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
        let blob_hash = BlobHash::from(&metadata.blob_hash);

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
        let mut mailbox_ids: TinyVec<[MessageUid; 2]> = TinyVec::with_capacity(mailboxes.len());
        let mut uid_slot = None;
        for mailbox_id in mailboxes.iter().copied() {
            let slot = batch.reserve_uid(to_account_id, mailbox_id);
            uid_slot.get_or_insert(slot);
            mailbox_ids.push(MessageUid::new_unassigned(mailbox_id));
        }

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

        let data = PendingMessageData {
            data: MessageData {
                mailboxes: mailbox_ids,
                keywords: keywords_flags,
                thread_id: thread_result.thread_id.unwrap_or_default(),
                size,
                keywords_extra,
                received_at,
                sent_at: sent_at
                    .map(|sent_at| (sent_at - received_at as i64) as i32)
                    .unwrap_or_default(),
                change_id: 0,
            },
            uid_slot,
            thread_slot,
            change_id: None,
        };
        let (thread_info, thread_info_patches) =
            ThreadInfo::serialize(data.thread_id(), &message_ids);

        batch
            .with_collection(Collection::Email)
            .create_document(document_slot)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_tenant_id(tenant_id)
                    .with_changes(data),
            )
            .caused_by(trc::location!())?
            .set_patched(
                ValueClass::IndexProperty(IndexPropertyClass::Hash {
                    property: EmailField::Threading.into(),
                    hash: thread_result.thread_hash,
                }),
                thread_info,
                thread_info_patches,
            )
            .queue_document_index(SearchIndex::Email, to_account_id, document_slot);

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
            None => MessageSortKeys::from_metadata(
                &archive
                    .deserialize::<MessageMetadata>()
                    .caused_by(trc::location!())?,
            )
            .serialize(),
        };

        metadata.index_verbatim(&mut batch, metadata_bytes.0, sort_keys);

        // Insert and obtain ids
        let queues = batch.queue_notify();
        let assigned_ids = self
            .store()
            .write_batch(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        let document_id = assigned_ids.slot(document_slot);

        // Request indexing
        self.notify_queues(queues).await;

        // Update response
        email.document_id = document_id;
        email.thread_id = thread_result.thread_id.unwrap_or(document_id);
        email.change_id =
            assigned_ids.last_change_id(to_account_id, SyncCollection::Email.change_group());
        email.imap_uids = uid_slot
            .into_iter()
            .flat_map(|uid_slot| (0..mailboxes.len()).map(move |offset| uid_slot.offset(offset)))
            .map(|uid_slot| assigned_ids.slot(uid_slot))
            .collect();
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
