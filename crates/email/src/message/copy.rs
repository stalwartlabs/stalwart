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
    messagedata::MessageData,
    metadata::{MetadataHeaderName, MetadataHeaderValue},
};
use common::{MessageUid, Server, storage::index::ObjectIndexBuilder};
use mail_parser::{DateTime, parsers::fields::thread::thread_name};
use registry::{
    schema::{
        enums::IndexDocumentType,
        structs::{Task, TaskIndexDocument, TaskMergeThreads, TaskStatus},
    },
    types::map::Map,
};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
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
        // Obtain metadata
        let metadata = if let Some(metadata) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                from_account_id,
                Collection::Email,
                from_message_id,
                EmailField::Metadata,
            ))
            .await?
        {
            metadata
                .deserialize::<MessageMetadata>()
                .caused_by(trc::location!())?
        } else {
            return Ok(Err(CopyMessageError::NotFound));
        };

        // Check quota
        let size = metadata.root_part().offset_end;
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
        for header in &metadata.contents[0].parts[0].headers {
            match &header.name {
                MetadataHeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.push(xxh3_128(id.as_bytes()));
                        }
                    });
                }
                MetadataHeaderName::InReplyTo
                | MetadataHeaderName::References
                | MetadataHeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.push(xxh3_128(id.as_bytes()));
                        }
                    });
                }
                MetadataHeaderName::Subject if subject.is_empty() => {
                    subject = thread_name(match &header.value {
                        MetadataHeaderValue::Text(text) => text.as_ref(),
                        MetadataHeaderValue::TextList(list) if !list.is_empty() => {
                            list.first().unwrap().as_ref()
                        }
                        _ => "",
                    });
                }
                MetadataHeaderName::Date => {
                    if let MetadataHeaderValue::DateTime(date) = &header.value {
                        sent_at = Some(DateTime::from(date).to_timestamp());
                    }
                }
                _ => (),
            }
        }

        // Obtain threadId
        let thread_result = self
            .find_thread_id(to_account_id, subject, &message_ids)
            .await
            .caused_by(trc::location!())?;

        // Assign id
        let mut email = IngestedEmail {
            size: size as usize,
            ..Default::default()
        };
        let blob_hash = metadata.blob_hash.clone();

        // Assign IMAP UIDs
        let mut mailbox_ids: TinyVec<[MessageUid; 2]> = TinyVec::with_capacity(mailboxes.len());
        email.imap_uids = Vec::with_capacity(mailboxes.len());
        let mut ids = self
            .assign_email_ids(to_account_id, mailboxes.iter().copied(), true)
            .await
            .caused_by(trc::location!())?;
        let document_id = ids.next().unwrap();
        for (uid, mailbox_id) in ids.zip(mailboxes.iter().copied()) {
            mailbox_ids.push(MessageUid::new(mailbox_id, uid));
            email.imap_uids.push(uid);
        }

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

        // Determine thread id
        let tenant_id = to_account.tenant_id();
        let thread_id = if let Some(thread_id) = thread_result.thread_id {
            thread_id
        } else {
            batch
                .with_collection(Collection::Thread)
                .with_document(document_id)
                .log_container_insert(SyncCollection::Thread);
            document_id
        };
        batch
            .with_collection(Collection::Email)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_tenant_id(tenant_id)
                    .with_changes(MessageData {
                        mailboxes: mailbox_ids,
                        keywords: keywords_flags,
                        thread_id,
                        size,
                        keywords_extra,
                        received_at,
                        sent_at: sent_at
                            .map(|sent_at| (sent_at - received_at as i64) as i32)
                            .unwrap_or_default(),
                        change_id: 0,
                    }),
            )
            .caused_by(trc::location!())?
            .set(
                ValueClass::IndexProperty(IndexPropertyClass::Hash {
                    property: EmailField::Threading.into(),
                    hash: thread_result.thread_hash,
                }),
                ThreadInfo::serialize(thread_id, &message_ids),
            )
            .schedule_task(Task::IndexDocument(TaskIndexDocument {
                account_id: to_account_id.into(),
                document_id: document_id.into(),
                document_type: IndexDocumentType::Email,
                status: TaskStatus::now(),
            }));

        // Merge threads if necessary
        if !thread_result.merge_ids.is_empty() {
            batch.schedule_task(Task::MergeThreads(TaskMergeThreads {
                account_id: to_account_id.into(),
                status: TaskStatus::now(),
                thread_name: thread_result.thread_hash.to_string(),
                message_ids: Map::new(message_ids.into_iter().map(|id| id.to_string()).collect()),
            }));
        }

        metadata
            .index(&mut batch, true)
            .caused_by(trc::location!())?;

        // Insert and obtain ids
        let change_id = self
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?
            .last_change_id(to_account_id)?;

        // Request indexing
        self.notify_task_queue();

        // Update response
        email.document_id = document_id;
        email.thread_id = thread_id;
        email.change_id = change_id;
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
