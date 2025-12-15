/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ingest::{EmailIngest, IngestedEmail},
    metadata::{MessageData, MessageMetadata},
};
use crate::{
    mailbox::UidMailbox,
    message::{
        index::extractors::VisitTextArchived,
        ingest::{MergeThreadIds, ThreadInfo},
        metadata::{
            MESSAGE_HAS_ATTACHMENT, MESSAGE_RECEIVED_MASK, MetadataHeaderName, MetadataHeaderValue,
        },
    },
};
use common::{Server, auth::ResourceToken, storage::index::ObjectIndexBuilder};
use mail_parser::parsers::fields::thread::thread_name;
use store::write::{
    BatchBuilder, IndexPropertyClass, SearchIndex, TaskEpoch, TaskQueueClass, ValueClass,
};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId},
    collection::{Collection, SyncCollection},
    field::EmailField,
    keyword::Keyword,
};
use utils::cheeky_hash::CheekyHash;

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
        resource_token: &ResourceToken,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<u64>,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<Result<IngestedEmail, CopyMessageError>>> + Send;
}

impl EmailCopy for Server {
    #[allow(clippy::too_many_arguments)]
    async fn copy_message(
        &self,
        from_account_id: u32,
        from_message_id: u32,
        resource_token: &ResourceToken,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<u64>,
        session_id: u64,
    ) -> trc::Result<Result<IngestedEmail, CopyMessageError>> {
        // Obtain metadata
        let account_id = resource_token.account_id;
        let mut metadata = if let Some(metadata) = self
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
        match self.has_available_quota(resource_token, size as u64).await {
            Ok(_) => (),
            Err(err) => {
                if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                    || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota))
                {
                    trc::error!(err.account_id(account_id).span_id(session_id));
                    return Ok(Err(CopyMessageError::OverQuota));
                } else {
                    return Err(err);
                }
            }
        }

        // Set receivedAt
        if let Some(received_at) = received_at {
            metadata.rcvd_attach = (metadata.rcvd_attach & MESSAGE_HAS_ATTACHMENT)
                | (received_at & MESSAGE_RECEIVED_MASK);
        }

        // Obtain threadId
        let mut message_ids = Vec::new();
        let mut subject = "";
        for header in &metadata.contents[0].parts[0].headers {
            match &header.name {
                MetadataHeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.push(CheekyHash::new(id.as_bytes()));
                        }
                    });
                }
                MetadataHeaderName::InReplyTo
                | MetadataHeaderName::References
                | MetadataHeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.push(CheekyHash::new(id.as_bytes()));
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
                _ => (),
            }
        }

        // Obtain threadId
        let thread_result = self
            .find_thread_id(account_id, subject, &message_ids)
            .await
            .caused_by(trc::location!())?;

        // Assign id
        let mut email = IngestedEmail {
            size: size as usize,
            ..Default::default()
        };
        let blob_hash = metadata.blob_hash.clone();

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(mailboxes.len());
        email.imap_uids = Vec::with_capacity(mailboxes.len());
        let mut ids = self
            .assign_email_ids(account_id, mailboxes.iter().copied(), true)
            .await
            .caused_by(trc::location!())?;
        let document_id = ids.next().unwrap();
        for (uid, mailbox_id) in ids.zip(mailboxes.iter().copied()) {
            mailbox_ids.push(UidMailbox::new(mailbox_id, uid));
            email.imap_uids.push(uid);
        }

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        // Determine thread id
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
                    .with_tenant_id(resource_token.tenant.map(|t| t.id))
                    .with_changes(MessageData {
                        mailboxes: mailbox_ids.into_boxed_slice(),
                        keywords: keywords.into_boxed_slice(),
                        thread_id,
                        size,
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
            .set(
                ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                    index: SearchIndex::Email,
                    due: TaskEpoch::now(),
                    is_insert: true,
                }),
                vec![],
            );

        // Merge threads if necessary
        if let Some(merge_threads) = MergeThreadIds::new(thread_result).serialize() {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::MergeThreads {
                    due: TaskEpoch::now(),
                }),
                merge_threads,
            );
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
            .last_change_id(account_id)?;

        // Request indexing
        self.notify_task_queue();

        // Update response
        email.document_id = document_id;
        email.thread_id = thread_id;
        email.change_id = change_id;
        email.blob_id = BlobId::new(
            blob_hash,
            BlobClass::Linked {
                account_id,
                collection: Collection::Email.into(),
                document_id,
            },
        );

        Ok(Ok(email))
    }
}
