/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    index::{MAX_SORT_FIELD_LENGTH, TrimTextValue, VisitText},
    ingest::{EmailIngest, IngestedEmail},
    metadata::{MessageData, MessageMetadata},
};
use crate::{
    mailbox::UidMailbox,
    message::ingest::{MergeThreadTask, ThreadInfo},
};
use common::{Server, auth::ResourceToken, storage::index::ObjectIndexBuilder};
use mail_parser::{HeaderName, HeaderValue, parsers::fields::thread::thread_name};
use store::write::{BatchBuilder, IndexPropertyClass, TaskQueueClass, ValueClass, now};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId},
    collection::{Collection, SyncCollection},
    field::EmailField,
    keyword::Keyword,
};
use utils::cheeky_hash::{CheekyHash, CheekyHashMap};

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
            .archive_by_property(
                from_account_id,
                Collection::Email,
                from_message_id,
                EmailField::Metadata.into(),
            )
            .await?
        {
            metadata
                .deserialize::<MessageMetadata>()
                .caused_by(trc::location!())?
        } else {
            return Ok(Err(CopyMessageError::NotFound));
        };

        // Check quota
        match self
            .has_available_quota(resource_token, metadata.size as u64)
            .await
        {
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
            metadata.received_at = received_at;
        }

        // Obtain threadId
        let mut message_ids = CheekyHashMap::default();
        let mut subject = "";
        for header in &metadata.contents[0].parts[0].headers {
            match &header.name {
                HeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.insert(CheekyHash::new(id.as_bytes()), true);
                        }
                    });
                }
                HeaderName::InReplyTo | HeaderName::References | HeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() {
                            message_ids.insert(CheekyHash::new(id.as_bytes()), false);
                        }
                    });
                }
                HeaderName::Subject if subject.is_empty() => {
                    subject = thread_name(match &header.value {
                        HeaderValue::Text(text) => text.as_ref(),
                        HeaderValue::TextList(list) if !list.is_empty() => {
                            list.first().unwrap().as_ref()
                        }
                        _ => "",
                    })
                    .trim_text(MAX_SORT_FIELD_LENGTH);
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
            size: metadata.size as usize,
            ..Default::default()
        };
        let blob_hash = metadata.blob_hash.clone();

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(mailboxes.len());
        email.imap_uids = Vec::with_capacity(mailboxes.len());
        for mailbox_id in &mailboxes {
            let uid = self
                .assign_imap_uid(account_id, *mailbox_id)
                .await
                .caused_by(trc::location!())?;
            mailbox_ids.push(UidMailbox::new(*mailbox_id, uid));
            email.imap_uids.push(uid);
        }

        // Obtain documentId
        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::Email, 1)
            .await
            .caused_by(trc::location!())?;

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
                ObjectIndexBuilder::<(), _>::new().with_changes(MessageData {
                    mailboxes: mailbox_ids,
                    keywords,
                    thread_id,
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
                ValueClass::TaskQueue(TaskQueueClass::IndexEmail { due: now() }),
                MergeThreadTask::new(thread_result).serialize(),
            );
        metadata
            .index(
                &mut batch,
                account_id,
                resource_token.tenant.map(|t| t.id),
                true,
            )
            .caused_by(trc::location!())?;

        // Insert and obtain ids
        let change_id = self
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?
            .last_change_id(account_id)?;

        // Request FTS index
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
