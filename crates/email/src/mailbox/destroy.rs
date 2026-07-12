/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        delete::EmailDeletion,
        messagedata::{EmailMessageData, MessageData},
    },
};
use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
use registry::schema::{
    enums::IndexDocumentType,
    structs::{Task, TaskIndexDocument, TaskStatus},
};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use store::{roaring::RoaringBitmap, write::BatchBuilder};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, VanishedCollection},
    field::MailboxField,
};

pub trait MailboxDestroy: Sync + Send {
    fn mailbox_destroy(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        remove_emails: bool,
    ) -> impl Future<Output = trc::Result<Result<Option<u64>, MailboxDestroyError>>> + Send;
}

pub enum MailboxDestroyError {
    CannotDestroy,
    Forbidden,
    HasChildren,
    HasEmails,
    NotFound,
    AssertionFailed,
}

impl MailboxDestroy for Server {
    async fn mailbox_destroy(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        remove_emails: bool,
    ) -> trc::Result<Result<Option<u64>, MailboxDestroyError>> {
        // Internal folders cannot be deleted
        #[cfg(not(feature = "test_mode"))]
        if [INBOX_ID, TRASH_ID, JUNK_ID].contains(&document_id) {
            return Ok(Err(MailboxDestroyError::CannotDestroy));
        }

        // Verify that this mailbox does not have sub-mailboxes
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        if cache
            .mailboxes
            .items
            .iter()
            .any(|item| item.parent_id == document_id)
        {
            return Ok(Err(MailboxDestroyError::HasChildren));
        }

        // Verify that the mailbox is empty
        let mut batch = BatchBuilder::new();

        batch.with_account_id(account_id);

        let message_ids =
            RoaringBitmap::from_iter(cache.in_mailbox(document_id).map(|m| m.document_id));

        if !message_ids.is_empty() {
            if remove_emails {
                // If the message is in multiple mailboxes, untag it from the current mailbox,
                // otherwise delete it.

                let mut deleted_ids = RoaringBitmap::new();
                let mut thread_ids = RoaringBitmap::new();
                self.message_datas(account_id, &message_ids, |message_id, prev_message_data| {
                    // Remove mailbox from list
                    if !prev_message_data
                        .mailboxes
                        .iter()
                        .any(|id| id.mailbox_id == document_id)
                    {
                        return Ok(true);
                    }

                    if prev_message_data.mailboxes.len() == 1 {
                        // Delete message
                        for mailbox in prev_message_data.mailboxes.iter() {
                            batch.log_vanished_item(
                                VanishedCollection::Email,
                                (mailbox.mailbox_id, mailbox.uid),
                            );
                        }
                        deleted_ids.insert(message_id);
                        thread_ids.insert(prev_message_data.thread_id);
                        batch
                            .with_collection(Collection::Email)
                            .with_document(message_id)
                            .custom(
                                ObjectIndexBuilder::<_, ()>::new()
                                    .with_changed_by(access_token.account_tenant_ids())
                                    .with_current(prev_message_data),
                            )
                            .caused_by(trc::location!())?
                            .schedule_task(Task::UnindexDocument(TaskIndexDocument {
                                account_id: account_id.into(),
                                document_id: message_id.into(),
                                document_type: IndexDocumentType::Email,
                                status: TaskStatus::now(),
                            }))
                            .commit_point();
                    } else {
                        let new_message_data = MessageData {
                            mailboxes: prev_message_data
                                .mailboxes
                                .iter()
                                .filter(|m| m.mailbox_id != document_id)
                                .copied()
                                .collect(),
                            keywords: prev_message_data.keywords,
                            thread_id: prev_message_data.thread_id,
                            size: prev_message_data.size,
                            keywords_extra: prev_message_data.keywords_extra.to_vec(),
                            received_at: prev_message_data.received_at,
                            sent_at: prev_message_data.sent_at,
                            change_id: prev_message_data.change_id,
                        };

                        // Untag message from mailbox
                        batch
                            .with_collection(Collection::Email)
                            .with_document(message_id)
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_changed_by(access_token.account_tenant_ids())
                                    .with_changes(new_message_data)
                                    .with_current(prev_message_data),
                            )
                            .caused_by(trc::location!())?
                            .commit_point();
                    }

                    Ok(true)
                })
                .await
                .caused_by(trc::location!())?;

                self.log_emptied_threads(account_id, &mut batch, thread_ids, &deleted_ids)
                    .await
                    .caused_by(trc::location!())?;
            } else {
                return Ok(Err(MailboxDestroyError::HasEmails));
            }
        }

        // Obtain mailbox
        if let Some(mailbox_) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Mailbox,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
        {
            let mailbox = mailbox_
                .to_unarchived::<Mailbox>()
                .caused_by(trc::location!())?;
            // Validate ACLs
            if access_token.is_shared(account_id) {
                let acl = mailbox.inner.acls.effective_acl(access_token);
                if !acl.contains(Acl::Delete) || (remove_emails && !acl.contains(Acl::RemoveItems))
                {
                    return Ok(Err(MailboxDestroyError::Forbidden));
                }
            }
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .with_document(document_id)
                .clear(MailboxField::UidCounter)
                .custom(ObjectIndexBuilder::<_, ()>::new().with_current(mailbox))
                .caused_by(trc::location!())?;
        } else {
            return Ok(Err(MailboxDestroyError::NotFound));
        };

        if !batch.is_empty() {
            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id) => {
                    self.notify_task_queue();

                    Ok(Ok(Some(change_id)))
                }
                Err(err) if err.is_assertion_failure() => {
                    Ok(Err(MailboxDestroyError::AssertionFailed))
                }
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        } else {
            Ok(Ok(None))
        }
    }
}
