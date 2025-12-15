/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::metadata::MessageData,
};
use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
use store::{
    SerializeInfallible,
    roaring::RoaringBitmap,
    write::{BatchBuilder, SearchIndex, TaskEpoch, TaskQueueClass, ValueClass},
};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
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

                self.archives(
                    account_id,
                    Collection::Email,
                    &message_ids,
                    |message_id, message_data_| {
                        // Remove mailbox from list
                        let prev_message_data = message_data_
                            .to_unarchived::<MessageData>()
                            .caused_by(trc::location!())?;
                        if !prev_message_data
                            .inner
                            .mailboxes
                            .iter()
                            .any(|id| id.mailbox_id == document_id)
                        {
                            return Ok(true);
                        }

                        if prev_message_data.inner.mailboxes.len() == 1 {
                            // Delete message
                            for mailbox in prev_message_data.inner.mailboxes.iter() {
                                batch.log_vanished_item(
                                    VanishedCollection::Email,
                                    (mailbox.mailbox_id.to_native(), mailbox.uid.to_native()),
                                );
                            }
                            batch
                                .with_collection(Collection::Email)
                                .with_document(message_id)
                                .custom(
                                    ObjectIndexBuilder::<_, ()>::new()
                                        .with_access_token(access_token)
                                        .with_current(prev_message_data),
                                )
                                .caused_by(trc::location!())?
                                .set(
                                    ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                        index: SearchIndex::Email,
                                        due: TaskEpoch::now(),
                                        is_insert: false,
                                    }),
                                    0u64.serialize(),
                                )
                                .commit_point();
                        } else {
                            let new_message_data = MessageData {
                                mailboxes: prev_message_data
                                    .inner
                                    .mailboxes
                                    .iter()
                                    .filter(|m| m.mailbox_id != document_id)
                                    .map(|m| m.to_native())
                                    .collect(),
                                keywords: prev_message_data
                                    .inner
                                    .keywords
                                    .iter()
                                    .map(|k| k.to_native())
                                    .collect(),
                                thread_id: prev_message_data.inner.thread_id.to_native(),
                                size: prev_message_data.inner.size.to_native(),
                            };

                            // Untag message from mailbox
                            batch
                                .with_collection(Collection::Email)
                                .with_document(message_id)
                                .custom(
                                    ObjectIndexBuilder::new()
                                        .with_access_token(access_token)
                                        .with_changes(new_message_data)
                                        .with_current(prev_message_data),
                                )
                                .caused_by(trc::location!())?
                                .commit_point();
                        }

                        Ok(true)
                    },
                )
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
