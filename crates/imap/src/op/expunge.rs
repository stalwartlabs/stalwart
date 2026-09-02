/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapContext, ToModSeq};
use crate::core::{ImapId, SavedSearch, SelectedMailbox, Session, SessionData};
use ahash::AHashMap;
use common::{network::SessionStream, storage::index::ObjectIndexBuilder};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{delete::EmailDeletion, messagedata::EmailMessageData},
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    parser::parse_sequence_set,
    receiver::{Request, Token},
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, SearchIndex},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, VanishedCollection},
    keyword::Keyword,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_expunge(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapExpunge)?;

        let op_start = Instant::now();
        let (data, mailbox) = self.state.select_data();

        // Validate ACL
        if !data
            .check_mailbox_acl(
                mailbox.id.account_id,
                mailbox.id.mailbox_id,
                Acl::RemoveItems,
            )
            .await
            .imap_ctx(&request.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(concat!(
                    "You do not have the required permissions ",
                    "to remove messages from this mailbox."
                ))
                .code(ResponseCode::NoPerm)
                .id(request.tag));
        }

        // Parse sequence to operate on
        let sequence = match request.tokens.into_iter().next() {
            Some(Token::Argument(value)) if is_uid => {
                let sequence = parse_sequence_set(&value).map_err(|err| {
                    trc::ImapEvent::Error
                        .into_err()
                        .details(err)
                        .ctx(trc::Key::Type, ResponseType::Bad)
                        .id(request.tag.clone())
                })?;
                Some(
                    mailbox
                        .sequence_to_ids(&sequence, true)
                        .await
                        .map_err(|err| err.id(request.tag.clone()))?,
                )
            }

            _ => None,
        };

        // RFC 9738 limits UID EXPUNGE but never a plain EXPUNGE
        let message_limit = if is_uid {
            self.server.core.imap.max_messages_per_command
        } else {
            u32::MAX
        };

        // Expunge
        let limited_uid = data
            .expunge(mailbox.clone(), sequence, message_limit, op_start)
            .await
            .imap_ctx(&request.tag, trc::location!())?;

        // Clear saved searches
        *mailbox.saved_search.lock() = SavedSearch::None;

        // Synchronize messages
        let modseq = data
            .write_mailbox_changes(&mailbox, self.is_qresync || self.is_uidonly)
            .await
            .imap_ctx(&request.tag, trc::location!())?;
        let mut response =
            StatusResponse::completed(Command::Expunge(is_uid)).with_tag(request.tag);

        let mut untagged = Vec::new();
        if let Some(uid) = limited_uid {
            let code = ResponseCode::MessageLimit {
                limit: message_limit,
                uid: uid.into(),
            };
            if self.is_condstore {
                untagged = StatusResponse::ok("Some messages were not expunged.")
                    .with_code(code)
                    .into_bytes();
            } else {
                response = response.with_code(code);
            }
        }
        if self.is_condstore {
            response = response.with_code(ResponseCode::HighestModseq {
                modseq: modseq.to_modseq(),
            });
        }

        self.write_bytes(response.serialize(untagged)).await
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn expunge(
        &self,
        mailbox: Arc<SelectedMailbox>,
        sequence: Option<AHashMap<u32, ImapId>>,
        message_limit: u32,
        op_start: Instant,
    ) -> trc::Result<Option<u32>> {
        // Obtain message ids
        let account_id = mailbox.id.account_id;
        let mut deleted_ids = RoaringBitmap::from_iter(
            self.server
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?
                .in_mailbox_with_keyword(mailbox.id.mailbox_id, &Keyword::Deleted)
                .map(|m| m.document_id()),
        );

        // Filter by sequence
        if let Some(sequence) = &sequence {
            deleted_ids &= RoaringBitmap::from_iter(sequence.keys());
        }

        // RFC 9738 requires the highest UIDs to be processed first when truncating.
        let mut limited_uid = None;
        if deleted_ids.len() > message_limit as u64 {
            let mut uids = {
                let state = mailbox.state.lock();
                deleted_ids
                    .iter()
                    .filter_map(|id| state.id_to_imap.get(&id).map(|imap_id| (imap_id.uid, id)))
                    .collect::<Vec<_>>()
            };

            if uids.len() > message_limit as usize {
                let cutoff = uids.len() - message_limit as usize;
                let (below, lowest, _) = uids.select_nth_unstable(cutoff);
                limited_uid = Some(lowest.0);
                for (_, id) in below {
                    deleted_ids.remove(*id);
                }
            }
        }

        // Delete ids
        let mut batch = BatchBuilder::new();
        let (fully_deleted, thread_ids) = self
            .email_untag_or_delete(account_id, mailbox.id.mailbox_id, &deleted_ids, &mut batch)
            .await
            .caused_by(trc::location!())?;
        self.server
            .log_emptied_threads(account_id, &mut batch, thread_ids, &fully_deleted)
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Imap(trc::ImapEvent::Expunge),
            SpanId = self.session_id,
            AccountId = account_id,
            MailboxId = mailbox.id.mailbox_id,
            DocumentId = deleted_ids.iter().map(trc::Value::from).collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Write changes on source account
        if !batch.is_empty() {
            self.server
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(limited_uid)
    }

    pub async fn email_untag_or_delete(
        &self,
        account_id: u32,
        mailbox_id: u32,
        deleted_ids: &RoaringBitmap,
        batch: &mut BatchBuilder,
    ) -> trc::Result<(RoaringBitmap, RoaringBitmap)> {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email);

        let mut fully_deleted = RoaringBitmap::new();
        let mut thread_ids = RoaringBitmap::new();
        self.server
            .message_datas(account_id, deleted_ids, |document_id, metadata| {
                if let Some(message_uid) = metadata.message_uid(mailbox_id) {
                    // Add vanished items
                    batch.with_document(document_id);
                    batch.log_vanished_item(VanishedCollection::Email, (mailbox_id, message_uid));

                    if metadata.mailboxes.len() == 1 {
                        // Delete message
                        fully_deleted.insert(document_id);
                        thread_ids.insert(metadata.thread_id);
                        batch
                            .custom(
                                ObjectIndexBuilder::<_, ()>::new()
                                    .with_changed_by(self.access_token.account_tenant_ids())
                                    .with_current(metadata),
                            )
                            .caused_by(trc::location!())?
                            .queue_document_unindex(SearchIndex::Email, account_id, document_id)
                            .commit_point();
                    } else {
                        // Untag message from this mailbox and remove Deleted flag
                        let mut new_metadata = metadata.clone();
                        new_metadata.remove_mailbox(mailbox_id);
                        new_metadata.remove_keyword(&Keyword::Deleted);

                        // Write changes
                        batch
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_current(metadata)
                                    .with_changes(new_metadata),
                            )
                            .caused_by(trc::location!())?
                            .commit_point();
                    }
                }

                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;

        Ok((fully_deleted, thread_ids))
    }
}
