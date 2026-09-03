/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ImapContext;
use crate::{
    core::{SelectedMailbox, Session, SessionData},
    spawn_op,
};
use common::{MessageStoreCache, cache::email::MessageRef, network::SessionStream};
use compact_str::CompactString;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::TRASH_ID,
    message::{
        ingest::EmailIngest,
        messagedata::{KeywordDiff, merge_keywords},
    },
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::{
        Flag, ImapResponse,
        fetch::{DataItem, FetchItem},
        store::{Arguments, Operation, Response},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use store::write::{BatchBuilder, PendingId};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    keyword::Keyword,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_store(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
        spawn: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStore)?;

        let op_start = Instant::now();
        let arguments = request.parse_store()?;
        let (data, mailbox) = self.state.select_data();
        let is_condstore = self.is_condstore || mailbox.is_condstore;
        let is_utf8 = self.is_utf8;
        let is_uidonly = self.is_uidonly;
        let message_limit = self.server.core.imap.max_messages_per_command;

        if spawn {
            spawn_op!(data, {
                let response = data
                    .store(
                        arguments,
                        mailbox,
                        is_uid,
                        is_condstore,
                        is_utf8,
                        is_uidonly,
                        message_limit,
                        op_start,
                    )
                    .await?;

                data.write_bytes(response).await
            })
        } else {
            let response = data
                .store(
                    arguments,
                    mailbox,
                    is_uid,
                    is_condstore,
                    is_utf8,
                    is_uidonly,
                    message_limit,
                    op_start,
                )
                .await?;

            data.write_bytes(response).await
        }
    }
}

#[derive(Default)]
struct KeywordEdit {
    added: u32,
    removed: u32,
    added_extra: Vec<CompactString>,
    removed_extra: Vec<CompactString>,
}

impl KeywordEdit {
    fn compute(
        cache: &MessageStoreCache,
        message: MessageRef<'_>,
        operation: &Operation,
        keywords: &[Keyword],
    ) -> Self {
        let mut edit = KeywordEdit::default();
        match operation {
            Operation::Set => {
                edit.add_missing(cache, message, keywords);
                for keyword in cache.expand_keywords(message).filter(|keyword| {
                    !matches!(keyword, Keyword::HasAttachment | Keyword::HasNoAttachment)
                        && !keywords.contains(keyword)
                }) {
                    match keyword.into_id() {
                        Ok(id) => edit.removed |= 1 << id,
                        Err(name) => edit.removed_extra.push(name),
                    }
                }
            }
            Operation::Add => {
                edit.add_missing(cache, message, keywords);
            }
            Operation::Clear => {
                for keyword in keywords
                    .iter()
                    .filter(|keyword| cache.has_keyword(message, keyword))
                {
                    match keyword.id() {
                        Ok(id) => edit.removed |= 1 << id,
                        Err(name) => edit.removed_extra.push(name.into()),
                    }
                }
            }
        }
        edit
    }

    fn add_missing(
        &mut self,
        cache: &MessageStoreCache,
        message: MessageRef<'_>,
        keywords: &[Keyword],
    ) {
        for keyword in keywords
            .iter()
            .filter(|keyword| !cache.has_keyword(message, keyword))
        {
            match keyword.id() {
                Ok(id) => self.added |= 1 << id,
                Err(name) => self.added_extra.push(name.into()),
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.added == 0
            && self.removed == 0
            && self.added_extra.is_empty()
            && self.removed_extra.is_empty()
    }

    fn adds(&self, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => self.added & (1 << id) != 0,
            Err(name) => self.added_extra.iter().any(|extra| extra == name),
        }
    }

    fn removes(&self, keyword: &Keyword) -> bool {
        match keyword.id() {
            Ok(id) => self.removed & (1 << id) != 0,
            Err(name) => self.removed_extra.iter().any(|extra| extra == name),
        }
    }

    fn spam_training(&self, message: MessageRef<'_>) -> Option<bool> {
        if self.adds(&Keyword::Junk) {
            Some(true)
        } else if !message.has_mailbox_id(TRASH_ID)
            && (self.adds(&Keyword::NotJunk) || self.removes(&Keyword::Junk))
        {
            Some(false)
        } else {
            None
        }
    }

    fn flags(
        &self,
        cache: &MessageStoreCache,
        message: MessageRef<'_>,
        keywords: &[Keyword],
    ) -> Vec<Flag> {
        cache
            .expand_keywords(message)
            .filter(|keyword| !self.removes(keyword))
            .chain(
                keywords
                    .iter()
                    .filter(|keyword| self.adds(keyword))
                    .cloned(),
            )
            .map(Flag::from)
            .collect()
    }

    fn into_diff(self, operation: &Operation, keywords: &[Keyword]) -> KeywordDiff {
        if matches!(operation, Operation::Set) {
            KeywordDiff::replace(keywords.to_vec())
        } else {
            KeywordDiff::Patch {
                added: self.added,
                removed: self.removed,
                added_extra: self.added_extra,
                removed_extra: self.removed_extra,
            }
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
        is_condstore: bool,
        is_utf8: bool,
        is_uidonly: bool,
        message_limit: u32,
        op_start: Instant,
    ) -> trc::Result<Vec<u8>> {
        // Resync messages if needed
        let account_id = mailbox.id.account_id;
        let cache = self
            .server
            .get_cached_messages(account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        self.sync_view(&mailbox, &cache, None)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert IMAP ids to JMAP ids.
        let mut ids = mailbox
            .resolve(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        if ids.is_empty() {
            return Ok(StatusResponse::completed(Command::Store(is_uid))
                .with_tag(arguments.tag)
                .into_bytes());
        }

        // Verify that the user can modify messages in this mailbox.
        if !self
            .check_mailbox_acl(
                Some(&cache),
                mailbox.id.account_id,
                mailbox.id.mailbox_id,
                Acl::ModifyItems,
            )
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(
                    "You do not have the required permissions to modify messages in this mailbox.",
                )
                .id(arguments.tag)
                .code(ResponseCode::NoPerm)
                .caused_by(trc::location!()));
        }

        // Filter out unchanged since ids
        let mut response_code = None;
        let mut unchanged_failed = false;
        if let Some(unchanged_since) = arguments.unchanged_since {
            let (mut modified, expunged) =
                mailbox.missing_in(&arguments.sequence_set, is_uid).await;
            unchanged_failed = expunged && !is_uid;

            ids.retain(|resolved| {
                let is_modified = cache
                    .email_by_id(&resolved.id)
                    .is_none_or(|message| message.change_id() >= unchanged_since);
                if is_modified {
                    let imap_id = resolved.imap_id(is_uid);
                    modified.push((imap_id, imap_id));
                }
                !is_modified
            });

            if !modified.is_empty() {
                modified.sort_unstable();
                modified.dedup_by(|next, prev| {
                    if next.0 <= prev.1.saturating_add(1) {
                        prev.1 = prev.1.max(next.1);
                        true
                    } else {
                        false
                    }
                });
                response_code = ResponseCode::Modified { ranges: modified }.into();
            }
        }

        // Build response
        let mut response = if !unchanged_failed {
            StatusResponse::completed(Command::Store(is_uid))
        } else {
            StatusResponse::no("Some of the messages no longer exist.")
        }
        .with_tag(arguments.tag);
        if let Some(response_code) = response_code {
            response = response.with_code(response_code)
        }
        if ids.is_empty() {
            trc::event!(
                Imap(trc::ImapEvent::Store),
                SpanId = self.session_id,
                AccountId = mailbox.id.account_id,
                MailboxId = mailbox.id.mailbox_id,
                Type = format!("{:?}", arguments.operation),
                Details = arguments
                    .keywords
                    .iter()
                    .map(|c| trc::Value::from(format!("{c:?}")))
                    .collect::<Vec<_>>(),
                Elapsed = op_start.elapsed()
            );

            return Ok(response.into_bytes());
        }

        // RFC 9738 requires the highest UIDs to be processed first when truncating.
        let message_limit = message_limit as usize;
        let mut untagged = Vec::new();
        if ids.len() > message_limit {
            ids.sort_unstable_by_key(|resolved| resolved.uid);
            ids.drain(..ids.len() - message_limit);
            let lowest_uid = ids.first().map_or(0, |resolved| resolved.uid);

            let code = ResponseCode::MessageLimit {
                limit: message_limit as u32,
                uid: lowest_uid.into(),
            };
            if response.code.is_none() {
                response = response.with_code(code);
            } else {
                untagged = StatusResponse::ok("Some messages were not modified.")
                    .with_code(code)
                    .into_bytes();
            }
        }

        let mut items = Response {
            is_utf8,
            items: Vec::with_capacity(ids.len()),
        };

        // Process each change
        let set_keywords = arguments
            .keywords
            .iter()
            .map(|k| Keyword::from(k.clone()))
            .collect::<Vec<_>>();
        let mut changed_mailboxes: Vec<u32> = Vec::new();
        let mut batch = BatchBuilder::new();

        for resolved in &ids {
            // Obtain message data
            let Some(message) = cache.email_by_id(&resolved.id) else {
                continue;
            };

            // Apply changes
            let edit = KeywordEdit::compute(&cache, message, &arguments.operation, &set_keywords);
            if edit.is_empty() {
                continue;
            }

            // Train spam filter
            let train_spam = edit.spam_training(message);

            // Convert keywords to flags
            let flags = if !arguments.is_silent {
                edit.flags(&cache, message, &set_keywords)
            } else {
                vec![]
            };

            // Set all current mailboxes as changed if the Seen tag changed
            if edit.adds(&Keyword::Seen) || edit.removes(&Keyword::Seen) {
                for membership in message.mailboxes() {
                    if !changed_mailboxes.contains(&membership.mailbox_id) {
                        changed_mailboxes.push(membership.mailbox_id);
                    }
                }
            }

            // Write changes
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .with_document(resolved.id);
            merge_keywords(
                &mut batch,
                message.thread_id(),
                edit.into_diff(&arguments.operation, &set_keywords),
            );

            // Add spam train task
            if let Some(learn_spam) = train_spam {
                self.server
                    .add_account_spam_sample(
                        &mut batch,
                        account_id,
                        resolved.id,
                        learn_spam,
                        self.session_id,
                    )
                    .await
                    .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;
            }

            // Set commit point
            batch.commit_point();

            // Add item to response
            if !arguments.is_silent {
                let mut data_items = vec![DataItem::Flags { flags }];
                if is_uid {
                    data_items.push(DataItem::Uid { uid: resolved.uid });
                }
                items.items.push(FetchItem {
                    id: resolved.imap_id(is_uidonly),
                    is_uidonly,
                    items: data_items,
                });
            } else if is_condstore {
                items.items.push(FetchItem {
                    id: resolved.imap_id(is_uidonly),
                    is_uidonly,
                    items: if is_uid {
                        vec![DataItem::Uid { uid: resolved.uid }]
                    } else {
                        vec![]
                    },
                });
            }
        }

        // Log mailbox changes
        for parent_id in changed_mailboxes {
            batch.log_container_property_change(
                SyncCollection::Email,
                PendingId::Assigned(parent_id),
            );
        }

        // Write changes
        if !batch.is_empty() {
            match self
                .server
                .commit_batch(batch)
                .await
                .map(|ids| ids.last_change_id(mailbox.id.account_id, SyncCollection::Email))
                .caused_by(trc::location!())
            {
                Ok(change_id) => {
                    if is_condstore {
                        let modseq = change_id + 1;
                        for item in items.items.iter_mut() {
                            item.items.push(DataItem::ModSeq { modseq });
                        }
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    items.items.clear();
                    response.rtype = ResponseType::No;
                    response.message = "Some messages were modified by another process.".into();
                }
                Err(err) => {
                    return Err(err.id(response.tag.unwrap()));
                }
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::Store),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            DocumentId = ids
                .iter()
                .map(|resolved| trc::Value::from(resolved.id))
                .collect::<Vec<_>>(),
            Type = format!("{:?}", arguments.operation),
            Details = arguments
                .keywords
                .iter()
                .map(|c| trc::Value::from(format!("{c:?}")))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Send response
        let items = items.serialize();
        Ok(response.serialize(if untagged.is_empty() {
            items
        } else {
            untagged.extend_from_slice(&items);
            untagged
        }))
    }
}
