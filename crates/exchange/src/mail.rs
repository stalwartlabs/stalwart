/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::ExchangeCacheFetch,
    store::{
        account::bump_objects_epoch,
        category::SpellingChanges,
        object::{ExchangeObjectWrite, StoredPlacement},
    },
};
use common::{
    MessageUid, Server,
    auth::AccessToken,
    config::mailstore::limits::EmailLimits,
    network::memory::MemoryReservation,
    storage::blob::FetchedBlob,
    storage::index::{CurrentObject, ObjectIndexBuilder},
};
use email::{
    mailbox::{JUNK_ID, TRASH_ID},
    message::{
        delete::EmailDeletion,
        ingest::{EmailIngest, SpamSamples},
        messagedata::{
            KEYWORD_BITS, KeywordDiff, MessageData, PendingMessageData, SERVER_SET_KEYWORDS,
            merge_keywords,
        },
        metadata::MetadataRow,
    },
};
use smallvec::SmallVec;
use std::{iter, mem};
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{BatchBuilder, PendingId, metadata::ExchangeClass},
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection, VanishedCollection},
    field::EmailField,
    keyword::{ANSWERED, DELETED, FLAGGED, FORWARDED, Keyword, MDN_SENT, SEEN},
};

pub mod category;

pub use category::{AccountCategories, CategoryOutcome};

pub(crate) const SEEN_BIT: u32 = 1 << SEEN;
const FLAGGED_BIT: u32 = 1 << FLAGGED;
const ANSWERED_BIT: u32 = 1 << ANSWERED;
const FORWARDED_BIT: u32 = 1 << FORWARDED;
const DELETED_BIT: u32 = 1 << DELETED;
pub(crate) const MDN_SENT_BIT: u32 = 1 << MDN_SENT;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlagEdit {
    pub read: Option<bool>,
    pub flagged: Option<bool>,
    pub answered: Option<bool>,
    pub forwarded: Option<bool>,
    pub deleted: Option<bool>,
    pub mdn_sent: Option<bool>,
}

pub struct MailEdits {
    account_id: u32,
    batch: BatchBuilder,
    touched: RoaringBitmap,
    destroy: RoaringBitmap,
    seen_mailboxes: SmallVec<[u32; 4]>,
    spam_samples: SpamSamples,
    spellings: SpellingChanges,
    aliases: AliasEpoch,
    objects: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AliasEpoch {
    Untouched,
    Pending,
    Bumped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed(Option<u64>),
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOutcome {
    Changed,
    Unchanged,
    KeywordLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOutcome {
    Copied,
    AlreadyThere,
    NotInSource,
    MailboxLimit,
}

impl FlagEdit {
    pub(crate) fn diff(&self, keywords: u32) -> (u32, u32) {
        let mut added = 0;
        let mut removed = 0;
        for (value, bit) in [
            (self.read, SEEN_BIT),
            (self.flagged, FLAGGED_BIT),
            (self.answered, ANSWERED_BIT),
            (self.forwarded, FORWARDED_BIT),
            (self.deleted, DELETED_BIT),
            (self.mdn_sent, MDN_SENT_BIT),
        ] {
            match value {
                Some(true) if keywords & bit == 0 => added |= bit,
                Some(false) if keywords & bit != 0 => removed |= bit,
                _ => {}
            }
        }
        (added, removed)
    }
}

pub(crate) fn keywords_fit(
    limits: &EmailLimits,
    data: &MessageData,
    added: u32,
    removed: u32,
) -> bool {
    let count = data.keyword_count();
    let next = count
        .saturating_add((added & !data.keywords).count_ones() as usize)
        .saturating_sub((removed & data.keywords).count_ones() as usize);
    limits.validate_keyword_change(count, next).is_ok()
}

impl MailEdits {
    pub fn new(account_id: u32) -> Self {
        MailEdits {
            account_id,
            batch: BatchBuilder::new(),
            touched: RoaringBitmap::new(),
            destroy: RoaringBitmap::new(),
            seen_mailboxes: SmallVec::new(),
            spam_samples: SpamSamples::default(),
            spellings: SpellingChanges::default(),
            aliases: AliasEpoch::Untouched,
            objects: false,
        }
    }

    pub fn take_touched(&mut self) -> RoaringBitmap {
        mem::take(&mut self.touched)
    }

    pub fn set_flags(
        &mut self,
        limits: &EmailLimits,
        document_id: u32,
        data: &MessageData,
        edit: FlagEdit,
    ) -> trc::Result<FlagOutcome> {
        let (added, removed) = edit.diff(data.keywords);
        if added == 0 && removed == 0 {
            return Ok(FlagOutcome::Unchanged);
        }
        if !keywords_fit(limits, data, added, removed) {
            return Ok(FlagOutcome::KeywordLimit);
        }
        self.claim(document_id)?;
        if added & MDN_SENT_BIT != 0 {
            data.assert(&mut self.batch);
        }
        if (added | removed) & SEEN_BIT != 0 {
            self.note_seen(data);
        }
        merge_keywords(
            &mut self.batch,
            data.thread_id,
            KeywordDiff::Patch {
                added,
                removed,
                added_extra: Vec::new(),
                removed_extra: Vec::new(),
            },
        );
        self.commit_point();
        Ok(FlagOutcome::Changed)
    }

    pub(crate) fn patch_keywords(
        &mut self,
        document_id: u32,
        data: &MessageData,
        (added, removed): (u32, u32),
    ) -> trc::Result<bool> {
        let added = added & !data.keywords;
        let removed = removed & data.keywords;
        if added == 0 && removed == 0 {
            return Ok(false);
        }
        self.claim(document_id)?;
        if (added | removed) & SEEN_BIT != 0 {
            self.note_seen(data);
        }
        merge_keywords(
            &mut self.batch,
            data.thread_id,
            KeywordDiff::Patch {
                added,
                removed,
                added_extra: Vec::new(),
                removed_extra: Vec::new(),
            },
        );
        self.commit_point();
        Ok(true)
    }

    pub fn write_object(&mut self, write: ExchangeObjectWrite<'_>) -> trc::Result<()> {
        write.build(&mut self.batch)?;
        self.objects = true;
        self.commit_point();
        Ok(())
    }

    pub fn replace_keywords(
        &mut self,
        limits: &EmailLimits,
        document_id: u32,
        data: &MessageData,
        keywords: &[Keyword],
    ) -> trc::Result<FlagOutcome> {
        let mut bits = data.keywords & (SERVER_SET_KEYWORDS | !KEYWORD_BITS);
        let mut extra = SmallVec::<[&str; 8]>::new();
        for keyword in keywords {
            match keyword.id() {
                Ok(id) => bits |= 1 << id,
                Err(name) if !extra.contains(&name) => extra.push(name),
                Err(_) => {}
            }
        }
        if bits == data.keywords
            && extra.len() == data.keywords_extra.len()
            && extra
                .iter()
                .all(|name| data.keywords_extra.iter().any(|stored| stored == name))
        {
            return Ok(FlagOutcome::Unchanged);
        }
        let count =
            (bits & KEYWORD_BITS & !SERVER_SET_KEYWORDS).count_ones() as usize + extra.len();
        if limits
            .validate_keyword_change(data.keyword_count(), count)
            .and_then(|()| {
                limits.validate_keyword_names(
                    extra
                        .iter()
                        .copied()
                        .filter(|name| !data.keywords_extra.iter().any(|stored| stored == name)),
                )
            })
            .is_err()
        {
            return Ok(FlagOutcome::KeywordLimit);
        }
        self.claim(document_id)?;
        if (bits ^ data.keywords) & SEEN_BIT != 0 {
            self.note_seen(data);
        }
        merge_keywords(
            &mut self.batch,
            data.thread_id,
            KeywordDiff::replace(keywords.to_vec()),
        );
        self.commit_point();
        Ok(FlagOutcome::Changed)
    }

    pub fn move_to(
        &mut self,
        document_id: u32,
        data: MessageData,
        from: u32,
        to: u32,
    ) -> trc::Result<bool> {
        self.move_message(document_id, data, (from, to), (0, 0), None)
    }

    pub fn move_to_alias(
        &mut self,
        document_id: u32,
        data: MessageData,
        from: u32,
        to: u32,
        alias_item: u32,
    ) -> trc::Result<bool> {
        let alias = StoredPlacement {
            container: to,
            item: alias_item,
        };
        self.move_message(document_id, data, (from, to), (0, 0), Some(alias))
    }

    pub(crate) fn move_with_keywords(
        &mut self,
        document_id: u32,
        data: MessageData,
        (from, to): (u32, u32),
        keywords: (u32, u32),
        alias_item: Option<u32>,
    ) -> trc::Result<bool> {
        let alias = alias_item.map(|item| StoredPlacement {
            container: to,
            item,
        });
        self.move_message(document_id, data, (from, to), keywords, alias)
    }

    pub fn alias_in(
        &mut self,
        document_id: u32,
        data: &MessageData,
        alias: StoredPlacement,
    ) -> trc::Result<bool> {
        if !data.has_mailbox_id(alias.container) {
            return Ok(false);
        }
        self.claim(document_id)?;
        self.batch.set(ExchangeClass::Alias, alias.serialize());
        self.aliases = AliasEpoch::Pending;
        Ok(true)
    }

    fn move_message(
        &mut self,
        document_id: u32,
        data: MessageData,
        (from, to): (u32, u32),
        (added, removed): (u32, u32),
        alias: Option<StoredPlacement>,
    ) -> trc::Result<bool> {
        if from == to || !data.has_mailbox_id(from) {
            return Ok(false);
        }
        self.claim(document_id)?;
        if let Some(alias) = alias {
            self.batch.set(ExchangeClass::Alias, alias.serialize());
            self.aliases = AliasEpoch::Pending;
        }
        let was_in_to = data.has_mailbox_id(to);
        let mut next = data.clone();
        next.keywords = (next.keywords | added) & !removed;
        next.remove_mailbox(from);
        next.add_mailbox(MessageUid::new_unassigned(to));
        if (data.keywords ^ next.keywords) & SEEN_BIT != 0 {
            self.note_seen(&next);
        }
        let uid_slots = self.batch.reserve_uids(
            self.account_id,
            next.mailboxes
                .iter()
                .filter(|mailbox| mailbox.uid == 0)
                .map(|mailbox| mailbox.mailbox_id),
        );
        self.write(
            data,
            PendingMessageData {
                data: next,
                uid_slots,
                thread_slot: None,
                change_id: None,
            },
            Some(from),
        )?;
        if !was_in_to {
            self.train_spam(document_id, from, to);
        }
        Ok(true)
    }

    pub fn copy_to(
        &mut self,
        limits: &EmailLimits,
        document_id: u32,
        data: MessageData,
        from: u32,
        to: u32,
    ) -> trc::Result<CopyOutcome> {
        if !data.has_mailbox_id(from) {
            return Ok(CopyOutcome::NotInSource);
        }
        let outcome = self.file_in(limits, document_id, data, to)?;
        if outcome == CopyOutcome::Copied {
            self.train_spam(document_id, from, to);
        }
        Ok(outcome)
    }

    pub fn file_in(
        &mut self,
        limits: &EmailLimits,
        document_id: u32,
        data: MessageData,
        to: u32,
    ) -> trc::Result<CopyOutcome> {
        if data.has_mailbox_id(to) {
            return Ok(CopyOutcome::AlreadyThere);
        }
        let count = data.mailboxes.len();
        if limits
            .validate_mailbox_change(count, count.saturating_add(1))
            .is_err()
        {
            return Ok(CopyOutcome::MailboxLimit);
        }
        self.claim(document_id)?;
        let mut next = data.clone();
        next.add_mailbox(MessageUid::new_unassigned(to));
        let uid_slots = self.batch.reserve_uids(
            self.account_id,
            next.mailboxes
                .iter()
                .filter(|mailbox| mailbox.uid == 0)
                .map(|mailbox| mailbox.mailbox_id),
        );
        self.write(
            data,
            PendingMessageData {
                data: next,
                uid_slots,
                thread_slot: None,
                change_id: None,
            },
            None,
        )?;
        Ok(CopyOutcome::Copied)
    }

    fn train_spam(&mut self, document_id: u32, from: u32, to: u32) {
        if to == JUNK_ID {
            self.spam_samples.add(document_id, true);
        } else if from == JUNK_ID && to != TRASH_ID {
            self.spam_samples.add(document_id, false);
        }
    }

    fn note_seen(&mut self, data: &MessageData) {
        for mailbox in data.mailboxes.iter() {
            if !self.seen_mailboxes.contains(&mailbox.mailbox_id) {
                self.seen_mailboxes.push(mailbox.mailbox_id);
            }
        }
    }

    pub fn remove_from(
        &mut self,
        document_id: u32,
        data: MessageData,
        from: u32,
    ) -> trc::Result<bool> {
        if !data.has_mailbox_id(from) {
            return Ok(false);
        }
        self.claim(document_id)?;
        if data
            .mailboxes
            .iter()
            .all(|mailbox| mailbox.mailbox_id == from)
        {
            data.assert(&mut self.batch);
            self.destroy.insert(document_id);
            return Ok(true);
        }
        let mut next = data.clone();
        next.remove_mailbox(from);
        let uid_slots = self.batch.reserve_uids(self.account_id, iter::empty());
        self.write(
            data,
            PendingMessageData {
                data: next,
                uid_slots,
                thread_slot: None,
                change_id: None,
            },
            Some(from),
        )?;
        Ok(true)
    }

    fn claim(&mut self, document_id: u32) -> trc::Result<()> {
        if !self.touched.insert(document_id) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Message edited twice in one batch.")
                .ctx(trc::Key::DocumentId, document_id)
                .caused_by(trc::location!()));
        }
        self.batch
            .with_account_id(self.account_id)
            .with_collection(Collection::Email)
            .with_document(document_id);
        Ok(())
    }

    fn write(
        &mut self,
        current: MessageData,
        next: PendingMessageData,
        vanished_from: Option<u32>,
    ) -> trc::Result<()> {
        let vanished =
            vanished_from.and_then(|from| current.message_uid(from).map(|uid| (from, uid)));
        self.batch
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(current)
                    .with_changes(next),
            )
            .caused_by(trc::location!())?;
        if let Some(vanished) = vanished {
            self.batch
                .log_vanished_item(VanishedCollection::Email, vanished);
        }
        self.commit_point();
        Ok(())
    }

    fn commit_point(&mut self) {
        if self.batch.is_large_batch() {
            self.flush_alias_epoch();
        }
        self.batch.commit_point();
    }

    fn flush_alias_epoch(&mut self) {
        if self.aliases == AliasEpoch::Pending {
            bump_objects_epoch(&mut self.batch, self.account_id);
            self.aliases = AliasEpoch::Bumped;
        }
    }

    pub async fn commit(
        mut self,
        server: &Server,
        access_token: &AccessToken,
        session_id: u64,
    ) -> trc::Result<CommitOutcome> {
        let account_id = self.account_id;
        self.flush_alias_epoch();
        let exchange_rows = self.objects || self.aliases != AliasEpoch::Untouched;
        if !self.destroy.is_empty() {
            server
                .emails_delete(
                    account_id,
                    access_token.changed_by(),
                    &mut self.batch,
                    self.destroy,
                )
                .await
                .caused_by(trc::location!())?;
        }
        for mailbox_id in self.seen_mailboxes {
            self.batch.log_container_property_change(
                SyncCollection::Email,
                PendingId::Assigned(mailbox_id),
            );
        }
        server
            .add_account_spam_samples(&mut self.batch, account_id, self.spam_samples, session_id)
            .await
            .caused_by(trc::location!())?;
        self.spellings.queue(&mut self.batch, account_id);
        if self.batch.is_empty() {
            return Ok(CommitOutcome::Committed(None));
        }
        match server.commit_batch(self.batch).await {
            Ok(assigned) => {
                server.mark_exchange_stale(account_id);
                Ok(CommitOutcome::Committed(
                    assigned.change_id(account_id, SyncCollection::Email),
                ))
            }
            Err(err) => {
                if exchange_rows {
                    server.mark_exchange_stale(account_id);
                }
                if err.is_assertion_failure() {
                    server
                        .inner
                        .mark_cache_stale(account_id, SyncCollection::Email);
                    Ok(CommitOutcome::Conflict)
                } else {
                    Err(err.caused_by(trc::location!()))
                }
            }
        }
    }
}

pub async fn fetch_raw_message(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<(Vec<u8>, MemoryReservation)>> {
    let Some(row) = metadata_row(server, account_id, document_id).await? else {
        return Ok(None);
    };
    let metadata = row.unarchive().caused_by(trc::location!())?;
    server
        .fetch_blob(
            &metadata.blob_hash(),
            0..usize::MAX,
            Some(metadata.size() as u64),
        )
        .await
        .map(|blob| blob.map(FetchedBlob::into_parts))
        .caused_by(trc::location!())
}

pub async fn stored_blob_hash(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<BlobHash>> {
    match metadata_row(server, account_id, document_id).await? {
        Some(row) => row
            .unarchive()
            .map(|metadata| Some(metadata.blob_hash()))
            .caused_by(trc::location!()),
        None => Ok(None),
    }
}

pub(crate) async fn metadata_row(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<MetadataRow>> {
    server
        .store()
        .get_value::<MetadataRow>(ValueKey::immutable(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .caused_by(trc::location!())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/mail/tests.rs"]
mod tests;
