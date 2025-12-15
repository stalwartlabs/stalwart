/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    mailbox::{JUNK_ID, TRASH_ID},
    message::metadata::{ArchivedMessageData, MessageData},
};
use common::storage::index::{IndexItem, IndexValue, IndexableObject};
use store::write::now;
use types::{blob_hash::BlobHash, collection::SyncCollection, field::EmailField};

pub mod extractors;
pub mod metadata;
pub mod search;

pub(super) const MAX_MESSAGE_PARTS: usize = 1000;
pub const PREVIEW_LENGTH: usize = 256;

impl IndexableObject for MessageData {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut mailboxes = Vec::with_capacity(self.mailboxes.len());
        let mut is_in_trash = false;

        for mailbox in &self.mailboxes {
            mailboxes.push(mailbox.mailbox_id);
            is_in_trash |= mailbox.mailbox_id == TRASH_ID || mailbox.mailbox_id == JUNK_ID;
        }

        [
            IndexValue::Property {
                field: EmailField::DeletedAt.into(),
                value: if is_in_trash {
                    IndexItem::from(now())
                } else {
                    IndexItem::None
                },
            },
            IndexValue::Quota { used: self.size },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Email,
                prefix: self.thread_id.into(),
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Thread,
                ids: vec![self.thread_id],
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Email,
                ids: mailboxes,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedMessageData {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut mailboxes = Vec::with_capacity(self.mailboxes.len());
        let mut is_in_trash = false;

        for mailbox in self.mailboxes.iter() {
            let mailbox_id = mailbox.mailbox_id.to_native();
            mailboxes.push(mailbox_id);
            is_in_trash |= mailbox_id == TRASH_ID || mailbox_id == JUNK_ID;
        }

        [
            IndexValue::Property {
                field: EmailField::DeletedAt.into(),
                value: if is_in_trash {
                    IndexItem::from(now())
                } else {
                    IndexItem::None
                },
            },
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Email,
                prefix: self.thread_id.to_native().into(),
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Thread,
                ids: vec![self.thread_id.to_native()],
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Email,
                ids: mailboxes,
            },
        ]
        .into_iter()
    }
}

pub(super) trait IndexMessage {
    #[allow(clippy::too_many_arguments)]
    fn index_message<'x>(
        &mut self,
        tenant_id: Option<u32>,
        message: mail_parser::Message<'x>,
        extra_headers: Vec<u8>,
        extra_headers_parsed: Vec<mail_parser::Header<'x>>,
        blob_hash: BlobHash,
        data: MessageData,
        received_at: u64,
    ) -> trc::Result<&mut Self>;
}
