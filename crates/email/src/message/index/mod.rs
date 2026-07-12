/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    mailbox::{JUNK_ID, TRASH_ID},
    message::messagedata::MessageData,
};
use common::storage::index::{
    CurrentObject, IndexItem, IndexValue, IndexableObject, SerializableObject,
};
use store::{
    Serialize, U64_LEN,
    write::{BatchBuilder, Params, assert::AssertValue, now},
};
use types::{
    blob_hash::BlobHash,
    collection::SyncCollection,
    field::{EmailField, Field},
};

pub mod extractors;
pub mod metadata;
pub mod search;

pub(super) const MAX_MESSAGE_PARTS: usize = 1000;
pub const PREVIEW_LENGTH: usize = 256;

impl CurrentObject for MessageData {
    fn assert(&self, batch: &mut BatchBuilder) {
        batch.assert_value(Field::ARCHIVE, AssertValue::U64(self.change_id));
    }

    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        IndexableObject::index_values(self)
    }

    fn clear(&self, batch: &mut BatchBuilder) {
        batch.clear(Field::ARCHIVE);
    }
}

impl SerializableObject for MessageData {
    fn serialize_into(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        let bytes = self.serialize()?;

        batch.set_fnc(
            Field::ARCHIVE,
            Params::with_capacity(2).with_bytes(bytes),
            |params, ids| {
                let change_id = ids.current_change_id()?;
                let data = params.bytes(0);

                let mut bytes = Vec::with_capacity(data.len());
                bytes.extend_from_slice(&data[..data.len() - U64_LEN]);
                bytes.extend_from_slice(&change_id.to_be_bytes()[..]);
                Ok(bytes)
            },
        );
        Ok(())
    }
}

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
    ) -> trc::Result<&mut Self>;
}
