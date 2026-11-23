/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    folders::{ContainerClass, FolderEntry, FolderNode, SpecialFolder, WritableFolder},
    store::{FolderKind, FolderRef, eas::StoredFolder},
};
use exchange_proto::{
    common::token::TokenBuf,
    eas::types::FolderType,
    ids::{eas::EasCollectionId, token::ObjectKind},
};

const STORED_KIND_MASK: u8 = 0x3F;
pub const STORED_PENDING_ADD: u8 = 0x40;
pub const STORED_PENDING_DELETE: u8 = 0x80;
pub const SYNC_GROUPS: usize = 4;
const VIRTUAL_GROUP: usize = 3;

impl FolderNode {
    pub(crate) fn eas_collection_id(&self) -> TokenBuf {
        let (kind, id) = self
            .object_id()
            .unwrap_or((ObjectKind::VirtualFolder, self.to_stored().id));
        EasCollectionId { kind, id }.encode()
    }

    pub(crate) fn from_eas_collection_id(id: &str) -> Option<Self> {
        let EasCollectionId { kind, id } = EasCollectionId::decode(id)?;
        FolderNode::from_object_id(kind, id)
    }

    pub(crate) fn from_eas_stored(stored: StoredFolder) -> Option<Self> {
        FolderNode::from_stored(stored.kind & STORED_KIND_MASK, stored.id)
    }

    pub(crate) fn eas_sync_group(&self) -> usize {
        match self {
            FolderNode::Stored(FolderRef { kind, .. }) => match kind {
                FolderKind::Mailbox => 0,
                FolderKind::Calendar => 1,
                FolderKind::AddressBook => 2,
                FolderKind::FileNode | FolderKind::Virtual => VIRTUAL_GROUP,
            },
            FolderNode::Special(_) => VIRTUAL_GROUP,
        }
    }
}

pub fn folder_type(entry: &FolderEntry) -> FolderType {
    match entry.special {
        Some(SpecialFolder::Inbox) => FolderType::INBOX,
        Some(SpecialFolder::Drafts) => FolderType::DRAFTS,
        Some(SpecialFolder::DeletedItems) => FolderType::DELETED_ITEMS,
        Some(SpecialFolder::SentItems) => FolderType::SENT_ITEMS,
        Some(SpecialFolder::Outbox) => FolderType::OUTBOX,
        Some(SpecialFolder::Tasks) => FolderType::TASKS,
        Some(SpecialFolder::Calendar) => FolderType::CALENDAR,
        Some(SpecialFolder::Contacts) => FolderType::CONTACTS,
        Some(SpecialFolder::Notes) => FolderType::NOTES,
        Some(SpecialFolder::Journal) => FolderType::JOURNAL,
        _ => match entry.class {
            ContainerClass::Note => FolderType::USER_MAIL,
            ContainerClass::Task | ContainerClass::Journal
                if matches!(
                    entry.node,
                    FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        ..
                    })
                ) =>
            {
                FolderType::USER_MAIL
            }
            ContainerClass::Appointment => FolderType::USER_CALENDAR,
            ContainerClass::Contact => FolderType::USER_CONTACTS,
            ContainerClass::Task => FolderType::USER_TASKS,
            ContainerClass::Journal => FolderType::USER_JOURNAL,
            ContainerClass::StickyNote => FolderType::USER_NOTES,
            ContainerClass::Other(_) => match entry.class.family() {
                Some(WritableFolder::Mailbox) => FolderType::USER_MAIL,
                Some(WritableFolder::Calendar) => FolderType::USER_CALENDAR,
                Some(WritableFolder::AddressBook) => FolderType::USER_CONTACTS,
                Some(WritableFolder::Virtual) | None => FolderType::GENERIC,
            },
        },
    }
}

pub fn is_listed(entry: &FolderEntry) -> bool {
    entry.ipm
        && !matches!(
            entry.special,
            Some(SpecialFolder::IpmSubtree | SpecialFolder::Root)
        )
}
