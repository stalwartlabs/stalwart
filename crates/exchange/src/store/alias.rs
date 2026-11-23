/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FolderKind, account::bump_objects_epoch, object::StoredPlacement};
use crate::cache::ExchangeCacheFetch;
use common::{Server, cache::exchange::FolderKey};
use store::write::{BatchBuilder, metadata::ExchangeClass};
use trc::AddContext;
use types::collection::Collection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupwareKind {
    Event,
    Contact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupwareAlias {
    pub kind: GroupwareKind,
    pub container: u32,
    pub document_id: u32,
    pub item: u32,
}

impl GroupwareKind {
    pub const fn from_folder(kind: FolderKind) -> Option<Self> {
        match kind {
            FolderKind::Calendar => Some(GroupwareKind::Event),
            FolderKind::AddressBook => Some(GroupwareKind::Contact),
            FolderKind::Mailbox | FolderKind::FileNode | FolderKind::Virtual => None,
        }
    }

    pub const fn from_collection(collection: Collection) -> Option<Self> {
        match collection {
            Collection::CalendarEvent => Some(GroupwareKind::Event),
            Collection::ContactCard => Some(GroupwareKind::Contact),
            _ => None,
        }
    }

    pub const fn collection(self) -> Collection {
        match self {
            GroupwareKind::Event => Collection::CalendarEvent,
            GroupwareKind::Contact => Collection::ContactCard,
        }
    }

    pub const fn folder_kind(self) -> FolderKind {
        match self {
            GroupwareKind::Event => FolderKind::Calendar,
            GroupwareKind::Contact => FolderKind::AddressBook,
        }
    }

    pub const fn folder(self, container: u32) -> FolderKey {
        FolderKey {
            kind: self.folder_kind() as u8,
            id: container,
        }
    }
}

pub async fn set_groupware_alias(
    server: &Server,
    account_id: u32,
    alias: GroupwareAlias,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(alias.kind.collection())
        .with_document(alias.document_id)
        .set(
            ExchangeClass::Alias,
            StoredPlacement {
                container: alias.container,
                item: alias.item,
            }
            .serialize(),
        );
    bump_objects_epoch(&mut batch, account_id);
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;
    server.mark_exchange_stale(account_id);
    Ok(())
}
