/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod account;
pub mod alias;
pub mod category;
pub mod cleanup;
pub mod eas;
pub mod folder;
pub mod named;
pub mod object;

use store::{
    U32_LEN, ValueKey,
    write::{
        BatchBuilder, ValueClass,
        metadata::{ExchangeClass, ExchangeFolder},
    },
};
use types::collection::Collection;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ExchangeProperty {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum FolderKind {
    Mailbox = 0,
    Calendar = 1,
    AddressBook = 2,
    FileNode = 3,
    Virtual = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FolderRef {
    pub kind: FolderKind,
    pub id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaOwner {
    pub account_id: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub tenant_id: Option<u32>,
    // SPDX-SnippetEnd
}

impl FolderKind {
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(FolderKind::Mailbox),
            1 => Some(FolderKind::Calendar),
            2 => Some(FolderKind::AddressBook),
            3 => Some(FolderKind::FileNode),
            4 => Some(FolderKind::Virtual),
            _ => None,
        }
    }
}

impl FolderRef {
    pub const fn stored(self) -> ExchangeFolder {
        ExchangeFolder {
            kind: self.kind as u8,
            id: self.id,
        }
    }

    pub const fn from_stored(folder: ExchangeFolder) -> Option<Self> {
        match FolderKind::from_code(folder.kind) {
            Some(kind) => Some(FolderRef {
                kind,
                id: folder.id,
            }),
            None => None,
        }
    }

    pub const fn collection(self) -> Option<Collection> {
        match self.kind {
            FolderKind::Mailbox => Some(Collection::Mailbox),
            FolderKind::Calendar => Some(Collection::Calendar),
            FolderKind::AddressBook => Some(Collection::AddressBook),
            FolderKind::FileNode => Some(Collection::FileNode),
            FolderKind::Virtual => None,
        }
    }
}

impl QuotaOwner {
    pub fn new(
        account_id: u32,
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")] tenant_id: Option<u32>,
        // SPDX-SnippetEnd
    ) -> Self {
        QuotaOwner {
            account_id,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            tenant_id,
            // SPDX-SnippetEnd
        }
    }

    pub fn add(self, batch: &mut BatchBuilder, delta: i64) {
        if delta != 0 {
            batch.with_account_id(self.account_id);
            batch.add(ValueClass::Quota, delta);
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            if let Some(tenant_id) = self.tenant_id {
                batch.add(ValueClass::TenantQuota(tenant_id), delta);
            }
            // SPDX-SnippetEnd
        }
    }
}

pub(crate) fn properties_size<'x>(properties: impl Iterator<Item = (&'x [u8], &'x [u8])>) -> i64 {
    properties
        .map(|(key, value)| (key.len() + value.len()) as i64)
        .sum()
}

pub(crate) fn exchange_key(
    account_id: u32,
    collection: Collection,
    document_id: u32,
    class: ExchangeClass,
) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: collection.into(),
        document_id,
        class: class.into(),
    }
}

pub(crate) fn exchange_range(
    account_id: u32,
    class: ExchangeClass,
) -> (ValueKey<ValueClass>, ValueKey<ValueClass>) {
    (
        exchange_key(account_id, Collection::Email, 0, class),
        ValueKey {
            account_id,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: class.into(),
        },
    )
}

pub(crate) fn key_tail(key: &[u8]) -> trc::Result<(u8, u32)> {
    key.len()
        .checked_sub(U32_LEN + 1)
        .and_then(|start| key.get(start..))
        .and_then(|tail| tail.split_first())
        .and_then(|(kind, id)| {
            id.first_chunk::<U32_LEN>()
                .map(|id| (*kind, u32::from_be_bytes(*id)))
        })
        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
}

pub(crate) fn fai_key_tail(key: &[u8]) -> trc::Result<(ExchangeFolder, u32)> {
    key.len()
        .checked_sub((U32_LEN * 2) + 1)
        .and_then(|start| key.get(start..))
        .and_then(|tail| tail.split_first())
        .and_then(|(kind, rest)| {
            let (folder, id) = rest.split_first_chunk::<U32_LEN>()?;
            let id = id.first_chunk::<U32_LEN>()?;
            Some((
                ExchangeFolder {
                    kind: *kind,
                    id: u32::from_be_bytes(*folder),
                },
                u32::from_be_bytes(*id),
            ))
        })
        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
}

pub(crate) fn account_key(account_id: u32, class: ExchangeClass) -> ValueKey<ValueClass> {
    exchange_key(account_id, Collection::Principal, 0, class)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/tests.rs"]
mod tests;
