/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod containers;
mod patch;

pub(crate) use containers::{
    ContainerRequest, ContainerWrites, DeadContainers, check_growth, container_kinds, copy_growth,
    edited_container, read_container, stored_entry_of,
};
pub(crate) use patch::{DeadPatch, DisplayName};

use common::storage::metadata::MetadataLog;
use store::write::PendingId;
use types::{collection::Collection, metadata::MetadataKinds};

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeadTarget {
    pub account_id: u32,
    pub collection: Collection,
    pub document_id: PendingId,
    pub kinds: MetadataKinds,
    pub log: MetadataLog,
}

impl DeadTarget {
    pub fn item(
        account_id: u32,
        collection: Collection,
        document_id: impl Into<PendingId>,
        kinds: MetadataKinds,
    ) -> Self {
        DeadTarget {
            account_id,
            collection,
            document_id: document_id.into(),
            kinds,
            log: MetadataLog::Item { prefix: None },
        }
    }

    pub fn container(
        account_id: u32,
        collection: Collection,
        document_id: impl Into<PendingId>,
        kinds: MetadataKinds,
    ) -> Self {
        DeadTarget {
            account_id,
            collection,
            document_id: document_id.into(),
            kinds,
            log: MetadataLog::Container,
        }
    }
}
