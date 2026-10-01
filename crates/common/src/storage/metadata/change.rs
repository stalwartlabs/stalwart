/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MetadataLog, MetadataWrite, PrivateMetadataWrite, StoredContainer};
use crate::auth::AccountCache;
use store::write::metadata::MetadataBuf;
use types::{
    collection::Collection,
    metadata::{EncodedMetadata, MetadataEdit},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerChange {
    previous: Option<StoredContainer>,
    next: Option<EncodedMetadata>,
    edit: MetadataEdit,
}

impl ContainerChange {
    pub fn new(
        previous: Option<&MetadataBuf>,
        next: Option<EncodedMetadata>,
        edit: MetadataEdit,
    ) -> Option<Self> {
        match (previous, &next) {
            (Some(previous), Some(next)) if previous.view().as_bytes() == next.as_bytes() => None,
            (None, None) => None,
            _ => Some(ContainerChange {
                previous: previous.map(StoredContainer::from),
                next,
                edit,
            }),
        }
    }

    pub fn copied(next: EncodedMetadata) -> Self {
        ContainerChange {
            previous: None,
            next: Some(next),
            edit: MetadataEdit::Write,
        }
    }

    pub fn previous(&self) -> Option<&StoredContainer> {
        self.previous.as_ref()
    }

    pub fn next(&self) -> Option<&EncodedMetadata> {
        self.next.as_ref()
    }

    pub fn edit(&self) -> MetadataEdit {
        self.edit
    }

    pub fn into_next(self) -> Option<EncodedMetadata> {
        self.next
    }

    pub fn into_write(
        self,
        owner: &AccountCache,
        collection: Collection,
        log: MetadataLog,
    ) -> MetadataWrite {
        MetadataWrite {
            account_id: owner.id,
            tenant_id: owner.id_tenant,
            collection,
            previous: self.previous,
            next: self.next,
            log,
        }
    }

    pub fn into_private_write(
        self,
        owner_id: u32,
        viewer: &AccountCache,
        collection: Collection,
        log: MetadataLog,
    ) -> PrivateMetadataWrite {
        PrivateMetadataWrite {
            owner_id,
            viewer_id: viewer.id,
            viewer_tenant_id: viewer.id_tenant,
            collection,
            previous: self.previous,
            next: self.next,
            log,
        }
    }
}
