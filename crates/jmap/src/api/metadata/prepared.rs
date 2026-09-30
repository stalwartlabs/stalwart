/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::write::ContainerChange;
use common::storage::{
    dav::FilePresence,
    metadata::{
        MetadataLog, MetadataPresence, MetadataWrite, PrivateMetadataCommit, PrivateMetadataWrite,
    },
};
use store::write::{BatchBuilder, PendingId};
use trc::AddContext;
use types::{collection::Collection, metadata::MetadataKinds};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreparedMetadata {
    pub(super) shared: Option<SharedWrite>,
    pub(super) private: Option<PrivateMetadataWrite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SharedWrite {
    pub account_id: u32,
    pub tenant_id: Option<u32>,
    pub collection: Collection,
    pub log: MetadataLog,
    pub change: ContainerChange,
}

impl PreparedMetadata {
    pub fn is_empty(&self) -> bool {
        self.shared.is_none() && self.private.is_none()
    }

    pub fn is_private_only(&self) -> bool {
        self.shared.is_none() && self.private.is_some()
    }

    pub fn shared_kinds(&self) -> Option<MetadataKinds> {
        self.shared.as_ref().map(|write| write.change.kinds())
    }

    pub fn file_presence(&self) -> Option<FilePresence> {
        self.shared.as_ref().map(|write| {
            write.change.next().map_or(FilePresence::NONE, |next| {
                FilePresence::from_view(&next.view())
            })
        })
    }

    pub fn build(
        self,
        document_id: impl Into<PendingId>,
        batch: &mut BatchBuilder,
        commit: &mut PrivateMetadataCommit,
    ) -> trc::Result<Option<MetadataPresence>> {
        let document_id = document_id.into();
        let presence = self
            .shared
            .map(|write| write.into_write(document_id).build(batch))
            .transpose()
            .caused_by(trc::location!())?;
        if let Some(write) = self.private {
            write
                .build(document_id, batch, commit)
                .caused_by(trc::location!())?;
        }
        Ok(presence)
    }
}

impl SharedWrite {
    fn into_write(self, document_id: PendingId) -> MetadataWrite {
        let (previous, next) = self.change.into_parts();
        MetadataWrite {
            account_id: self.account_id,
            tenant_id: self.tenant_id,
            collection: self.collection,
            document_id,
            previous,
            next,
            log: self.log,
        }
    }
}
