/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::{
    dav::FilePresence,
    metadata::{MetadataPresence, MetadataWrite, PrivateMetadataCommit, PrivateMetadataWrite},
};
use store::write::{BatchBuilder, PendingId};
use trc::AddContext;
use types::metadata::{EncodedMetadata, MetadataKinds};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreparedMetadata {
    pub(super) shared: Option<MetadataWrite>,
    pub(super) private: Option<PrivateMetadataWrite>,
}

impl PreparedMetadata {
    pub fn is_empty(&self) -> bool {
        self.shared.is_none() && self.private.is_none()
    }

    pub fn is_private_only(&self) -> bool {
        self.shared.is_none() && self.private.is_some()
    }

    pub fn shared_kinds(&self) -> Option<MetadataKinds> {
        self.shared.as_ref().map(|write| {
            write
                .next
                .as_ref()
                .map_or(MetadataKinds::NONE, EncodedMetadata::kinds)
        })
    }

    pub fn file_presence(&self) -> Option<FilePresence> {
        self.shared.as_ref().map(|write| {
            write.next.as_ref().map_or(FilePresence::NONE, |next| {
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
            .map(|write| write.build(document_id, batch))
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
