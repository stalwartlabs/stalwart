/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedFileNode, FileNode};
use common::storage::index::{
    IndexValue, IndexableAndSerializableObject, IndexableObject, SerializableObject,
    serialize_object,
};
use store::write::{ArchiveCompression, BatchBuilder, Compression, Slot};
use types::{acl::AclGrant, collection::SyncCollection};

impl IndexableObject for FileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::LogItem {
                prefix: None,
                sync_collection: SyncCollection::FileNode,
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
        ]);

        if let Some(file) = &self.file {
            values.extend([IndexValue::Blob {
                value: file.blob_hash.clone(),
            }]);
        }

        values.into_iter()
    }
}

impl IndexableObject for &ArchivedFileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::LogItem {
                prefix: None,
                sync_collection: SyncCollection::FileNode,
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
        ]);

        if let Some(file) = self.file.as_ref() {
            values.extend([IndexValue::Blob {
                value: (&file.blob_hash).into(),
            }]);
        }

        values.into_iter()
    }
}

impl IndexableAndSerializableObject for FileNode {
    fn is_versioned() -> bool {
        true
    }

    fn set_pending_id(&mut self, document_id: u32) {
        self.parent_id = document_id + 1;
    }

    fn size_hint(&self) -> usize {
        self.size()
    }
}

impl FileNode {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.name.len()
            + self.file.as_ref().map_or(0, |f| f.size as usize)
            + std::mem::size_of::<FileNode>()
    }
}

impl ArchivedFileNode {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.name.len()
            + self
                .file
                .as_ref()
                .map_or(0, |f| f.size.to_native() as usize)
            + std::mem::size_of::<FileNode>()
    }
}

impl ArchiveCompression for FileNode {
    const COMPRESSION: Compression = Compression::None;
}

impl SerializableObject for FileNode {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}
