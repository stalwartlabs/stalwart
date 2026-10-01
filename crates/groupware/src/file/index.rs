/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedFileNode, ArchivedFileNodeContent, FileNode, FileNodeContent, content::FileContentKind,
};
use common::storage::index::{
    IndexValue, IndexableAndSerializableObject, IndexableObject, SerializableObject,
    serialize_object,
};
use store::write::{ArchiveCompression, BatchBuilder, Compression, SearchIndex, Slot};
use types::{acl::AclGrant, collection::SyncCollection, metadata::MetadataKinds};

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

        if let Some(file) = self.file() {
            values.extend([
                IndexValue::SearchIndex {
                    index: SearchIndex::File,
                    hash: FileContentKind::index_hash(
                        FileContentKind::detect(&self.name, file.media_type.as_deref()),
                        file.blob_hash.as_slice(),
                    ),
                },
                IndexValue::Blob {
                    value: file.blob_hash.clone(),
                },
            ]);
        }

        values.into_iter()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        FileNode::metadata_kinds(self)
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

        if let Some(file) = self.file() {
            values.extend([
                IndexValue::SearchIndex {
                    index: SearchIndex::File,
                    hash: FileContentKind::index_hash(
                        FileContentKind::detect(&self.name, file.media_type.as_deref()),
                        file.blob_hash.0.as_slice(),
                    ),
                },
                IndexValue::Blob {
                    value: (&file.blob_hash).into(),
                },
            ]);
        }

        values.into_iter()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        ArchivedFileNode::metadata_kinds(self)
    }
}

impl IndexableAndSerializableObject for FileNode {
    fn is_versioned() -> bool {
        true
    }

    fn set_pending_id(&mut self, document_id: u32) {
        self.parent_id = document_id + 1;
        self.etag = self.compute_etag();
    }

    fn size_hint(&self) -> usize {
        self.size()
    }
}

impl FileNode {
    pub fn size(&self) -> usize {
        self.name.len()
            + match &self.content {
                FileNodeContent::Directory => 0,
                FileNodeContent::File(file) => {
                    file.size as usize + file.media_type.as_ref().map_or(0, |t| t.len())
                }
                FileNodeContent::Symlink(target) => target.len(),
            }
            + std::mem::size_of::<FileNode>()
    }
}

impl ArchivedFileNode {
    pub fn size(&self) -> usize {
        self.name.len()
            + match &self.content {
                ArchivedFileNodeContent::Directory => 0,
                ArchivedFileNodeContent::File(file) => {
                    file.size.to_native() as usize + file.media_type.as_ref().map_or(0, |t| t.len())
                }
                ArchivedFileNodeContent::Symlink(target) => target.len(),
            }
            + std::mem::size_of::<FileNode>()
    }
}

impl ArchiveCompression for FileNode {
    const COMPRESSION: Compression = Compression::None;
}

impl SerializableObject for FileNode {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        let mut node = self;
        node.etag = node.compute_etag();
        let etag = node.etag;
        serialize_object(node, batch, pending_id)?;
        if pending_id.is_none() {
            batch.set_archive_hash(Some(etag));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        METADATA_KINDS,
        file::{FileNodeRole, FileProperties},
    };
    use common::storage::{dav::FilePresence, index::CurrentObject};
    use rkyv::rancor::Error;
    use store::{
        Deserialize, Serialize,
        write::{
            Archive, ArchiveBytes, Archiver, Operation, ValueClass, ValueOp,
            metadata::MetadataClass,
        },
    };
    use types::{
        acl::{Acl, AclGrant},
        blob_hash::BlobHash,
        collection::Collection,
    };
    use utils::map::bitmap::Bitmap;

    fn file() -> FileNode {
        FileNode {
            parent_id: 4,
            name: "report.txt".to_string(),
            content: FileNodeContent::File(FileProperties {
                blob_hash: BlobHash::generate(b"contents"),
                size: 8,
                media_type: Some("text/plain".to_string()),
                executable: false,
            }),
            created: 1_700_000_000,
            modified: 1_700_000_100,
            accessed: 1_700_000_200,
            changed: 1_700_000_300,
            ..Default::default()
        }
    }

    fn archived_etag(node: &FileNode) -> u32 {
        let bytes = rkyv::to_bytes::<Error>(node).expect("the node archives");
        rkyv::access::<ArchivedFileNode, Error>(&bytes)
            .expect("the archive validates")
            .compute_etag()
    }

    fn with(mut node: FileNode, change: impl FnOnce(&mut FileNode)) -> FileNode {
        change(&mut node);
        node
    }

    fn file_properties(node: &mut FileNode) -> &mut FileProperties {
        node.file_mut().expect("a file node")
    }

    #[test]
    fn etag_moves_with_identity_location_and_content() {
        let base = file();
        let etag = base.compute_etag();
        let changes = [
            with(file(), |n| n.name = "renamed.txt".to_string()),
            with(file(), |n| n.parent_id = 5),
            with(file(), |n| {
                file_properties(n).blob_hash = BlobHash::generate(b"other");
            }),
            with(file(), |n| file_properties(n).size = 9),
            with(file(), |n| file_properties(n).media_type = None),
            with(file(), |n| file_properties(n).executable = true),
            with(file(), |n| n.set_role(Some(FileNodeRole::Documents))),
            with(file(), |n| n.content = FileNodeContent::Directory),
            with(file(), |n| {
                n.content = FileNodeContent::Symlink("report.txt".to_string())
            }),
        ];
        for changed in changes {
            assert_ne!(changed.compute_etag(), etag, "{changed:?}");
        }

        let link = |target: &str| {
            with(file(), |n| {
                n.content = FileNodeContent::Symlink(target.to_string())
            })
        };
        assert_ne!(link("a").compute_etag(), link("b").compute_etag());
    }

    #[test]
    fn etag_ignores_timestamps_sharing_and_presence() {
        let etag = file().compute_etag();
        let unchanged = [
            with(file(), |n| n.created += 1),
            with(file(), |n| n.modified += 1),
            with(file(), |n| n.accessed += 1),
            with(file(), |n| n.changed += 1),
            with(file(), |n| n.unsubscribed.push(7)),
            with(file(), |n| {
                n.acls.push(AclGrant {
                    account_id: 7,
                    grants: Bitmap::from_iter([Acl::Read]),
                })
            }),
            with(file(), |n| {
                n.set_presence(FilePresence::from_kinds(METADATA_KINDS).with_dav_display_name())
            }),
            with(file(), |n| n.etag = 12345),
        ];
        for changed in unchanged {
            assert_eq!(changed.compute_etag(), etag, "{changed:?}");
        }
    }

    #[test]
    fn archived_etag_matches_the_owned_etag() {
        for node in [
            file(),
            with(file(), |n| n.content = FileNodeContent::Directory),
            with(file(), |n| {
                n.content = FileNodeContent::Symlink("target".to_string());
                n.set_role(Some(FileNodeRole::Trash));
            }),
        ] {
            assert_eq!(archived_etag(&node), node.compute_etag());
        }
    }

    #[test]
    fn serialization_stamps_the_etag() {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(1)
            .with_collection(Collection::FileNode)
            .with_document(2);
        let node = file();
        let etag = node.compute_etag();
        node.serialize_into(&mut batch, None)
            .expect("the node serializes");
        assert_eq!(batch.last_archive_hash(), Some(etag));
    }

    #[test]
    fn presence_is_reported_to_the_index_builder() {
        let node = with(file(), |n| {
            n.set_presence(FilePresence::NONE.with_dav_display_name())
        });
        let bytes = rkyv::to_bytes::<Error>(&node).expect("the node archives");
        let archived =
            rkyv::access::<ArchivedFileNode, Error>(&bytes).expect("the archive validates");
        assert_eq!(archived.presence(), node.presence());
        assert_eq!(
            IndexableObject::metadata_kinds(&archived),
            MetadataKinds::DAV
        );
        assert_eq!(IndexableObject::metadata_kinds(&node), MetadataKinds::DAV);

        let bytes = rkyv::to_bytes::<Error>(&file()).expect("the node archives");
        let archived =
            rkyv::access::<ArchivedFileNode, Error>(&bytes).expect("the archive validates");
        assert!(IndexableObject::metadata_kinds(&archived).is_empty());
        assert!(IndexableObject::metadata_kinds(&file()).is_empty());
    }

    #[test]
    fn deleting_an_owned_node_clears_its_container_only_when_flagged() {
        for (presence, is_flagged) in [
            (FilePresence::NONE, false),
            (FilePresence::NONE.with_dav_display_name(), true),
            (FilePresence::from_kinds(MetadataKinds::JMAP), true),
        ] {
            let node = with(file(), |n| n.set_presence(presence));
            let bytes = Archiver::new(node)
                .serialize()
                .expect("the node serializes");
            let current = <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes)
                .expect("the archive validates")
                .into_deserialized::<FileNode>()
                .expect("the node deserializes");
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(1)
                .with_collection(Collection::FileNode)
                .with_document(2);
            let ops_before = batch.ops().len();
            current.clear(&mut batch);
            let clears = batch
                .ops()
                .iter()
                .filter(|op| {
                    matches!(
                        op,
                        Operation::Value {
                            class: ValueClass::Metadata(MetadataClass::Shared),
                            op: ValueOp::Clear,
                        }
                    )
                })
                .count();
            assert_eq!(clears, usize::from(is_flagged), "{presence:?}");
            assert_eq!(
                batch.ops().len() - ops_before,
                1 + usize::from(is_flagged),
                "{presence:?}"
            );
        }
    }
}
