/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedMailbox, Mailbox};
use common::storage::index::{
    ArchivedIdField, IndexValue, IndexableAndSerializableObject, IndexableObject,
};
use store::write::{ArchiveCompression, Compression};
use types::{acl::AclGrant, collection::SyncCollection};

impl IndexableObject for Mailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Email,
            },
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedMailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Email,
            },
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for Mailbox {
    const PENDING_ID_FIELD: Option<ArchivedIdField> =
        Some(ArchivedIdField::new(std::mem::offset_of!(ArchivedMailbox, parent_id)).one_based());

    fn is_versioned() -> bool {
        false
    }
}

impl ArchiveCompression for Mailbox {
    const COMPRESSION: Compression = Compression::None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::{
        Deserialize,
        write::{Archive, ArchiveBytes, Archiver, AssignedIds, Patch, Slot},
    };

    #[test]
    fn a_pending_parent_id_patches_into_the_archive() {
        let mut mailbox = Mailbox::new("Sent");
        mailbox.uid_validity = 0x1234_5678;
        mailbox.subscribers = vec![7, 8, 9];
        let expected = Mailbox {
            parent_id: 7,
            ..mailbox.clone()
        };

        let field = <Mailbox as IndexableAndSerializableObject>::PENDING_ID_FIELD
            .expect("Mailbox opts into pending id patching");
        let (payload_len, mut archive) = Archiver::new(mailbox)
            .serialize_patchable()
            .expect("serialize");
        let root_offset = payload_len as usize - std::mem::size_of::<ArchivedMailbox>();

        let mut ids = AssignedIds::default();
        ids.fill_slots(Slot::new(0), 1, 6);
        Patch::apply(
            &[field.patch(root_offset, Slot::new(0))],
            &mut archive,
            &ids,
        );

        assert_eq!(
            <Archive<ArchiveBytes> as Deserialize>::deserialize(&archive)
                .expect("the patched archive failed its integrity check")
                .deserialize::<Mailbox>()
                .expect("unarchive"),
            expected
        );
    }
}
