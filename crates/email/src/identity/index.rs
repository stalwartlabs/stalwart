/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedIdentity, Identity};
use common::storage::index::{
    IndexValue, IndexableAndSerializableObject, IndexableObject, SerializableObject,
    serialize_object,
};
use store::write::{ArchiveCompression, BatchBuilder, Compression, Dictionary, Slot};
use types::collection::SyncCollection;

impl IndexableObject for Identity {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [IndexValue::LogItem {
            sync_collection: SyncCollection::Identity,
            prefix: None,
        }]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedIdentity {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [IndexValue::LogItem {
            sync_collection: SyncCollection::Identity,
            prefix: None,
        }]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for Identity {
    fn is_versioned() -> bool {
        false
    }
}

impl ArchiveCompression for Identity {
    const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Common));
}

impl SerializableObject for Identity {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}
