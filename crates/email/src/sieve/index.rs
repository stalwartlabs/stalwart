/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedSieveScript, SieveScript};
use common::storage::index::{
    IndexValue, IndexableAndSerializableObject, IndexableObject, SerializableObject,
    serialize_object,
};
use store::write::{ArchiveCompression, BatchBuilder, Compression, Dictionary, Slot};
use types::{collection::SyncCollection, field::SieveField};

impl IndexableObject for SieveScript {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: SieveField::Name.into(),
                value: self.name.as_str().to_lowercase().into(),
            },
            IndexValue::Blob {
                value: self.blob_hash.clone(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::SieveScript,
                prefix: None,
            },
            IndexValue::Quota { used: self.size },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for SieveScript {
    fn is_versioned() -> bool {
        false
    }
}

impl IndexableObject for &ArchivedSieveScript {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: SieveField::Name.into(),
                value: self.name.to_lowercase().into(),
            },
            IndexValue::Blob {
                value: (&self.blob_hash).into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::SieveScript,
                prefix: None,
            },
            IndexValue::Quota {
                used: u32::from(self.size),
            },
        ]
        .into_iter()
    }
}

impl ArchiveCompression for SieveScript {
    const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Sieve));
}

impl SerializableObject for SieveScript {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}
