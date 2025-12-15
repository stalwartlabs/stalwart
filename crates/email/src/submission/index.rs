/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedEmailSubmission, EmailSubmission};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use store::{
    U32_LEN,
    write::{IndexPropertyClass, ValueClass, key::KeySerializer},
};
use types::{collection::SyncCollection, field::EmailSubmissionField};

impl IndexableObject for EmailSubmission {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: EmailSubmissionField::Metadata.into(),
                    value: self.send_at,
                }),
                value: KeySerializer::new(U32_LEN * 3 + 1)
                    .write(self.email_id)
                    .write(self.thread_id)
                    .write(self.identity_id)
                    .write(self.undo_status.as_index())
                    .finalize()
                    .into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::EmailSubmission,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedEmailSubmission {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: EmailSubmissionField::Metadata.into(),
                    value: self.send_at.to_native(),
                }),
                value: KeySerializer::new(U32_LEN * 3 + 1)
                    .write(self.email_id.to_native())
                    .write(self.thread_id.to_native())
                    .write(self.identity_id.to_native())
                    .write(self.undo_status.as_index())
                    .finalize()
                    .into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::EmailSubmission,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for EmailSubmission {
    fn is_versioned() -> bool {
        false
    }
}
