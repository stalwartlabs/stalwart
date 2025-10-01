/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedEmailSubmission, EmailSubmission};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use types::{collection::SyncCollection, field::EmailSubmissionField};

impl IndexableObject for EmailSubmission {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: EmailSubmissionField::UndoStatus.into(),
                value: self.undo_status.as_index().into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::EmailId.into(),
                value: self.email_id.into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::ThreadId.into(),
                value: self.thread_id.into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::IdentityId.into(),
                value: self.identity_id.into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::SendAt.into(),
                value: self.send_at.into(),
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
            IndexValue::Index {
                field: EmailSubmissionField::UndoStatus.into(),
                value: self.undo_status.as_index().into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::EmailId.into(),
                value: self.email_id.into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::ThreadId.into(),
                value: self.thread_id.into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::IdentityId.into(),
                value: self.identity_id.into(),
            },
            IndexValue::Index {
                field: EmailSubmissionField::SendAt.into(),
                value: self.send_at.into(),
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
