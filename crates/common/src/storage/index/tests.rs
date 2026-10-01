/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedSplitObject, CurrentObject, IndexValue, IndexableObject, SplitCurrent};
use store::write::{
    Archive, ArchiveVersion, BatchBuilder, Operation, ValueClass, ValueOp, metadata::MetadataClass,
};
use types::{
    collection::Collection,
    field::{CalendarEventField, Field},
    metadata::MetadataKinds,
};

struct Unflagged;

struct Flagged(MetadataKinds);

impl IndexableObject for Unflagged {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        std::iter::empty()
    }
}

impl IndexableObject for Flagged {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        std::iter::empty()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        self.0
    }
}

impl ArchivedSplitObject for Flagged {
    type ArchivedContent = ();

    const CONTENT_FIELD: Field = CalendarEventField::Content.field();

    fn meta_hash(&self) -> u32 {
        0
    }

    fn etag(&self) -> u32 {
        0
    }

    fn meta_index_values(&self) -> Vec<IndexValue<'_>> {
        Vec::new()
    }

    fn full_index_values<'x>(&'x self, _: &'x ()) -> Vec<IndexValue<'x>> {
        Vec::new()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        self.0
    }
}

fn archive<T>(inner: T) -> Archive<T> {
    Archive {
        inner,
        version: ArchiveVersion::Unversioned,
    }
}

fn cleared(object: &impl CurrentObject) -> Vec<ValueClass> {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(1)
        .with_collection(Collection::CalendarEvent)
        .with_document(2);
    let start = batch.ops().len();
    object.clear(&mut batch);
    batch
        .ops()
        .iter()
        .skip(start)
        .map(|op| match op {
            Operation::Value {
                class,
                op: ValueOp::Clear,
            } => class.clone(),
            op => panic!("clearing an object must only clear keys, got {op:?}"),
        })
        .collect()
}

#[test]
fn deleting_an_object_clears_its_container_only_when_flagged() {
    let archive_field = || ValueClass::from(Field::ARCHIVE);
    let content_field = || ValueClass::from(<Flagged as ArchivedSplitObject>::CONTENT_FIELD);
    let container = || ValueClass::Metadata(MetadataClass::Shared);

    assert_eq!(cleared(&archive(Unflagged)), [archive_field()]);
    assert_eq!(
        cleared(&archive(Flagged(MetadataKinds::NONE))),
        [archive_field()]
    );
    for kinds in [MetadataKinds::JMAP, MetadataKinds::DAV, MetadataKinds::IMAP] {
        assert_eq!(
            cleared(&archive(Flagged(kinds))),
            [archive_field(), container()]
        );
    }

    let unflagged = Flagged(MetadataKinds::NONE);
    let flagged = Flagged(MetadataKinds::DAV);
    assert_eq!(
        cleared(&SplitCurrent::MetaOnly(archive(&unflagged))),
        [archive_field(), content_field()]
    );
    assert_eq!(
        cleared(&SplitCurrent::Full {
            meta: archive(&unflagged),
            content: &(),
        }),
        [archive_field(), content_field()]
    );
    assert_eq!(
        cleared(&SplitCurrent::MetaOnly(archive(&flagged))),
        [archive_field(), content_field(), container()]
    );
}
