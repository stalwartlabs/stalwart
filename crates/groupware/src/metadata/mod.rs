/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    METADATA_KINDS,
    calendar::{ArchivedCalendarEvent, Calendar, CalendarEvent},
    contact::{AddressBook, ArchivedContactCard, ContactCard},
    file::{ArchivedFileNode, FileNode},
};
use common::storage::{
    dav::FilePresence,
    index::{GroupwareWrite, PresenceFlags, RewritePresence, rewrite_archive},
};
use store::write::{Archive, BatchBuilder};
use trc::AddContext;
use types::{collection::Collection, metadata::MetadataKinds};

impl PresenceFlags for Calendar {
    const COLLECTION: Collection = Collection::Calendar;
    const TRACKED: MetadataKinds = METADATA_KINDS;

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.presence = kinds.bits() & Self::TRACKED.bits();
    }
}

impl PresenceFlags for AddressBook {
    const COLLECTION: Collection = Collection::AddressBook;
    const TRACKED: MetadataKinds = METADATA_KINDS;

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.presence = kinds.bits() & Self::TRACKED.bits();
    }
}

impl RewritePresence for CalendarEvent {
    fn rewrite_presence(
        current: &Archive<&ArchivedCalendarEvent>,
        kinds: MetadataKinds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.metadata_kinds() == tracked_kinds(kinds.bits()) {
            return Ok(());
        }
        let mut event = current
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        event.set_metadata_kinds(kinds);
        rewrite_archive(
            current,
            GroupwareWrite::meta_only(event, current.inner),
            Collection::CalendarEvent,
            account_id,
            document_id,
            batch,
        )
    }
}

impl RewritePresence for ContactCard {
    fn rewrite_presence(
        current: &Archive<&ArchivedContactCard>,
        kinds: MetadataKinds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.metadata_kinds() == tracked_kinds(kinds.bits()) {
            return Ok(());
        }
        let mut card = current
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        card.set_metadata_kinds(kinds);
        rewrite_archive(
            current,
            GroupwareWrite::meta_only(card, current.inner),
            Collection::ContactCard,
            account_id,
            document_id,
            batch,
        )
    }
}

impl FileNode {
    pub fn rewrite_presence(
        current: &Archive<&ArchivedFileNode>,
        presence: FilePresence,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.presence() == presence {
            return Ok(());
        }
        let mut node = current
            .deserialize::<FileNode>()
            .caused_by(trc::location!())?;
        node.set_presence(presence);
        rewrite_archive(
            current,
            node,
            Collection::FileNode,
            account_id,
            document_id,
            batch,
        )
    }
}

pub(crate) fn tracked_kinds(bits: u8) -> MetadataKinds {
    MetadataKinds::from_bits(bits & METADATA_KINDS.bits()).unwrap_or(MetadataKinds::NONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        calendar::{EVENT_HAS_ALARMS, EVENT_PRIVATE},
        file::{FileNodeContent, FileProperties},
    };
    use common::{DavName, storage::index::IndexableAndSerializableObject};
    use store::{
        Deserialize,
        write::{
            ArchiveBytes, Archiver, Operation, PendingId, SetValue, ValueOp, assert::AssertValue,
        },
    };

    const ACCOUNT_ID: u32 = 1;
    const DOCUMENT_ID: u32 = 9;

    fn stored<T: IndexableAndSerializableObject>(object: T) -> Archive<ArchiveBytes> {
        let (_, bytes) = Archiver::new(object)
            .serialize_versioned()
            .expect("the object serializes");
        <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("the archive validates")
    }

    fn written(batch: &BatchBuilder) -> Archive<ArchiveBytes> {
        assert!(!batch.has_changes(), "a presence rewrite must not log");
        assert!(
            batch.ops().iter().any(|op| matches!(
                op,
                Operation::AssertValue {
                    assert_value: AssertValue::Archive(_),
                    ..
                }
            )),
            "the current archive is not asserted"
        );
        assert_eq!(batch.last_account_id(), Some(ACCOUNT_ID));
        assert_eq!(
            batch.last_document_id(),
            Some(PendingId::Assigned(DOCUMENT_ID))
        );
        let archives = batch
            .ops()
            .iter()
            .filter_map(|op| match op {
                Operation::Value {
                    op: ValueOp::Set(SetValue::Patched(bytes, _) | SetValue::Fixed(bytes)),
                    ..
                } => Some(bytes),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [bytes] = archives.as_slice() else {
            panic!("expected one archive write, found {}", archives.len());
        };
        <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes).expect("the archive validates")
    }

    #[test]
    fn calendar_presence_rewrites_only_the_presence() {
        let calendar = stored(Calendar {
            name: "work".to_string(),
            ..Default::default()
        });
        let current = calendar.to_unarchived::<Calendar>().expect("unarchives");
        let mut batch = BatchBuilder::new();
        Calendar::rewrite_presence(
            &current,
            MetadataKinds::JMAP,
            ACCOUNT_ID,
            DOCUMENT_ID,
            &mut batch,
        )
        .expect("the rewrite builds");
        assert_eq!(batch.last_collection(), Some(Collection::Calendar));

        let written = written(&batch);
        let written = written
            .deserialize::<Calendar>()
            .expect("the calendar deserializes");
        assert_eq!(written.metadata_kinds(), MetadataKinds::JMAP);
        assert_eq!(written.name, "work");
    }

    #[test]
    fn unchanged_presence_writes_nothing() {
        let mut calendar = Calendar::default();
        calendar.set_metadata_kinds(MetadataKinds::DAV);
        let calendar = stored(calendar);
        let mut batch = BatchBuilder::new();
        Calendar::rewrite_presence(
            &calendar.to_unarchived::<Calendar>().expect("unarchives"),
            MetadataKinds::DAV.union(MetadataKinds::IMAP),
            ACCOUNT_ID,
            DOCUMENT_ID,
            &mut batch,
        )
        .expect("the rewrite builds");
        assert!(batch.is_empty());
    }

    #[test]
    fn address_book_presence_rewrites_only_the_presence() {
        let book = stored(AddressBook {
            name: "contacts".to_string(),
            ..Default::default()
        });
        let mut batch = BatchBuilder::new();
        AddressBook::rewrite_presence(
            &book.to_unarchived::<AddressBook>().expect("unarchives"),
            MetadataKinds::DAV,
            ACCOUNT_ID,
            DOCUMENT_ID,
            &mut batch,
        )
        .expect("the rewrite builds");
        assert_eq!(batch.last_collection(), Some(Collection::AddressBook));

        let written = written(&batch)
            .deserialize::<AddressBook>()
            .expect("the address book deserializes");
        assert_eq!(written.metadata_kinds(), MetadataKinds::DAV);
        assert_eq!(written.name, "contacts");
    }

    #[test]
    fn event_presence_keeps_the_etag_and_other_flags() {
        let event = stored(CalendarEvent {
            names: vec![DavName::new("event.ics".to_string(), 1)],
            uid: "event".to_string(),
            etag: 55,
            flags: EVENT_HAS_ALARMS | EVENT_PRIVATE,
            ..Default::default()
        });
        let mut batch = BatchBuilder::new();
        CalendarEvent::rewrite_presence(
            &event.to_unarchived::<CalendarEvent>().expect("unarchives"),
            MetadataKinds::JMAP.union(MetadataKinds::DAV),
            ACCOUNT_ID,
            DOCUMENT_ID,
            &mut batch,
        )
        .expect("the rewrite builds");
        assert_eq!(batch.last_collection(), Some(Collection::CalendarEvent));

        let written = written(&batch)
            .deserialize::<CalendarEvent>()
            .expect("the event deserializes");
        assert_eq!(
            written.metadata_kinds(),
            MetadataKinds::JMAP.union(MetadataKinds::DAV)
        );
        assert_eq!(written.etag, 55);
        assert_eq!(
            written.flags & (EVENT_HAS_ALARMS | EVENT_PRIVATE),
            EVENT_HAS_ALARMS | EVENT_PRIVATE
        );
    }

    #[test]
    fn card_presence_keeps_the_etag() {
        let mut card = ContactCard {
            names: vec![DavName::new("card.vcf".to_string(), 1)],
            uid: "card".to_string(),
            etag: 66,
            ..Default::default()
        };
        card.set_metadata_kinds(MetadataKinds::DAV);
        let card = stored(card);
        let mut batch = BatchBuilder::new();
        ContactCard::rewrite_presence(
            &card.to_unarchived::<ContactCard>().expect("unarchives"),
            MetadataKinds::NONE,
            ACCOUNT_ID,
            DOCUMENT_ID,
            &mut batch,
        )
        .expect("the rewrite builds");
        assert_eq!(batch.last_collection(), Some(Collection::ContactCard));

        let written = written(&batch)
            .deserialize::<ContactCard>()
            .expect("the card deserializes");
        assert!(written.metadata_kinds().is_empty());
        assert_eq!(written.etag, 66);
    }

    #[test]
    fn file_presence_keeps_the_etag() {
        let mut node = FileNode {
            parent_id: 3,
            name: "notes.txt".to_string(),
            content: FileNodeContent::File(FileProperties {
                size: 5,
                ..Default::default()
            }),
            ..Default::default()
        };
        node.etag = node.compute_etag();
        let etag = node.etag;
        let node = stored(node);
        let presence = FilePresence::from_kinds(MetadataKinds::DAV).with_dav_display_name();
        let mut batch = BatchBuilder::new();
        FileNode::rewrite_presence(
            &node.to_unarchived::<FileNode>().expect("unarchives"),
            presence,
            ACCOUNT_ID,
            DOCUMENT_ID,
            &mut batch,
        )
        .expect("the rewrite builds");
        assert_eq!(batch.last_collection(), Some(Collection::FileNode));
        assert_eq!(batch.last_archive_hash(), Some(etag));

        let written = written(&batch)
            .deserialize::<FileNode>()
            .expect("the node deserializes");
        assert_eq!(written.presence(), presence);
        assert_eq!(written.etag, etag);
    }
}
