/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    mailbox::{ArchivedMailbox, Mailbox},
    message::messagedata::{HAS_JMAP_METADATA, MessageData},
    sieve::{ArchivedSieveScript, SieveScript},
};
use common::storage::metadata::MetadataPresence;
use store::{
    Deserialize, Serialize,
    write::{Archive, Archiver, BatchBuilder, MergeResult},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::Field,
    metadata::MetadataKinds,
};

impl MessageData {
    pub const TRACKED_METADATA: MetadataKinds = MetadataKinds::JMAP;

    pub fn metadata_kinds(&self) -> MetadataKinds {
        Self::metadata_kinds_of(self.keywords)
    }

    pub fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        if kinds.intersects(Self::TRACKED_METADATA) {
            self.keywords |= HAS_JMAP_METADATA;
        } else {
            self.keywords &= !HAS_JMAP_METADATA;
        }
    }

    pub(crate) fn has_metadata(keywords: u32) -> bool {
        keywords & HAS_JMAP_METADATA != 0
    }

    pub(crate) fn metadata_kinds_of(keywords: u32) -> MetadataKinds {
        if Self::has_metadata(keywords) {
            MetadataKinds::JMAP
        } else {
            MetadataKinds::NONE
        }
    }
}

impl Mailbox {
    pub const TRACKED_METADATA: MetadataKinds = MetadataKinds::JMAP.union(MetadataKinds::IMAP);

    pub fn metadata_kinds(&self) -> MetadataKinds {
        tracked_kinds(self.metadata_flags, Self::TRACKED_METADATA)
    }

    pub fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.metadata_flags = kinds.bits() & Self::TRACKED_METADATA.bits();
    }
}

impl ArchivedMailbox {
    pub fn metadata_kinds(&self) -> MetadataKinds {
        tracked_kinds(self.metadata_flags, Mailbox::TRACKED_METADATA)
    }
}

impl SieveScript {
    pub const TRACKED_METADATA: MetadataKinds = MetadataKinds::JMAP;

    pub fn metadata_kinds(&self) -> MetadataKinds {
        tracked_kinds(self.metadata_flags, Self::TRACKED_METADATA)
    }

    pub fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.metadata_flags = kinds.bits() & Self::TRACKED_METADATA.bits();
    }
}

impl ArchivedSieveScript {
    pub fn metadata_kinds(&self) -> MetadataKinds {
        tracked_kinds(self.metadata_flags, SieveScript::TRACKED_METADATA)
    }
}

fn tracked_kinds(flags: u8, tracked: MetadataKinds) -> MetadataKinds {
    MetadataKinds::from_bits(flags & tracked.bits()).unwrap_or_default()
}

fn tracked_target(presence: MetadataPresence, tracked: MetadataKinds) -> MetadataKinds {
    tracked_kinds(presence.after.bits(), tracked)
}

fn merge_metadata_kinds(batch: &mut BatchBuilder, account_id: u32, kinds: MetadataKinds) {
    let group = SyncCollection::Email.change_group();
    batch.merge_fnc(Field::ARCHIVE, move |ids, bytes| {
        apply_metadata_kinds(bytes, kinds, ids.change_id(account_id, group))
    });
}

fn apply_metadata_kinds(
    bytes: Option<&[u8]>,
    kinds: MetadataKinds,
    change_id: Option<u64>,
) -> trc::Result<MergeResult> {
    let change_id = change_id.ok_or_else(|| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("No change id was allocated for the message presence update.")
            .caused_by(trc::location!())
    })?;
    let bytes = bytes.ok_or_else(|| {
        trc::StoreEvent::AssertValueFailed
            .into_err()
            .details("Message no longer exists.")
            .caused_by(trc::location!())
    })?;
    let mut data = MessageData::deserialize(bytes)?;
    let keywords = data.keywords;
    data.set_metadata_kinds(kinds);
    if data.keywords != keywords {
        data.serialize_with_change_id(change_id)
            .map(MergeResult::Update)
    } else {
        Ok(MergeResult::Skip)
    }
}

pub fn update_email_presence(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    current: MetadataKinds,
    presence: MetadataPresence,
) {
    let target = tracked_target(presence, MessageData::TRACKED_METADATA);
    if presence.has_changed_for(MessageData::TRACKED_METADATA)
        || tracked_kinds(current.bits(), MessageData::TRACKED_METADATA) != target
    {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(document_id);
        merge_metadata_kinds(batch, account_id, target);
    }
}

pub fn update_mailbox_presence(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    current: &Archive<&ArchivedMailbox>,
    presence: MetadataPresence,
) -> trc::Result<()> {
    let target = tracked_target(presence, Mailbox::TRACKED_METADATA);
    if current.inner.metadata_kinds() == target {
        return Ok(());
    }
    let mut mailbox = current
        .deserialize::<Mailbox>()
        .caused_by(trc::location!())?;
    mailbox.set_metadata_kinds(target);
    let archive = Archiver::new(mailbox)
        .serialize()
        .caused_by(trc::location!())?;
    rewrite_archive(
        batch,
        account_id,
        Collection::Mailbox,
        document_id,
        current,
        archive,
    );
    Ok(())
}

pub fn update_sieve_presence(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    current: &Archive<&ArchivedSieveScript>,
    presence: MetadataPresence,
) -> trc::Result<()> {
    let target = tracked_target(presence, SieveScript::TRACKED_METADATA);
    if current.inner.metadata_kinds() == target {
        return Ok(());
    }
    let mut script = current
        .deserialize::<SieveScript>()
        .caused_by(trc::location!())?;
    script.set_metadata_kinds(target);
    let archive = Archiver::new(script)
        .serialize()
        .caused_by(trc::location!())?;
    rewrite_archive(
        batch,
        account_id,
        Collection::SieveScript,
        document_id,
        current,
        archive,
    );
    Ok(())
}

fn rewrite_archive<T>(
    batch: &mut BatchBuilder,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    current: &Archive<T>,
    archive: Vec<u8>,
) {
    batch
        .with_account_id(account_id)
        .with_collection(collection)
        .with_document(document_id)
        .assert_value(Field::ARCHIVE, current)
        .set(Field::ARCHIVE, archive);
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        MessageUid,
        storage::index::{CurrentObject, IndexableAndSerializableObject},
    };
    use store::write::{
        ArchiveBytes, AssignedIds, ChangeCounter, Operation, ValueClass, ValueOp,
        metadata::MetadataClass,
    };
    use types::keyword::{SEEN, UNSUBSCRIBED};

    fn message(keywords: u32, change_id: u64) -> MessageData {
        MessageData {
            mailboxes: [MessageUid {
                mailbox_id: 3,
                uid: 9,
            }]
            .into_iter()
            .collect(),
            keywords,
            keywords_extra: vec!["custom".into()],
            thread_id: 4,
            size: 1024,
            received_at: 1_700_000_000,
            sent_at: -60,
            change_id,
        }
    }

    const MERGE_CHANGE_ID: u64 = 91;

    fn merged(bytes: &[u8], kinds: MetadataKinds) -> Option<MessageData> {
        match apply_metadata_kinds(Some(bytes), kinds, Some(MERGE_CHANGE_ID))
            .expect("merge succeeds")
        {
            MergeResult::Update(bytes) => Some(MessageData::deserialize(&bytes).expect("valid")),
            MergeResult::Skip => None,
            MergeResult::Delete => panic!("the merge never deletes"),
        }
    }

    #[test]
    fn the_merge_flips_only_the_presence_bit_and_stamps_the_new_change_id() {
        let keywords = (1 << SEEN) | (1 << UNSUBSCRIBED);
        let original = message(keywords, 77);
        let bytes = original.serialize().expect("serializable");

        let flagged = merged(&bytes, MetadataKinds::JMAP).expect("the bit is set");
        assert_eq!(flagged.keywords, keywords | HAS_JMAP_METADATA);
        assert_eq!(flagged.change_id, MERGE_CHANGE_ID);
        assert_eq!(flagged.metadata_kinds(), MetadataKinds::JMAP);
        assert_eq!(flagged.keywords_extra, original.keywords_extra);
        assert_eq!(flagged.mailboxes, original.mailboxes);
        assert_eq!(flagged.sent_at, original.sent_at);
        assert!(!flagged.has_keyword_changes(&original));

        let flagged_bytes = flagged.serialize().expect("serializable");
        assert!(merged(&flagged_bytes, MetadataKinds::JMAP).is_none());
        assert!(
            merged(
                &flagged_bytes,
                MetadataKinds::JMAP.union(MetadataKinds::DAV)
            )
            .is_none()
        );

        let cleared = merged(&flagged_bytes, MetadataKinds::NONE).expect("the bit is cleared");
        assert_eq!(cleared.keywords, keywords);
        assert_eq!(cleared.change_id, MERGE_CHANGE_ID);
        assert_eq!(cleared.metadata_kinds(), MetadataKinds::NONE);
        assert!(merged(&bytes, MetadataKinds::DAV).is_none());
    }

    fn clears_container(clear: impl FnOnce(&mut BatchBuilder)) -> bool {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(1)
            .with_collection(Collection::Email)
            .with_document(2);
        clear(&mut batch);
        batch.ops().iter().any(|op| {
            matches!(
                op,
                Operation::Value {
                    class: ValueClass::Metadata(MetadataClass::Shared),
                    op: ValueOp::Clear,
                }
            )
        })
    }

    fn archived<T: IndexableAndSerializableObject>(object: T) -> Archive<ArchiveBytes> {
        let bytes = Archiver::new(object).serialize().expect("serializable");
        <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("valid archive")
    }

    #[test]
    fn deleting_a_flagged_object_clears_its_container() {
        let plain = message(0, 1);
        let mut flagged = message(0, 1);
        flagged.set_metadata_kinds(MetadataKinds::JMAP);
        assert!(!clears_container(|batch| plain.clear(batch)));
        assert!(clears_container(|batch| flagged.clear(batch)));

        for kinds in [MetadataKinds::NONE, MetadataKinds::IMAP] {
            let mut mailbox = Mailbox::new("Folder");
            mailbox.set_metadata_kinds(kinds);
            let archive = archived(mailbox);
            let current = archive.to_unarchived::<Mailbox>().expect("valid");
            assert_eq!(
                clears_container(|batch| current.clear(batch)),
                !kinds.is_empty()
            );

            let mut script = SieveScript::default();
            script.set_metadata_kinds(kinds.union(MetadataKinds::JMAP));
            let archive = archived(script);
            let current = archive.to_unarchived::<SieveScript>().expect("valid");
            assert!(clears_container(|batch| current.clear(batch)));
        }

        let archive = archived(SieveScript::default());
        let current = archive.to_unarchived::<SieveScript>().expect("valid");
        assert!(!clears_container(|batch| current.clear(batch)));
    }

    #[test]
    fn the_merge_fails_when_the_message_is_gone() {
        assert!(apply_metadata_kinds(None, MetadataKinds::JMAP, Some(MERGE_CHANGE_ID)).is_err());
    }

    #[test]
    fn the_merge_fails_without_an_allocated_change_id() {
        let bytes = message(0, 77).serialize().expect("serializable");
        for kinds in [MetadataKinds::JMAP, MetadataKinds::NONE] {
            assert!(apply_metadata_kinds(Some(&bytes), kinds, None).is_err());
        }
    }

    #[test]
    fn the_merge_reads_the_change_id_of_the_email_group() {
        let mut ids = AssignedIds::default();
        ids.push_change_id(
            ChangeCounter {
                account_id: 1,
                group: SyncCollection::Calendar.change_group(),
            },
            40,
        );
        assert_eq!(ids.change_id(1, SyncCollection::Email.change_group()), None);
        ids.push_change_id(
            ChangeCounter {
                account_id: 1,
                group: SyncCollection::Email.change_group(),
            },
            MERGE_CHANGE_ID,
        );
        let bytes = message(0, 77).serialize().expect("serializable");
        let MergeResult::Update(bytes) = apply_metadata_kinds(
            Some(&bytes),
            MetadataKinds::JMAP,
            ids.change_id(1, SyncCollection::Email.change_group()),
        )
        .expect("merge succeeds") else {
            panic!("the bit was not set");
        };
        assert_eq!(
            MessageData::deserialize(&bytes).expect("valid").change_id,
            MERGE_CHANGE_ID
        );
    }

    #[test]
    fn a_stale_full_rewrite_fails_after_the_merge() {
        let stale = message(1 << SEEN, 77);
        let stored = stale.serialize().expect("serializable");
        let flagged = merged(&stored, MetadataKinds::JMAP).expect("the bit is set");
        let merged_bytes = flagged.serialize().expect("serializable");

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(1)
            .with_collection(Collection::Email)
            .with_document(2);
        stale.assert(&mut batch);
        let assertion = batch
            .ops()
            .iter()
            .find_map(|op| match op {
                Operation::AssertValue {
                    class: ValueClass::Property(field),
                    assert_value,
                } if *field == u8::from(Field::ARCHIVE) => Some(*assert_value),
                _ => None,
            })
            .expect("the full rewrite asserts the archive");
        assert!(assertion.matches(&stored));
        assert!(
            !assertion.matches(&merged_bytes),
            "a rewrite built before the presence merge must not overwrite the bit"
        );
    }

    #[test]
    fn email_presence_is_written_only_when_it_changes() {
        let added = MetadataPresence {
            before: MetadataKinds::NONE,
            after: MetadataKinds::JMAP,
        };
        let edited = MetadataPresence {
            before: MetadataKinds::JMAP,
            after: MetadataKinds::JMAP,
        };

        let mut batch = BatchBuilder::new();
        update_email_presence(&mut batch, 1, 2, MetadataKinds::JMAP, edited);
        assert!(batch.is_empty());
        update_email_presence(&mut batch, 1, 2, MetadataKinds::NONE, added);
        assert!(!batch.is_empty());

        let mut batch = BatchBuilder::new();
        update_email_presence(&mut batch, 1, 2, MetadataKinds::NONE, edited);
        assert!(!batch.is_empty(), "a stale flag is repaired");
    }

    #[test]
    fn stored_flags_only_expose_tracked_kinds() {
        let mut mailbox = Mailbox::new("Inbox");
        assert_eq!(mailbox.metadata_kinds(), MetadataKinds::NONE);
        mailbox.set_metadata_kinds(
            MetadataKinds::IMAP
                .union(MetadataKinds::DAV)
                .union(MetadataKinds::JMAP),
        );
        assert_eq!(
            mailbox.metadata_kinds(),
            MetadataKinds::IMAP.union(MetadataKinds::JMAP)
        );
        mailbox.metadata_flags = 0xFF;
        assert_eq!(mailbox.metadata_kinds(), Mailbox::TRACKED_METADATA);

        let mut script = SieveScript::default();
        script.set_metadata_kinds(MetadataKinds::IMAP);
        assert_eq!(script.metadata_kinds(), MetadataKinds::NONE);
        script.set_metadata_kinds(MetadataKinds::JMAP.union(MetadataKinds::IMAP));
        assert_eq!(script.metadata_kinds(), MetadataKinds::JMAP);
    }

    #[test]
    fn archive_presence_is_rewritten_only_on_a_mismatch() {
        let mut mailbox = Mailbox::new("Projects");
        mailbox.set_metadata_kinds(MetadataKinds::IMAP);
        let archive = archived(mailbox);
        let current = archive.to_unarchived::<Mailbox>().expect("valid mailbox");

        let mut batch = BatchBuilder::new();
        update_mailbox_presence(
            &mut batch,
            1,
            5,
            &current,
            MetadataPresence {
                before: MetadataKinds::IMAP,
                after: MetadataKinds::IMAP,
            },
        )
        .expect("no rewrite");
        assert!(batch.is_empty());

        update_mailbox_presence(
            &mut batch,
            1,
            5,
            &current,
            MetadataPresence {
                before: MetadataKinds::IMAP,
                after: MetadataKinds::IMAP.union(MetadataKinds::JMAP),
            },
        )
        .expect("rewrite");
        assert!(!batch.is_empty());
    }
}
