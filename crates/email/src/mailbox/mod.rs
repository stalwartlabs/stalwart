/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::PresenceFlags;
use store::{
    Deserialize, Serialize,
    write::{Archive, ArchiveBytes, Archiver, BatchBuilder, MergeResult},
};
use trc::AddContext;
use types::{acl::AclGrant, collection::SyncCollection, field::Field, special_use::SpecialUse};

pub mod destroy;
pub mod index;
pub mod manage;
pub mod role;

pub const INBOX_ID: u32 = 0;
pub const TRASH_ID: u32 = 1;
pub const JUNK_ID: u32 = 2;
pub const DRAFTS_ID: u32 = 3;
pub const SENT_ID: u32 = 4;
pub const ARCHIVE_ID: u32 = 5;

const ROLE_MASK: u16 = 0x000F;
pub(crate) const METADATA_SHIFT: u32 = 4;
pub(crate) const METADATA_MASK: u16 = 0x00F0;

const _: () = assert!(((Mailbox::TRACKED.bits() as u16) << METADATA_SHIFT) & !METADATA_MASK == 0);

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct Mailbox {
    pub name: String,
    pub parent_id: u32,
    pub sort_order: Option<u32>,
    pub uid_validity: u32,
    pub subscribers: Vec<u32>,
    pub acls: Vec<AclGrant>,
    pub flags: u16,
}

impl Mailbox {
    pub fn new(name: impl Into<String>) -> Self {
        Mailbox {
            name: name.into(),
            parent_id: 0,
            sort_order: None,
            uid_validity: rand::random::<u32>(),
            subscribers: vec![],
            acls: vec![],
            flags: 0,
        }
    }

    pub fn with_role(mut self, role: SpecialUse) -> Self {
        self.set_role(role);
        self
    }

    pub fn role(&self) -> SpecialUse {
        Self::role_of(self.flags)
    }

    pub fn set_role(&mut self, role: SpecialUse) {
        self.flags = (self.flags & !ROLE_MASK) | u16::from(role.id());
    }

    fn role_of(flags: u16) -> SpecialUse {
        SpecialUse::from_id((flags & ROLE_MASK) as u8)
    }

    pub fn with_parent_id(mut self, parent_id: u32) -> Self {
        self.parent_id = parent_id;
        self
    }

    pub fn with_sort_order(mut self, sort_order: u32) -> Self {
        self.sort_order = Some(sort_order);
        self
    }

    pub fn with_subscriber(mut self, subscriber: u32) -> Self {
        self.subscribers.push(subscriber);
        self
    }

    pub fn add_subscriber(&mut self, subscriber: u32) -> bool {
        if !self.subscribers.contains(&subscriber) {
            self.subscribers.push(subscriber);
            true
        } else {
            false
        }
    }

    pub fn remove_subscriber(&mut self, subscriber: u32) {
        self.subscribers.retain(|&x| x != subscriber);
    }

    pub fn is_subscribed(&self, subscriber: u32) -> bool {
        self.subscribers.contains(&subscriber)
    }
}

impl ArchivedMailbox {
    pub fn role(&self) -> SpecialUse {
        Mailbox::role_of(self.flags.to_native())
    }

    pub fn is_subscribed(&self, subscriber: u32) -> bool {
        self.subscribers.iter().any(|x| u32::from(x) == subscriber)
    }
}

pub fn merge_subscription(batch: &mut BatchBuilder, subscriber: u32, subscribe: bool) {
    batch.log_container_update(SyncCollection::Email);
    batch.merge_fnc(Field::ARCHIVE, move |_, bytes| {
        let Some(bytes) = bytes else {
            return Err(trc::StoreEvent::AssertValueFailed
                .into_err()
                .details("Mailbox no longer exists.")
                .caused_by(trc::location!()));
        };

        let mut mailbox = <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)
            .and_then(|archive| archive.deserialize::<Mailbox>())
            .caused_by(trc::location!())?;

        let changed = if subscribe {
            mailbox.add_subscriber(subscriber)
        } else {
            let was_subscribed = mailbox.is_subscribed(subscriber);
            mailbox.remove_subscriber(subscriber);
            was_subscribed
        };

        if changed {
            Archiver::new(mailbox).serialize().map(MergeResult::Update)
        } else {
            Ok(MergeResult::Skip)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::rancor::Error;
    use types::metadata::MetadataKinds;

    const SPECIAL_USES: [SpecialUse; 12] = [
        SpecialUse::None,
        SpecialUse::Inbox,
        SpecialUse::Trash,
        SpecialUse::Junk,
        SpecialUse::Drafts,
        SpecialUse::Archive,
        SpecialUse::Sent,
        SpecialUse::Shared,
        SpecialUse::Important,
        SpecialUse::Memos,
        SpecialUse::Scheduled,
        SpecialUse::Snoozed,
    ];

    fn all_kinds() -> impl Iterator<Item = MetadataKinds> {
        (0..=u8::MAX).map_while(MetadataKinds::from_bits)
    }

    fn tracked(kinds: MetadataKinds) -> MetadataKinds {
        MetadataKinds::from_bits(kinds.bits() & Mailbox::TRACKED.bits()).expect("valid kinds")
    }

    fn archived(mailbox: &Mailbox) -> (SpecialUse, MetadataKinds) {
        let bytes = rkyv::to_bytes::<Error>(mailbox).expect("the mailbox archives");
        let archived =
            rkyv::access::<ArchivedMailbox, Error>(&bytes).expect("the archive validates");
        (archived.role(), archived.metadata_kinds())
    }

    #[test]
    fn every_role_round_trips_with_every_presence_pattern() {
        assert_eq!(all_kinds().count(), 8);
        let fresh = Mailbox::new("Folder");
        assert_eq!(fresh.role(), SpecialUse::None);
        assert_eq!(fresh.metadata_kinds(), MetadataKinds::NONE);

        for (id, role) in SPECIAL_USES.into_iter().enumerate() {
            assert_eq!(usize::from(role.id()), id);
            assert_eq!(SpecialUse::from_id(role.id()), role);
            for kinds in all_kinds() {
                let mut mailbox = Mailbox::new("Folder").with_role(role);
                mailbox.set_metadata_kinds(kinds);
                assert_eq!(mailbox.role(), role);
                assert_eq!(mailbox.metadata_kinds(), tracked(kinds));
                assert_eq!(archived(&mailbox), (role, tracked(kinds)));

                let mut reversed = Mailbox::new("Folder");
                reversed.set_metadata_kinds(kinds);
                reversed.set_role(role);
                assert_eq!(reversed.flags, mailbox.flags);
            }
        }
    }

    #[test]
    fn role_and_presence_setters_do_not_clobber_each_other() {
        for start in [0, u16::MAX, 0x5A5A, 0xA5A5] {
            let mut mailbox = Mailbox::new("Folder");
            mailbox.flags = start;
            for role in SPECIAL_USES {
                let before = mailbox.flags;
                mailbox.set_role(role);
                assert_eq!(mailbox.role(), role);
                assert_eq!(mailbox.flags & !ROLE_MASK, before & !ROLE_MASK);
            }
            for kinds in all_kinds() {
                let before = mailbox.flags;
                mailbox.set_metadata_kinds(kinds);
                assert_eq!(mailbox.metadata_kinds(), tracked(kinds));
                assert_eq!(mailbox.flags & !METADATA_MASK, before & !METADATA_MASK);
            }
        }
    }

    #[test]
    fn unknown_role_bits_read_as_no_role() {
        for id in SPECIAL_USES.len() as u16..=ROLE_MASK {
            let mut mailbox = Mailbox::new("Folder");
            mailbox.flags = id | METADATA_MASK;
            assert_eq!(mailbox.role(), SpecialUse::None);
            assert_eq!(mailbox.metadata_kinds(), Mailbox::TRACKED);
            assert_eq!(archived(&mailbox), (SpecialUse::None, Mailbox::TRACKED));
        }
        for id in SPECIAL_USES.len() as u8..=u8::MAX {
            assert_eq!(SpecialUse::from_id(id), SpecialUse::None);
        }
    }

    #[test]
    fn archived_mailbox_size_is_pinned() {
        assert_eq!(size_of::<ArchivedMailbox>(), 39);
    }
}
