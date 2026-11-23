/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    folders::{FolderNode, SpecialFolder},
    store::{
        FolderKind, FolderRef,
        alias::GroupwareKind,
        folder::{FaiClientKey, FaiKey},
    },
};
use common::cache::exchange::{EXCHANGE_GROUPS, ExchangeAccountCache, FolderKey};
use exchange_proto::ids::{Eid, Globcnt, ReplGuid, ReplId, Xid};
use types::collection::SyncCollection;

const SPACE_SHIFT: u32 = 44;
const SPACE_MASK: u64 = 0xF;
const ID_MASK: u64 = 0xFFFF_FFFF;
const RESERVED_MASK: u64 = ((1 << SPACE_SHIFT) - 1) & !ID_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum IdSpace {
    Fixed = 0,
    Mailbox = 1,
    Calendar = 2,
    AddressBook = 3,
    FileNode = 4,
    Virtual = 5,
    Email = 8,
    Event = 9,
    Contact = 10,
    File = 11,
    Fai = 12,
}

impl IdSpace {
    fn from_bits(bits: u64) -> Option<Self> {
        Some(match bits {
            0 => IdSpace::Fixed,
            1 => IdSpace::Mailbox,
            2 => IdSpace::Calendar,
            3 => IdSpace::AddressBook,
            4 => IdSpace::FileNode,
            5 => IdSpace::Virtual,
            8 => IdSpace::Email,
            9 => IdSpace::Event,
            10 => IdSpace::Contact,
            11 => IdSpace::File,
            12 => IdSpace::Fai,
            _ => return None,
        })
    }

    pub fn is_folder(self) -> bool {
        (self as u8) < 8
    }

    pub const fn of_groupware(kind: GroupwareKind) -> Self {
        match kind {
            GroupwareKind::Event => IdSpace::Event,
            GroupwareKind::Contact => IdSpace::Contact,
        }
    }

    pub const fn groupware(self) -> Option<GroupwareKind> {
        match self {
            IdSpace::Event => Some(GroupwareKind::Event),
            IdSpace::Contact => Some(GroupwareKind::Contact),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MapiId {
    pub space: IdSpace,
    pub id: u32,
}

impl MapiId {
    pub const fn new(space: IdSpace, id: u32) -> Self {
        MapiId { space, id }
    }

    pub const fn counter(self) -> u64 {
        ((self.space as u64) << SPACE_SHIFT) | self.id as u64
    }

    pub const fn to_eid(self) -> Eid {
        let counter = match Globcnt::new(self.counter()) {
            Some(counter) => counter,
            None => Globcnt::from_wire([0; 6]),
        };
        Eid::new(ReplId::LOCAL, counter)
    }

    pub fn from_counter(counter: u64) -> Option<Self> {
        if counter & RESERVED_MASK != 0 {
            return None;
        }
        let space = IdSpace::from_bits((counter >> SPACE_SHIFT) & SPACE_MASK)?;
        let id = u32::try_from(counter & ID_MASK).ok()?;
        Some(MapiId { space, id })
    }

    pub fn from_eid(eid: Eid) -> Option<Self> {
        if eid.replid == ReplId::LOCAL {
            Self::from_counter(eid.counter.get())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ChangeSpace {
    Email = SyncCollection::Email.change_group().to_u8(),
    Calendar = SyncCollection::Calendar.change_group().to_u8(),
    AddressBook = SyncCollection::AddressBook.change_group().to_u8(),
    FileNode = SyncCollection::FileNode.change_group().to_u8(),
    Exchange = 15,
}

const CN_COUNTER_MAX: u64 = (1 << SPACE_SHIFT) - 1;

const _: () = assert!((ChangeSpace::FileNode as u8) < ChangeSpace::Exchange as u8);

impl ChangeSpace {
    pub const CACHE_GROUPS: [ChangeSpace; EXCHANGE_GROUPS] = [
        ChangeSpace::Email,
        ChangeSpace::Calendar,
        ChangeSpace::AddressBook,
        ChangeSpace::FileNode,
    ];

    pub fn from_cache_group(index: usize) -> Option<Self> {
        Self::CACHE_GROUPS.get(index).copied()
    }

    const fn base(self) -> u64 {
        (self as u64) << SPACE_SHIFT
    }

    pub const fn cn(self, counter: u64) -> Option<ChangeNumber> {
        if counter == 0 || counter > CN_COUNTER_MAX {
            None
        } else {
            Some(ChangeNumber(low_globcnt(self.base() | counter)))
        }
    }

    pub const fn first(self) -> Globcnt {
        low_globcnt(self.base() | 1)
    }

    pub const fn counter_of(self, globcnt: Globcnt) -> Option<u64> {
        if globcnt.get() >> SPACE_SHIFT == self as u64 {
            Some(globcnt.get() & CN_COUNTER_MAX)
        } else {
            None
        }
    }
}

const fn low_globcnt(value: u64) -> Globcnt {
    let [_, _, b0, b1, b2, b3, b4, b5] = value.to_be_bytes();
    Globcnt::from_wire([b0, b1, b2, b3, b4, b5])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChangeNumber(Globcnt);

impl ChangeNumber {
    pub const fn from_globcnt(globcnt: Globcnt) -> Option<Self> {
        if globcnt.get() & CN_COUNTER_MAX == 0 {
            None
        } else {
            Some(ChangeNumber(globcnt))
        }
    }

    pub const fn globcnt(self) -> Globcnt {
        self.0
    }

    pub const fn counter(self) -> u64 {
        self.0.get() & CN_COUNTER_MAX
    }

    pub const fn to_eid(self) -> Eid {
        Eid::new(ReplId::LOCAL, self.0)
    }

    pub fn xid(self, guid: ReplGuid) -> Xid {
        Xid::from_cn(guid, self.0)
    }
}

impl MapiId {
    pub const fn special(folder: SpecialFolder) -> Self {
        MapiId::new(IdSpace::Fixed, folder.code() as u32 + 1)
    }

    pub const fn from_node(node: FolderNode) -> Self {
        match node {
            FolderNode::Special(folder) => MapiId::special(folder),
            FolderNode::Stored(folder) => MapiId::new(
                match folder.kind {
                    FolderKind::Mailbox => IdSpace::Mailbox,
                    FolderKind::Calendar => IdSpace::Calendar,
                    FolderKind::AddressBook => IdSpace::AddressBook,
                    FolderKind::FileNode => IdSpace::FileNode,
                    FolderKind::Virtual => IdSpace::Virtual,
                },
                folder.id,
            ),
        }
    }

    pub const fn client_fai(key: FaiClientKey) -> Self {
        MapiId::new(IdSpace::Fai, key.id())
    }

    pub fn from_client_fai(self) -> Option<Self> {
        match self.space {
            IdSpace::Fai => Some(self),
            IdSpace::Email => FaiClientKey::new(self.id).map(MapiId::client_fai),
            _ => None,
        }
    }

    pub const fn to_client_message(self) -> Self {
        match (self.space, FaiKey::from_id(self.id)) {
            (IdSpace::Fai, FaiKey::Client(key)) => MapiId::new(IdSpace::Email, key),
            _ => self,
        }
    }

    pub fn from_folder(exchange: &ExchangeAccountCache, node: FolderNode) -> Self {
        match node {
            FolderNode::Stored(FolderRef { kind, id }) => exchange
                .folder_client_key(FolderKey {
                    kind: kind as u8,
                    id,
                })
                .map_or_else(
                    || MapiId::from_node(node),
                    |key| MapiId::new(IdSpace::Email, key),
                ),
            FolderNode::Special(_) => MapiId::from_node(node),
        }
    }

    pub fn to_client(self, exchange: &ExchangeAccountCache) -> Self {
        self.to_node()
            .map_or(self, |node| MapiId::from_folder(exchange, node))
    }

    pub fn to_folder(self, exchange: &ExchangeAccountCache) -> Option<FolderNode> {
        if self.space != IdSpace::Email {
            return self.to_node();
        }
        let key = exchange.resolve_folder_key(self.id)?;
        Some(FolderNode::Stored(FolderRef {
            kind: FolderKind::from_code(key.kind)?,
            id: key.id,
        }))
    }

    pub fn to_node(self) -> Option<FolderNode> {
        let kind = match self.space {
            IdSpace::Fixed => {
                return u8::try_from(self.id.checked_sub(1)?)
                    .ok()
                    .and_then(SpecialFolder::from_code)
                    .map(FolderNode::Special);
            }
            IdSpace::Mailbox => FolderKind::Mailbox,
            IdSpace::Calendar => FolderKind::Calendar,
            IdSpace::AddressBook => FolderKind::AddressBook,
            IdSpace::FileNode => FolderKind::FileNode,
            IdSpace::Virtual => FolderKind::Virtual,
            _ => return None,
        };
        Some(FolderNode::Stored(FolderRef { kind, id: self.id }))
    }
}

pub mod fixed {
    use super::MapiId;
    use crate::folders::SpecialFolder;

    pub const ROOT: MapiId = MapiId::special(SpecialFolder::Root);
    pub const DEFERRED_ACTION: MapiId = MapiId::special(SpecialFolder::DeferredAction);
    pub const SPOOLER_QUEUE: MapiId = MapiId::special(SpecialFolder::SpoolerQueue);
    pub const IPM_SUBTREE: MapiId = MapiId::special(SpecialFolder::IpmSubtree);
    pub const OUTBOX: MapiId = MapiId::special(SpecialFolder::Outbox);
    pub const COMMON_VIEWS: MapiId = MapiId::special(SpecialFolder::CommonViews);
    pub const SCHEDULE: MapiId = MapiId::special(SpecialFolder::Schedule);
    pub const FINDER: MapiId = MapiId::special(SpecialFolder::Finder);
    pub const VIEWS: MapiId = MapiId::special(SpecialFolder::Views);
    pub const SHORTCUTS: MapiId = MapiId::special(SpecialFolder::Shortcuts);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/mapi/ids/tests.rs"]
mod tests;
