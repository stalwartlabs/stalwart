/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::object::AnyId;
use store::{
    ahash::AHashMap,
    write::{
        Slot,
        log::{PENDING_ID_MARKER, is_pending_id},
    },
};
use types::id::Id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParentRef {
    #[default]
    Root,
    Node(u32),
    Pending(Slot),
}

impl ParentRef {
    pub const ROOT: ParentRef = ParentRef::Root;

    pub fn pending(slot: Slot) -> Self {
        ParentRef::Pending(slot)
    }

    pub fn concrete(document_id: u32) -> Self {
        ParentRef::Node(document_id)
    }

    pub fn from_id(id: Id) -> Self {
        if is_pending_id(id.id()) {
            ParentRef::Pending(Slot::new((id.id() & u32::MAX as u64) as u32))
        } else {
            ParentRef::Node(id.document_id())
        }
    }

    pub fn from_stored(parent_id: u32) -> Self {
        match parent_id {
            0 => ParentRef::Root,
            parent_id => ParentRef::Node(parent_id - 1),
        }
    }

    pub fn to_id(self) -> Option<Id> {
        match self {
            ParentRef::Root => None,
            ParentRef::Node(document_id) => Some(Id::from(document_id)),
            ParentRef::Pending(slot) => Some(Id::new(PENDING_ID_MARKER | slot.index() as u64)),
        }
    }

    pub fn is_root(self) -> bool {
        matches!(self, ParentRef::Root)
    }

    pub fn is_pending(self) -> bool {
        matches!(self, ParentRef::Pending(_))
    }

    pub fn slot(self) -> Option<Slot> {
        match self {
            ParentRef::Pending(slot) => Some(slot),
            _ => None,
        }
    }

    pub fn document_id(self) -> Option<u32> {
        match self {
            ParentRef::Node(document_id) => Some(document_id),
            _ => None,
        }
    }

    pub fn cache_id(self) -> Option<Option<u32>> {
        match self {
            ParentRef::Root => Some(None),
            ParentRef::Node(document_id) => Some(Some(document_id)),
            ParentRef::Pending(_) => None,
        }
    }

    pub fn as_stored(self) -> u32 {
        match self {
            ParentRef::Root | ParentRef::Pending(_) => 0,
            ParentRef::Node(document_id) => document_id + 1,
        }
    }

    fn as_packed(self) -> u64 {
        match self {
            ParentRef::Root => 0,
            ParentRef::Node(document_id) => document_id as u64 + 1,
            ParentRef::Pending(slot) => PENDING_ID_MARKER | slot.index() as u64,
        }
    }
}

impl std::hash::Hash for ParentRef {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.as_packed());
    }
}

pub struct CreateResolver<'x>(&'x AHashMap<String, Slot>);

impl<'x> CreateResolver<'x> {
    pub fn new(pending_creates: &'x AHashMap<String, Slot>) -> Self {
        CreateResolver(pending_creates)
    }

    pub fn created_id(&self, id_ref: &str) -> Option<AnyId> {
        self.0
            .get(id_ref)
            .and_then(|slot| ParentRef::Pending(*slot).to_id())
            .map(AnyId::Id)
    }

    fn contains_slot(&self, slot: Slot) -> bool {
        self.0.values().any(|created| *created == slot)
    }
}

impl ParentRef {
    pub fn from_client_id(id: Id, resolver: Option<&CreateResolver<'_>>) -> Option<Self> {
        match ParentRef::from_id(id) {
            ParentRef::Pending(slot)
                if resolver.is_none_or(|resolver| !resolver.contains_slot(slot)) =>
            {
                None
            }
            parent => Some(parent),
        }
    }
}
