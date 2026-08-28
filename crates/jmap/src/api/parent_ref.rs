/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::write::{
    Slot,
    log::{PENDING_ID_MARKER, is_pending_id},
};
use types::id::Id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ParentRef(u64);

impl ParentRef {
    pub const ROOT: ParentRef = ParentRef(0);

    pub fn pending(slot: Slot) -> Self {
        ParentRef(PENDING_ID_MARKER | slot.index() as u64)
    }

    pub fn concrete(document_id: u32) -> Self {
        ParentRef(document_id as u64 + 1)
    }

    pub fn from_id(id: Id) -> Self {
        if is_pending_id(id.id()) {
            ParentRef(id.id())
        } else {
            ParentRef::concrete(id.document_id())
        }
    }

    pub fn from_stored(parent_id: u32) -> Self {
        ParentRef(parent_id as u64)
    }

    pub fn is_root(self) -> bool {
        self.0 == 0
    }

    pub fn is_pending(self) -> bool {
        is_pending_id(self.0)
    }

    pub fn slot(self) -> Option<Slot> {
        self.is_pending()
            .then(|| Slot::new((self.0 & u32::MAX as u64) as u32))
    }

    pub fn document_id(self) -> Option<u32> {
        (!self.is_root() && !self.is_pending()).then(|| (self.0 - 1) as u32)
    }

    pub fn key(self) -> Option<u64> {
        match self.0 {
            0 => None,
            parent if self.is_pending() => Some(parent),
            parent => Some(parent - 1),
        }
    }

    pub fn cache_id(self) -> Option<Option<u32>> {
        match self.0 {
            0 => Some(None),
            _ if self.is_pending() => None,
            parent => Some(Some((parent - 1) as u32)),
        }
    }

    pub fn as_stored(self) -> u32 {
        if self.is_pending() { 0 } else { self.0 as u32 }
    }
}
