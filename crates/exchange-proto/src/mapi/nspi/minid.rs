/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MinimalId(pub u32);

const KIND_SHIFT: u32 = 30;
const LIST_FLAG: u32 = 0x2000_0000;
const VALUE_MASK: u32 = LIST_FLAG - 1;
const RESERVED: u32 = 0x10;

impl MinimalId {
    pub const BEGINNING_OF_TABLE: Self = MinimalId(0);
    pub const CURRENT: Self = MinimalId(1);
    pub const END_OF_TABLE: Self = MinimalId(2);
    pub const UNRESOLVED: Self = MinimalId(0);
    pub const AMBIGUOUS: Self = MinimalId(1);
    pub const RESOLVED: Self = MinimalId(2);
    pub const KIND_ADDRESS: u8 = 0;
    pub const KIND_CONTAINER: u8 = 1;
    pub const KIND_LIST: u8 = 2;
    pub const MAX_ID: u32 = VALUE_MASK - RESERVED;

    pub fn from_principal(kind: u8, id: u32) -> Option<Self> {
        let value = id.checked_add(RESERVED).filter(|v| *v <= VALUE_MASK)?;
        let prefix = match kind {
            Self::KIND_ADDRESS => 0,
            Self::KIND_CONTAINER => 1 << KIND_SHIFT,
            Self::KIND_LIST => LIST_FLAG,
            _ => return None,
        };
        Some(MinimalId(prefix | value))
    }

    pub fn principal(self) -> Option<(u8, u32)> {
        let kind = match (self.0 >> KIND_SHIFT, self.0 & LIST_FLAG != 0) {
            (0, false) => Self::KIND_ADDRESS,
            (0, true) => Self::KIND_LIST,
            (1, false) => Self::KIND_CONTAINER,
            _ => return None,
        };
        let id = (self.0 & VALUE_MASK).checked_sub(RESERVED)?;
        Some((kind, id))
    }

    pub fn is_reserved(self) -> bool {
        self.0 < RESERVED
    }
}
