/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::Guid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplId(pub u16);

impl ReplId {
    pub const LOCAL: Self = ReplId(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Globcnt(u64);

impl Globcnt {
    pub const MAX: u64 = 0xFFFF_FFFF_FFFF;

    pub const fn new(v: u64) -> Option<Self> {
        if v <= Self::MAX {
            Some(Globcnt(v))
        } else {
            None
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn to_wire(self) -> [u8; 6] {
        let [_, _, b0, b1, b2, b3, b4, b5] = self.0.to_be_bytes();
        [b0, b1, b2, b3, b4, b5]
    }

    pub const fn from_wire(b: [u8; 6]) -> Self {
        let [b0, b1, b2, b3, b4, b5] = b;
        Globcnt(u64::from_be_bytes([0, 0, b0, b1, b2, b3, b4, b5]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Eid {
    pub replid: ReplId,
    pub counter: Globcnt,
}

pub type Fid = Eid;
pub type Mid = Eid;
pub type Cn = Eid;

impl Eid {
    pub const fn new(replid: ReplId, counter: Globcnt) -> Self {
        Eid { replid, counter }
    }

    pub const fn to_wire(self) -> [u8; 8] {
        let [r0, r1] = self.replid.0.to_le_bytes();
        let [c0, c1, c2, c3, c4, c5] = self.counter.to_wire();
        [r0, r1, c0, c1, c2, c3, c4, c5]
    }

    pub const fn from_wire(b: [u8; 8]) -> Self {
        let [r0, r1, c0, c1, c2, c3, c4, c5] = b;
        Eid {
            replid: ReplId(u16::from_le_bytes([r0, r1])),
            counter: Globcnt::from_wire([c0, c1, c2, c3, c4, c5]),
        }
    }

    pub const fn to_le_u64(self) -> u64 {
        u64::from_le_bytes(self.to_wire())
    }

    pub const fn from_le_u64(v: u64) -> Self {
        Self::from_wire(v.to_le_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplGuid(pub Guid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gid {
    pub guid: ReplGuid,
    pub counter: Globcnt,
}

impl Gid {
    pub const LEN: usize = 22;

    pub fn to_wire(&self) -> [u8; 22] {
        let [
            g0,
            g1,
            g2,
            g3,
            g4,
            g5,
            g6,
            g7,
            g8,
            g9,
            g10,
            g11,
            g12,
            g13,
            g14,
            g15,
        ] = self.guid.0.0;
        let [c0, c1, c2, c3, c4, c5] = self.counter.to_wire();
        [
            g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15, c0, c1, c2, c3,
            c4, c5,
        ]
    }

    pub fn from_wire(b: &[u8]) -> Option<Self> {
        let (guid, counter) = b.split_first_chunk::<16>()?;
        let counter: [u8; 6] = counter.try_into().ok()?;
        Some(Gid {
            guid: ReplGuid(Guid(*guid)),
            counter: Globcnt::from_wire(counter),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LongTermId {
    pub gid: Gid,
}

impl LongTermId {
    pub const LEN: usize = 24;

    pub fn to_wire(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        if let Some((gid, _)) = out.split_first_chunk_mut::<22>() {
            *gid = self.gid.to_wire();
        }
        out
    }

    pub fn from_wire(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        let (gid, _) = b.split_first_chunk::<22>()?;
        Some(LongTermId {
            gid: Gid::from_wire(gid)?,
        })
    }
}
