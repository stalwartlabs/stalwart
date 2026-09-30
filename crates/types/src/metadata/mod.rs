/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod builder;
mod codec;
mod json;
mod limits;
mod registry;
mod view;
mod xml;

#[cfg(test)]
mod tests;

pub use builder::{EncodedMetadata, MetadataBuilder, MetadataEdit, STORAGE_TRAILER_CAPACITY};
pub use json::{EncodedJson, JsonError, JsonItems, JsonKind, JsonMembers, JsonView};
pub use limits::{LimitViolation, MetadataLimits, MetadataScope};
pub use registry::{
    Namespace, NamespaceError, NamespaceScope, NamespaceUsage, REGISTERED_NAMESPACES,
    RegisteredNamespace,
};
pub use view::{DavEntries, ImapEntries, JmapEntries, MetadataView};
pub use xml::{
    DavValueView, EncodedDavValue, XmlAttribute, XmlElement, XmlError, XmlName, XmlNode, XmlValue,
};

pub const FORMAT_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct MetadataKinds(u8);

impl MetadataKinds {
    pub const NONE: MetadataKinds = MetadataKinds(0);
    pub const JMAP: MetadataKinds = MetadataKinds(1);
    pub const DAV: MetadataKinds = MetadataKinds(1 << 1);
    pub const IMAP: MetadataKinds = MetadataKinds(1 << 2);
    const ALL: u8 = Self::JMAP.0 | Self::DAV.0 | Self::IMAP.0;

    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL == 0 {
            Some(MetadataKinds(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: MetadataKinds) -> bool {
        self.0 & other.0 == other.0 && other.0 != 0
    }

    pub const fn intersects(self, other: MetadataKinds) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: MetadataKinds) -> Self {
        MetadataKinds(self.0 | other.0)
    }

    pub fn insert(&mut self, other: MetadataKinds) {
        self.0 |= other.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub(crate) enum EntryKind {
    JmapVendor = 0,
    JmapRegistered = 1,
    Dav = 2,
    Imap = 3,
}

impl EntryKind {
    const MASK: u64 = 0b11;
    const SHIFT: u32 = 2;

    pub(crate) const fn from_code(code: u64) -> Self {
        match code & Self::MASK {
            0 => EntryKind::JmapVendor,
            1 => EntryKind::JmapRegistered,
            2 => EntryKind::Dav,
            _ => EntryKind::Imap,
        }
    }

    pub(crate) const fn code(self, value: u64) -> u64 {
        (value << Self::SHIFT) | self as u64
    }

    pub(crate) const fn kinds(self) -> MetadataKinds {
        match self {
            EntryKind::JmapVendor | EntryKind::JmapRegistered => MetadataKinds::JMAP,
            EntryKind::Dav => MetadataKinds::DAV,
            EntryKind::Imap => MetadataKinds::IMAP,
        }
    }
}
