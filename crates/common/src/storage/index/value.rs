/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rkyv::{
    option::ArchivedOption,
    primitive::{ArchivedU32, ArchivedU64},
    string::ArchivedString,
};
use std::borrow::Cow;
use store::write::{PendingId, SearchIndex, ValueClass};
use types::{acl::AclGrant, blob_hash::BlobHash, collection::SyncCollection, field::Field};

pub const SEARCH_HASH_UNCHANGED: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue<'x> {
    Index {
        field: Field,
        value: IndexItem<'x>,
    },
    Property {
        field: ValueClass,
        value: IndexItem<'x>,
    },
    SearchIndex {
        index: SearchIndex,
        hash: u64,
    },
    Blob {
        value: BlobHash,
    },
    Quota {
        used: u32,
    },
    LogContainer {
        sync_collection: SyncCollection,
    },
    LogContainerProperty {
        sync_collection: SyncCollection,
        ids: Vec<PendingId>,
    },
    LogItem {
        sync_collection: SyncCollection,
        prefix: Option<PendingId>,
    },
    Acl {
        value: Cow<'x, [AclGrant]>,
    },
}

#[derive(Debug, Clone)]
pub enum IndexItem<'x> {
    Vec(Vec<u8>),
    Slice(&'x [u8]),
    ShortInt([u8; std::mem::size_of::<u32>()]),
    LongInt([u8; std::mem::size_of::<u64>()]),
    None,
}

impl IndexItem<'_> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            IndexItem::Vec(v) => v,
            IndexItem::Slice(s) => s,
            IndexItem::ShortInt(s) => s,
            IndexItem::LongInt(s) => s,
            IndexItem::None => &[],
        }
    }

    pub fn into_owned(self) -> Vec<u8> {
        match self {
            IndexItem::Vec(v) => v,
            IndexItem::Slice(s) => s.to_vec(),
            IndexItem::ShortInt(s) => s.to_vec(),
            IndexItem::LongInt(s) => s.to_vec(),
            IndexItem::None => vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            IndexItem::Vec(v) => v.is_empty(),
            IndexItem::Slice(s) => s.is_empty(),
            IndexItem::None => true,
            _ => false,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, IndexItem::None)
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }
}

impl PartialEq for IndexItem<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for IndexItem<'_> {}

impl std::hash::Hash for IndexItem<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            IndexItem::Vec(v) => v.as_slice().hash(state),
            IndexItem::Slice(s) => s.hash(state),
            IndexItem::ShortInt(s) => s.as_slice().hash(state),
            IndexItem::LongInt(s) => s.as_slice().hash(state),
            IndexItem::None => 0.hash(state),
        }
    }
}

impl From<u32> for IndexItem<'_> {
    fn from(value: u32) -> Self {
        IndexItem::ShortInt(value.to_be_bytes())
    }
}

impl From<&u32> for IndexItem<'_> {
    fn from(value: &u32) -> Self {
        IndexItem::ShortInt(value.to_be_bytes())
    }
}

impl From<u64> for IndexItem<'_> {
    fn from(value: u64) -> Self {
        IndexItem::LongInt(value.to_be_bytes())
    }
}

impl From<i64> for IndexItem<'_> {
    fn from(value: i64) -> Self {
        IndexItem::LongInt(value.to_be_bytes())
    }
}

impl<'x> From<&'x [u8]> for IndexItem<'x> {
    fn from(value: &'x [u8]) -> Self {
        IndexItem::Slice(value)
    }
}

impl From<Vec<u8>> for IndexItem<'_> {
    fn from(value: Vec<u8>) -> Self {
        IndexItem::Vec(value)
    }
}

impl<'x> From<&'x str> for IndexItem<'x> {
    fn from(value: &'x str) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl<'x> From<&'x String> for IndexItem<'x> {
    fn from(value: &'x String) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl From<String> for IndexItem<'_> {
    fn from(value: String) -> Self {
        IndexItem::Vec(value.into_bytes())
    }
}

impl<'x> From<&'x ArchivedString> for IndexItem<'x> {
    fn from(value: &'x ArchivedString) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl From<ArchivedU32> for IndexItem<'_> {
    fn from(value: ArchivedU32) -> Self {
        IndexItem::ShortInt(value.to_native().to_be_bytes())
    }
}

impl From<&ArchivedU32> for IndexItem<'_> {
    fn from(value: &ArchivedU32) -> Self {
        IndexItem::ShortInt(value.to_native().to_be_bytes())
    }
}

impl From<ArchivedU64> for IndexItem<'_> {
    fn from(value: ArchivedU64) -> Self {
        IndexItem::LongInt(value.to_native().to_be_bytes())
    }
}

impl<'x, T: Into<IndexItem<'x>>> From<Option<T>> for IndexItem<'x> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => v.into(),
            None => IndexItem::None,
        }
    }
}

impl<'x, T: Into<IndexItem<'x>>> From<ArchivedOption<T>> for IndexItem<'x> {
    fn from(value: ArchivedOption<T>) -> Self {
        match value {
            ArchivedOption::Some(v) => v.into(),
            ArchivedOption::None => IndexItem::None,
        }
    }
}
