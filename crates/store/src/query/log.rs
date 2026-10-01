/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, LogKey, Store, U64_LEN,
    write::{
        LogCollection,
        key::DeserializeBigEndian,
        log::{
            BASE_LISTS, CHANGE_LISTS, CONTAINER_INSERTS, CONTAINER_LISTS, CONTAINER_METADATA,
            CONTAINER_PROPERTY_CHANGES, CONTAINER_UPDATES, ITEM_INSERTS, ITEM_METADATA,
            ITEM_UPDATES, PRESENCE_EXTENDED, zigzag_decode,
        },
    },
};
use ahash::AHashMap;
use std::slice::Iter;
use trc::AddContext;
use types::collection::{SyncCollection, VanishedCollection};
use utils::codec::leb128::{Leb128Iterator, Leb128Reader};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    InsertContainer(u64),
    UpdateContainer(u64),
    UpdateContainerPartial(u64, PartialChange),
    DeleteContainer(u64),
    InsertItem(u64),
    UpdateItem(u64),
    UpdateItemMetadata(u64),
    DeleteItem(u64),
}

const _: () = assert!(size_of::<Change>() == 16);

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
#[repr(transparent)]
pub struct PartialChange(u8);

impl PartialChange {
    pub const PROPERTIES: PartialChange = PartialChange(1);
    pub const METADATA: PartialChange = PartialChange(1 << 1);

    #[inline(always)]
    pub const fn has_properties(self) -> bool {
        self.0 & Self::PROPERTIES.0 != 0
    }

    #[inline(always)]
    pub const fn has_metadata(self) -> bool {
        self.0 & Self::METADATA.0 != 0
    }

    #[inline(always)]
    pub const fn is_metadata_only(self) -> bool {
        self.0 == Self::METADATA.0
    }

    #[inline(always)]
    pub const fn union(self, other: PartialChange) -> Self {
        PartialChange(self.0 | other.0)
    }
}

#[derive(Debug)]
pub struct Changes {
    pub changes: Vec<Change>,
    pub from_change_id: u64,
    pub to_change_id: u64,
    pub container_change_id: Option<u64>,
    pub item_change_id: Option<u64>,
    pub is_truncated: bool,
    container_index: AHashMap<u64, usize>,
    item_index: AHashMap<u64, usize>,
    discarded: Option<Vec<bool>>,
    live: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum Query {
    All,
    Since(u64),
    SinceInclusive(u64),
    RangeInclusive(u64, u64),
    Range(u64, u64),
}

pub trait DeserializeVanished: Sized + Sync + Send {
    fn deserialize_vanished(bytes: &[u8], items: &mut Vec<Self>) -> Option<()>;
}

impl Default for Changes {
    fn default() -> Self {
        Self {
            changes: Vec::with_capacity(10),
            from_change_id: 0,
            to_change_id: 0,
            container_change_id: None,
            item_change_id: None,
            is_truncated: false,
            container_index: AHashMap::new(),
            item_index: AHashMap::new(),
            discarded: None,
            live: 0,
        }
    }
}

impl Changes {
    pub fn needs_full_rebuild(&self, since: u64) -> bool {
        self.is_truncated || (since != 0 && self.to_change_id == 0)
    }
}

impl Store {
    pub async fn changes(
        &self,
        account_id: u32,
        collection_: LogCollection,
        query: Query,
    ) -> trc::Result<Changes> {
        let is_share_log = matches!(
            collection_,
            LogCollection::Sync(SyncCollection::ShareNotification)
        );
        let is_prefixed = collection_.is_prefixed();

        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
            Query::Range(from_change_id, to_change_id) => (false, from_change_id, to_change_id),
        };
        let from_key = collection_.log_key(account_id, from_change_id);
        let to_key = collection_.log_key(account_id, to_change_id);

        let mut changelog = Changes::default();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if is_inclusive || change_id != from_change_id {
                    if value.is_empty() {
                        changelog.is_truncated = true;
                        return Ok(true);
                    }
                    if changelog.live == 0 {
                        changelog.from_change_id = change_id;
                    }
                    changelog.to_change_id = change_id;
                    if !is_share_log {
                        let (has_container_changes, has_item_changes) =
                            changelog.deserialize(value, is_prefixed).ok_or_else(|| {
                                trc::Error::corrupted_key(key, value.into(), trc::location!())
                            })?;
                        if has_container_changes {
                            changelog.container_change_id = Some(change_id);
                        }
                        if has_item_changes {
                            changelog.item_change_id = Some(change_id);
                        }
                    } else {
                        changelog.push_share_notification(change_id);
                    }
                } else {
                    changelog.from_change_id = change_id;
                    changelog.to_change_id = change_id;
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        changelog.finalize();

        Ok(changelog)
    }

    pub async fn vanished<T: DeserializeVanished>(
        &self,
        account_id: u32,
        collection: LogCollection,
        query: Query,
    ) -> trc::Result<Vec<T>> {
        let collection = u8::from(collection);
        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
            Query::Range(from_change_id, to_change_id) => (false, from_change_id, to_change_id),
        };
        let from_key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: to_change_id,
        };

        let mut vanished = Vec::default();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if (is_inclusive || change_id != from_change_id)
                    && T::deserialize_vanished(value, &mut vanished).is_none()
                {
                    return Err(trc::Error::corrupted_key(
                        key,
                        value.into(),
                        trc::location!(),
                    ));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(vanished)
    }

    pub async fn vanished_uids(
        &self,
        account_id: u32,
        mailbox_id: u32,
        query: Query,
    ) -> trc::Result<Vec<u32>> {
        let collection = u8::from(LogCollection::Vanished(VanishedCollection::Email));
        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
            Query::Range(from_change_id, to_change_id) => (false, from_change_id, to_change_id),
        };
        let from_key = LogKey {
            account_id,
            collection,
            change_id: from_change_id,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: to_change_id,
        };

        let mut uids = Vec::new();

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if (is_inclusive || change_id != from_change_id)
                    && decode_vanished_uids(value, mailbox_id, &mut uids).is_none()
                {
                    return Err(trc::Error::corrupted_key(
                        key,
                        value.into(),
                        trc::location!(),
                    ));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(uids)
    }

    pub async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: LogCollection,
    ) -> trc::Result<Option<u64>> {
        let from_key = collection.log_key(account_id, 0);
        let to_key = collection.log_key(account_id, u64::MAX);

        let mut last_change_id = None;

        self.iterate(
            IterateParams::new(from_key, to_key)
                .descending()
                .no_values()
                .only_first(),
            |key, _| {
                last_change_id = key.deserialize_be_u64(key.len() - U64_LEN)?.into();
                Ok(false)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(last_change_id)
    }
}

impl From<VanishedCollection> for LogCollection {
    fn from(value: VanishedCollection) -> Self {
        LogCollection::Vanished(value)
    }
}

impl From<SyncCollection> for LogCollection {
    fn from(value: SyncCollection) -> Self {
        LogCollection::Sync(value)
    }
}

impl Changes {
    fn push_change(&mut self, id: u64, change: Change, is_container: bool) {
        let index = if is_container {
            &mut self.container_index
        } else {
            &mut self.item_index
        };

        if let Some(pos) = index.get(&id).copied() {
            let current = self.changes[pos];
            let (is_insert, is_update, is_delete) = match current {
                Change::InsertContainer(_) | Change::InsertItem(_) => (true, false, false),
                Change::UpdateContainer(_) | Change::UpdateItem(_) => (false, true, false),
                Change::DeleteContainer(_) | Change::DeleteItem(_) => (false, false, true),
                Change::UpdateContainerPartial(..) | Change::UpdateItemMetadata(_) => {
                    (false, false, false)
                }
            };

            match change {
                Change::UpdateContainer(_)
                | Change::UpdateContainerPartial(..)
                | Change::UpdateItem(_)
                | Change::UpdateItemMetadata(_)
                    if is_insert || is_delete =>
                {
                    return;
                }
                Change::UpdateContainerPartial(..) | Change::UpdateItemMetadata(_) if is_update => {
                    return;
                }
                Change::UpdateContainerPartial(_, partial) => {
                    if let Change::UpdateContainerPartial(_, current) = current {
                        self.changes[pos] =
                            Change::UpdateContainerPartial(id, current.union(partial));
                    } else {
                        self.changes[pos] = change;
                    }
                    return;
                }
                Change::DeleteContainer(_) | Change::DeleteItem(_) if is_insert => {
                    index.remove(&id);
                    self.discard(pos);
                    self.live -= 1;
                    return;
                }
                _ => {
                    self.changes[pos] = change;
                    return;
                }
            }
        }

        index.insert(id, self.changes.len());
        self.changes.push(change);
        self.live += 1;
    }

    fn discard(&mut self, pos: usize) {
        let discarded = self.discarded.get_or_insert_default();
        if discarded.len() <= pos {
            discarded.resize(pos + 1, false);
        }
        discarded[pos] = true;
    }

    pub(crate) fn push_share_notification(&mut self, change_id: u64) {
        self.changes.push(Change::InsertItem(change_id));
        self.live += 1;
    }

    pub(crate) fn finalize(&mut self) {
        if let Some(discarded) = self.discarded.take() {
            let mut pos = 0;
            self.changes.retain(|_| {
                let keep = !discarded.get(pos).copied().unwrap_or(false);
                pos += 1;
                keep
            });
        }

        self.container_index = AHashMap::new();
        self.item_index = AHashMap::new();
    }

    pub fn deserialize(&mut self, bytes: &[u8], is_prefixed: bool) -> Option<(bool, bool)> {
        let (&first, rest) = bytes.split_first()?;
        let mut bytes_it = rest.iter();
        let (mut has_container_changes, mut has_item_changes) = self.deserialize_lists(
            &mut bytes_it,
            u16::from(first & !PRESENCE_EXTENDED),
            is_prefixed,
        )?;

        if first & PRESENCE_EXTENDED != 0 {
            let extended = *bytes_it.next()?;
            if u32::from(extended) >> (CHANGE_LISTS - BASE_LISTS) != 0 {
                return None;
            }
            let (containers, items) = self.deserialize_lists(
                &mut bytes_it,
                u16::from(extended) << BASE_LISTS,
                is_prefixed,
            )?;
            has_container_changes |= containers;
            has_item_changes |= items;
        }

        Some((has_container_changes, has_item_changes))
    }

    #[inline(always)]
    fn deserialize_lists(
        &mut self,
        bytes_it: &mut Iter<'_, u8>,
        presence: u16,
        is_prefixed: bool,
    ) -> Option<(bool, bool)> {
        let mut counts = [0usize; CHANGE_LISTS];
        let mut bits = presence;
        while bits != 0 {
            let slot = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            *counts.get_mut(slot)? = bytes_it.next_leb128()?;
        }

        let mut has_container_changes = false;
        let mut has_item_changes = false;
        let mut bits = presence;
        while bits != 0 {
            let slot = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            let count = *counts.get(slot)?;

            if CONTAINER_LISTS & (1 << slot) != 0 {
                has_container_changes |= count > 0;
                let mut prev = 0u64;
                for _ in 0..count {
                    prev += bytes_it.next_leb128::<u64>()?;
                    let change = match slot {
                        CONTAINER_INSERTS => Change::InsertContainer(prev),
                        CONTAINER_UPDATES => Change::UpdateContainer(prev),
                        CONTAINER_PROPERTY_CHANGES => {
                            Change::UpdateContainerPartial(prev, PartialChange::PROPERTIES)
                        }
                        CONTAINER_METADATA => {
                            Change::UpdateContainerPartial(prev, PartialChange::METADATA)
                        }
                        _ => Change::DeleteContainer(prev),
                    };
                    self.push_change(prev, change, true);
                }
            } else {
                has_item_changes |= count > 0;
                let mut prev_prefix = 0i64;
                let mut prev_document_id = 0i64;
                let mut prev_id = 0u64;

                for _ in 0..count {
                    let id = if is_prefixed {
                        prev_prefix += bytes_it.next_leb128::<u64>()? as i64;
                        prev_document_id += zigzag_decode(bytes_it.next_leb128::<u64>()?);
                        ((prev_prefix as u64) << 32) | (prev_document_id as u64 & u32::MAX as u64)
                    } else {
                        prev_id += bytes_it.next_leb128::<u64>()?;
                        prev_id
                    };

                    let change = match slot {
                        ITEM_INSERTS => Change::InsertItem(id),
                        ITEM_UPDATES => Change::UpdateItem(id),
                        ITEM_METADATA => Change::UpdateItemMetadata(id),
                        _ => Change::DeleteItem(id),
                    };
                    self.push_change(id, change, false);
                }
            }
        }

        Some((has_container_changes, has_item_changes))
    }
}

impl Changes {
    pub fn total_container_changes(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.is_container_change())
            .count()
    }

    pub fn total_item_changes(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.is_item_change())
            .count()
    }
}

impl Change {
    pub fn item_id(&self) -> Option<u64> {
        match self {
            Change::InsertItem(id)
            | Change::UpdateItem(id)
            | Change::UpdateItemMetadata(id)
            | Change::DeleteItem(id) => Some(*id),
            _ => None,
        }
    }

    pub fn container_id(&self) -> Option<u64> {
        match self {
            Change::InsertContainer(id)
            | Change::UpdateContainer(id)
            | Change::UpdateContainerPartial(id, _)
            | Change::DeleteContainer(id) => Some(*id),
            _ => None,
        }
    }

    pub fn try_unwrap_item_id(self) -> Option<u64> {
        self.item_id()
    }

    pub fn try_unwrap_container_id(self) -> Option<u64> {
        self.container_id()
    }

    pub fn is_container_change(&self) -> bool {
        matches!(
            self,
            Change::InsertContainer(_)
                | Change::UpdateContainer(_)
                | Change::UpdateContainerPartial(..)
                | Change::DeleteContainer(_)
        )
    }

    pub fn is_item_change(&self) -> bool {
        matches!(
            self,
            Change::InsertItem(_)
                | Change::UpdateItem(_)
                | Change::UpdateItemMetadata(_)
                | Change::DeleteItem(_)
        )
    }

    pub fn is_metadata_only(&self) -> bool {
        match self {
            Change::UpdateItemMetadata(_) => true,
            Change::UpdateContainerPartial(_, partial) => partial.is_metadata_only(),
            _ => false,
        }
    }
}

pub(crate) fn decode_vanished_uids(
    bytes: &[u8],
    mailbox_id: u32,
    uids: &mut Vec<u32>,
) -> Option<()> {
    let mut bytes_it = bytes.iter();
    let mut group = 0u64;

    while let Some(group_delta) = bytes_it.next_leb128::<u64>() {
        group += group_delta;
        let count: usize = bytes_it.next_leb128()?;

        if group as u32 != mailbox_id {
            for _ in 0..count {
                bytes_it.next_leb128::<u64>()?;
            }
            continue;
        }

        let mut uid = 0u64;
        for _ in 0..count {
            uid += bytes_it.next_leb128::<u64>()?;
            uids.push(uid as u32);
        }
    }

    Some(())
}

impl DeserializeVanished for (u32, u32) {
    fn deserialize_vanished(bytes: &[u8], items: &mut Vec<Self>) -> Option<()> {
        let mut bytes_it = bytes.iter();
        let mut group = 0u64;

        while let Some(group_delta) = bytes_it.next_leb128::<u64>() {
            group += group_delta;
            let count: usize = bytes_it.next_leb128()?;

            let mut id = 0u64;
            for _ in 0..count {
                id += bytes_it.next_leb128::<u64>()?;
                items.push((group as u32, id as u32));
            }
        }

        Some(())
    }
}

impl DeserializeVanished for String {
    fn deserialize_vanished(bytes: &[u8], items: &mut Vec<Self>) -> Option<()> {
        let first = items.len();
        let mut pos = 0;

        while pos < bytes.len() {
            let shared = if items.len() != first {
                let (shared, read) = bytes.get(pos..)?.read_leb128::<usize>()?;
                pos += read;
                shared
            } else {
                0
            };
            let (len, read) = bytes.get(pos..)?.read_leb128::<usize>()?;
            pos += read;
            let end = pos.checked_add(len)?;
            let suffix = std::str::from_utf8(bytes.get(pos..end)?).ok()?;

            let mut name = String::with_capacity(shared + len);
            if shared != 0 {
                name.push_str(items.last()?.get(..shared)?);
            }
            name.push_str(suffix);
            items.push(name);
            pos = end;
        }

        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::Changes;

    #[test]
    fn a_change_log_without_the_cache_revision_needs_a_rebuild() {
        let empty = Changes::default();
        assert!(!empty.needs_full_rebuild(0));
        assert!(empty.needs_full_rebuild(7));

        let current = Changes {
            from_change_id: 7,
            to_change_id: 7,
            ..Default::default()
        };
        assert!(!current.needs_full_rebuild(7));

        let truncated = Changes {
            is_truncated: true,
            to_change_id: 12,
            ..Default::default()
        };
        assert!(truncated.needs_full_rebuild(7));
    }
}
