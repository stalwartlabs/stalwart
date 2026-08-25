/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;
use types::collection::{SyncCollection, VanishedCollection};
use utils::codec::leb128::Leb128Iterator;

use crate::{
    IterateParams, LogKey, Store, U64_LEN,
    write::{
        LogCollection,
        key::DeserializeBigEndian,
        log::{
            CHANGE_LISTS, CONTAINER_DELETES, CONTAINER_INSERTS, CONTAINER_PROPERTY_CHANGES,
            CONTAINER_UPDATES, ITEM_DELETES, ITEM_INSERTS, ITEM_UPDATES, zigzag_decode,
        },
    },
};
use ahash::AHashMap;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    InsertContainer(u64),
    UpdateContainer(u64),
    UpdateContainerProperty(u64),
    DeleteContainer(u64),
    InsertItem(u64),
    UpdateItem(u64),
    DeleteItem(u64),
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
    discarded: Vec<bool>,
    has_discarded: bool,
    live: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum Query {
    All,
    Since(u64),
    SinceInclusive(u64),
    RangeInclusive(u64, u64),
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
            discarded: Vec::new(),
            has_discarded: false,
            live: 0,
        }
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
        let is_prefixed =
            matches!(collection_, LogCollection::Sync(collection) if collection.is_prefixed());
        let collection = u8::from(collection_);

        let (is_inclusive, from_change_id, to_change_id) = match query {
            Query::All => (true, 0, u64::MAX),
            Query::Since(change_id) => (false, change_id, u64::MAX),
            Query::SinceInclusive(change_id) => (true, change_id, u64::MAX),
            Query::RangeInclusive(from_change_id, to_change_id) => {
                (true, from_change_id, to_change_id)
            }
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
                    return Err(trc::Error::corrupted_key(key, value.into(), trc::location!()));
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
                    return Err(trc::Error::corrupted_key(key, value.into(), trc::location!()));
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
        let collection = u8::from(collection);
        let from_key = LogKey {
            account_id,
            collection,
            change_id: 0,
        };
        let to_key = LogKey {
            account_id,
            collection,
            change_id: u64::MAX,
        };

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
            let is_insert = matches!(
                self.changes[pos],
                Change::InsertContainer(_) | Change::InsertItem(_)
            );

            match change {
                Change::UpdateContainer(_)
                | Change::UpdateContainerProperty(_)
                | Change::UpdateItem(_)
                    if is_insert =>
                {
                    return;
                }
                Change::UpdateContainerProperty(_)
                    if matches!(self.changes[pos], Change::UpdateContainer(_)) =>
                {
                    return;
                }
                Change::DeleteContainer(_) | Change::DeleteItem(_) if is_insert => {
                    index.remove(&id);
                    self.discarded[pos] = true;
                    self.has_discarded = true;
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
        self.discarded.push(false);
        self.live += 1;
    }

    pub(crate) fn push_share_notification(&mut self, change_id: u64) {
        self.changes.push(Change::InsertItem(change_id));
        self.discarded.push(false);
        self.live += 1;
    }

    pub(crate) fn finalize(&mut self) {
        if self.has_discarded {
            let mut pos = 0;
            let discarded = std::mem::take(&mut self.discarded);
            self.changes.retain(|_| {
                let keep = !discarded[pos];
                pos += 1;
                keep
            });
            self.has_discarded = false;
        }

        self.discarded = Vec::new();
        self.container_index = AHashMap::new();
        self.item_index = AHashMap::new();
    }

    pub fn deserialize(&mut self, bytes: &[u8], is_prefixed: bool) -> Option<(bool, bool)> {
        let mut bytes_it = bytes.iter();
        let presence = *bytes_it.next()?;

        let mut counts = [0usize; CHANGE_LISTS];
        for (idx, count) in counts.iter_mut().enumerate() {
            if presence & (1 << idx) != 0 {
                *count = bytes_it.next_leb128()?;
            }
        }

        let has_container_changes = counts[CONTAINER_INSERTS]
            + counts[CONTAINER_UPDATES]
            + counts[CONTAINER_PROPERTY_CHANGES]
            + counts[CONTAINER_DELETES]
            > 0;
        let has_item_changes =
            counts[ITEM_INSERTS] + counts[ITEM_UPDATES] + counts[ITEM_DELETES] > 0;

        for (idx, count) in counts.iter().enumerate().take(ITEM_INSERTS) {
            let mut prev = 0u64;
            for _ in 0..*count {
                prev += bytes_it.next_leb128::<u64>()?;
                let change = match idx {
                    CONTAINER_INSERTS => Change::InsertContainer(prev),
                    CONTAINER_UPDATES => Change::UpdateContainer(prev),
                    CONTAINER_PROPERTY_CHANGES => Change::UpdateContainerProperty(prev),
                    _ => Change::DeleteContainer(prev),
                };
                self.push_change(prev, change, true);
            }
        }

        for (idx, count) in counts.iter().enumerate().skip(ITEM_INSERTS) {
            let mut prev_prefix = 0i64;
            let mut prev_document_id = 0i64;
            let mut prev_id = 0u64;

            for _ in 0..*count {
                let id = if is_prefixed {
                    prev_prefix += bytes_it.next_leb128::<u64>()? as i64;
                    prev_document_id += zigzag_decode(bytes_it.next_leb128::<u64>()?);
                    ((prev_prefix as u64) << 32) | (prev_document_id as u64 & u32::MAX as u64)
                } else {
                    prev_id += bytes_it.next_leb128::<u64>()?;
                    prev_id
                };

                let change = match idx {
                    ITEM_INSERTS => Change::InsertItem(id),
                    ITEM_UPDATES => Change::UpdateItem(id),
                    _ => Change::DeleteItem(id),
                };
                self.push_change(id, change, false);
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
            Change::InsertItem(id) => Some(*id),
            Change::UpdateItem(id) => Some(*id),
            Change::DeleteItem(id) => Some(*id),
            _ => None,
        }
    }

    pub fn container_id(&self) -> Option<u64> {
        match self {
            Change::InsertContainer(id) => Some(*id),
            Change::UpdateContainer(id) => Some(*id),
            Change::UpdateContainerProperty(id) => Some(*id),
            Change::DeleteContainer(id) => Some(*id),
            _ => None,
        }
    }

    pub fn try_unwrap_item_id(self) -> Option<u64> {
        match self {
            Change::InsertItem(id) => Some(id),
            Change::UpdateItem(id) => Some(id),
            Change::DeleteItem(id) => Some(id),
            _ => None,
        }
    }

    pub fn try_unwrap_container_id(self) -> Option<u64> {
        match self {
            Change::InsertContainer(id) => Some(id),
            Change::UpdateContainer(id) => Some(id),
            Change::UpdateContainerProperty(id) => Some(id),
            Change::DeleteContainer(id) => Some(id),
            _ => None,
        }
    }

    pub fn is_container_change(&self) -> bool {
        matches!(
            self,
            Change::InsertContainer(_)
                | Change::UpdateContainer(_)
                | Change::UpdateContainerProperty(_)
                | Change::DeleteContainer(_)
        )
    }

    pub fn is_item_change(&self) -> bool {
        matches!(
            self,
            Change::InsertItem(_) | Change::UpdateItem(_) | Change::DeleteItem(_)
        )
    }
}

pub(crate) fn decode_vanished_uids(bytes: &[u8], mailbox_id: u32, uids: &mut Vec<u32>) -> Option<()> {
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
        let mut pos = 0;

        while pos < bytes.len() {
            let mut bytes_it = bytes.get(pos..)?.iter();
            let len: usize = bytes_it.next_leb128()?;
            let start = bytes.len() - bytes_it.len();
            let end = start.checked_add(len)?;

            items.push(std::str::from_utf8(bytes.get(start..end)?).ok()?.to_string());
            pos = end;
        }

        Some(())
    }
}
