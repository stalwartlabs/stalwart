/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{UpdateLock, Verification};
use ahash::AHashMap;
use arc_swap::ArcSwapOption;
use std::sync::Arc;
use store::{roaring::RoaringBitmap, write::metadata::ExchangeFolder};
use types::collection::Collection;
use utils::cache::CacheItemWeight;

pub const EXCHANGE_GROUPS: usize = 4;
const CONTAINER_META_WEIGHT: u64 = 64;
const CONTAINER_ENTRY_WEIGHT: u64 = 48;
const CATEGORY_WEIGHT: u64 = 32;
pub const MAX_FOREIGN_REPLICAS: usize = 1024;
pub const FIRST_FOREIGN_REPLID: u16 = 2;

pub fn foreign_replica_id(replicas: &[[u8; 16]], guid: &[u8; 16]) -> Option<u16> {
    replicas
        .iter()
        .position(|known| known == guid)
        .and_then(foreign_replid)
}

pub fn foreign_replid(index: usize) -> Option<u16> {
    u16::try_from(index).ok()?.checked_add(FIRST_FOREIGN_REPLID)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Placement {
    pub container: u32,
    pub item: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FolderKey {
    pub kind: u8,
    pub id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GroupwareDocument {
    kind: u8,
    document_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupwarePlacement {
    pub folder: FolderKey,
    pub item: u32,
}

#[derive(Debug, Default, Clone)]
pub struct GroupwareAliases {
    placements: AHashMap<GroupwareDocument, GroupwarePlacement>,
    documents: AHashMap<GroupwarePlacement, u32>,
}

#[derive(Debug, Clone)]
pub struct ExchangeDevice {
    pub slot: u16,
    pub device_id: Box<str>,
    pub device_type: Box<str>,
    pub policy_key: u32,
    pub wipe: u8,
}

#[derive(Debug, Default, Clone)]
pub struct NamedPropertyTable {
    pub names: Vec<Box<[u8]>>,
    pub ids: AHashMap<Box<[u8]>, u16>,
}

#[derive(Debug, Default, Clone)]
pub struct CategoryTable {
    entries: Box<[(Box<str>, Box<str>)]>,
}

#[derive(Debug, Clone)]
pub struct ExchangeAccountCache {
    pub store_instance: u64,
    pub objects_epoch: u64,
    pub objects: Arc<[(Collection, RoaringBitmap)]>,
    pub aliases: Arc<AHashMap<u32, Placement>>,
    pub aliased: Arc<AHashMap<Placement, u32>>,
    pub groupware_aliases: Arc<GroupwareAliases>,
    pub folder_aliases: Arc<AHashMap<FolderKey, u32>>,
    pub folder_aliased: Arc<AHashMap<u32, FolderKey>>,
    pub replicas: Arc<[[u8; 16]]>,
    pub named: Arc<NamedPropertyTable>,
    pub categories_version: u32,
    pub categories: Arc<CategoryTable>,
    pub devices: Arc<[ExchangeDevice]>,
    pub folder_change_ids: Arc<AHashMap<FolderKey, u64>>,
    pub folder_base: [u64; EXCHANGE_GROUPS],
    pub change_ids: [u64; EXCHANGE_GROUPS],
    pub exchange_change: u64,
    pub revision: u64,
    pub verification: Verification,
    pub update_lock: Arc<UpdateLock>,
    pub containers: Arc<ArcSwapOption<ContainerMeta>>,
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct ContainerMeta {
    pub calendar_change_id: u64,
    pub address_book_change_id: u64,
    pub entries: Box<[ContainerEntry]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEntry {
    pub kind: u8,
    pub id: u32,
    pub components: u8,
    pub parent: ExchangeFolder,
    pub name: Box<str>,
}

impl ContainerMeta {
    pub fn size(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.name.len() as u64 + CONTAINER_ENTRY_WEIGHT)
            .sum::<u64>()
            + CONTAINER_META_WEIGHT
    }
}

impl NamedPropertyTable {
    pub fn from_names(names: &[Vec<u8>]) -> Self {
        let mut table = NamedPropertyTable {
            names: Vec::with_capacity(names.len()),
            ids: AHashMap::with_capacity(names.len()),
        };
        for name in names {
            table.push(name.as_slice().into());
        }
        table
    }

    pub fn push(&mut self, name: Box<[u8]>) {
        if let Ok(index) = u16::try_from(self.names.len()) {
            self.ids.insert(name.clone(), index);
            self.names.push(name);
        }
    }

    pub fn size(&self) -> u64 {
        self.names
            .iter()
            .map(|name| (name.len() as u64 * 2) + 48)
            .sum()
    }
}

impl GroupwareAliases {
    pub fn insert(&mut self, document_id: u32, placement: GroupwarePlacement) {
        let document = GroupwareDocument {
            kind: placement.folder.kind,
            document_id,
        };
        if let Some(previous) = self.placements.insert(document, placement) {
            self.forget(previous, document_id);
        }
        self.documents.insert(placement, document_id);
    }

    pub fn document(&self, placement: GroupwarePlacement) -> Option<u32> {
        self.documents.get(&placement).copied()
    }

    pub fn placement(&self, kind: u8, document_id: u32) -> Option<GroupwarePlacement> {
        self.placements
            .get(&GroupwareDocument { kind, document_id })
            .copied()
    }

    pub fn holds_any(&self, kind: u8, document_ids: &RoaringBitmap) -> bool {
        !self.placements.is_empty()
            && document_ids
                .iter()
                .any(|document_id| self.placement(kind, document_id).is_some())
    }

    pub fn remove(&mut self, kind: u8, document_ids: &RoaringBitmap) {
        for document_id in document_ids {
            if let Some(placement) = self
                .placements
                .remove(&GroupwareDocument { kind, document_id })
            {
                self.forget(placement, document_id);
            }
        }
    }

    fn forget(&mut self, placement: GroupwarePlacement, document_id: u32) {
        if self.documents.get(&placement) == Some(&document_id) {
            self.documents.remove(&placement);
        }
    }

    pub fn len(&self) -> usize {
        self.placements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.placements.is_empty()
    }
}

impl CategoryTable {
    pub fn new(entries: impl IntoIterator<Item = (Box<str>, Box<str>)>) -> Self {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        entries.dedup_by(|(a, _), (b, _)| a == b);
        CategoryTable {
            entries: entries.into_boxed_slice(),
        }
    }

    pub fn spelling(&self, keyword: &str) -> Option<&str> {
        self.entries
            .binary_search_by(|(entry, _)| (**entry).cmp(keyword))
            .ok()
            .and_then(|index| self.entries.get(index))
            .map(|(_, name)| &**name)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn size(&self) -> u64 {
        self.entries
            .iter()
            .map(|(keyword, name)| (keyword.len() + name.len()) as u64 + CATEGORY_WEIGHT)
            .sum()
    }
}

impl ExchangeAccountCache {
    pub fn objects(&self, collection: Collection) -> Option<&RoaringBitmap> {
        self.objects
            .iter()
            .find(|(c, _)| *c == collection)
            .map(|(_, ids)| ids)
    }

    pub fn has_object(&self, collection: Collection, document_id: u32) -> bool {
        self.objects(collection)
            .is_some_and(|ids| ids.contains(document_id))
    }

    pub fn alias_of(&self, document_id: u32) -> Option<Placement> {
        self.aliases.get(&document_id).copied()
    }

    pub fn resolve_alias(&self, placement: Placement) -> Option<u32> {
        self.aliased.get(&placement).copied()
    }

    pub fn email_document(&self, container: u32, item: u32) -> u32 {
        if self.aliased.is_empty() {
            item
        } else {
            self.resolve_alias(Placement { container, item })
                .unwrap_or(item)
        }
    }

    pub fn email_item(&self, container: u32, document_id: u32) -> u32 {
        if self.aliases.is_empty() {
            document_id
        } else {
            self.alias_of(document_id)
                .filter(|placement| placement.container == container)
                .map_or(document_id, |placement| placement.item)
        }
    }

    pub fn groupware_document(&self, folder: FolderKey, item: u32) -> Option<u32> {
        self.groupware_aliases
            .document(GroupwarePlacement { folder, item })
    }

    pub fn groupware_item(&self, folder: FolderKey, document_id: u32) -> Option<u32> {
        self.groupware_aliases
            .placement(folder.kind, document_id)
            .filter(|placement| placement.folder == folder)
            .map(|placement| placement.item)
    }

    pub fn folder_client_key(&self, folder: FolderKey) -> Option<u32> {
        self.folder_aliases.get(&folder).copied()
    }

    pub fn resolve_folder_key(&self, client_key: u32) -> Option<FolderKey> {
        self.folder_aliased.get(&client_key).copied()
    }

    pub fn replica_id(&self, guid: &[u8; 16]) -> Option<u16> {
        foreign_replica_id(&self.replicas, guid)
    }

    pub fn replica_guid(&self, replid: u16) -> Option<&[u8; 16]> {
        replid
            .checked_sub(FIRST_FOREIGN_REPLID)
            .and_then(|index| self.replicas.get(usize::from(index)))
    }

    pub fn device(&self, device_id: &str) -> Option<&ExchangeDevice> {
        self.devices
            .iter()
            .find(|device| &*device.device_id == device_id)
    }

    pub fn containers(
        &self,
        calendar_change_id: u64,
        address_book_change_id: u64,
    ) -> Option<Arc<ContainerMeta>> {
        self.containers.load_full().filter(|meta| {
            meta.calendar_change_id == calendar_change_id
                && meta.address_book_change_id == address_book_change_id
        })
    }

    pub fn publish_containers(&self, meta: Arc<ContainerMeta>) {
        self.containers.store(Some(meta));
    }

    pub fn folder_change_id(&self, folder: FolderKey) -> Option<u64> {
        self.folder_change_ids
            .get(&folder)
            .or_else(|| self.folder_base.get(usize::from(folder.kind)))
            .copied()
    }
}

impl CacheItemWeight for ExchangeAccountCache {
    fn weight(&self) -> u64 {
        self.size
    }
}
