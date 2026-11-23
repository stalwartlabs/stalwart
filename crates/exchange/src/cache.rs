/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::store::{
    FolderKind,
    account::{EasDevice, ExchangeAccount, ExchangeAccountStore},
    alias::GroupwareKind,
    category::read_category_table,
    named::{NamedProperties, read_named_properties},
};
use ahash::AHashMap;
use common::{
    Inner, Server, UpdateLock, Verification,
    cache::{
        LockResult,
        exchange::{
            EXCHANGE_GROUPS, ExchangeAccountCache, ExchangeDevice, FolderKey, GroupwareAliases,
            GroupwarePlacement, NamedPropertyTable, Placement,
        },
    },
};
use std::sync::Arc;
use store::{
    query::log::{Change, Changes, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

const GROUPS: [SyncCollection; EXCHANGE_GROUPS] = [
    SyncCollection::Email,
    SyncCollection::Calendar,
    SyncCollection::AddressBook,
    SyncCollection::FileNode,
];

const ITEMS: [Collection; EXCHANGE_GROUPS] = [
    Collection::Email,
    Collection::CalendarEvent,
    Collection::ContactCard,
    Collection::FileNode,
];

const CONTAINERS: [Collection; EXCHANGE_GROUPS] = [
    Collection::Mailbox,
    Collection::Calendar,
    Collection::AddressBook,
    Collection::FileNode,
];

const ALIAS_WEIGHT: u64 = 48;
const DEVICE_WEIGHT: u64 = 96;
const FOLDER_WEIGHT: u64 = 32;
const REPLICA_WEIGHT: u64 = 16;

#[derive(Default)]
struct Aliases {
    items: AHashMap<u32, Placement>,
    placements: AHashMap<Placement, u32>,
    groupware: GroupwareAliases,
    folders: AHashMap<FolderKey, u32>,
    client_keys: AHashMap<u32, FolderKey>,
}

pub trait ExchangeCacheFetch: Sync + Send {
    fn get_cached_exchange(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<ExchangeAccountCache>>> + Send;

    fn build_exchange_cache(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<ExchangeAccountCache>> + Send;

    fn refresh_exchange_cache(
        &self,
        account_id: u32,
        cache: Arc<ExchangeAccountCache>,
    ) -> impl Future<Output = trc::Result<Arc<ExchangeAccountCache>>> + Send;

    fn publish_named_properties(&self, account_id: u32, table: NamedPropertyTable);

    fn mark_exchange_stale(&self, account_id: u32);
}

impl ExchangeCacheFetch for Server {
    async fn get_cached_exchange(&self, account_id: u32) -> trc::Result<Arc<ExchangeAccountCache>> {
        match self.inner.cache.exchange.get(&account_id) {
            Some(cache) => self.refresh_exchange_cache(account_id, cache).await,
            None => {
                let cache = Arc::new(self.build_exchange_cache(account_id).await?);
                self.inner.cache.exchange.insert(account_id, cache.clone());
                Ok(cache)
            }
        }
    }

    async fn build_exchange_cache(&self, account_id: u32) -> trc::Result<ExchangeAccountCache> {
        let change_ids = last_change_ids(self, account_id).await?;
        let account = match self
            .exchange_account(account_id)
            .await?
            .map(|account| account.deserialize::<ExchangeAccount>())
            .transpose()?
        {
            Some(account) if account.store_instance != 0 => account,
            _ => {
                self.update_exchange_account(account_id, |account| {
                    if account.store_instance == 0 {
                        account.store_instance = store::rand::random::<u64>() | 1;
                    }
                    Ok(())
                })
                .await?
                .0
            }
        };
        let named = match read_named_properties(self, account_id).await? {
            Some(named) => {
                NamedPropertyTable::from_names(&named.deserialize::<NamedProperties>()?.names)
            }
            None => NamedPropertyTable::default(),
        };
        let categories = read_category_table(self, account_id).await?;
        let objects = self.exchange_object_ids(account_id).await?;
        let aliases = load_aliases(self, account_id).await?;
        let update_lock = Arc::new(UpdateLock::new());
        let mut cache = ExchangeAccountCache {
            store_instance: account.store_instance,
            objects_epoch: account.objects_epoch,
            objects: objects.into(),
            aliases: Arc::new(aliases.items),
            aliased: Arc::new(aliases.placements),
            groupware_aliases: Arc::new(aliases.groupware),
            folder_aliases: Arc::new(aliases.folders),
            folder_aliased: Arc::new(aliases.client_keys),
            replicas: account.replicas.as_slice().into(),
            named: Arc::new(named),
            categories_version: account.categories_version,
            categories: Arc::new(categories),
            devices: devices(&account.devices),
            folder_change_ids: Arc::new(AHashMap::new()),
            folder_base: change_ids,
            change_ids,
            exchange_change: account.next_change.saturating_sub(1),
            revision: 0,
            verification: Verification::capture(&self.inner.cache.revalidate, &*update_lock),
            update_lock,
            containers: Default::default(),
            size: 0,
        };
        cache.size = weight(&cache);
        Ok(cache)
    }

    async fn refresh_exchange_cache(
        &self,
        account_id: u32,
        cache: Arc<ExchangeAccountCache>,
    ) -> trc::Result<Arc<ExchangeAccountCache>> {
        let revalidate = &self.inner.cache.revalidate;
        if cache.verification.is_fresh(&*cache.update_lock, revalidate) {
            return Ok(cache);
        }
        let update_lock = cache.update_lock.clone();
        let verification = Verification::capture(revalidate, &*update_lock);
        let _permit = match update_lock.acquire(cache.revision).await? {
            LockResult::Acquired(permit) => permit,
            LockResult::Stale(_) => {
                return Ok(self.inner.cache.exchange.get(&account_id).unwrap_or(cache));
            }
        };

        let change_ids = last_change_ids(self, account_id).await?;

        let account = self
            .exchange_account(account_id)
            .await?
            .map(|account| account.deserialize::<ExchangeAccount>())
            .transpose()?
            .unwrap_or_default();
        if account.store_instance != cache.store_instance
            || account.next_change.saturating_sub(1) < cache.exchange_change
            || change_ids
                .iter()
                .zip(cache.change_ids)
                .any(|(last, since)| *last < since)
        {
            return rebuild_exchange_cache(self, account_id, &cache, verification).await;
        }
        let mut windows: [Option<(Changes, u64)>; EXCHANGE_GROUPS] = Default::default();
        for (window, ((sync_collection, since), last)) in windows
            .iter_mut()
            .zip(GROUPS.into_iter().zip(cache.change_ids).zip(change_ids))
        {
            if since == last {
                continue;
            }
            let changes = self
                .store()
                .changes(account_id, sync_collection.into(), Query::Since(since))
                .await
                .caused_by(trc::location!())?;
            if changes.needs_full_rebuild(since) {
                return rebuild_exchange_cache(self, account_id, &cache, verification).await;
            }
            *window = Some((changes, last));
        }

        let mut next = (*cache).clone();
        next.revision += 1;
        if account.objects_epoch != cache.objects_epoch {
            let aliases = load_aliases(self, account_id).await?;
            next.objects = self.exchange_object_ids(account_id).await?.into();
            next.aliases = Arc::new(aliases.items);
            next.aliased = Arc::new(aliases.placements);
            next.groupware_aliases = Arc::new(aliases.groupware);
            next.folder_aliases = Arc::new(aliases.folders);
            next.folder_aliased = Arc::new(aliases.client_keys);
            next.objects_epoch = account.objects_epoch;
        }
        next.exchange_change = account.next_change.saturating_sub(1);
        if *next.replicas != *account.replicas {
            next.replicas = account.replicas.as_slice().into();
        }
        for (group, window) in windows.iter().enumerate() {
            if let Some((changes, last)) = window {
                apply_changes(
                    &mut next,
                    group,
                    &changes.changes,
                    changes.to_change_id.max(*last),
                );
            }
        }
        next.change_ids = change_ids;
        if usize::try_from(account.named_count).unwrap_or(usize::MAX) != next.named.names.len() {
            next.named = Arc::new(match read_named_properties(self, account_id).await? {
                Some(named) => {
                    NamedPropertyTable::from_names(&named.deserialize::<NamedProperties>()?.names)
                }
                None => NamedPropertyTable::default(),
            });
        }
        if account.categories_version != next.categories_version {
            next.categories = Arc::new(read_category_table(self, account_id).await?);
            next.categories_version = account.categories_version;
        }
        if !same_devices(&next.devices, &account.devices) {
            next.devices = devices(&account.devices);
        }
        next.verification = verification;
        next.size = weight(&next);
        update_lock.set_revision(next.revision);
        let next = Arc::new(next);
        self.inner.cache.exchange.insert(account_id, next.clone());
        Ok(next)
    }

    fn publish_named_properties(&self, account_id: u32, table: NamedPropertyTable) {
        if let Some(cache) = self.inner.cache.exchange.get(&account_id) {
            if table.names.len() > cache.named.names.len() {
                let mut next = (*cache).clone();
                next.named = Arc::new(table);
                next.size = weight(&next);
                self.inner.cache.exchange.insert(account_id, Arc::new(next));
            }
            cache.update_lock.mark_stale();
        }
    }

    fn mark_exchange_stale(&self, account_id: u32) {
        mark_stale(&self.inner, account_id);
    }
}

pub(crate) fn mark_stale(inner: &Inner, account_id: u32) {
    if let Some(cache) = inner.cache.exchange.peek(&account_id) {
        cache.update_lock.mark_stale();
    }
}

fn apply_changes(
    cache: &mut ExchangeAccountCache,
    group: usize,
    changes: &[Change],
    change_id: u64,
) {
    let (Some(items), Some(containers)) = (ITEMS.get(group), CONTAINERS.get(group)) else {
        return;
    };
    let mut deleted_items = RoaringBitmap::new();
    let mut deleted_containers = RoaringBitmap::new();
    let kind = u8::try_from(group).unwrap_or(u8::MAX);
    for change in changes {
        match *change {
            Change::DeleteItem(id) => {
                deleted_items.insert(id as u32);
            }
            Change::DeleteContainer(id) => {
                deleted_containers.insert(id as u32);
                Arc::make_mut(&mut cache.folder_change_ids).remove(&FolderKey {
                    kind,
                    id: id as u32,
                });
            }
            Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                Arc::make_mut(&mut cache.folder_change_ids).insert(
                    FolderKey {
                        kind,
                        id: id as u32,
                    },
                    change_id,
                );
            }
            _ => {}
        }
    }
    let hits = |collection: &Collection, ids: &RoaringBitmap| {
        (collection == items && !ids.is_disjoint(&deleted_items))
            || (collection == containers && !ids.is_disjoint(&deleted_containers))
    };
    if cache
        .objects
        .iter()
        .any(|(collection, ids)| hits(collection, ids))
    {
        for (collection, ids) in Arc::make_mut(&mut cache.objects).iter_mut() {
            if collection == items {
                *ids -= &deleted_items;
            }
            if collection == containers {
                *ids -= &deleted_containers;
            }
        }
    }
    if *items == Collection::Email && !deleted_items.is_empty() {
        let removed = deleted_items
            .iter()
            .filter_map(|id| cache.aliases.get(&id).map(|placement| (id, *placement)))
            .collect::<Vec<_>>();
        if !removed.is_empty() {
            let aliases = Arc::make_mut(&mut cache.aliases);
            let aliased = Arc::make_mut(&mut cache.aliased);
            for (id, placement) in removed {
                aliases.remove(&id);
                aliased.remove(&placement);
            }
        }
    } else if GroupwareKind::from_collection(*items).is_some()
        && cache.groupware_aliases.holds_any(kind, &deleted_items)
    {
        Arc::make_mut(&mut cache.groupware_aliases).remove(kind, &deleted_items);
    }
}

async fn rebuild_exchange_cache(
    server: &Server,
    account_id: u32,
    cache: &ExchangeAccountCache,
    verification: Verification,
) -> trc::Result<Arc<ExchangeAccountCache>> {
    let mut rebuilt = server.build_exchange_cache(account_id).await?;
    rebuilt.update_lock = cache.update_lock.clone();
    rebuilt.verification = verification;
    rebuilt.revision = cache.revision + 1;
    cache.update_lock.set_revision(rebuilt.revision);
    let rebuilt = Arc::new(rebuilt);
    server
        .inner
        .cache
        .exchange
        .insert(account_id, rebuilt.clone());
    Ok(rebuilt)
}

pub(crate) async fn last_change_ids(
    server: &Server,
    account_id: u32,
) -> trc::Result<[u64; EXCHANGE_GROUPS]> {
    let mut change_ids = [0u64; EXCHANGE_GROUPS];
    for (change_id, collection) in change_ids.iter_mut().zip(GROUPS) {
        *change_id = server
            .store()
            .get_last_change_id(account_id, collection.into())
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
    }
    Ok(change_ids)
}

async fn load_aliases(server: &Server, account_id: u32) -> trc::Result<Aliases> {
    let mut aliases = Aliases::default();
    server
        .exchange_aliases(account_id, |collection, document_id, placement| {
            if let Some(kind) = GroupwareKind::from_collection(collection) {
                aliases.groupware.insert(
                    document_id,
                    GroupwarePlacement {
                        folder: kind.folder(placement.container),
                        item: placement.item,
                    },
                );
                return true;
            }
            let kind = match collection {
                Collection::Email => {
                    let placement = Placement {
                        container: placement.container,
                        item: placement.item,
                    };
                    aliases.items.insert(document_id, placement);
                    aliases.placements.insert(placement, document_id);
                    return true;
                }
                Collection::Mailbox => FolderKind::Mailbox,
                Collection::Calendar => FolderKind::Calendar,
                Collection::AddressBook => FolderKind::AddressBook,
                Collection::FileNode => FolderKind::FileNode,
                _ => return true,
            };
            let folder = FolderKey {
                kind: kind as u8,
                id: document_id,
            };
            aliases.folders.insert(folder, placement.item);
            aliases.client_keys.insert(placement.item, folder);
            true
        })
        .await?;
    Ok(aliases)
}

fn same_devices(cached: &[ExchangeDevice], stored: &[EasDevice]) -> bool {
    cached.len() == stored.len()
        && cached.iter().zip(stored).all(|(cached, stored)| {
            cached.slot == stored.slot
                && cached.policy_key == stored.policy_key
                && cached.wipe == stored.wipe
                && *cached.device_id == *stored.device_id
                && *cached.device_type == *stored.device_type
        })
}

fn devices(devices: &[EasDevice]) -> Arc<[ExchangeDevice]> {
    devices
        .iter()
        .map(|device| ExchangeDevice {
            slot: device.slot,
            device_id: device.device_id.as_str().into(),
            device_type: device.device_type.as_str().into(),
            policy_key: device.policy_key,
            wipe: device.wipe,
        })
        .collect()
}

fn weight(cache: &ExchangeAccountCache) -> u64 {
    cache
        .objects
        .iter()
        .map(|(_, ids)| ids.serialized_size() as u64)
        .sum::<u64>()
        + ((cache.aliases.len() + cache.groupware_aliases.len() + cache.folder_aliases.len())
            as u64
            * ALIAS_WEIGHT
            * 2)
        + (cache.replicas.len() as u64 * REPLICA_WEIGHT)
        + cache.named.size()
        + cache.categories.size()
        + (cache.devices.len() as u64 * DEVICE_WEIGHT)
        + (cache.folder_change_ids.len() as u64 * FOLDER_WEIGHT)
        + cache
            .containers
            .load()
            .as_ref()
            .map_or(0, |meta| meta.size())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/cache/tests.rs"]
mod tests;
